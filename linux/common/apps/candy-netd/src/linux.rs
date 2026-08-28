use crate::NetworkError;
use candy_netd_proto::{
    Ipv4Prefix, PrepareDeclaration, RouteKind, UnderlayExclusion, CANDY_INTERFACE_NAME,
    CANDY_TABLE_MIN,
};

#[cfg(target_os = "linux")]
mod backend {
    use super::*;
    use crate::{nft, restore_sysctl_value, NetworkBackend, SysctlChange, SysctlKey};
    use futures_util::TryStreamExt;
    use netlink_packet_route::{
        link::{InfoKind, LinkAttribute, LinkInfo},
        route::{RouteAttribute, RouteMetric, RouteProtocol, RouteScope, RouteType},
        rule::{RuleAction, RuleAttribute},
    };
    use rtnetlink::{new_connection, Handle, LinkUnspec, RouteMessageBuilder};
    use std::fs::OpenOptions;
    use std::io::{Read, Write};
    use std::net::Ipv4Addr;
    use std::os::unix::fs::OpenOptionsExt;
    use std::path::Path;

    fn route_delete_is_idempotent(error: &rtnetlink::Error) -> bool {
        matches!(
            error,
            rtnetlink::Error::NetlinkError(message)
                if matches!(
                    message.to_io().raw_os_error(),
                    Some(nix::libc::ENOENT | nix::libc::ESRCH)
                )
        )
    }

    fn address_add_is_idempotent(error: &rtnetlink::Error) -> bool {
        matches!(
            error,
            rtnetlink::Error::NetlinkError(message)
                if message.to_io().raw_os_error() == Some(nix::libc::EEXIST)
        )
    }

    pub struct LinuxNetworkBackend {
        runtime: tokio::runtime::Runtime,
        handle: Handle,
    }

    impl LinuxNetworkBackend {
        pub fn new() -> Result<Self, NetworkError> {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .build()
                .map_err(|_| NetworkError::Backend)?;
            let guard = runtime.enter();
            let (connection, handle, _) = new_connection().map_err(|_| NetworkError::Backend)?;
            drop(guard);
            runtime.spawn(connection);
            Ok(Self { runtime, handle })
        }

        fn plan(declaration: &PrepareDeclaration) -> Result<LinuxNetworkPlan, NetworkError> {
            LinuxNetworkPlan::compile(declaration)
        }

        fn with_async<T>(
            &mut self,
            future: impl std::future::Future<Output = Result<T, NetworkError>>,
        ) -> Result<T, NetworkError> {
            self.runtime.block_on(future)
        }

        async fn candy_link(
            handle: &Handle,
        ) -> Result<Option<netlink_packet_route::link::LinkMessage>, NetworkError> {
            let mut links = handle
                .link()
                .get()
                .match_name(CANDY_INTERFACE_NAME.to_string())
                .execute();
            let link = links.try_next().await.map_err(|_| NetworkError::Backend)?;
            if links
                .try_next()
                .await
                .map_err(|_| NetworkError::Backend)?
                .is_some()
            {
                return Err(NetworkError::Backend);
            }
            Ok(link)
        }

        fn link_is_tun(link: &netlink_packet_route::link::LinkMessage) -> bool {
            link.attributes.iter().any(|attribute| {
                matches!(
                    attribute,
                    LinkAttribute::LinkInfo(values)
                        if values.iter().any(|value| matches!(value, LinkInfo::Kind(InfoKind::Tun)))
                )
            })
        }

        async fn rules_conflict(
            handle: &Handle,
            plan: &LinuxNetworkPlan,
        ) -> Result<bool, NetworkError> {
            let mut rules = handle.rule().get(rtnetlink::IpVersion::V4).execute();
            while let Some(rule) = rules.try_next().await.map_err(|_| NetworkError::Backend)? {
                let priority = rule.attributes.iter().find_map(|value| match value {
                    RuleAttribute::Priority(value) => Some(*value),
                    _ => None,
                });
                let table = rule.attributes.iter().find_map(|value| match value {
                    RuleAttribute::Table(value) => Some(*value),
                    _ => None,
                });
                if priority == Some(plan.policy_priority) || table == Some(plan.route_table) {
                    return Ok(true);
                }
            }
            Ok(false)
        }

        async fn route_conflict(
            handle: &Handle,
            plan: &LinuxNetworkPlan,
        ) -> Result<bool, NetworkError> {
            let query = RouteMessageBuilder::<Ipv4Addr>::new()
                .table_id(plan.route_table)
                .build();
            let mut routes = handle.route().get(query).execute();
            while let Some(route) = routes.try_next().await.map_err(|_| NetworkError::Backend)? {
                let table = route.attributes.iter().find_map(|value| match value {
                    RouteAttribute::Table(value) => Some(*value),
                    _ => None,
                });
                if table == Some(plan.route_table)
                    || (plan.route_table <= u8::MAX.into()
                        && u32::from(route.header.table) == plan.route_table)
                {
                    return Ok(true);
                }
            }
            Ok(false)
        }

        async fn link_index(handle: &Handle) -> Result<u32, NetworkError> {
            let link = Self::candy_link(handle)
                .await?
                .ok_or(NetworkError::Backend)?;
            if !Self::link_is_tun(&link) {
                return Err(NetworkError::Backend);
            }
            Ok(link.header.index)
        }

        async fn add_routes(handle: &Handle, plan: &LinuxNetworkPlan) -> Result<(), NetworkError> {
            let index = Self::link_index(handle).await?;
            for prefix in &plan.remote_routes {
                let mut route = RouteMessageBuilder::<Ipv4Addr>::new()
                    .destination_prefix(Ipv4Addr::from(prefix.network), prefix.prefix_len)
                    .output_interface(index)
                    .table_id(plan.route_table)
                    .protocol(RouteProtocol::Static)
                    .scope(RouteScope::Link)
                    .build();
                route.attributes.push(RouteAttribute::Metrics(vec![
                    RouteMetric::Mtu(u32::from(plan.route_mtu)),
                    RouteMetric::Advmss(u32::from(plan.tcp_advmss)),
                ]));
                handle
                    .route()
                    .add(route)
                    .execute()
                    .await
                    .map_err(|_| NetworkError::Backend)?;
            }
            for prefix in plan.throw_prefixes() {
                let route = RouteMessageBuilder::<Ipv4Addr>::new()
                    .destination_prefix(Ipv4Addr::from(prefix.network), prefix.prefix_len)
                    .table_id(plan.route_table)
                    .protocol(RouteProtocol::Static)
                    .kind(RouteType::Throw)
                    .build();
                handle
                    .route()
                    .add(route)
                    .execute()
                    .await
                    .map_err(|_| NetworkError::Backend)?;
            }
            Ok(())
        }

        async fn delete_routes(
            handle: &Handle,
            plan: &LinuxNetworkPlan,
        ) -> Result<(), NetworkError> {
            let Some(link) = Self::candy_link(handle).await? else {
                return Ok(());
            };
            if !Self::link_is_tun(&link) {
                return Err(NetworkError::Backend);
            }
            for prefix in &plan.remote_routes {
                let route = RouteMessageBuilder::<Ipv4Addr>::new()
                    .destination_prefix(Ipv4Addr::from(prefix.network), prefix.prefix_len)
                    .output_interface(link.header.index)
                    .table_id(plan.route_table)
                    .protocol(RouteProtocol::Static)
                    .scope(RouteScope::Link)
                    .build();
                if let Err(error) = handle.route().del(route).execute().await {
                    if !route_delete_is_idempotent(&error) {
                        return Err(NetworkError::Backend);
                    }
                }
            }
            for prefix in plan.throw_prefixes() {
                let route = RouteMessageBuilder::<Ipv4Addr>::new()
                    .destination_prefix(Ipv4Addr::from(prefix.network), prefix.prefix_len)
                    .table_id(plan.route_table)
                    .protocol(RouteProtocol::Static)
                    .kind(RouteType::Throw)
                    .build();
                if let Err(error) = handle.route().del(route).execute().await {
                    if !route_delete_is_idempotent(&error) {
                        return Err(NetworkError::Backend);
                    }
                }
            }
            Ok(())
        }

        async fn find_policy_rules(
            handle: &Handle,
            plan: &LinuxNetworkPlan,
        ) -> Result<Vec<netlink_packet_route::rule::RuleMessage>, NetworkError> {
            let mut found = Vec::new();
            let mut rules = handle.rule().get(rtnetlink::IpVersion::V4).execute();
            while let Some(rule) = rules.try_next().await.map_err(|_| NetworkError::Backend)? {
                let priority = rule.attributes.iter().find_map(|value| match value {
                    RuleAttribute::Priority(value) => Some(*value),
                    _ => None,
                });
                let table = rule.attributes.iter().find_map(|value| match value {
                    RuleAttribute::Table(value) => Some(*value),
                    _ => None,
                });
                if priority == Some(plan.policy_priority) && table == Some(plan.route_table) {
                    found.push(rule);
                }
            }
            Ok(found)
        }
    }

    impl NetworkBackend for LinuxNetworkBackend {
        fn preflight(
            &mut self,
            declaration: &PrepareDeclaration,
        ) -> Result<Vec<SysctlChange>, NetworkError> {
            let plan = Self::plan(declaration)?;
            nft::preflight_nft(&plan)?;
            let async_plan = plan.clone();
            let handle = self.handle.clone();
            self.with_async(async move {
                if Self::rules_conflict(&handle, &async_plan).await?
                    || Self::route_conflict(&handle, &async_plan).await?
                {
                    return Err(NetworkError::Backend);
                }
                if let Some(link) = Self::candy_link(&handle).await? {
                    if !Self::link_is_tun(&link) {
                        return Err(NetworkError::Backend);
                    }
                }
                Ok(())
            })?;
            snapshot_sysctls(declaration)
        }

        fn prepare_link(&mut self, declaration: &PrepareDeclaration) -> Result<(), NetworkError> {
            let plan = Self::plan(declaration)?;
            let handle = self.handle.clone();
            self.with_async(async move {
                let link = Self::candy_link(&handle)
                    .await?
                    .ok_or(NetworkError::Backend)?;
                if !Self::link_is_tun(&link) {
                    return Err(NetworkError::Backend);
                }
                handle
                    .link()
                    .set(
                        LinkUnspec::new_with_index(link.header.index)
                            .up()
                            .mtu(u32::from(plan.route_mtu))
                            .build(),
                    )
                    .execute()
                    .await
                    .map_err(|_| NetworkError::Backend)?;
                let result = handle
                    .address()
                    .add(
                        link.header.index,
                        Ipv4Addr::from(declaration.overlay_router_ipv4).into(),
                        32,
                    )
                    .execute()
                    .await;
                match result {
                    Ok(()) => Ok(()),
                    Err(error) if address_add_is_idempotent(&error) => Ok(()),
                    Err(_) => Err(NetworkError::Backend),
                }
            })
        }

        fn prepare_routes(&mut self, declaration: &PrepareDeclaration) -> Result<(), NetworkError> {
            let plan = Self::plan(declaration)?;
            let handle = self.handle.clone();
            self.with_async(async move { Self::add_routes(&handle, &plan).await })
        }

        fn prepare_firewall(
            &mut self,
            declaration: &PrepareDeclaration,
        ) -> Result<(), NetworkError> {
            nft::stage_firewall(
                &Self::plan(declaration)?,
                declaration.firewall.allow_forward,
                declaration.firewall.clamp_tcp_mss,
            )
        }

        fn prepare_sysctls(
            &mut self,
            _declaration: &PrepareDeclaration,
            changes: &[SysctlChange],
        ) -> Result<(), NetworkError> {
            for change in changes {
                write_sysctl(change.key, change.applied)?;
            }
            Ok(())
        }

        fn activate_link(&mut self, _declaration: &PrepareDeclaration) -> Result<(), NetworkError> {
            let handle = self.handle.clone();
            self.with_async(async move {
                let index = Self::link_index(&handle).await?;
                handle
                    .link()
                    .set(LinkUnspec::new_with_index(index).up().build())
                    .execute()
                    .await
                    .map_err(|_| NetworkError::Backend)
            })
        }

        fn update_link_mtu(
            &mut self,
            _declaration: &PrepareDeclaration,
            effective_mtu: u16,
        ) -> Result<(), NetworkError> {
            let handle = self.handle.clone();
            self.with_async(async move {
                let index = Self::link_index(&handle).await?;
                handle
                    .link()
                    .set(
                        LinkUnspec::new_with_index(index)
                            .mtu(u32::from(effective_mtu))
                            .build(),
                    )
                    .execute()
                    .await
                    .map_err(|_| NetworkError::Backend)
            })
        }

        fn install_policy_rule(
            &mut self,
            declaration: &PrepareDeclaration,
        ) -> Result<(), NetworkError> {
            let plan = Self::plan(declaration)?;
            let handle = self.handle.clone();
            self.with_async(async move {
                for (source, destination) in plan.policy_selectors() {
                    let request = handle.rule().add().v4().destination_prefix(
                        Ipv4Addr::from(destination.network),
                        destination.prefix_len,
                    );
                    let request = match source {
                        Some(source) => {
                            request.source_prefix(Ipv4Addr::from(source.network), source.prefix_len)
                        }
                        None => request,
                    };
                    request
                        .table_id(plan.route_table)
                        .priority(plan.policy_priority)
                        .action(RuleAction::ToTable)
                        .execute()
                        .await
                        .map_err(|_| NetworkError::Backend)?;
                }
                Ok(())
            })
        }

        fn remove_policy_rule(
            &mut self,
            declaration: &PrepareDeclaration,
        ) -> Result<(), NetworkError> {
            let plan = Self::plan(declaration)?;
            let handle = self.handle.clone();
            self.with_async(async move {
                let rules = Self::find_policy_rules(&handle, &plan).await?;
                let mut failed = false;
                for rule in rules {
                    if handle.rule().del(rule).execute().await.is_err() {
                        failed = true;
                    }
                }
                if failed {
                    return Err(NetworkError::Backend);
                }
                Ok(())
            })
        }

        fn deactivate_link(
            &mut self,
            _declaration: &PrepareDeclaration,
        ) -> Result<(), NetworkError> {
            let handle = self.handle.clone();
            self.with_async(async move {
                let Some(link) = Self::candy_link(&handle).await? else {
                    return Ok(());
                };
                if !Self::link_is_tun(&link) {
                    return Err(NetworkError::Backend);
                }
                handle
                    .link()
                    .set(LinkUnspec::new_with_index(link.header.index).down().build())
                    .execute()
                    .await
                    .map_err(|_| NetworkError::Backend)
            })
        }

        fn remove_firewall(
            &mut self,
            declaration: &PrepareDeclaration,
        ) -> Result<(), NetworkError> {
            nft::remove_firewall(&Self::plan(declaration)?)
        }

        fn remove_routes(&mut self, declaration: &PrepareDeclaration) -> Result<(), NetworkError> {
            let plan = Self::plan(declaration)?;
            let handle = self.handle.clone();
            self.with_async(async move { Self::delete_routes(&handle, &plan).await })
        }

        fn remove_link(&mut self, _declaration: &PrepareDeclaration) -> Result<(), NetworkError> {
            let handle = self.handle.clone();
            self.with_async(async move {
                let Some(link) = Self::candy_link(&handle).await? else {
                    return Ok(());
                };
                if !Self::link_is_tun(&link) {
                    return Err(NetworkError::Backend);
                }
                handle
                    .link()
                    .del(link.header.index)
                    .execute()
                    .await
                    .map_err(|_| NetworkError::Backend)
            })
        }

        fn restore_sysctls(
            &mut self,
            _declaration: &PrepareDeclaration,
            changes: &[SysctlChange],
        ) -> Result<(), NetworkError> {
            for change in changes.iter().rev() {
                let Some(current) = read_sysctl_for_restore(change.key)? else {
                    continue;
                };
                let original = change.original.to_string();
                let applied = change.applied.to_string();
                if restore_sysctl_value(&original, &applied, &current.to_string()).is_some() {
                    write_sysctl(change.key, change.original)?;
                }
            }
            Ok(())
        }
    }

    fn snapshot_sysctls(
        declaration: &PrepareDeclaration,
    ) -> Result<Vec<SysctlChange>, NetworkError> {
        let mut changes = Vec::new();
        if declaration.firewall.require_ipv4_forwarding {
            push_change(&mut changes, SysctlKey::Ipv4Forward, 1)?;
        }
        if declaration.firewall.manage_rp_filter {
            push_change(&mut changes, SysctlKey::AllRpFilter, 0)?;
            let candy_path = sysctl_path(SysctlKey::CandyRpFilter);
            if candy_path.exists() {
                push_change(&mut changes, SysctlKey::CandyRpFilter, 0)?;
            }
        }
        Ok(changes)
    }

    fn push_change(
        changes: &mut Vec<SysctlChange>,
        key: SysctlKey,
        applied: u8,
    ) -> Result<(), NetworkError> {
        let original = read_sysctl(key)?;
        if original != applied {
            changes.push(SysctlChange {
                key,
                original,
                applied,
            });
        }
        Ok(())
    }

    fn sysctl_path(key: SysctlKey) -> &'static Path {
        match key {
            SysctlKey::Ipv4Forward => Path::new("/proc/sys/net/ipv4/ip_forward"),
            SysctlKey::AllRpFilter => Path::new("/proc/sys/net/ipv4/conf/all/rp_filter"),
            SysctlKey::CandyRpFilter => Path::new("/proc/sys/net/ipv4/conf/candy0/rp_filter"),
        }
    }

    fn read_sysctl(key: SysctlKey) -> Result<u8, NetworkError> {
        read_sysctl_path(sysctl_path(key), false)?.ok_or(NetworkError::Backend)
    }

    fn read_sysctl_for_restore(key: SysctlKey) -> Result<Option<u8>, NetworkError> {
        read_sysctl_path(sysctl_path(key), key == SysctlKey::CandyRpFilter)
    }

    fn read_sysctl_path(path: &Path, missing_is_clean: bool) -> Result<Option<u8>, NetworkError> {
        let mut file = match OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW)
            .open(path)
        {
            Ok(file) => file,
            Err(error) if missing_is_clean && error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(None);
            }
            Err(_) => return Err(NetworkError::Backend),
        };
        let metadata = file.metadata().map_err(|_| NetworkError::Backend)?;
        if !metadata.file_type().is_file() {
            return Err(NetworkError::Backend);
        }
        let mut value = String::new();
        file.read_to_string(&mut value)
            .map_err(|_| NetworkError::Backend)?;
        match value.trim() {
            "0" => Ok(Some(0)),
            "1" => Ok(Some(1)),
            "2" => Ok(Some(2)),
            _ => Err(NetworkError::Backend),
        }
    }

    fn write_sysctl(key: SysctlKey, value: u8) -> Result<(), NetworkError> {
        let mut file = OpenOptions::new()
            .write(true)
            .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW)
            .open(sysctl_path(key))
            .map_err(|_| NetworkError::Backend)?;
        let metadata = file.metadata().map_err(|_| NetworkError::Backend)?;
        if !metadata.file_type().is_file() {
            return Err(NetworkError::Backend);
        }
        file.write_all(value.to_string().as_bytes())
            .map_err(|_| NetworkError::Backend)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn missing_interface_sysctl_is_clean_during_restore() {
            let missing = std::env::temp_dir()
                .join(format!("candy-netd-missing-sysctl-{}", std::process::id()));
            let _ = std::fs::remove_file(&missing);

            assert!(matches!(read_sysctl_path(&missing, true), Ok(None)));
            assert!(matches!(
                read_sysctl_path(&missing, false),
                Err(NetworkError::Backend)
            ));
        }
    }

    pub use LinuxNetworkBackend as ExportedLinuxNetworkBackend;
}

#[cfg(target_os = "linux")]
pub use backend::ExportedLinuxNetworkBackend as LinuxNetworkBackend;

pub const CANDY_POLICY_PRIORITY_MIN: u32 = 20_000;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct LinuxNetworkPlan {
    pub interface_name: &'static str,
    pub route_table: u32,
    pub policy_priority: u32,
    pub local_prefixes: Vec<Ipv4Prefix>,
    pub remote_routes: Vec<Ipv4Prefix>,
    pub remote_egress_gateway_routes: Vec<Ipv4Prefix>,
    pub exclusions: Vec<UnderlayExclusion>,
    pub nft_table_name: String,
    pub route_mtu: u16,
    pub tcp_advmss: u16,
    pub remote_egress: bool,
}

impl LinuxNetworkPlan {
    pub fn compile(declaration: &PrepareDeclaration) -> Result<Self, NetworkError> {
        declaration.validate().map_err(|_| NetworkError::Backend)?;
        let policy_priority = CANDY_POLICY_PRIORITY_MIN
            .checked_add(declaration.table_id - CANDY_TABLE_MIN)
            .ok_or(NetworkError::Backend)?;
        let remote_egress = declaration
            .routes
            .iter()
            .any(|route| route.kind == RouteKind::RemoteEgressGateway);
        let remote_egress_gateway_routes = declaration
            .routes
            .iter()
            .filter_map(|route| {
                (route.kind == RouteKind::RemoteEgressGateway).then_some(route.prefix)
            })
            .collect::<Vec<_>>();
        let remote_routes = declaration
            .routes
            .iter()
            .filter_map(|route| {
                matches!(
                    route.kind,
                    RouteKind::Remote | RouteKind::RemoteEgress | RouteKind::RemoteEgressGateway
                )
                .then_some(route.prefix)
            })
            .collect::<Vec<_>>();
        let local_prefixes = declaration
            .routes
            .iter()
            .filter_map(|route| (route.kind == RouteKind::Local).then_some(route.prefix))
            .collect::<Vec<_>>();
        Ok(Self {
            interface_name: CANDY_INTERFACE_NAME,
            route_table: declaration.table_id,
            policy_priority,
            local_prefixes,
            remote_routes,
            remote_egress_gateway_routes,
            exclusions: declaration.exclusions.clone(),
            nft_table_name: format!("candy_sdwan_{}", declaration.table_id),
            route_mtu: declaration.effective_mtu,
            tcp_advmss: declaration
                .effective_mtu
                .checked_sub(40)
                .ok_or(NetworkError::Backend)?,
            remote_egress,
        })
    }

    pub fn policy_selectors(&self) -> Vec<(Option<Ipv4Prefix>, Ipv4Prefix)> {
        self.remote_routes
            .iter()
            .flat_map(|destination| {
                // Replies from the public Internet arrive with arbitrary
                // source addresses. An egress gateway must route them back by
                // destination Site prefix alone; local-prefix source filters
                // are valid only for ordinary inter-Site forwarding.
                if self.remote_egress_gateway_routes.contains(destination)
                    || self.local_prefixes.is_empty()
                {
                    vec![(None, *destination)]
                } else {
                    self.local_prefixes
                        .iter()
                        .map(|source| (Some(*source), *destination))
                        .collect()
                }
            })
            .collect()
    }

    #[cfg(any(target_os = "linux", test))]
    fn throw_prefixes(&self) -> Vec<Ipv4Prefix> {
        let mut prefixes = self.local_prefixes.clone();
        prefixes.extend(self.exclusions.iter().map(|exclusion| exclusion.prefix));
        prefixes.sort_unstable();
        prefixes.dedup();
        prefixes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use candy_netd_proto::{FirewallPolicy, RouteDeclaration, UnderlayKind};

    #[test]
    fn local_networks_and_underlay_endpoints_bypass_remote_egress_rules() {
        let local = Ipv4Prefix::new([192, 168, 1, 0], 24).unwrap();
        let cloud = Ipv4Prefix::new([47, 83, 1, 189], 32).unwrap();
        let declaration = PrepareDeclaration {
            table_id: 20_614,
            overlay_router_ipv4: [100, 64, 0, 2],
            effective_mtu: 1_300,
            routes: vec![
                RouteDeclaration {
                    prefix: Ipv4Prefix::new([0, 0, 0, 0], 1).unwrap(),
                    kind: RouteKind::RemoteEgress,
                },
                RouteDeclaration {
                    prefix: Ipv4Prefix::new([128, 0, 0, 0], 1).unwrap(),
                    kind: RouteKind::RemoteEgress,
                },
                RouteDeclaration {
                    prefix: local,
                    kind: RouteKind::Local,
                },
            ],
            exclusions: vec![UnderlayExclusion {
                prefix: cloud,
                kind: UnderlayKind::CloudApi,
            }],
            firewall: FirewallPolicy {
                allow_forward: true,
                clamp_tcp_mss: true,
                require_ipv4_forwarding: true,
                manage_rp_filter: true,
            },
        };

        let plan = LinuxNetworkPlan::compile(&declaration).unwrap();
        assert_eq!(plan.throw_prefixes(), vec![cloud, local]);
    }
}

#![forbid(unsafe_code)]

use std::cmp::Ordering;
use thiserror::Error;

pub const NETD_PROTOCOL_VERSION: u64 = 1;
pub const CANDY_INTERFACE_NAME: &str = "candy0";
pub const CANDY_TABLE_MIN: u32 = 20_000;
pub const CANDY_TABLE_MAX: u32 = 20_999;
pub const MAX_NETD_FRAME_LEN: usize = 64 * 1024;
pub const MAX_ROUTES: usize = 4096;
pub const MAX_EXCLUSIONS: usize = 64;

#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub struct Ipv4Prefix {
    pub network: [u8; 4],
    pub prefix_len: u8,
}

impl Ipv4Prefix {
    pub fn new(network: [u8; 4], prefix_len: u8) -> Result<Self, NetdProtocolError> {
        if prefix_len == 0 || prefix_len > 32 {
            return Err(NetdProtocolError::InvalidDeclaration);
        }
        let value = u32::from_be_bytes(network);
        let mask = u32::MAX << (32 - prefix_len);
        if value & !mask != 0 {
            return Err(NetdProtocolError::InvalidDeclaration);
        }
        Ok(Self {
            network,
            prefix_len,
        })
    }

    pub fn contains(self, address: [u8; 4]) -> bool {
        let mask = u32::MAX << (32 - self.prefix_len);
        u32::from_be_bytes(address) & mask == u32::from_be_bytes(self.network)
    }

    pub fn overlaps(self, other: Self) -> bool {
        self.contains(other.network) || other.contains(self.network)
    }
}

impl Ord for Ipv4Prefix {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.network, self.prefix_len).cmp(&(other.network, other.prefix_len))
    }
}

impl PartialOrd for Ipv4Prefix {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[repr(u64)]
pub enum RouteKind {
    Local = 1,
    Remote = 2,
}

impl TryFrom<u64> for RouteKind {
    type Error = NetdProtocolError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Local),
            2 => Ok(Self::Remote),
            _ => Err(NetdProtocolError::UnknownEnum),
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct RouteDeclaration {
    pub prefix: Ipv4Prefix,
    pub kind: RouteKind,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[repr(u64)]
pub enum UnderlayKind {
    CloudApi = 1,
    HubEndpoint = 2,
    Management = 3,
}

impl TryFrom<u64> for UnderlayKind {
    type Error = NetdProtocolError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::CloudApi),
            2 => Ok(Self::HubEndpoint),
            3 => Ok(Self::Management),
            _ => Err(NetdProtocolError::UnknownEnum),
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct UnderlayExclusion {
    pub prefix: Ipv4Prefix,
    pub kind: UnderlayKind,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct FirewallPolicy {
    pub allow_forward: bool,
    pub clamp_tcp_mss: bool,
    pub require_ipv4_forwarding: bool,
    pub manage_rp_filter: bool,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PrepareDeclaration {
    pub table_id: u32,
    pub overlay_router_ipv4: [u8; 4],
    pub effective_mtu: u16,
    pub routes: Vec<RouteDeclaration>,
    pub exclusions: Vec<UnderlayExclusion>,
    pub firewall: FirewallPolicy,
}

impl PrepareDeclaration {
    pub fn validate(&self) -> Result<(), NetdProtocolError> {
        if !(CANDY_TABLE_MIN..=CANDY_TABLE_MAX).contains(&self.table_id)
            || !(576..=1400).contains(&self.effective_mtu)
            || self.routes.is_empty()
            || self.routes.len() > MAX_ROUTES
            || self.exclusions.is_empty()
            || self.exclusions.len() > MAX_EXCLUSIONS
        {
            return Err(NetdProtocolError::InvalidDeclaration);
        }
        if !strictly_sorted_by(&self.routes, |route| (route.prefix, route.kind as u64))
            || !strictly_sorted_by(&self.exclusions, |value| (value.prefix, value.kind as u64))
            || has_prefix_overlap(self.routes.iter().map(|route| route.prefix))
            || has_prefix_overlap(self.exclusions.iter().map(|value| value.prefix))
            || self.routes.iter().any(|route| {
                self.exclusions
                    .iter()
                    .any(|exclusion| route.prefix.overlaps(exclusion.prefix))
            })
            || self
                .routes
                .iter()
                .any(|route| route.prefix.contains(self.overlay_router_ipv4))
            || self
                .exclusions
                .iter()
                .any(|value| value.prefix.contains(self.overlay_router_ipv4))
            || self.overlay_router_ipv4 == [0; 4]
            || self.overlay_router_ipv4[0] >= 224
        {
            return Err(NetdProtocolError::InvalidDeclaration);
        }
        Ok(())
    }
}

fn strictly_sorted_by<T, K: Ord>(values: &[T], key: impl Fn(&T) -> K) -> bool {
    values.windows(2).all(|pair| key(&pair[0]) < key(&pair[1]))
}

fn has_prefix_overlap(prefixes: impl IntoIterator<Item = Ipv4Prefix>) -> bool {
    let values: Vec<Ipv4Prefix> = prefixes.into_iter().collect();
    values.iter().enumerate().any(|(index, prefix)| {
        values[index + 1..]
            .iter()
            .any(|other| prefix.overlaps(*other))
    })
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct LeaseOwner {
    pub instance_id: [u8; 16],
    pub pid: u32,
    pub generation: u64,
    pub lease_deadline_mono_ms: u64,
}

impl LeaseOwner {
    fn validate(self) -> Result<(), NetdProtocolError> {
        if self.instance_id == [0; 16]
            || self.pid == 0
            || self.generation == 0
            || self.lease_deadline_mono_ms == 0
        {
            return Err(NetdProtocolError::InvalidOwner);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum NetdOperation {
    Prepare(PrepareDeclaration),
    Commit,
    Rollback,
    Status,
    LeaseRenew,
    MtuUpdate { effective_mtu: u16 },
}

impl NetdOperation {
    fn tag(&self) -> u64 {
        match self {
            Self::Prepare(_) => 1,
            Self::Commit => 2,
            Self::Rollback => 3,
            Self::Status => 4,
            Self::LeaseRenew => 5,
            Self::MtuUpdate { .. } => 6,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct NetdRequest {
    pub request_id: u64,
    pub owner: LeaseOwner,
    pub operation: NetdOperation,
}

impl NetdRequest {
    pub fn validate(&self) -> Result<(), NetdProtocolError> {
        if self.request_id == 0 {
            return Err(NetdProtocolError::InvalidRequest);
        }
        self.owner.validate()?;
        if let NetdOperation::Prepare(value) = &self.operation {
            value.validate()?;
        }
        if let NetdOperation::MtuUpdate { effective_mtu } = &self.operation {
            if !(576..=1400).contains(effective_mtu) {
                return Err(NetdProtocolError::InvalidDeclaration);
            }
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, NetdProtocolError> {
        self.validate()?;
        let mut out = Vec::new();
        varint(NETD_PROTOCOL_VERSION, &mut out);
        varint(self.operation.tag(), &mut out);
        varint(self.request_id, &mut out);
        out.extend_from_slice(&self.owner.instance_id);
        varint(u64::from(self.owner.pid), &mut out);
        varint(self.owner.generation, &mut out);
        varint(self.owner.lease_deadline_mono_ms, &mut out);
        if let NetdOperation::Prepare(value) = &self.operation {
            encode_declaration(value, &mut out);
        }
        if let NetdOperation::MtuUpdate { effective_mtu } = &self.operation {
            varint(u64::from(*effective_mtu), &mut out);
        }
        ensure_frame(&out)?;
        Ok(out)
    }

    pub fn decode(input: &[u8]) -> Result<Self, NetdProtocolError> {
        ensure_frame(input)?;
        let mut reader = Reader::new(input);
        if reader.varint()? != NETD_PROTOCOL_VERSION {
            return Err(NetdProtocolError::UnsupportedVersion);
        }
        let tag = reader.varint()?;
        let request_id = reader.varint()?;
        let owner = LeaseOwner {
            instance_id: reader.fixed()?,
            pid: u32::try_from(reader.varint()?).map_err(|_| NetdProtocolError::InvalidOwner)?,
            generation: reader.varint()?,
            lease_deadline_mono_ms: reader.varint()?,
        };
        let operation = match tag {
            1 => NetdOperation::Prepare(decode_declaration(&mut reader)?),
            2 => NetdOperation::Commit,
            3 => NetdOperation::Rollback,
            4 => NetdOperation::Status,
            5 => NetdOperation::LeaseRenew,
            6 => NetdOperation::MtuUpdate {
                effective_mtu: u16::try_from(reader.varint()?)
                    .map_err(|_| NetdProtocolError::InvalidDeclaration)?,
            },
            _ => return Err(NetdProtocolError::UnknownEnum),
        };
        reader.finish()?;
        let value = Self {
            request_id,
            owner,
            operation,
        };
        value.validate()?;
        Ok(value)
    }
}

fn encode_declaration(value: &PrepareDeclaration, out: &mut Vec<u8>) {
    varint(u64::from(value.table_id), out);
    out.extend_from_slice(&value.overlay_router_ipv4);
    varint(u64::from(value.effective_mtu), out);
    varint(value.routes.len() as u64, out);
    for route in &value.routes {
        encode_prefix(route.prefix, out);
        varint(route.kind as u64, out);
    }
    varint(value.exclusions.len() as u64, out);
    for exclusion in &value.exclusions {
        encode_prefix(exclusion.prefix, out);
        varint(exclusion.kind as u64, out);
    }
    for flag in [
        value.firewall.allow_forward,
        value.firewall.clamp_tcp_mss,
        value.firewall.require_ipv4_forwarding,
        value.firewall.manage_rp_filter,
    ] {
        varint(u64::from(flag), out);
    }
}

fn decode_declaration(reader: &mut Reader<'_>) -> Result<PrepareDeclaration, NetdProtocolError> {
    let table_id =
        u32::try_from(reader.varint()?).map_err(|_| NetdProtocolError::InvalidDeclaration)?;
    let overlay_router_ipv4 = reader.fixed()?;
    let effective_mtu =
        u16::try_from(reader.varint()?).map_err(|_| NetdProtocolError::InvalidDeclaration)?;
    let route_count = reader.count(1, MAX_ROUTES)?;
    let mut routes = Vec::with_capacity(route_count);
    for _ in 0..route_count {
        routes.push(RouteDeclaration {
            prefix: reader.prefix()?,
            kind: RouteKind::try_from(reader.varint()?)?,
        });
    }
    let exclusion_count = reader.count(1, MAX_EXCLUSIONS)?;
    let mut exclusions = Vec::with_capacity(exclusion_count);
    for _ in 0..exclusion_count {
        exclusions.push(UnderlayExclusion {
            prefix: reader.prefix()?,
            kind: UnderlayKind::try_from(reader.varint()?)?,
        });
    }
    let firewall = FirewallPolicy {
        allow_forward: reader.boolean()?,
        clamp_tcp_mss: reader.boolean()?,
        require_ipv4_forwarding: reader.boolean()?,
        manage_rp_filter: reader.boolean()?,
    };
    let value = PrepareDeclaration {
        table_id,
        overlay_router_ipv4,
        effective_mtu,
        routes,
        exclusions,
        firewall,
    };
    value.validate()?;
    Ok(value)
}

fn encode_prefix(prefix: Ipv4Prefix, out: &mut Vec<u8>) {
    out.extend_from_slice(&prefix.network);
    varint(u64::from(prefix.prefix_len), out);
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[repr(u64)]
pub enum ErrorCode {
    InvalidRequest = 1,
    UnauthorizedPeer = 2,
    GenerationConflict = 3,
    PreflightFailed = 4,
    SystemFailure = 5,
}

impl TryFrom<u64> for ErrorCode {
    type Error = NetdProtocolError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::InvalidRequest),
            2 => Ok(Self::UnauthorizedPeer),
            3 => Ok(Self::GenerationConflict),
            4 => Ok(Self::PreflightFailed),
            5 => Ok(Self::SystemFailure),
            _ => Err(NetdProtocolError::UnknownEnum),
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[repr(u64)]
pub enum SessionPhase {
    Stopped = 1,
    Prepared = 2,
    Active = 3,
}

impl TryFrom<u64> for SessionPhase {
    type Error = NetdProtocolError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Stopped),
            2 => Ok(Self::Prepared),
            3 => Ok(Self::Active),
            _ => Err(NetdProtocolError::UnknownEnum),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ResponseBody {
    Prepared {
        generation: u64,
        tun_fd_attached: bool,
    },
    Committed {
        generation: u64,
    },
    RolledBack {
        generation: u64,
    },
    Status {
        phase: SessionPhase,
        generation: u64,
    },
    LeaseRenewed {
        generation: u64,
    },
    MtuUpdated {
        generation: u64,
        effective_mtu: u16,
    },
    Error(ErrorCode),
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct NetdResponse {
    pub request_id: u64,
    pub body: ResponseBody,
}

impl NetdResponse {
    pub fn encode(&self) -> Result<Vec<u8>, NetdProtocolError> {
        if self.request_id == 0 {
            return Err(NetdProtocolError::InvalidRequest);
        }
        let mut out = Vec::new();
        varint(NETD_PROTOCOL_VERSION, &mut out);
        let tag = match self.body {
            ResponseBody::Prepared { .. } => 1,
            ResponseBody::Committed { .. } => 2,
            ResponseBody::RolledBack { .. } => 3,
            ResponseBody::Status { .. } => 4,
            ResponseBody::LeaseRenewed { .. } => 5,
            ResponseBody::Error(_) => 6,
            ResponseBody::MtuUpdated { .. } => 7,
        };
        varint(tag, &mut out);
        varint(self.request_id, &mut out);
        match self.body {
            ResponseBody::Prepared {
                generation,
                tun_fd_attached,
            } => {
                valid_generation(generation)?;
                varint(generation, &mut out);
                varint(u64::from(tun_fd_attached), &mut out);
            }
            ResponseBody::Committed { generation }
            | ResponseBody::RolledBack { generation }
            | ResponseBody::LeaseRenewed { generation } => {
                valid_generation(generation)?;
                varint(generation, &mut out);
            }
            ResponseBody::Status { phase, generation } => {
                if phase != SessionPhase::Stopped {
                    valid_generation(generation)?;
                }
                varint(phase as u64, &mut out);
                varint(generation, &mut out);
            }
            ResponseBody::MtuUpdated {
                generation,
                effective_mtu,
            } => {
                valid_generation(generation)?;
                if !(576..=1400).contains(&effective_mtu) {
                    return Err(NetdProtocolError::InvalidDeclaration);
                }
                varint(generation, &mut out);
                varint(u64::from(effective_mtu), &mut out);
            }
            ResponseBody::Error(code) => varint(code as u64, &mut out),
        }
        ensure_frame(&out)?;
        Ok(out)
    }

    pub fn decode(input: &[u8]) -> Result<Self, NetdProtocolError> {
        ensure_frame(input)?;
        let mut reader = Reader::new(input);
        if reader.varint()? != NETD_PROTOCOL_VERSION {
            return Err(NetdProtocolError::UnsupportedVersion);
        }
        let tag = reader.varint()?;
        let request_id = reader.varint()?;
        let body = match tag {
            1 => ResponseBody::Prepared {
                generation: reader.varint()?,
                tun_fd_attached: reader.boolean()?,
            },
            2 => ResponseBody::Committed {
                generation: reader.varint()?,
            },
            3 => ResponseBody::RolledBack {
                generation: reader.varint()?,
            },
            4 => ResponseBody::Status {
                phase: SessionPhase::try_from(reader.varint()?)?,
                generation: reader.varint()?,
            },
            5 => ResponseBody::LeaseRenewed {
                generation: reader.varint()?,
            },
            6 => ResponseBody::Error(ErrorCode::try_from(reader.varint()?)?),
            7 => ResponseBody::MtuUpdated {
                generation: reader.varint()?,
                effective_mtu: u16::try_from(reader.varint()?)
                    .map_err(|_| NetdProtocolError::InvalidDeclaration)?,
            },
            _ => return Err(NetdProtocolError::UnknownEnum),
        };
        reader.finish()?;
        let value = Self { request_id, body };
        value.encode()?;
        Ok(value)
    }
}

fn valid_generation(value: u64) -> Result<(), NetdProtocolError> {
    if value == 0 {
        Err(NetdProtocolError::InvalidRequest)
    } else {
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Error)]
pub enum NetdSessionError {
    #[error("request generation conflicts with retained owner state")]
    GenerationConflict,
    #[error("request is invalid for the current netd lifecycle phase")]
    InvalidTransition,
    #[error("request owner differs from the retained owner")]
    OwnerMismatch,
    #[error("request declaration is invalid")]
    InvalidDeclaration,
}

#[derive(Debug, Clone)]
pub struct NetdSession {
    phase: SessionPhase,
    owner: Option<LeaseOwner>,
    declaration: Option<PrepareDeclaration>,
}

impl NetdSession {
    pub fn new() -> Self {
        Self {
            phase: SessionPhase::Stopped,
            owner: None,
            declaration: None,
        }
    }

    pub fn phase(&self) -> SessionPhase {
        self.phase
    }

    pub fn apply(&mut self, request: &NetdRequest) -> Result<(), NetdSessionError> {
        request
            .validate()
            .map_err(|_| NetdSessionError::InvalidDeclaration)?;
        let mut advancing_generation = false;
        if let Some(owner) = self.owner {
            if owner.instance_id != request.owner.instance_id || owner.pid != request.owner.pid {
                return Err(NetdSessionError::OwnerMismatch);
            }
            if owner.generation != request.owner.generation {
                advancing_generation = self.phase == SessionPhase::Stopped
                    && request.owner.generation > owner.generation
                    && matches!(request.operation, NetdOperation::Prepare(_));
                if !advancing_generation {
                    return Err(NetdSessionError::GenerationConflict);
                }
            }
        }
        if advancing_generation {
            self.owner = None;
            self.declaration = None;
        }
        match &request.operation {
            NetdOperation::Prepare(declaration) => {
                if let Some(existing) = &self.declaration {
                    if existing != declaration {
                        return Err(NetdSessionError::GenerationConflict);
                    }
                    if self.phase == SessionPhase::Stopped {
                        self.phase = SessionPhase::Prepared;
                    }
                    return Ok(());
                }
                if self.phase != SessionPhase::Stopped {
                    return Err(NetdSessionError::InvalidTransition);
                }
                self.owner = Some(request.owner);
                self.declaration = Some(declaration.clone());
                self.phase = SessionPhase::Prepared;
                Ok(())
            }
            NetdOperation::Commit => match self.phase {
                SessionPhase::Prepared => {
                    self.phase = SessionPhase::Active;
                    Ok(())
                }
                SessionPhase::Active => Ok(()),
                SessionPhase::Stopped => Err(NetdSessionError::InvalidTransition),
            },
            NetdOperation::Rollback => {
                if self.owner.is_none() {
                    return Err(NetdSessionError::InvalidTransition);
                }
                self.phase = SessionPhase::Stopped;
                Ok(())
            }
            NetdOperation::Status => Ok(()),
            NetdOperation::LeaseRenew => {
                if self.owner.is_none() {
                    return Err(NetdSessionError::InvalidTransition);
                }
                self.owner = Some(request.owner);
                Ok(())
            }
            NetdOperation::MtuUpdate { effective_mtu } => {
                if self.phase != SessionPhase::Active
                    || *effective_mtu
                        >= self
                            .declaration
                            .as_ref()
                            .map_or(576, |value| value.effective_mtu)
                {
                    return Err(NetdSessionError::InvalidTransition);
                }
                let declaration = self
                    .declaration
                    .as_mut()
                    .ok_or(NetdSessionError::InvalidTransition)?;
                declaration.effective_mtu = *effective_mtu;
                Ok(())
            }
        }
    }
}

impl Default for NetdSession {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Error)]
pub enum NetdProtocolError {
    #[error("netd frame is empty or too large")]
    FrameSize,
    #[error("unsupported netd protocol version")]
    UnsupportedVersion,
    #[error("unknown netd enum value")]
    UnknownEnum,
    #[error("malformed netd frame")]
    Malformed,
    #[error("netd frame has trailing bytes")]
    TrailingBytes,
    #[error("invalid netd request")]
    InvalidRequest,
    #[error("invalid netd lease owner")]
    InvalidOwner,
    #[error("invalid netd network declaration")]
    InvalidDeclaration,
}

fn ensure_frame(input: &[u8]) -> Result<(), NetdProtocolError> {
    if input.is_empty() || input.len() > MAX_NETD_FRAME_LEN {
        Err(NetdProtocolError::FrameSize)
    } else {
        Ok(())
    }
}

fn varint(value: u64, out: &mut Vec<u8>) {
    encode_varint(value, out);
}

fn encode_varint(mut value: u64, out: &mut Vec<u8>) {
    while value >= 0x80 {
        out.push((value as u8 & 0x7f) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

fn decode_varint(input: &[u8]) -> Result<(u64, usize), ()> {
    let mut value = 0_u64;
    for (index, byte) in input.iter().copied().take(10).enumerate() {
        let payload = u64::from(byte & 0x7f);
        if index == 9 && payload > 1 {
            return Err(());
        }
        value |= payload << (index * 7);
        if byte & 0x80 == 0 {
            if index > 0 && payload == 0 {
                return Err(());
            }
            return Ok((value, index + 1));
        }
    }
    Err(())
}

struct Reader<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    fn varint(&mut self) -> Result<u64, NetdProtocolError> {
        let (value, used) =
            decode_varint(&self.input[self.offset..]).map_err(|_| NetdProtocolError::Malformed)?;
        self.offset = self
            .offset
            .checked_add(used)
            .ok_or(NetdProtocolError::Malformed)?;
        Ok(value)
    }

    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], NetdProtocolError> {
        let end = self
            .offset
            .checked_add(N)
            .ok_or(NetdProtocolError::Malformed)?;
        let value = self
            .input
            .get(self.offset..end)
            .ok_or(NetdProtocolError::Malformed)?;
        self.offset = end;
        value.try_into().map_err(|_| NetdProtocolError::Malformed)
    }

    fn count(&mut self, min: usize, max: usize) -> Result<usize, NetdProtocolError> {
        let value = usize::try_from(self.varint()?).map_err(|_| NetdProtocolError::Malformed)?;
        if !(min..=max).contains(&value) {
            return Err(NetdProtocolError::InvalidDeclaration);
        }
        Ok(value)
    }

    fn boolean(&mut self) -> Result<bool, NetdProtocolError> {
        match self.varint()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(NetdProtocolError::Malformed),
        }
    }

    fn prefix(&mut self) -> Result<Ipv4Prefix, NetdProtocolError> {
        let network = self.fixed()?;
        let prefix_len =
            u8::try_from(self.varint()?).map_err(|_| NetdProtocolError::InvalidDeclaration)?;
        Ipv4Prefix::new(network, prefix_len)
    }

    fn finish(self) -> Result<(), NetdProtocolError> {
        if self.offset == self.input.len() {
            Ok(())
        } else {
            Err(NetdProtocolError::TrailingBytes)
        }
    }
}

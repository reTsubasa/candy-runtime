#![cfg(target_os = "linux")]

use crate::{LinuxNetworkPlan, NetworkError};
use nix::sys::socket::{
    bind, recv, sendto, socket, AddressFamily, MsgFlags, NetlinkAddr, SockFlag, SockProtocol,
    SockType,
};
use std::os::fd::{AsRawFd, OwnedFd};

const NFNETLINK_V0: u8 = 0;
const NLA_F_NESTED: u16 = 1 << 15;
const NFTA_TABLE_NAME: u16 = 1;
const NFTA_TABLE_USERDATA: u16 = 6;
const NFTA_CHAIN_TABLE: u16 = 1;
const NFTA_CHAIN_NAME: u16 = 3;
const NFTA_CHAIN_HOOK: u16 = 4;
const NFTA_CHAIN_POLICY: u16 = 5;
const NFTA_CHAIN_TYPE: u16 = 7;
const NFTA_HOOK_HOOKNUM: u16 = 1;
const NFTA_HOOK_PRIORITY: u16 = 2;
const NFTA_RULE_TABLE: u16 = 1;
const NFTA_RULE_CHAIN: u16 = 2;
const NFTA_RULE_EXPRESSIONS: u16 = 4;
const NFTA_LIST_ELEM: u16 = 1;
const NFTA_EXPR_NAME: u16 = 1;
const NFTA_EXPR_DATA: u16 = 2;
const NFTA_META_DREG: u16 = 1;
const NFTA_META_KEY: u16 = 2;
const NFTA_CMP_SREG: u16 = 1;
const NFTA_CMP_OP: u16 = 2;
const NFTA_CMP_DATA: u16 = 3;
const NFTA_DATA_VALUE: u16 = 1;
const NFTA_DATA_VERDICT: u16 = 2;
const NFTA_IMMEDIATE_DREG: u16 = 1;
const NFTA_IMMEDIATE_DATA: u16 = 2;
const NFTA_VERDICT_CODE: u16 = 1;
const NFTA_PAYLOAD_DREG: u16 = 1;
const NFTA_PAYLOAD_BASE: u16 = 2;
const NFTA_PAYLOAD_OFFSET: u16 = 3;
const NFTA_PAYLOAD_LEN: u16 = 4;
const NFTA_BITWISE_SREG: u16 = 1;
const NFTA_BITWISE_DREG: u16 = 2;
const NFTA_BITWISE_LEN: u16 = 3;
const NFTA_BITWISE_MASK: u16 = 4;
const NFTA_BITWISE_XOR: u16 = 5;
const NFTA_RT_DREG: u16 = 1;
const NFTA_RT_KEY: u16 = 2;
const NFTA_BYTEORDER_SREG: u16 = 1;
const NFTA_BYTEORDER_DREG: u16 = 2;
const NFTA_BYTEORDER_OP: u16 = 3;
const NFTA_BYTEORDER_LEN: u16 = 4;
const NFTA_BYTEORDER_SIZE: u16 = 5;
const NFTA_EXTHDR_TYPE: u16 = 2;
const NFTA_EXTHDR_OFFSET: u16 = 3;
const NFTA_EXTHDR_LEN: u16 = 4;
const NFTA_EXTHDR_OP: u16 = 6;
const NFTA_EXTHDR_SREG: u16 = 7;
const NFT_CHAIN_NAME: &str = "forward";
const OWNER_PREFIX: &[u8] = b"candy-netd-v1:";

pub fn preflight_nft(plan: &LinuxNetworkPlan) -> Result<(), NetworkError> {
    let socket = open_socket()?;
    if owned_table_state(&socket, plan)? != OwnedTableState::Absent {
        return Err(NetworkError::Backend);
    }
    Ok(())
}

pub fn stage_firewall(
    plan: &LinuxNetworkPlan,
    allow_forward: bool,
    clamp_tcp_mss: bool,
) -> Result<(), NetworkError> {
    if !allow_forward {
        return Err(NetworkError::Backend);
    }
    let socket = open_socket()?;
    if owned_table_state(&socket, plan)? != OwnedTableState::Absent {
        return Err(NetworkError::Backend);
    }
    let mut batch = Batch::new();
    batch.push(
        nft_type(nix::libc::NFT_MSG_NEWTABLE),
        create_flags(),
        vec![
            string_attr(NFTA_TABLE_NAME, &plan.nft_table_name),
            bytes_attr(NFTA_TABLE_USERDATA, &owner_tag(plan)),
        ],
    );
    batch.push(
        nft_type(nix::libc::NFT_MSG_NEWCHAIN),
        create_flags(),
        vec![
            string_attr(NFTA_CHAIN_TABLE, &plan.nft_table_name),
            string_attr(NFTA_CHAIN_NAME, NFT_CHAIN_NAME),
            string_attr(NFTA_CHAIN_TYPE, "filter"),
            nested_attr(
                NFTA_CHAIN_HOOK,
                vec![
                    u32_attr(NFTA_HOOK_HOOKNUM, nix::libc::NF_INET_FORWARD as u32),
                    i32_attr(NFTA_HOOK_PRIORITY, -200),
                ],
            ),
            u32_attr(NFTA_CHAIN_POLICY, nix::libc::NF_ACCEPT as u32),
        ],
    );
    batch.push(
        nft_type(nix::libc::NFT_MSG_NEWRULE),
        create_flags(),
        interface_accept_rule(plan, nix::libc::NFT_META_IIFNAME as u32),
    );
    batch.push(
        nft_type(nix::libc::NFT_MSG_NEWRULE),
        create_flags(),
        interface_accept_rule(plan, nix::libc::NFT_META_OIFNAME as u32),
    );
    if clamp_tcp_mss {
        batch.push(
            nft_type(nix::libc::NFT_MSG_NEWRULE),
            create_flags(),
            tcp_mss_clamp_rule(plan),
        );
    }
    send_batch(&socket, batch)
}

fn tcp_mss_clamp_rule(plan: &LinuxNetworkPlan) -> Vec<Attribute> {
    let expressions = vec![
        expression(
            "meta",
            vec![
                u32_attr(NFTA_META_DREG, nix::libc::NFT_REG_1 as u32),
                u32_attr(NFTA_META_KEY, nix::libc::NFT_META_OIFNAME as u32),
            ],
        ),
        compare_data(
            nix::libc::NFT_CMP_EQ as u32,
            format!("{}\0", plan.interface_name).as_bytes(),
        ),
        expression(
            "meta",
            vec![
                u32_attr(NFTA_META_DREG, nix::libc::NFT_REG_1 as u32),
                u32_attr(NFTA_META_KEY, nix::libc::NFT_META_L4PROTO as u32),
            ],
        ),
        compare_data(
            nix::libc::NFT_CMP_EQ as u32,
            &[nix::libc::IPPROTO_TCP as u8],
        ),
        expression(
            "payload",
            vec![
                u32_attr(NFTA_PAYLOAD_DREG, nix::libc::NFT_REG_1 as u32),
                u32_attr(NFTA_PAYLOAD_BASE, 2),
                u32_attr(NFTA_PAYLOAD_OFFSET, 13),
                u32_attr(NFTA_PAYLOAD_LEN, 1),
            ],
        ),
        expression(
            "bitwise",
            vec![
                u32_attr(NFTA_BITWISE_SREG, nix::libc::NFT_REG_1 as u32),
                u32_attr(NFTA_BITWISE_DREG, nix::libc::NFT_REG_1 as u32),
                u32_attr(NFTA_BITWISE_LEN, 1),
                nested_attr(
                    NFTA_BITWISE_MASK,
                    vec![bytes_attr(NFTA_DATA_VALUE, &[0x02])],
                ),
                nested_attr(NFTA_BITWISE_XOR, vec![bytes_attr(NFTA_DATA_VALUE, &[0])]),
            ],
        ),
        compare_data(nix::libc::NFT_CMP_NEQ as u32, &[0]),
        expression(
            "rt",
            vec![
                u32_attr(NFTA_RT_DREG, nix::libc::NFT_REG_1 as u32),
                u32_attr(NFTA_RT_KEY, 3),
            ],
        ),
        expression(
            "byteorder",
            vec![
                u32_attr(NFTA_BYTEORDER_SREG, nix::libc::NFT_REG_1 as u32),
                u32_attr(NFTA_BYTEORDER_DREG, nix::libc::NFT_REG_1 as u32),
                u32_attr(NFTA_BYTEORDER_OP, 1),
                u32_attr(NFTA_BYTEORDER_LEN, 2),
                u32_attr(NFTA_BYTEORDER_SIZE, 2),
            ],
        ),
        expression(
            "exthdr",
            vec![
                u8_attr(NFTA_EXTHDR_TYPE, 2),
                u32_attr(NFTA_EXTHDR_OFFSET, 2),
                u32_attr(NFTA_EXTHDR_LEN, 2),
                u32_attr(NFTA_EXTHDR_OP, 1),
                u32_attr(NFTA_EXTHDR_SREG, nix::libc::NFT_REG_1 as u32),
            ],
        ),
    ];
    vec![
        string_attr(NFTA_RULE_TABLE, &plan.nft_table_name),
        string_attr(NFTA_RULE_CHAIN, NFT_CHAIN_NAME),
        nested_attr(NFTA_RULE_EXPRESSIONS, expressions),
    ]
}

fn compare_data(operation: u32, value: &[u8]) -> Attribute {
    expression(
        "cmp",
        vec![
            u32_attr(NFTA_CMP_SREG, nix::libc::NFT_REG_1 as u32),
            u32_attr(NFTA_CMP_OP, operation),
            nested_attr(NFTA_CMP_DATA, vec![bytes_attr(NFTA_DATA_VALUE, value)]),
        ],
    )
}

pub fn remove_firewall(plan: &LinuxNetworkPlan) -> Result<(), NetworkError> {
    let socket = open_socket()?;
    match owned_table_state(&socket, plan)? {
        OwnedTableState::Absent => return Ok(()),
        OwnedTableState::Foreign => return Err(NetworkError::Backend),
        OwnedTableState::Candy => {}
    }
    let mut batch = Batch::new();
    batch.push(
        nft_type(nix::libc::NFT_MSG_DELTABLE),
        nix::libc::NLM_F_ACK as u16,
        vec![string_attr(NFTA_TABLE_NAME, &plan.nft_table_name)],
    );
    send_batch(&socket, batch)
}

fn interface_accept_rule(plan: &LinuxNetworkPlan, meta_key: u32) -> Vec<Attribute> {
    let expressions = vec![
        expression(
            "meta",
            vec![
                u32_attr(NFTA_META_DREG, nix::libc::NFT_REG_1 as u32),
                u32_attr(NFTA_META_KEY, meta_key),
            ],
        ),
        expression(
            "cmp",
            vec![
                u32_attr(NFTA_CMP_SREG, nix::libc::NFT_REG_1 as u32),
                u32_attr(NFTA_CMP_OP, nix::libc::NFT_CMP_EQ as u32),
                nested_attr(
                    NFTA_CMP_DATA,
                    vec![bytes_attr(
                        NFTA_DATA_VALUE,
                        format!("{}\0", plan.interface_name).as_bytes(),
                    )],
                ),
            ],
        ),
        expression(
            "immediate",
            vec![
                u32_attr(NFTA_IMMEDIATE_DREG, nix::libc::NFT_REG_VERDICT as u32),
                nested_attr(
                    NFTA_IMMEDIATE_DATA,
                    vec![nested_attr(
                        NFTA_DATA_VERDICT,
                        vec![i32_attr(NFTA_VERDICT_CODE, nix::libc::NF_ACCEPT)],
                    )],
                ),
            ],
        ),
    ];
    vec![
        string_attr(NFTA_RULE_TABLE, &plan.nft_table_name),
        string_attr(NFTA_RULE_CHAIN, NFT_CHAIN_NAME),
        nested_attr(NFTA_RULE_EXPRESSIONS, expressions),
    ]
}

fn expression(name: &str, data: Vec<Attribute>) -> Attribute {
    nested_attr(
        NFTA_LIST_ELEM,
        vec![
            string_attr(NFTA_EXPR_NAME, name),
            nested_attr(NFTA_EXPR_DATA, data),
        ],
    )
}

#[derive(Debug, Clone)]
struct Attribute {
    kind: u16,
    payload: Vec<u8>,
}

fn string_attr(kind: u16, value: &str) -> Attribute {
    let mut payload = value.as_bytes().to_vec();
    payload.push(0);
    Attribute { kind, payload }
}

fn bytes_attr(kind: u16, value: &[u8]) -> Attribute {
    Attribute {
        kind,
        payload: value.to_vec(),
    }
}

fn u32_attr(kind: u16, value: u32) -> Attribute {
    bytes_attr(kind, &value.to_be_bytes())
}

fn u8_attr(kind: u16, value: u8) -> Attribute {
    bytes_attr(kind, &[value])
}

fn i32_attr(kind: u16, value: i32) -> Attribute {
    bytes_attr(kind, &value.to_be_bytes())
}

fn nested_attr(kind: u16, values: Vec<Attribute>) -> Attribute {
    let mut payload = Vec::new();
    for value in values {
        emit_attr(&mut payload, value);
    }
    Attribute {
        kind: kind | NLA_F_NESTED,
        payload,
    }
}

fn emit_attr(output: &mut Vec<u8>, attribute: Attribute) {
    let length = 4 + attribute.payload.len();
    output.extend_from_slice(&(length as u16).to_ne_bytes());
    output.extend_from_slice(&attribute.kind.to_ne_bytes());
    output.extend_from_slice(&attribute.payload);
    output.resize(align4(output.len()), 0);
}

struct Batch {
    bytes: Vec<u8>,
    next_sequence: u32,
    acknowledgements: usize,
}

impl Batch {
    fn new() -> Self {
        let mut value = Self {
            bytes: Vec::new(),
            next_sequence: 1,
            acknowledgements: 0,
        };
        value.message(
            nix::libc::NFNL_MSG_BATCH_BEGIN as u16,
            nix::libc::NLM_F_REQUEST as u16,
            0,
            Vec::new(),
            nix::libc::NFNL_SUBSYS_NFTABLES as u16,
        );
        value
    }

    fn push(&mut self, kind: u16, flags: u16, attributes: Vec<Attribute>) {
        self.message(
            kind,
            nix::libc::NLM_F_REQUEST as u16 | flags,
            1,
            attributes,
            0,
        );
        self.acknowledgements += 1;
    }

    fn finish(mut self) -> Self {
        self.message(
            nix::libc::NFNL_MSG_BATCH_END as u16,
            nix::libc::NLM_F_REQUEST as u16,
            0,
            Vec::new(),
            nix::libc::NFNL_SUBSYS_NFTABLES as u16,
        );
        self
    }

    fn message(
        &mut self,
        kind: u16,
        flags: u16,
        family: u8,
        attributes: Vec<Attribute>,
        resource: u16,
    ) {
        let start = self.bytes.len();
        self.bytes.extend_from_slice(&0_u32.to_ne_bytes());
        self.bytes.extend_from_slice(&kind.to_ne_bytes());
        self.bytes.extend_from_slice(&flags.to_ne_bytes());
        self.bytes
            .extend_from_slice(&self.next_sequence.to_ne_bytes());
        self.bytes.extend_from_slice(&0_u32.to_ne_bytes());
        self.bytes.push(family);
        self.bytes.push(NFNETLINK_V0);
        self.bytes.extend_from_slice(&resource.to_be_bytes());
        for attribute in attributes {
            emit_attr(&mut self.bytes, attribute);
        }
        let length = u32::try_from(self.bytes.len() - start).expect("bounded nft message");
        self.bytes[start..start + 4].copy_from_slice(&length.to_ne_bytes());
        self.bytes.resize(align4(self.bytes.len()), 0);
        self.next_sequence += 1;
    }
}

fn send_batch(socket: &OwnedFd, batch: Batch) -> Result<(), NetworkError> {
    let batch = batch.finish();
    let target = NetlinkAddr::new(0, 0);
    let sent = sendto(socket.as_raw_fd(), &batch.bytes, &target, MsgFlags::empty())
        .map_err(|_| NetworkError::Backend)?;
    if sent != batch.bytes.len() {
        return Err(NetworkError::Backend);
    }
    receive_acks(socket, batch.acknowledgements)
}

fn receive_acks(socket: &OwnedFd, expected: usize) -> Result<(), NetworkError> {
    if expected == 0 {
        return Ok(());
    }
    let mut acknowledged = 0;
    let mut buffer = vec![0_u8; 64 * 1024];
    while acknowledged < expected {
        let length = recv(socket.as_raw_fd(), &mut buffer, MsgFlags::empty())
            .map_err(|_| NetworkError::Backend)?;
        let mut offset = 0;
        while offset + 20 <= length {
            let message_len = u32::from_ne_bytes(
                buffer[offset..offset + 4]
                    .try_into()
                    .map_err(|_| NetworkError::Backend)?,
            ) as usize;
            if message_len < 20 || offset + message_len > length {
                return Err(NetworkError::Backend);
            }
            let kind = u16::from_ne_bytes([buffer[offset + 4], buffer[offset + 5]]);
            if kind == nix::libc::NLMSG_ERROR as u16 {
                let error = i32::from_ne_bytes(
                    buffer[offset + 16..offset + 20]
                        .try_into()
                        .map_err(|_| NetworkError::Backend)?,
                );
                if error != 0 {
                    return Err(NetworkError::Backend);
                }
                acknowledged += 1;
            }
            offset += align4(message_len);
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum OwnedTableState {
    Absent,
    Candy,
    Foreign,
}

fn owned_table_state(
    socket: &OwnedFd,
    plan: &LinuxNetworkPlan,
) -> Result<OwnedTableState, NetworkError> {
    let sequence = 1_u32;
    let mut request = Vec::new();
    emit_message(
        &mut request,
        nft_type(nix::libc::NFT_MSG_GETTABLE),
        (nix::libc::NLM_F_REQUEST | nix::libc::NLM_F_DUMP) as u16,
        sequence,
        1,
        Vec::new(),
    );
    let target = NetlinkAddr::new(0, 0);
    sendto(socket.as_raw_fd(), &request, &target, MsgFlags::empty())
        .map_err(|_| NetworkError::Backend)?;
    let mut state = OwnedTableState::Absent;
    let expected_tag = owner_tag(plan);
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let length = recv(socket.as_raw_fd(), &mut buffer, MsgFlags::empty())
            .map_err(|_| NetworkError::Backend)?;
        let mut offset = 0;
        while offset + 16 <= length {
            let message_len = u32::from_ne_bytes(
                buffer[offset..offset + 4]
                    .try_into()
                    .map_err(|_| NetworkError::Backend)?,
            ) as usize;
            if message_len < 16 || offset + message_len > length {
                return Err(NetworkError::Backend);
            }
            let kind = u16::from_ne_bytes([buffer[offset + 4], buffer[offset + 5]]);
            if kind == nix::libc::NLMSG_DONE as u16 {
                return Ok(state);
            }
            if kind == nix::libc::NLMSG_ERROR as u16 {
                return Err(NetworkError::Backend);
            }
            if message_len >= 20 {
                let attributes = parse_attrs(&buffer[offset + 20..offset + message_len])?;
                let name = attributes
                    .iter()
                    .find(|(kind, _)| *kind == NFTA_TABLE_NAME)
                    .map(|(_, value)| trim_nul(value));
                if name == Some(plan.nft_table_name.as_bytes()) {
                    let userdata = attributes
                        .iter()
                        .find(|(kind, _)| *kind == NFTA_TABLE_USERDATA)
                        .map(|(_, value)| *value);
                    state = if userdata.map(trim_nul) == Some(expected_tag.as_slice()) {
                        OwnedTableState::Candy
                    } else {
                        OwnedTableState::Foreign
                    };
                }
            }
            offset += align4(message_len);
        }
    }
}

fn emit_message(
    output: &mut Vec<u8>,
    kind: u16,
    flags: u16,
    sequence: u32,
    family: u8,
    attributes: Vec<Attribute>,
) {
    let mut batch = Batch {
        bytes: Vec::new(),
        next_sequence: sequence,
        acknowledgements: 0,
    };
    batch.message(kind, flags, family, attributes, 0);
    output.extend_from_slice(&batch.bytes);
}

fn parse_attrs(mut input: &[u8]) -> Result<Vec<(u16, &[u8])>, NetworkError> {
    let mut values = Vec::new();
    while !input.is_empty() {
        if input.len() < 4 {
            return Err(NetworkError::Backend);
        }
        let length = usize::from(u16::from_ne_bytes([input[0], input[1]]));
        if length < 4 || length > input.len() {
            return Err(NetworkError::Backend);
        }
        let kind = u16::from_ne_bytes([input[2], input[3]]) & !(NLA_F_NESTED);
        values.push((kind, &input[4..length]));
        let aligned = align4(length);
        if aligned > input.len() {
            return Err(NetworkError::Backend);
        }
        input = &input[aligned..];
    }
    Ok(values)
}

fn trim_nul(value: &[u8]) -> &[u8] {
    value.strip_suffix(&[0]).unwrap_or(value)
}

fn owner_tag(plan: &LinuxNetworkPlan) -> Vec<u8> {
    let mut value = OWNER_PREFIX.to_vec();
    value.extend_from_slice(plan.route_table.to_string().as_bytes());
    value
}

fn open_socket() -> Result<OwnedFd, NetworkError> {
    let socket = socket(
        AddressFamily::Netlink,
        SockType::Raw,
        SockFlag::SOCK_CLOEXEC,
        SockProtocol::NetlinkNetFilter,
    )
    .map_err(|_| NetworkError::Backend)?;
    bind(socket.as_raw_fd(), &NetlinkAddr::new(0, 0)).map_err(|_| NetworkError::Backend)?;
    Ok(socket)
}

fn nft_type(operation: i32) -> u16 {
    ((nix::libc::NFNL_SUBSYS_NFTABLES as u16) << 8) | operation as u16
}

fn create_flags() -> u16 {
    (nix::libc::NLM_F_ACK | nix::libc::NLM_F_CREATE | nix::libc::NLM_F_EXCL) as u16
}

const fn align4(value: usize) -> usize {
    (value + 3) & !3
}

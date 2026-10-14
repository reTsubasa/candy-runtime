//! Packet I/O and authenticated ownership boundaries without Candy transport dependencies.
#![cfg(unix)]

pub mod fd;
pub mod packet_port;
pub mod packet_port_ipc;
pub mod packet_port_manager;

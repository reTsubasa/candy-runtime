//! Packet-preserving inherited descriptor owned by the infrastructure process.

use crate::packet_port::PacketPort;
use std::io;
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use tokio::io::unix::AsyncFd;

const MAX_INNER_PACKET: usize = 65_535;

/// A Runtime-owned inherited packet device.  The descriptor must already be a
/// packet-preserving TUN/fd; reopening a path or creating one is deliberately
/// outside Core's process contract.
pub struct InheritedPacketFd {
    io: AsyncFd<OwnedFd>,
}

impl PacketPort for InheritedPacketFd {
    fn try_send_packet(&self, packet: &[u8]) -> io::Result<bool> {
        if packet.is_empty() || packet.len() > MAX_INNER_PACKET {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid packet size",
            ));
        }
        match self.io.try_io(tokio::io::Interest::WRITABLE, |inner| {
            nix::unistd::write(inner.as_fd(), packet)
                .map_err(|error| io::Error::from_raw_os_error(error as i32))
        }) {
            Ok(length) if length == packet.len() => Ok(true),
            Ok(_) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "packet fd short write",
            )),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(false),
            Err(error) => Err(error),
        }
    }
    async fn recv_packet(&self) -> io::Result<Vec<u8>> {
        InheritedPacketFd::recv_packet(self).await
    }

    async fn send_packet(&self, packet: &[u8]) -> io::Result<()> {
        InheritedPacketFd::send_packet(self, packet).await
    }
}

impl InheritedPacketFd {
    pub fn new(fd: OwnedFd) -> io::Result<Self> {
        let flags = nix::fcntl::fcntl(fd.as_raw_fd(), nix::fcntl::FcntlArg::F_GETFL)
            .map_err(|error| io::Error::from_raw_os_error(error as i32))?;
        nix::fcntl::fcntl(
            fd.as_raw_fd(),
            nix::fcntl::FcntlArg::F_SETFL(
                nix::fcntl::OFlag::from_bits_truncate(flags) | nix::fcntl::OFlag::O_NONBLOCK,
            ),
        )
        .map_err(|error| io::Error::from_raw_os_error(error as i32))?;
        Ok(Self {
            io: AsyncFd::new(fd)?,
        })
    }

    pub async fn recv_packet(&self) -> io::Result<Vec<u8>> {
        loop {
            let mut ready = self.io.readable().await?;
            match ready.try_io(|inner| {
                // read initializes only the returned prefix. Avoid clearing a
                // 64 KiB buffer for every MTU-sized packet on the hot path.
                let mut buffer = MaybeUninit::<[u8; MAX_INNER_PACKET]>::uninit();
                // SAFETY: buffer is writable for MAX_INNER_PACKET bytes; the
                // nonblocking descriptor remains owned for this entire call.
                let length = unsafe {
                    libc::read(
                        inner.get_ref().as_raw_fd(),
                        buffer.as_mut_ptr().cast(),
                        MAX_INNER_PACKET,
                    )
                };
                match length {
                    -1 => Err(io::Error::last_os_error()),
                    0 => Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "packet fd closed",
                    )),
                    length => {
                        // SAFETY: successful read initialized exactly length
                        // bytes, bounded above by the supplied buffer size.
                        let mut packet = unsafe {
                            std::slice::from_raw_parts(
                                buffer.as_ptr().cast::<u8>(),
                                length as usize,
                            )
                        };
                        // Some OpenWrt kernels keep the four-byte TUN packet
                        // information header even when the device was opened
                        // with IFF_NO_PI (typically after an in-place netd
                        // upgrade).  Core owns a packet-preserving fd, so
                        // accept only the unambiguous IPv4 PI form here and
                        // normalize it before the signed packet validator.
                        if packet.first().is_none_or(|byte| byte >> 4 != 4)
                            && packet.len() >= 24
                            && packet[2] == 0x08
                            && packet[3] == 0
                        {
                            packet = &packet[4..];
                        }
                        Ok(packet.to_vec())
                    }
                }
            }) {
                Ok(Err(error)) if error.kind() == io::ErrorKind::Interrupted => continue,
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }

    pub async fn send_packet(&self, packet: &[u8]) -> io::Result<()> {
        if packet.is_empty() || packet.len() > MAX_INNER_PACKET {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid packet size",
            ));
        }
        loop {
            let mut ready = self.io.writable().await?;
            match ready.try_io(|inner| {
                nix::unistd::write(inner.get_ref().as_fd(), packet)
                    .map_err(|error| io::Error::from_raw_os_error(error as i32))
            }) {
                Ok(Ok(length)) if length == packet.len() => return Ok(()),
                Ok(Ok(0)) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "packet fd write returned zero",
                    ))
                }
                Ok(Ok(_)) => {
                    // A suffix is another packet on TUN/datagram descriptors.
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "packet fd short write",
                    ));
                }
                Ok(Err(error)) if error.kind() == io::ErrorKind::Interrupted => continue,
                Ok(Err(error)) => return Err(error),
                Err(_would_block) => continue,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::UnixDatagram;

    #[tokio::test]
    async fn inherited_receive_preserves_boundaries_and_allocates_only_received_bytes() {
        let (fd, peer) = UnixDatagram::pair().unwrap();
        // Test full-size packets without the simulated port's small default buffers.
        nix::sys::socket::setsockopt(&fd, nix::sys::socket::sockopt::RcvBuf, &(128 * 1024))
            .unwrap();
        nix::sys::socket::setsockopt(&peer, nix::sys::socket::sockopt::SndBuf, &(128 * 1024))
            .unwrap();
        let port = InheritedPacketFd::new(OwnedFd::from(fd.into_std().unwrap())).unwrap();
        for size in [1, 64, 1398, 65_535] {
            let payload = vec![0x45; size];
            peer.send(&payload).await.unwrap();
            let received = port.recv_packet().await.unwrap();
            assert_eq!(received, payload);
            assert_eq!(received.capacity(), received.len());
        }
    }
}

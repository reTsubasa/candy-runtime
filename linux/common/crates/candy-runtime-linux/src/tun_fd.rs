use nix::fcntl::{fcntl, FcntlArg, OFlag};
use nix::unistd::{read, write};
use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use thiserror::Error;
use tokio::io::unix::AsyncFd;

pub const MAX_TUN_PACKET_BYTES: usize = 1400;

#[derive(Debug, Error)]
pub enum TunPacketFdError {
    #[error("TUN descriptor I/O failed")]
    Io(#[from] io::Error),
    #[error("TUN packet is empty or exceeds the packet lane limit")]
    InvalidPacketLength,
    #[error("TUN descriptor accepted only part of one packet")]
    PartialPacketWrite,
}

pub struct TunPacketFd {
    descriptor: AsyncFd<OwnedFd>,
}

impl TunPacketFd {
    pub fn new(descriptor: OwnedFd) -> Result<Self, TunPacketFdError> {
        let raw = descriptor.as_raw_fd();
        let current = fcntl(raw, FcntlArg::F_GETFL).map_err(io::Error::from)?;
        let flags = OFlag::from_bits_truncate(current) | OFlag::O_NONBLOCK;
        fcntl(raw, FcntlArg::F_SETFL(flags)).map_err(io::Error::from)?;
        Ok(Self {
            descriptor: AsyncFd::new(descriptor)?,
        })
    }

    pub async fn read_packet(&self) -> Result<Vec<u8>, TunPacketFdError> {
        let mut packet = vec![0_u8; MAX_TUN_PACKET_BYTES + 1];
        loop {
            let mut ready = self.descriptor.readable().await?;
            match ready.try_io(|inner| {
                read(inner.get_ref().as_raw_fd(), &mut packet).map_err(io::Error::from)
            }) {
                Ok(Ok(bytes)) if (1..=MAX_TUN_PACKET_BYTES).contains(&bytes) => {
                    packet.truncate(bytes);
                    return Ok(packet);
                }
                Ok(Ok(_)) => return Err(TunPacketFdError::InvalidPacketLength),
                Ok(Err(error)) => return Err(error.into()),
                Err(_) => continue,
            }
        }
    }

    pub async fn write_packet(&self, packet: &[u8]) -> Result<(), TunPacketFdError> {
        if packet.is_empty() || packet.len() > MAX_TUN_PACKET_BYTES {
            return Err(TunPacketFdError::InvalidPacketLength);
        }
        loop {
            let mut ready = self.descriptor.writable().await?;
            match ready.try_io(|inner| write(inner.get_ref(), packet).map_err(io::Error::from)) {
                Ok(Ok(bytes)) if bytes == packet.len() => return Ok(()),
                Ok(Ok(_)) => return Err(TunPacketFdError::PartialPacketWrite),
                Ok(Err(error)) => return Err(error.into()),
                Err(_) => continue,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixDatagram;

    #[tokio::test]
    async fn packet_fd_preserves_complete_packet_reads_and_writes() {
        let (lane, peer) = UnixDatagram::pair().unwrap();
        let lane = TunPacketFd::new(OwnedFd::from(lane)).unwrap();
        peer.send(&[0x11; 1200]).unwrap();
        assert_eq!(lane.read_packet().await.unwrap(), vec![0x11; 1200]);

        lane.write_packet(&[0x22; 1180]).await.unwrap();
        let mut output = [0_u8; MAX_TUN_PACKET_BYTES + 1];
        let bytes = peer.recv(&mut output).unwrap();
        assert_eq!(bytes, 1180);
        assert_eq!(&output[..bytes], &[0x22; 1180]);
    }

    #[tokio::test]
    async fn packet_fd_rejects_empty_and_oversized_packets() {
        let (lane, peer) = UnixDatagram::pair().unwrap();
        let lane = TunPacketFd::new(OwnedFd::from(lane)).unwrap();
        assert!(matches!(
            lane.write_packet(&[]).await,
            Err(TunPacketFdError::InvalidPacketLength)
        ));
        assert!(matches!(
            lane.write_packet(&vec![0; MAX_TUN_PACKET_BYTES + 1]).await,
            Err(TunPacketFdError::InvalidPacketLength)
        ));

        peer.send(&vec![0x33; MAX_TUN_PACKET_BYTES + 1]).unwrap();
        assert!(matches!(
            lane.read_packet().await,
            Err(TunPacketFdError::InvalidPacketLength)
        ));
    }
}

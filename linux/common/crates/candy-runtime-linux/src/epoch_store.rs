use candy_tun::{EpochStore, FailoverError, RouteDomainId};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const MAGIC: &[u8; 8] = b"CNDEPC01";
const CONTENT_LEN: usize = 8 + 16 + 16 + 8;
const RECORD_LEN: usize = CONTENT_LEN + 32;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

pub struct FileEpochStore {
    path: PathBuf,
    domain: RouteDomainId,
}

impl FileEpochStore {
    pub fn new(path: PathBuf, domain: RouteDomainId) -> Result<Self, FailoverError> {
        validate_parent(&path)?;
        Ok(Self { path, domain })
    }

    fn read_epoch(&self) -> Result<u64, FailoverError> {
        validate_parent(&self.path)?;
        let mut file = match open_existing(&self.path)? {
            Some(file) => file,
            None => return Ok(0),
        };
        if file.metadata().map_err(store_error)?.len() != RECORD_LEN as u64 {
            return Err(FailoverError::EpochStore);
        }
        let mut bytes = [0; RECORD_LEN];
        file.read_exact(&mut bytes).map_err(store_error)?;
        if &bytes[..8] != MAGIC
            || Sha256::digest(&bytes[..CONTENT_LEN]).as_slice() != &bytes[CONTENT_LEN..]
            || bytes[8..24] != self.domain.tenant_id
            || bytes[24..40] != self.domain.segment_id.0
        {
            return Err(FailoverError::EpochStore);
        }
        let epoch = u64::from_be_bytes(
            bytes[40..48]
                .try_into()
                .map_err(|_| FailoverError::EpochStore)?,
        );
        if epoch == 0 {
            return Err(FailoverError::EpochStore);
        }
        Ok(epoch)
    }

    fn write_epoch(&self, epoch: u64) -> Result<(), FailoverError> {
        let mut bytes = Vec::with_capacity(RECORD_LEN);
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&self.domain.tenant_id);
        bytes.extend_from_slice(&self.domain.segment_id.0);
        bytes.extend_from_slice(&epoch.to_be_bytes());
        let checksum = Sha256::digest(&bytes);
        bytes.extend_from_slice(&checksum);

        let parent = self.path.parent().ok_or(FailoverError::EpochStore)?;
        let name = self
            .path
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or(FailoverError::EpochStore)?;
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let temporary = parent.join(format!(".{name}.tmp.{}.{sequence}", std::process::id()));
        let result = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW)
                .open(&temporary)
                .map_err(store_error)?;
            file.write_all(&bytes).map_err(store_error)?;
            file.sync_all().map_err(store_error)?;
            fs::rename(&temporary, &self.path).map_err(store_error)?;
            File::open(parent)
                .map_err(store_error)?
                .sync_all()
                .map_err(store_error)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }
}

impl EpochStore for FileEpochStore {
    fn load(&self, domain: RouteDomainId) -> Result<u64, FailoverError> {
        if domain != self.domain {
            return Err(FailoverError::EpochStore);
        }
        self.read_epoch()
    }

    fn store(&mut self, domain: RouteDomainId, epoch: u64) -> Result<(), FailoverError> {
        if domain != self.domain || epoch == 0 {
            return Err(FailoverError::EpochStore);
        }
        let current = self.read_epoch()?;
        if current.checked_add(1) != Some(epoch) {
            return Err(FailoverError::InvalidEpoch);
        }
        self.write_epoch(epoch)
    }
}

fn validate_parent(path: &Path) -> Result<(), FailoverError> {
    let parent = path.parent().ok_or(FailoverError::EpochStore)?;
    let metadata = fs::symlink_metadata(parent).map_err(store_error)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.permissions().mode() & 0o022 != 0
        || metadata.uid() != nix::unistd::geteuid().as_raw()
    {
        return Err(FailoverError::EpochStore);
    }
    Ok(())
}

fn open_existing(path: &Path) -> Result<Option<File>, FailoverError> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(store_error(error)),
    };
    let metadata = file.metadata().map_err(store_error)?;
    if !metadata.file_type().is_file()
        || metadata.permissions().mode() & 0o177 != 0
        || metadata.uid() != nix::unistd::geteuid().as_raw()
    {
        return Err(FailoverError::EpochStore);
    }
    Ok(Some(file))
}

fn store_error(_error: std::io::Error) -> FailoverError {
    FailoverError::EpochStore
}

#[cfg(test)]
mod tests {
    use super::*;
    use candy_proto::ip_tunnel::SegmentId;
    use std::os::unix::fs::{symlink, PermissionsExt};

    fn domain(value: u8) -> RouteDomainId {
        RouteDomainId {
            tenant_id: [value; 16],
            segment_id: SegmentId([value + 1; 16]),
        }
    }

    fn test_directory(suffix: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "candy-epoch-store-test-{}-{suffix}",
            std::process::id()
        ))
    }

    fn prepare_directory(suffix: &str) -> PathBuf {
        let directory = test_directory(suffix);
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        directory
    }

    #[test]
    fn epoch_round_trips_privately_and_only_advances_by_one() {
        let directory = prepare_directory("roundtrip");
        let path = directory.join("epoch.state");
        let mut store = FileEpochStore::new(path.clone(), domain(1)).unwrap();
        assert_eq!(store.load(domain(1)), Ok(0));
        store.store(domain(1), 1).unwrap();
        assert_eq!(store.load(domain(1)), Ok(1));
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(store.store(domain(1), 3), Err(FailoverError::InvalidEpoch));
        assert_eq!(store.load(domain(2)), Err(FailoverError::EpochStore));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn epoch_store_rejects_corruption_symlinks_and_unsafe_parents() {
        let directory = prepare_directory("reject");
        let path = directory.join("epoch.state");
        let mut store = FileEpochStore::new(path.clone(), domain(1)).unwrap();
        store.store(domain(1), 1).unwrap();
        let mut bytes = fs::read(&path).unwrap();
        bytes[40] ^= 0x40;
        fs::write(&path, bytes).unwrap();
        assert_eq!(store.load(domain(1)), Err(FailoverError::EpochStore));

        fs::remove_file(&path).unwrap();
        let target = directory.join("target");
        fs::write(&target, b"preserve").unwrap();
        symlink(&target, &path).unwrap();
        assert_eq!(store.load(domain(1)), Err(FailoverError::EpochStore));
        assert_eq!(fs::read(&target).unwrap(), b"preserve");
        fs::remove_file(&path).unwrap();

        fs::set_permissions(&directory, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(FileEpochStore::new(path, domain(1)).is_err());
        fs::remove_dir_all(directory).unwrap();
    }
}

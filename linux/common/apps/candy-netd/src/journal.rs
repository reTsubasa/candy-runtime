use crate::{
    NetworkError, NetworkJournal, SysctlChange, SysctlKey, TransactionPhase, TransactionRecord,
};
use candy_netd_proto::{NetdOperation, NetdRequest, MAX_NETD_FRAME_LEN};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const MAGIC_V1: &[u8; 8] = b"CNDJNL01";
const MAGIC_V2: &[u8; 8] = b"CNDJNL02";
const HEADER_LEN: usize = 8 + 1 + 2 + 1 + 4;
const CHECKSUM_LEN: usize = 32;
const MAX_JOURNAL_LEN: usize =
    HEADER_LEN + 3 * 3 + MAX_NETD_FRAME_LEN + 4 + MAX_NETD_FRAME_LEN + CHECKSUM_LEN;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

pub struct FileNetworkJournal {
    path: PathBuf,
}

impl FileNetworkJournal {
    pub fn new(path: PathBuf) -> Result<Self, NetworkError> {
        validate_parent(&path)?;
        Ok(Self { path })
    }
}

impl NetworkJournal for FileNetworkJournal {
    fn load(&self) -> Result<Option<TransactionRecord>, NetworkError> {
        validate_parent(&self.path)?;
        let mut file = match open_existing(&self.path)? {
            Some(file) => file,
            None => return Ok(None),
        };
        let length = usize::try_from(file.metadata().map_err(journal_error)?.len())
            .map_err(|_| NetworkError::Journal)?;
        if !(HEADER_LEN + CHECKSUM_LEN..=MAX_JOURNAL_LEN).contains(&length) {
            return Err(NetworkError::Journal);
        }
        let mut bytes = Vec::with_capacity(length);
        file.read_to_end(&mut bytes).map_err(journal_error)?;
        decode_record(&bytes).map(Some)
    }

    fn store(&mut self, record: &TransactionRecord) -> Result<(), NetworkError> {
        validate_parent(&self.path)?;
        let _ = open_existing(&self.path)?;
        let bytes = encode_record(record)?;
        let parent = self.path.parent().ok_or(NetworkError::Journal)?;
        let name = self
            .path
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or(NetworkError::Journal)?;
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let temporary = parent.join(format!(".{name}.tmp.{}.{sequence}", std::process::id()));
        let result = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW)
                .open(&temporary)
                .map_err(journal_error)?;
            file.write_all(&bytes).map_err(journal_error)?;
            file.sync_all().map_err(journal_error)?;
            fs::rename(&temporary, &self.path).map_err(journal_error)?;
            sync_directory(parent)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }

    fn clear(&mut self) -> Result<(), NetworkError> {
        validate_parent(&self.path)?;
        if open_existing(&self.path)?.is_none() {
            return Ok(());
        }
        fs::remove_file(&self.path).map_err(journal_error)?;
        sync_directory(self.path.parent().ok_or(NetworkError::Journal)?)
    }
}

fn encode_record(record: &TransactionRecord) -> Result<Vec<u8>, NetworkError> {
    if record.sysctls.len() > 3
        || !record
            .sysctls
            .windows(2)
            .all(|pair| pair[0].key < pair[1].key)
        || record.sysctls.iter().any(|change| {
            change.original > 2 || change.applied > 2 || change.original == change.applied
        })
    {
        return Err(NetworkError::Journal);
    }
    if record.recovery_candidate.is_some() && record.phase != TransactionPhase::RollingBack {
        return Err(NetworkError::Journal);
    }
    let request = NetdRequest {
        request_id: 1,
        owner: record.owner,
        operation: NetdOperation::Prepare(record.declaration.clone()),
    };
    let request = request.encode().map_err(|_| NetworkError::Journal)?;
    let recovery_request = record
        .recovery_candidate
        .as_ref()
        .map(|declaration| {
            NetdRequest {
                request_id: 1,
                owner: record.owner,
                operation: NetdOperation::Prepare(declaration.clone()),
            }
            .encode()
            .map_err(|_| NetworkError::Journal)
        })
        .transpose()?;
    let mut bytes = Vec::with_capacity(
        HEADER_LEN
            + request.len()
            + recovery_request.as_ref().map_or(0, |value| 4 + value.len())
            + CHECKSUM_LEN,
    );
    bytes.extend_from_slice(if recovery_request.is_some() {
        MAGIC_V2
    } else {
        MAGIC_V1
    });
    bytes.push(match record.phase {
        TransactionPhase::Preparing => 1,
        TransactionPhase::Prepared => 2,
        TransactionPhase::Active => 3,
        TransactionPhase::RollingBack => 4,
        TransactionPhase::Suspended => 5,
    });
    bytes.extend_from_slice(&record.completed_steps.to_be_bytes());
    bytes.push(u8::try_from(record.sysctls.len()).map_err(|_| NetworkError::Journal)?);
    for change in &record.sysctls {
        bytes.extend_from_slice(&[change.key as u8, change.original, change.applied]);
    }
    bytes.extend_from_slice(
        &u32::try_from(request.len())
            .map_err(|_| NetworkError::Journal)?
            .to_be_bytes(),
    );
    bytes.extend_from_slice(&request);
    if let Some(recovery_request) = recovery_request {
        bytes.extend_from_slice(
            &u32::try_from(recovery_request.len())
                .map_err(|_| NetworkError::Journal)?
                .to_be_bytes(),
        );
        bytes.extend_from_slice(&recovery_request);
    }
    let checksum = Sha256::digest(&bytes);
    bytes.extend_from_slice(&checksum);
    Ok(bytes)
}

fn decode_record(bytes: &[u8]) -> Result<TransactionRecord, NetworkError> {
    if bytes.len() < HEADER_LEN + CHECKSUM_LEN
        || (&bytes[..8] != MAGIC_V1 && &bytes[..8] != MAGIC_V2)
    {
        return Err(NetworkError::Journal);
    }
    let version = &bytes[..8];
    let content_len = bytes.len() - CHECKSUM_LEN;
    if Sha256::digest(&bytes[..content_len]).as_slice() != &bytes[content_len..] {
        return Err(NetworkError::Journal);
    }
    let phase = match bytes[8] {
        1 => TransactionPhase::Preparing,
        2 => TransactionPhase::Prepared,
        3 => TransactionPhase::Active,
        4 => TransactionPhase::RollingBack,
        5 => TransactionPhase::Suspended,
        _ => return Err(NetworkError::Journal),
    };
    let completed_steps = u16::from_be_bytes([bytes[9], bytes[10]]);
    if completed_steps & !0x3f != 0 {
        return Err(NetworkError::Journal);
    }
    let sysctl_count = usize::from(bytes[11]);
    if sysctl_count > 3 {
        return Err(NetworkError::Journal);
    }
    let sysctl_end = 12_usize
        .checked_add(sysctl_count.checked_mul(3).ok_or(NetworkError::Journal)?)
        .ok_or(NetworkError::Journal)?;
    let request_header_end = sysctl_end.checked_add(4).ok_or(NetworkError::Journal)?;
    if request_header_end > content_len {
        return Err(NetworkError::Journal);
    }
    let mut sysctls = Vec::with_capacity(sysctl_count);
    for chunk in bytes[12..sysctl_end].chunks_exact(3) {
        let change = SysctlChange {
            key: SysctlKey::try_from(chunk[0])?,
            original: chunk[1],
            applied: chunk[2],
        };
        if change.original > 2
            || change.applied > 2
            || change.original == change.applied
            || sysctls
                .last()
                .is_some_and(|previous: &SysctlChange| previous.key >= change.key)
        {
            return Err(NetworkError::Journal);
        }
        sysctls.push(change);
    }
    let request_len = usize::try_from(u32::from_be_bytes(
        bytes[sysctl_end..request_header_end]
            .try_into()
            .map_err(|_| NetworkError::Journal)?,
    ))
    .map_err(|_| NetworkError::Journal)?;
    if request_len == 0 || request_len > MAX_NETD_FRAME_LEN {
        return Err(NetworkError::Journal);
    }
    let request_end = request_header_end
        .checked_add(request_len)
        .ok_or(NetworkError::Journal)?;
    if request_end > content_len {
        return Err(NetworkError::Journal);
    }
    let request = NetdRequest::decode(&bytes[request_header_end..request_end])
        .map_err(|_| NetworkError::Journal)?;
    let NetdOperation::Prepare(declaration) = request.operation else {
        return Err(NetworkError::Journal);
    };
    let recovery_candidate = if version == MAGIC_V1 {
        if request_end != content_len {
            return Err(NetworkError::Journal);
        }
        None
    } else {
        let recovery_header_end = request_end.checked_add(4).ok_or(NetworkError::Journal)?;
        if recovery_header_end > content_len {
            return Err(NetworkError::Journal);
        }
        let recovery_len = usize::try_from(u32::from_be_bytes(
            bytes[request_end..recovery_header_end]
                .try_into()
                .map_err(|_| NetworkError::Journal)?,
        ))
        .map_err(|_| NetworkError::Journal)?;
        let recovery_end = recovery_header_end
            .checked_add(recovery_len)
            .ok_or(NetworkError::Journal)?;
        if recovery_len == 0 || recovery_len > MAX_NETD_FRAME_LEN || recovery_end != content_len {
            return Err(NetworkError::Journal);
        }
        let recovery = NetdRequest::decode(&bytes[recovery_header_end..recovery_end])
            .map_err(|_| NetworkError::Journal)?;
        if recovery.owner != request.owner || phase != TransactionPhase::RollingBack {
            return Err(NetworkError::Journal);
        }
        let NetdOperation::Prepare(candidate) = recovery.operation else {
            return Err(NetworkError::Journal);
        };
        Some(candidate)
    };
    Ok(TransactionRecord {
        owner: request.owner,
        declaration,
        recovery_candidate,
        phase,
        completed_steps,
        sysctls,
    })
}

fn validate_parent(path: &Path) -> Result<(), NetworkError> {
    let parent = path.parent().ok_or(NetworkError::Journal)?;
    let metadata = fs::symlink_metadata(parent).map_err(journal_error)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.permissions().mode() & 0o022 != 0
        || metadata.uid() != nix::unistd::geteuid().as_raw()
    {
        return Err(NetworkError::Journal);
    }
    Ok(())
}

fn open_existing(path: &Path) -> Result<Option<File>, NetworkError> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(journal_error(error)),
    };
    let metadata = file.metadata().map_err(journal_error)?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.permissions().mode() & 0o177 != 0
    {
        return Err(NetworkError::Journal);
    }
    Ok(Some(file))
}

fn sync_directory(path: &Path) -> Result<(), NetworkError> {
    File::open(path)
        .map_err(journal_error)?
        .sync_all()
        .map_err(journal_error)
}

fn journal_error(_error: std::io::Error) -> NetworkError {
    NetworkError::Journal
}

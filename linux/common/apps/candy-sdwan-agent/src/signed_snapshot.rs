use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};
use toml_edit::{value, DocumentMut, Item};

const FILE_LIMIT: u64 = 8 * 1024 * 1024;
// Keep the entire referenced closure bounded at 16 MiB: at most two maximum-sized files.
const CLOSURE_LIMIT: u64 = 16 * 1024 * 1024;
const FILE_COUNT_LIMIT: usize = 128;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SnapshotFile {
    name: String,
    sha256: String,
    bytes: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Snapshot {
    pub directory: PathBuf,
    pub config: PathBuf,
    pub closure_sha256: String,
    files: Vec<SnapshotFile>,
}

pub(super) struct CleanupGuard {
    snapshot: Option<Snapshot>,
    files: Vec<PathBuf>,
}

impl CleanupGuard {
    pub fn new(snapshot: &Snapshot) -> Self {
        Self {
            snapshot: Some(snapshot.clone()),
            files: Vec::new(),
        }
    }

    pub fn track_file(&mut self, path: PathBuf) {
        self.files.push(path);
    }

    pub fn transfer(&mut self) {
        self.snapshot = None;
        self.files.clear();
    }
}

impl Drop for CleanupGuard {
    fn drop(&mut self) {
        if let Some(snapshot) = &self.snapshot {
            if let Err(error) = snapshot.retire() {
                eprintln!("level=warn code=signed_snapshot_cleanup_pending module=sdwan_activation directory={} detail={error:#}", snapshot.directory.display());
            }
            for path in &self.files {
                if let Err(error) = remove_if_present(path) {
                    eprintln!("level=warn code=signed_snapshot_cleanup_pending module=sdwan_activation file={} detail={error:#}", path.display());
                }
            }
        }
    }
}

fn private_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !path.is_absolute()
        || !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.mode() & 0o777 != 0o700
    {
        bail!("signed snapshot requires a private current-user 0700 directory");
    }
    Ok(())
}

fn read_bounded(path: &Path) -> Result<Vec<u8>> {
    read_with_budget(path, FILE_LIMIT)
}

fn read_with_budget(path: &Path, remaining: u64) -> Result<Vec<u8>> {
    let limit = FILE_LIMIT.min(remaining);
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > limit {
        bail!("signed snapshot input must be a bounded regular file");
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        bail!("signed snapshot input grew beyond its limit");
    }
    Ok(bytes)
}

pub(super) fn fingerprint(config: &Path) -> Result<Vec<u8>> {
    let mut total = 0;
    let mut entries = Vec::new();
    let mut read_entry = |name: String, path: &Path| -> Result<Vec<u8>> {
        if entries.len() >= FILE_COUNT_LIMIT {
            bail!("signed closure exceeds file budget");
        }
        let bytes = read_with_budget(path, CLOSURE_LIMIT - total)?;
        total += bytes.len() as u64;
        entries.push((name, format!("{:x}", Sha256::digest(&bytes))));
        Ok(bytes)
    };
    let document: DocumentMut =
        String::from_utf8(read_entry("config".to_owned(), config)?)?.parse()?;
    if document
        .get("peers")
        .and_then(Item::as_array_of_tables)
        .is_some_and(|peers| peers.len() > FILE_COUNT_LIMIT - 3)
    {
        bail!("signed closure exceeds file budget");
    }
    let reference_path = |item: &Item| -> Result<PathBuf> {
        let path = item
            .as_str()
            .context("signed reference must be a path string")?;
        if !Path::new(path).is_absolute() {
            bail!("signed reference must be absolute");
        }
        Ok(PathBuf::from(path))
    };
    for key in ["segment_snapshot", "site_projection"] {
        read_entry(
            key.to_owned(),
            &reference_path(document.get(key).context("signed reference absent")?)?,
        )?;
    }
    if let Some(peers) = document.get("peers").and_then(Item::as_array_of_tables) {
        for (index, peer) in peers.iter().enumerate() {
            let bytes = read_entry(
                format!("peer-{index}-transport"),
                &reference_path(
                    peer.get("transport_config")
                        .context("peer transport absent")?,
                )?,
            )?;
            let transport: DocumentMut = String::from_utf8(bytes)?.parse()?;
            if let Some(cloud) = transport.get("cloud_auth").and_then(Item::as_table_like) {
                for key in ["grant_envelope_path", "device_signing_key_path"] {
                    if let Some(reference) = cloud.get(key) {
                        read_entry(format!("peer-{index}-{key}"), &reference_path(reference)?)?;
                    }
                }
            }
        }
    }
    Ok(Sha256::digest(serde_json::to_vec(&entries)?).to_vec())
}

struct Builder {
    directory: PathBuf,
    files: Vec<SnapshotFile>,
    total: u64,
}

impl Builder {
    fn read(&self, path: &Path) -> Result<Vec<u8>> {
        if self.files.len() >= FILE_COUNT_LIMIT {
            bail!("signed snapshot closure exceeds file budget");
        }
        read_with_budget(path, CLOSURE_LIMIT.saturating_sub(self.total))
    }

    fn write(&mut self, name: String, bytes: &[u8]) -> Result<PathBuf> {
        if bytes.len() as u64 > FILE_LIMIT {
            bail!("signed snapshot generated file exceeds eight MiB input budget");
        }
        self.total = self
            .total
            .checked_add(bytes.len() as u64)
            .context("snapshot size overflow")?;
        if self.total > CLOSURE_LIMIT || self.files.len() >= FILE_COUNT_LIMIT {
            bail!("signed snapshot closure exceeds explicit byte/file budget");
        }
        let path = self.directory.join(&name);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o400)
            .open(&path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        self.files.push(SnapshotFile {
            name,
            sha256: format!("{:x}", Sha256::digest(bytes)),
            bytes: bytes.len() as u64,
        });
        Ok(path)
    }

    fn reference(&mut self, item: &mut Item, label: &str) -> Result<()> {
        let path = item
            .as_str()
            .context("signed configuration reference must be a string")?;
        if !Path::new(path).is_absolute() {
            bail!("signed snapshot requires absolute source references");
        }
        let bytes = self.read(Path::new(path))?;
        let output = self.write(format!("{}-{label}.bin", self.files.len()), &bytes)?;
        *item = value(output.to_str().context("snapshot reference is not UTF-8")?);
        Ok(())
    }

    fn transport(&mut self, item: &mut Item) -> Result<()> {
        let path = item
            .as_str()
            .context("transport reference must be a string")?;
        if !Path::new(path).is_absolute() {
            bail!("transport snapshot requires an absolute source reference");
        }
        let mut config: DocumentMut = String::from_utf8(self.read(Path::new(path))?)?.parse()?;
        if let Some(cloud) = config
            .get_mut("cloud_auth")
            .and_then(Item::as_table_like_mut)
        {
            for key in ["grant_envelope_path", "device_signing_key_path"] {
                if let Some(reference) = cloud.get_mut(key) {
                    self.reference(reference, key)?;
                }
            }
        }
        let output = self.write(
            format!("{}-transport.toml", self.files.len()),
            config.to_string().as_bytes(),
        )?;
        *item = value(output.to_str().context("snapshot transport is not UTF-8")?);
        Ok(())
    }
}

impl Snapshot {
    pub fn capture(config: &Path, parent: &Path) -> Result<Self> {
        private_directory(parent)?;
        let directory = parent.join(format!("signed-snapshot-{}", uuid::Uuid::new_v4().simple()));
        fs::create_dir(&directory)?;
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
        let result = (|| {
            let mut document: DocumentMut = String::from_utf8(read_bounded(config)?)?.parse()?;
            let mut builder = Builder {
                directory: directory.clone(),
                files: Vec::new(),
                total: 0,
            };
            for key in ["segment_snapshot", "site_projection"] {
                builder.reference(
                    document.get_mut(key).context("missing signed reference")?,
                    key,
                )?;
            }
            if let Some(peers) = document
                .get_mut("peers")
                .and_then(Item::as_array_of_tables_mut)
            {
                for peer in peers.iter_mut() {
                    builder.transport(
                        peer.get_mut("transport_config")
                            .context("missing peer transport")?,
                    )?;
                }
            }
            let config =
                builder.write("client.toml".to_owned(), document.to_string().as_bytes())?;
            let closure_sha256 =
                format!("{:x}", Sha256::digest(serde_json::to_vec(&builder.files)?));
            let snapshot = Self {
                directory: directory.clone(),
                config,
                closure_sha256,
                files: builder.files,
            };
            let mut manifest = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o400)
                .open(directory.join("manifest.json"))?;
            manifest.write_all(&serde_json::to_vec(&snapshot)?)?;
            manifest.sync_all()?;
            OpenOptions::new().read(true).open(&directory)?.sync_all()?;
            snapshot.verify()?;
            Ok(snapshot)
        })();
        if result.is_err() {
            let _ = fs::remove_dir_all(&directory);
        }
        result
    }

    pub fn verify(&self) -> Result<()> {
        self.verify_remaining(false)
    }

    fn verify_remaining(&self, allow_missing: bool) -> Result<()> {
        private_directory(&self.directory)?;
        if self.files.len() > FILE_COUNT_LIMIT
            || self.config != self.directory.join("client.toml")
            || format!("{:x}", Sha256::digest(serde_json::to_vec(&self.files)?))
                != self.closure_sha256
        {
            bail!("signed snapshot manifest identity changed");
        }
        for entry in &self.files {
            if entry.name.contains('/') || entry.name == "." || entry.name == ".." {
                bail!("snapshot reference escapes private directory");
            }
            let path = self.directory.join(&entry.name);
            let metadata = match fs::symlink_metadata(&path) {
                Ok(metadata) => metadata,
                Err(error) if allow_missing && error.kind() == std::io::ErrorKind::NotFound => {
                    continue;
                }
                Err(error) => return Err(error.into()),
            };
            let bytes = read_bounded(&path)?;
            if metadata.uid() != nix::unistd::geteuid().as_raw()
                || metadata.mode() & 0o777 != 0o400
                || entry.bytes != bytes.len() as u64
                || format!("{:x}", Sha256::digest(&bytes)) != entry.sha256
            {
                bail!("code=signed_snapshot_changed module=sdwan_activation detail=exact signed configuration closure changed");
            }
        }
        Ok(())
    }

    pub fn retire(&self) -> Result<()> {
        if !self.directory.try_exists()? {
            return Ok(());
        }
        self.verify_remaining(true)?;
        for file in &self.files {
            remove_if_present(&self.directory.join(&file.name))?;
        }
        remove_if_present(&self.directory.join("manifest.json"))?;
        fs::remove_dir(&self.directory)?;
        Ok(())
    }
}

fn remove_if_present(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn closure_reader_rejects_file_before_reading_beyond_remaining_budget() {
        let root = tempfile::tempdir().unwrap();
        let input = root.path().join("input");
        fs::write(&input, [0; 17]).unwrap();
        assert!(read_with_budget(&input, 16).is_err());
        assert_eq!(read_with_budget(&input, 17).unwrap().len(), 17);
        let builder = Builder {
            directory: root.path().to_path_buf(),
            files: Vec::new(),
            total: CLOSURE_LIMIT - 16,
        };
        assert!(builder.read(&input).is_err());
    }

    #[test]
    fn signed_file_limit_accepts_large_geo_inputs_and_rejects_over_limit_without_mutation() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let input = root.path().join("geo-routes");
        let active = root.path().join("active-config");
        fs::write(&input, vec![b'4'; (1024 * 1024) + 1]).unwrap();
        fs::write(&active, b"currently-active").unwrap();

        assert_eq!(read_bounded(&input).unwrap().len(), (1024 * 1024) + 1);
        fs::write(&input, vec![b'4'; FILE_LIMIT as usize]).unwrap();
        assert_eq!(read_bounded(&input).unwrap().len() as u64, FILE_LIMIT);
        fs::write(&input, vec![b'4'; FILE_LIMIT as usize + 1]).unwrap();
        assert!(read_bounded(&input).is_err());
        assert_eq!(fs::read(active).unwrap(), b"currently-active");
    }

    #[test]
    fn signed_closure_keeps_sixteen_mib_total_budget_for_multiple_large_files() {
        let root = tempfile::tempdir().unwrap();
        let mut builder = Builder {
            directory: root.path().to_path_buf(),
            files: Vec::new(),
            total: 0,
        };
        let large = vec![0; (8 * 1024 * 1024) as usize];
        builder.write("first".into(), &large).unwrap();
        builder.write("second".into(), &large).unwrap();
        assert!(builder.write("third".into(), b"x").is_err());
    }

    #[test]
    fn oversized_candidate_snapshot_preserves_existing_active_snapshot() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        for name in ["segment", "projection"] {
            fs::write(root.path().join(name), name).unwrap();
        }
        let config = root.path().join("config");
        fs::write(
            &config,
            format!(
                "segment_snapshot = {:?}\nsite_projection = {:?}\n",
                root.path().join("segment"),
                root.path().join("projection")
            ),
        )
        .unwrap();
        let active = Snapshot::capture(&config, root.path()).unwrap();
        let active_config = fs::read(&active.config).unwrap();
        OpenOptions::new()
            .write(true)
            .open(root.path().join("projection"))
            .unwrap()
            .set_len(FILE_LIMIT + 1)
            .unwrap();
        assert!(Snapshot::capture(&config, root.path()).is_err());
        active.verify().unwrap();
        assert_eq!(fs::read(&active.config).unwrap(), active_config);
        active.retire().unwrap();
    }

    #[test]
    fn unjournaled_snapshot_guard_retires_only_owned_generated_resources() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        for name in ["segment", "projection"] {
            fs::write(root.path().join(name), name).unwrap();
        }
        let config = root.path().join("config");
        fs::write(
            &config,
            format!(
                "segment_snapshot = {:?}\nsite_projection = {:?}\n",
                root.path().join("segment"),
                root.path().join("projection")
            ),
        )
        .unwrap();
        let snapshot = Snapshot::capture(&config, root.path()).unwrap();
        let generated_plan = root.path().join("generated-plan");
        fs::write(&generated_plan, "private plan").unwrap();
        let mut guard = CleanupGuard::new(&snapshot);
        guard.track_file(generated_plan.clone());
        drop(guard);
        assert!(!snapshot.directory.exists());
        assert!(!generated_plan.exists());
        assert!(config.exists());
        let snapshot = Snapshot::capture(&config, root.path()).unwrap();
        let mut guard = CleanupGuard::new(&snapshot);
        guard.transfer();
        drop(guard);
        snapshot.verify().unwrap();
        snapshot.retire().unwrap();
    }

    #[test]
    fn fingerprint_enforces_reference_budget_before_loading_peer_files() {
        let root = tempfile::tempdir().unwrap();
        let config = root.path().join("config");
        let mut contents =
            "segment_snapshot = '/missing'\nsite_projection = '/missing'\n".to_owned();
        for _ in 0..FILE_COUNT_LIMIT - 2 {
            contents.push_str("[[peers]]\ntransport_config = '/missing'\n");
        }
        fs::write(&config, contents).unwrap();
        assert!(fingerprint(&config)
            .unwrap_err()
            .to_string()
            .contains("file budget"));
    }

    #[test]
    fn fingerprint_limits_total_bytes_across_repeated_credential_references() {
        let root = tempfile::tempdir().unwrap();
        let grant = root.path().join("grant");
        fs::write(&grant, vec![0; FILE_LIMIT as usize]).unwrap();
        for name in ["segment", "projection"] {
            fs::write(root.path().join(name), name).unwrap();
        }
        let transport = root.path().join("transport");
        fs::write(
            &transport,
            format!("[cloud_auth]\ngrant_envelope_path = {grant:?}\n"),
        )
        .unwrap();
        let config = root.path().join("config");
        let mut contents = format!(
            "segment_snapshot = {:?}\nsite_projection = {:?}\n",
            root.path().join("segment"),
            root.path().join("projection")
        );
        for _ in 0..16 {
            contents.push_str(&format!("[[peers]]\ntransport_config = {transport:?}\n"));
        }
        fs::write(&config, contents).unwrap();
        assert!(fingerprint(&config).is_err());
    }

    #[test]
    fn snapshot_copies_referenced_credentials_and_detects_mutation() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        for name in ["segment", "projection", "grant", "key"] {
            fs::write(root.path().join(name), name).unwrap();
        }
        let transport = root.path().join("transport.toml");
        fs::write(
            &transport,
            format!(
                "[cloud_auth]\ngrant_envelope_path = {:?}\ndevice_signing_key_path = {:?}\n",
                root.path().join("grant"),
                root.path().join("key")
            ),
        )
        .unwrap();
        let config = root.path().join("client.toml");
        fs::write(&config, format!("segment_snapshot = {:?}\nsite_projection = {:?}\n[[peers]]\ntransport_config = {:?}\n", root.path().join("segment"), root.path().join("projection"), transport)).unwrap();
        let snapshot = Snapshot::capture(&config, root.path()).unwrap();
        let original_fingerprint = fingerprint(&config).unwrap();
        fs::write(root.path().join("grant"), "new grant").unwrap();
        assert_ne!(original_fingerprint, fingerprint(&config).unwrap());
        snapshot.verify().unwrap();
        let changed = snapshot.directory.join(&snapshot.files[0].name);
        fs::set_permissions(&changed, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(changed, "tampered").unwrap();
        assert!(snapshot.verify().is_err());
    }

    #[test]
    fn snapshot_rejects_symlink_input_and_cleans_partial_directory() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(root.path().join("real"), "config").unwrap();
        let link = root.path().join("link");
        std::os::unix::fs::symlink(root.path().join("real"), &link).unwrap();
        assert!(Snapshot::capture(&link, root.path()).is_err());
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 2);
    }

    #[test]
    fn verified_owned_snapshot_can_be_retired_without_removing_source_files() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        for name in ["segment", "projection"] {
            fs::write(root.path().join(name), name).unwrap();
        }
        let config = root.path().join("config");
        fs::write(
            &config,
            format!(
                "segment_snapshot = {:?}\nsite_projection = {:?}\n",
                root.path().join("segment"),
                root.path().join("projection")
            ),
        )
        .unwrap();
        let snapshot = Snapshot::capture(&config, root.path()).unwrap();
        fs::remove_file(snapshot.directory.join(&snapshot.files[0].name)).unwrap();
        snapshot.retire().unwrap();
        snapshot.retire().unwrap();
        assert!(!snapshot.directory.exists());
        assert!(config.exists());
        assert!(root.path().join("segment").exists());
    }
}

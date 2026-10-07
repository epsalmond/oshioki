//! Hook-local registry transactions. Wire records and signed bytes are unchanged.
use anyhow::{Context as _, Result, bail};
use nix::fcntl::{Flock, FlockArg};
use oshioki_protocol::{DevicePublicRecordV1, DeviceRegistryV1, VERSION_V1};
use serde::{Deserialize, Serialize};
use std::{
    fs, io,
    os::unix::fs::{MetadataExt as _, OpenOptionsExt as _},
    path::Path,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct LocalRegistry {
    #[serde(flatten)]
    pub registry: DeviceRegistryV1,
    // Local only: any revoke invalidates every outstanding recipient snapshot.
    // Retained after cleanup to fence identical-key remove/re-enroll (ABA).
    #[serde(default)]
    pub revocation_epoch: u64,
}

#[derive(Debug)]
pub(super) struct Busy(pub &'static str);
impl std::fmt::Display for Busy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} is busy; retry the operation", self.0)
    }
}
impl std::error::Error for Busy {}

fn protected(metadata: &fs::Metadata, directory: bool) -> Result<()> {
    if metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.mode() & 0o077 != 0
        || if directory {
            !metadata.is_dir()
        } else {
            !metadata.is_file()
        }
    {
        bail!("registry path must be owner-controlled with no group/other permissions");
    }
    Ok(())
}

// Separate stable files: devices.json is atomically renamed, these never are.
// Lock order is lifecycle -> registry. Decisions acquire registry only.
fn lock(directory: &Path, name: &'static str) -> Result<Flock<fs::File>> {
    let mut options = fs::OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY);
    let parent = options.open(directory).context("open registry directory")?;
    protected(&parent.metadata()?, true)?;
    let path_metadata = fs::symlink_metadata(directory)?;
    protected(&path_metadata, true)?;
    let opened = parent.metadata()?;
    if (opened.dev(), opened.ino()) != (path_metadata.dev(), path_metadata.ino()) {
        bail!("registry directory changed while opening");
    }
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(directory.join(name))
        .context("open registry lock")?;
    let metadata = file.metadata()?;
    protected(&metadata, false)?;
    // Hardlinks could join an unrelated lock domain and are never needed.
    if metadata.nlink() != 1 {
        bail!("registry lock must have one link");
    }
    Flock::lock(file, FlockArg::LockExclusiveNonblock).map_err(|(_, error)| {
        if error == nix::errno::Errno::EWOULDBLOCK {
            anyhow::Error::new(Busy(name))
        } else {
            anyhow::Error::new(error).context("lock registry state")
        }
    })
}

pub(super) struct LifecycleGuard {
    _lock: Flock<fs::File>,
}
impl LifecycleGuard {
    pub fn acquire(directory: &Path) -> Result<Self> {
        Ok(Self {
            _lock: lock(directory, ".devices-lifecycle.lock")?,
        })
    }
}

pub(super) struct Transaction<'a> {
    directory: &'a Path,
    _lock: Flock<fs::File>,
}
impl<'a> Transaction<'a> {
    pub fn acquire(directory: &'a Path) -> Result<Self> {
        Ok(Self {
            directory,
            _lock: lock(directory, ".devices.lock")?,
        })
    }
    pub fn load(&self) -> Result<LocalRegistry> {
        let file = match fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(self.directory.join("devices.json"))
        {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(LocalRegistry {
                    registry: DeviceRegistryV1 {
                        version: VERSION_V1,
                        devices: Vec::new(),
                    },
                    revocation_epoch: 0,
                });
            }
            Err(error) => return Err(error).context("read device registry"),
        };
        protected(&file.metadata()?, false)?;
        let state: LocalRegistry =
            serde_json::from_reader(file).context("parse device registry")?;
        state.registry.validate()?;
        Ok(state)
    }
    pub fn write(&self, state: &LocalRegistry) -> Result<()> {
        state.registry.validate()?;
        super::atomic_write_json(&self.directory.join("devices.json"), state, 0o600)
    }
}

// Free-function adapter keeps all transaction lifetimes late-bound for the
// injected writer seam; an inherent method item binds its self lifetime early.
pub(super) fn persist(transaction: &Transaction<'_>, state: &LocalRegistry) -> Result<()> {
    transaction.write(state)
}

pub(super) fn snapshot(directory: &Path) -> Result<LocalRegistry> {
    Transaction::acquire(directory)?.load()
}

fn same_credential(a: &DevicePublicRecordV1, b: &DevicePublicRecordV1) -> bool {
    a.version == b.version
        && a.kind == b.kind
        && a.fingerprint == b.fingerprint
        && a.credential_id == b.credential_id
        && a.credential_public_key == b.credential_public_key
        && a.box_public_key == b.box_public_key
}

pub(super) fn same_identity(a: &DevicePublicRecordV1, b: &DevicePublicRecordV1) -> bool {
    same_credential(a, b) && a.api_token_hash == b.api_token_hash
}

// Caller owns lifecycle across the subsequent bounded remote activation.
pub(super) fn pin(directory: &Path, device: &DevicePublicRecordV1) -> Result<()> {
    device.validate()?;
    if !device.active {
        bail!("cannot pin an inactive device");
    }
    let transaction = Transaction::acquire(directory)?;
    let mut state = transaction.load()?;
    if state.registry.devices.iter().any(|stored| {
        stored.credential_id == device.credential_id && stored.fingerprint != device.fingerprint
    }) {
        bail!("credential id is already enrolled under another record");
    }
    let mut device = device.clone();
    if let Some(stored) = state
        .registry
        .devices
        .iter()
        .find(|stored| stored.fingerprint == device.fingerprint)
    {
        if !stored.active {
            bail!("device revocation is pending; retry revoke before enrolling or pinning");
        }
        if same_credential(stored, &device) {
            device.sign_count = device.sign_count.max(stored.sign_count);
        }
    }
    state
        .registry
        .devices
        .retain(|stored| stored.fingerprint != device.fingerprint);
    state.registry.devices.push(device);
    transaction.write(&state)
}

#[derive(Debug)]
pub(super) enum GateError {
    Host(anyhow::Error),
    Denied(&'static str),
}

pub(super) fn authorize(
    directory: &Path,
    device: &DevicePublicRecordV1,
    epoch: u64,
    expires_at: i64,
    observed: Option<u32>,
    warning_only: bool,
) -> std::result::Result<(), GateError> {
    authorize_with(
        directory,
        device,
        epoch,
        expires_at,
        observed,
        warning_only,
        super::now,
        persist,
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn authorize_with(
    directory: &Path,
    device: &DevicePublicRecordV1,
    epoch: u64,
    expires_at: i64,
    observed: Option<u32>,
    warning_only: bool,
    clock: impl FnOnce() -> i64,
    write: impl FnOnce(&Transaction<'_>, &LocalRegistry) -> Result<()>,
) -> std::result::Result<(), GateError> {
    let transaction = Transaction::acquire(directory).map_err(GateError::Host)?;
    let mut state = transaction.load().map_err(GateError::Host)?;
    if epoch != state.revocation_epoch {
        return Err(GateError::Denied(
            "request predates local device revocation",
        ));
    }
    let stored = state
        .registry
        .devices
        .iter_mut()
        .find(|stored| stored.active && same_identity(stored, device))
        .ok_or(GateError::Denied(
            "request credential is revoked, missing, or replaced",
        ))?;
    if expires_at <= clock() {
        return Err(GateError::Denied("request expired at final authorization"));
    }
    // This locked gate orders authorization against durable inactive commits;
    // it cannot cancel an execution authorized before a later revoke.
    if let Some(observed) = observed {
        if observed != 0 && observed <= stored.sign_count && stored.sign_count != 0 {
            tracing::warn!(fingerprint=%stored.fingerprint, stored=stored.sign_count, observed, "authenticator signature counter regressed");
        }
        if observed > stored.sign_count {
            stored.sign_count = observed;
            if let Err(error) = write(&transaction, &state) {
                if !warning_only {
                    return Err(GateError::Host(error));
                }
                tracing::warn!(fingerprint=%device.fingerprint, error=%format!("{error:#}"), "sign count was not persisted");
            }
        }
    }
    Ok(())
}

//! Host process owns the global capture lock, private ticket and signer.
use crate::container_transport::Server;
use crate::{capture_lock, enrollment, read, refused, Enrollment, Ticket};
use hypermesh_crash_retention as retention;
use hypermesh_local_storage as storage;
use std::{
    fs::{self, File},
    io::{self, Write},
    path::{Path, PathBuf},
};
use uuid::Uuid;
#[derive(serde::Serialize)]
pub struct Mounts {
    pub run_id: Uuid,
    pub database: PathBuf,
    pub control: PathBuf,
}
pub struct Run {
    run: PathBuf,
    control: PathBuf,
    lock: File,
    server: Option<Server>,
    handoff: bool,
}
impl Run {
    pub fn prepare(state_path: &Path) -> io::Result<Self> {
        retention::host::require_root()?;
        let owner = retention::Owner::open()?;
        if owner.authority() != retention::Authority::Host {
            return Err(refused());
        }
        let directory = retention::root()?.join("config");
        owner.require(&directory)?;
        if state_path.file_name().and_then(|v| v.to_str()) != Some("device.json") {
            return Err(refused());
        }
        let state: Enrollment =
            serde_json::from_slice(&read(state_path)?).map_err(|_| refused())?;
        if !enrollment(&state) {
            return Err(refused());
        }
        let lock = capture_lock(&directory)?;
        let root = directory.join("crash-runs");
        storage::create_dir(&root)?;
        // Never reset an old run's age or multiply the account-wide allowance.
        if fs::read_dir(&root)?.next().is_some() {
            return Err(refused());
        }
        let id = Uuid::new_v4();
        let run = root.join(id.to_string());
        storage::create_dir(&run)?;
        let controls = directory.join("controls");
        storage::create_dir(&controls)?;
        let control = controls.join(id.to_string());
        storage::create_dir(&control)?;
        let value = Self {
            run,
            control,
            lock,
            server: None,
            handoff: false,
        };
        storage::create_dir(&value.run.join("database"))?;
        retention::stamp(&value.run)?;
        let ticket = Ticket {
            kind: "host-terms-v1",
            run_id: id,
            state_path: state_path.to_owned(),
            device: state.device_id,
            terms_version: state.terms_version,
            terms_sha256: state.terms_sha256,
            accepted_at: state.accepted_at,
        };
        let mut file = storage::open(&value.run.join("host-ticket.json"), storage::Open::New)?;
        file.write_all(&serde_json::to_vec(&ticket).map_err(|_| refused())?)?;
        file.sync_all()?;
        storage::sync_dir(&value.run)?;
        retention::host::validate(&value.run)?;
        retention::raw_mount_linux::create(&value.run)?;
        retention::permit(&value.run)?;
        Ok(value)
    }
    pub fn mounts(&self) -> io::Result<Mounts> {
        Ok(Mounts {
            run_id: Uuid::parse_str(
                self.run
                    .file_name()
                    .and_then(|v| v.to_str())
                    .ok_or_else(refused)?,
            )
            .map_err(|_| refused())?,
            database: self.run.join("database"),
            control: self.control.clone(),
        })
    }
    pub fn bind(&mut self, worker: &str, init_pid: i32) -> io::Result<()> {
        if self.server.is_some() {
            return Err(refused());
        }
        self.server = Some(Server::bind(&self.run, worker, init_pid, &self.control)?);
        Ok(())
    }
    pub fn serve_once(&mut self) -> io::Result<bool> {
        self.server.as_mut().ok_or_else(refused)?.serve_once()
    }
    /// Host calls this only after stopping the exact container. Raw reduction
    /// and deletion then happen under the existing collector's capture lock.
    pub fn handoff(&mut self) -> io::Result<()> {
        if let Some(server) = self.server.as_mut() {
            server.revoke();
        }
        retention::request_stop(&self.run)?;
        self.handoff = true;
        Ok(())
    }
}
impl Drop for Run {
    fn drop(&mut self) {
        if let Some(server) = self.server.as_mut() {
            server.revoke();
        }
        self.server.take();
        let _ = retention::request_stop(&self.run);
        if !self.handoff {
            if self.run.join("database").exists() {
                let _ = retention::raw_mount_linux::remove(&self.run);
            } else {
                let _ = fs::remove_dir_all(&self.run);
            }
        }
        let _ = fs::remove_dir_all(&self.control);
        if let Some(parent) = self.run.parent() {
            let _ = storage::sync_dir(parent);
        }
        drop(storage::UnlockOnDrop(&self.lock));
    }
}

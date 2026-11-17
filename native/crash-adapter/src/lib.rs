//! Native worker attachment. Raw SDK transport is permanently disabled.
#[cfg(target_os = "linux")]
pub mod container_peer;
#[cfg(target_os = "linux")]
pub mod container_transport;
use hypermesh_crash_retention as retention;
use hypermesh_local_storage as storage;
use serde::{Deserialize, Serialize};
use std::{
    ffi::{c_char, CStr, CString},
    fs::{self, File},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::Mutex,
    thread,
    time::{Duration, Instant},
};
use uuid::Uuid;

static ACTIVE: Mutex<Option<PathBuf>> = Mutex::new(None);
fn refused() -> io::Error {
    io::Error::other("Host native capture unavailable")
}
#[cfg(not(test))]
unsafe extern "C" {
    fn hypermesh_host_sdk_initialize(database: *const c_char, handler: *const c_char) -> i32;
    fn hypermesh_host_sdk_close();
}
#[cfg(test)]
unsafe fn hypermesh_host_sdk_initialize(_: *const c_char, _: *const c_char) -> i32 {
    1
}
#[cfg(test)]
unsafe fn hypermesh_host_sdk_close() {}

#[derive(Deserialize)]
struct Enrollment {
    device_id: Uuid,
    terms_version: String,
    terms_sha256: String,
    accepted_at: String,
}
#[derive(Serialize)]
struct Ticket {
    kind: &'static str,
    run_id: Uuid,
    state_path: PathBuf,
    device: Uuid,
    terms_version: String,
    terms_sha256: String,
    accepted_at: String,
}
fn read(path: &Path) -> io::Result<Vec<u8>> {
    if !path.is_absolute() || fs::canonicalize(path)? != path {
        return Err(refused());
    }
    storage::check_dir(path.parent().ok_or_else(refused)?)?;
    let mut bytes = Vec::new();
    storage::open(path, storage::Open::Read { private: true })?
        .take(16385)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 16384 {
        return Err(refused());
    }
    Ok(bytes)
}
fn enrollment(state: &Enrollment) -> bool {
    !state.device_id.is_nil()
        && state.terms_version == retention::host::TERMS_VERSION
        && state.terms_sha256 == retention::host::TERMS_SHA256
        && !state.accepted_at.trim().is_empty()
        && state.accepted_at.len() <= 64
}
fn capture_lock(directory: &Path) -> io::Result<File> {
    let file = storage::open(
        &directory.join("health-consent/crash-capture.lock"),
        storage::Open::Lock,
    )?;
    storage::lock(&file)?;
    Ok(file)
}
fn cleanup(run: &Path) -> io::Result<()> {
    retention::request_stop(run)?;
    let directory = run.parent().and_then(Path::parent).ok_or_else(refused)?;
    let deadline = Instant::now() + Duration::from_secs(5);
    let file = loop {
        match capture_lock(directory) {
            Ok(file) => break file,
            Err(_) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
            Err(_) => return Err(refused()),
        }
    };
    let _unlock = storage::UnlockOnDrop(&file);
    storage::check_dir(run)?;
    fs::remove_dir_all(run)?;
    storage::sync_dir(run.parent().ok_or_else(refused)?)
}
fn marker(run: &Path, name: &str, expected: &[u8]) -> io::Result<bool> {
    match storage::open(&run.join(name), storage::Open::Read { private: true }) {
        Ok(file) => {
            let mut bytes = Vec::new();
            file.take(65).read_to_end(&mut bytes)?;
            Ok(bytes == expected)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}
fn start(handler: &Path) -> io::Result<()> {
    if std::env::var("HYPERMESH_HOST_NATIVE_CRASH_ENABLED").as_deref() != Ok("1") {
        return Ok(());
    }
    retention::host::require_root()?;
    let mut active = ACTIVE.lock().map_err(|_| refused())?;
    if active.is_some() {
        return Err(refused());
    }
    let owner = retention::Owner::open()?;
    if owner.authority() != retention::Authority::Host {
        return Err(refused());
    }
    let directory = retention::root()?.join("config");
    owner.require(&directory)?;
    let state_path =
        PathBuf::from(std::env::var_os("HYPERMESH_HOST_CRASH_STATE").ok_or_else(refused)?);
    if state_path.file_name().and_then(|x| x.to_str()) != Some("device.json") {
        return Err(refused());
    }
    let state: Enrollment = serde_json::from_slice(&read(&state_path)?).map_err(|_| refused())?;
    if !enrollment(&state) {
        return Err(refused());
    }
    let id_text = std::env::var("HYPERMESH_HOST_CRASH_RUN").map_err(|_| refused())?;
    let id = Uuid::parse_str(&id_text).map_err(|_| refused())?;
    if id.is_nil() || id.to_string() != id_text {
        return Err(refused());
    }
    if !handler.is_absolute() || fs::canonicalize(handler)? != handler {
        return Err(refused());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = fs::symlink_metadata(handler)?;
        if !meta.is_file() || meta.uid() != 0 || meta.mode() & 0o022 != 0 || meta.nlink() != 1 {
            return Err(refused());
        }
    }
    let capture = capture_lock(&directory)?;
    let root = directory.join("crash-runs");
    storage::create_dir(&root)?;
    // A prior stopped run is discarded, never revived or sent after restart.
    // The shared capture lock proves no guarded writer owns these files.
    for (index, entry) in fs::read_dir(&root)?.enumerate() {
        if index >= 4096 {
            return Err(refused());
        }
        let old = entry?.path();
        storage::check_dir(&old)?;
        let name = old
            .file_name()
            .and_then(|x| x.to_str())
            .ok_or_else(refused)?;
        let prior = Uuid::parse_str(name).map_err(|_| refused())?;
        if prior.is_nil() || prior.to_string() != name {
            return Err(refused());
        }
        fs::remove_dir_all(old)?;
    }
    storage::sync_dir(&root)?;
    // Never replace an existing run or reset its retention clock.
    let run = root.join(id.to_string());
    if run.try_exists()? {
        return Err(refused());
    }
    storage::create_dir(&run)?;
    let prepared = (|| -> io::Result<()> {
        storage::create_dir(&run.join("database"))?;
        retention::stamp(&run)?;
        let ticket = Ticket {
            kind: "host-terms-v1",
            run_id: id,
            state_path,
            device: state.device_id,
            terms_version: state.terms_version,
            terms_sha256: state.terms_sha256,
            accepted_at: state.accepted_at,
        };
        let mut file = storage::open(&run.join("host-ticket.json"), storage::Open::New)?;
        file.write_all(&serde_json::to_vec(&ticket).map_err(|_| refused())?)?;
        file.sync_all()?;
        storage::sync_dir(&run)?;
        retention::host::validate(&run)?;
        retention::permit(&run)
    })();
    if prepared.is_err() {
        drop(storage::UnlockOnDrop(&capture));
        let _ = cleanup(&run);
        return Err(refused());
    }
    let database =
        CString::new(run.join("database").to_str().ok_or_else(refused)?).map_err(|_| refused())?;
    let handler = CString::new(handler.to_str().ok_or_else(refused)?).map_err(|_| refused())?;
    let result = thread::scope(|scope| {
        let handoff = scope.spawn(|| -> io::Result<()> {
            let _unlock = storage::UnlockOnDrop(&capture);
            let deadline = Instant::now() + Duration::from_secs(5);
            while !marker(&run, "handler-ready", b"host-crash-guard-v1")? {
                if Instant::now() >= deadline {
                    return Err(refused());
                }
                thread::sleep(Duration::from_millis(10));
            }
            Ok(())
        });
        let result = unsafe { hypermesh_host_sdk_initialize(database.as_ptr(), handler.as_ptr()) };
        handoff.join().map_err(|_| refused())??;
        if result != 0 {
            return Err(refused());
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        while !marker(&run, "handler-active", b"active")? {
            if Instant::now() >= deadline {
                return Err(refused());
            }
            thread::sleep(Duration::from_millis(10));
        }
        Ok(())
    });
    if result.is_err() {
        unsafe { hypermesh_host_sdk_close() };
        cleanup(&run)?;
        return Err(refused());
    }
    *active = Some(run);
    Ok(())
}
/// Called by the linked native constructor; no error includes runtime bytes.
#[no_mangle]
pub unsafe extern "C" fn hypermesh_host_crash_start(handler: *const c_char) {
    let _ = std::panic::catch_unwind(|| {
        if handler.is_null() {
            return;
        }
        if let Ok(handler) = CStr::from_ptr(handler).to_str() {
            let _ = start(Path::new(handler));
        }
    });
}
#[no_mangle]
pub extern "C" fn hypermesh_host_crash_stop() {
    let _ = std::panic::catch_unwind(|| {
        if let Ok(mut active) = ACTIVE.lock() {
            if let Some(run) = active.take() {
                unsafe { hypermesh_host_sdk_close() };
                let _ = cleanup(&run);
            }
        }
    });
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_recorded_current_terms_admit_worker_metadata() {
        let mut state = Enrollment {
            device_id: Uuid::new_v4(),
            terms_version: retention::host::TERMS_VERSION.into(),
            terms_sha256: retention::host::TERMS_SHA256.into(),
            accepted_at: "2026-11-17T00:00:00Z".into(),
        };
        assert!(enrollment(&state));
        state.terms_sha256 = "0".repeat(64);
        assert!(!enrollment(&state));
        state.terms_sha256 = retention::host::TERMS_SHA256.into();
        state.device_id = Uuid::nil();
        assert!(!enrollment(&state));
    }
}

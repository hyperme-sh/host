//! Host-owned bounded transport. This module does not start listeners itself.
use crate::container_peer::ContainerPeer;
use hypermesh_crash_retention::delegation::{
    HostSession, PublicConfig, CHALLENGE_TIMEOUT, REQUEST_SIZE, RESPONSE_SIZE,
};
use hypermesh_local_storage as storage;
use std::{
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    net::Shutdown,
    os::unix::{
        fs::OpenOptionsExt,
        net::{UnixListener, UnixStream},
    },
    path::Path,
    time::Instant,
};
fn refused() -> io::Error {
    io::Error::other("Host cleanup delegation refused")
}
fn remaining(start: Instant) -> io::Result<std::time::Duration> {
    CHALLENGE_TIMEOUT
        .checked_sub(start.elapsed())
        .filter(|d| !d.is_zero())
        .ok_or_else(refused)
}
fn request(stream: &mut UnixStream, start: Instant) -> io::Result<[u8; REQUEST_SIZE]> {
    // One fixed frame followed by write-half close. No trailing bytes or second
    // request can hide behind a valid prefix; the total deadline is monotonic.
    let mut bytes = [0; REQUEST_SIZE];
    let mut offset = 0;
    while offset < bytes.len() {
        stream.set_read_timeout(Some(remaining(start)?))?;
        let count = stream.read(&mut bytes[offset..])?;
        if count == 0 {
            return Err(refused());
        }
        offset += count;
    }
    stream.set_read_timeout(Some(remaining(start)?))?;
    if stream.read(&mut [0; 1])? != 0 {
        return Err(refused());
    }
    remaining(start)?;
    Ok(bytes)
}
/// Control directory is a fresh private Host-owned directory outside the raw
/// database. Bind-mount it read-only into only the selected container. The API
/// accepts no caller-provided identity or private-key serialization.
pub struct Server {
    session: HostSession,
    peer: ContainerPeer,
    listener: UnixListener,
}
impl Server {
    pub fn bind(run: &Path, worker: &str, init_pid: i32, control: &Path) -> io::Result<Self> {
        let peer = ContainerPeer::inspect(worker, init_pid)?;
        if !control.is_absolute() || control.starts_with(run) {
            return Err(refused());
        }
        storage::check_dir(control)?;
        // Fresh directory only; never replace/revive a prior public key/socket.
        if fs::read_dir(control)?.next().is_some() {
            return Err(refused());
        }
        let session = HostSession::open(run, worker)?;
        let listener = UnixListener::bind(control.join("cleanup.sock"))?;
        listener.set_nonblocking(true)?;
        let mut config = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o400)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(control.join("public.json"))?;
        config.write_all(&session.public_config().to_bytes()?)?;
        config.sync_all()?;
        storage::sync_dir(control)?;
        Ok(Self {
            session,
            peer,
            listener,
        })
    }
    pub fn public_config(&self) -> PublicConfig {
        self.session.public_config()
    }
    pub fn revoke(&mut self) {
        self.session.revoke();
    }
    /// Caller owns cancellation and calls this from a dedicated Host worker.
    /// No connection is a nonblocking false result. Any malformed or substituted
    /// peer, dead init, timeout or cleanup refusal permanently revokes this run.
    pub fn serve_once(&mut self) -> io::Result<bool> {
        let (mut stream, _) = match self.listener.accept() {
            Ok(value) => value,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(false),
            Err(_) => {
                self.revoke();
                return Err(refused());
            }
        };
        let start = Instant::now();
        let result = (|| {
            let peer = self.peer.accept(&stream)?;
            let bytes = request(&mut stream, start)?;
            let worker = self.peer.recheck(&peer)?;
            let response: [u8; RESPONSE_SIZE] = self.session.respond(&bytes, worker)?;
            self.peer.recheck(&peer)?;
            stream.set_write_timeout(Some(remaining(start)?))?;
            stream.write_all(&response)?;
            stream.shutdown(Shutdown::Write)?;
            remaining(start)?;
            Ok(true)
        })();
        if result.is_err() {
            self.revoke();
        }
        result.map_err(|_| refused())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn frame(bytes: &[u8]) -> io::Result<[u8; REQUEST_SIZE]> {
        let (mut client, mut server) = UnixStream::pair().unwrap();
        client.write_all(bytes).unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        request(&mut server, Instant::now())
    }
    #[test]
    fn only_one_complete_bounded_frame() {
        assert_eq!(frame(&[7; REQUEST_SIZE]).unwrap(), [7; REQUEST_SIZE]);
        for size in [0, 1, REQUEST_SIZE - 1, REQUEST_SIZE + 1, 4096] {
            assert!(frame(&vec![7; size]).is_err());
        }
    }
    #[test]
    fn deadline_includes_all_prior_work() {
        let (_client, mut server) = UnixStream::pair().unwrap();
        assert!(request(&mut server, Instant::now() - CHALLENGE_TIMEOUT).is_err());
    }
}

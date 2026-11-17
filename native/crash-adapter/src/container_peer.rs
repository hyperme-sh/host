//! Linux-only, kernel-derived identity for the Host cleanup delegation socket.
//! Request bytes never select a worker. Unsupported cgroup layouts fail closed.
use std::{
    ffi::CString,
    fs::File,
    io::{self, Read},
    os::{
        fd::{AsRawFd, FromRawFd, RawFd},
        unix::{fs::MetadataExt, net::UnixStream},
    },
    path::PathBuf,
};

fn refused() -> io::Error {
    io::Error::other("Host container peer refused")
}
fn open_at(dir: RawFd, name: &str, flags: i32) -> io::Result<File> {
    let name = CString::new(name).map_err(|_| refused())?;
    let fd = unsafe { libc::openat(dir, name.as_ptr(), flags | libc::O_CLOEXEC, 0) };
    if fd < 0 {
        return Err(refused());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}
fn bounded(mut file: File) -> io::Result<String> {
    let mut bytes = Vec::new();
    file.by_ref().take(8193).read_to_end(&mut bytes)?;
    if bytes.len() > 8192 {
        return Err(refused());
    }
    String::from_utf8(bytes).map_err(|_| refused())
}
fn worker_id(worker: &str) -> bool {
    worker.len() == 64
        && worker
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        && worker.bytes().any(|c| c != b'0')
}
fn cgroup_path(text: &str, worker: &str) -> io::Result<PathBuf> {
    if !worker_id(worker) {
        return Err(refused());
    }
    let mut lines = text.lines();
    let path = lines
        .next()
        .and_then(|s| s.strip_prefix("0::"))
        .ok_or_else(refused)?;
    if lines.next().is_some() || !path.starts_with('/') || path.len() > 4096 {
        return Err(refused());
    }
    let parts: Vec<_> = path[1..].split('/').collect();
    if parts.iter().any(|p| {
        p.is_empty()
            || *p == "."
            || *p == ".."
            || !p
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
    }) {
        return Err(refused());
    }
    let leaf = *parts.last().ok_or_else(refused)?;
    if leaf != worker && leaf != format!("docker-{worker}.scope") {
        return Err(refused());
    }
    Ok(PathBuf::from(path))
}
fn same(a: &File, b: &File) -> io::Result<bool> {
    let a = a.metadata()?;
    let b = b.metadata()?;
    Ok(a.dev() == b.dev() && a.ino() == b.ino())
}
fn cgroup_file(path: &std::path::Path) -> io::Result<File> {
    let mut dir = open_at(
        libc::AT_FDCWD,
        "/sys/fs/cgroup",
        libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW,
    )?;
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(dir.as_raw_fd(), &mut stat) } != 0 || stat.f_type != 0x63677270 {
        return Err(refused());
    }
    for part in path.components().skip(1) {
        let std::path::Component::Normal(name) = part else {
            return Err(refused());
        };
        dir = open_at(
            dir.as_raw_fd(),
            name.to_str().ok_or_else(refused)?,
            libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW,
        )?;
    }
    Ok(dir)
}
struct Process {
    proc: File,
    pidfd: File,
}
impl Process {
    fn open(pid: i32) -> io::Result<Self> {
        if pid <= 1 {
            return Err(refused());
        }
        // A live pidfd prevents a PID-reuse race from admitting a replacement.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        if fd < 0 {
            return Err(refused());
        }
        let pidfd = unsafe { File::from_raw_fd(fd as i32) };
        let proc = open_at(
            libc::AT_FDCWD,
            &format!("/proc/{pid}"),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW,
        )?;
        let process = Self { proc, pidfd };
        process.live()?;
        Ok(process)
    }
    fn live(&self) -> io::Result<()> {
        let mut poll = libc::pollfd {
            fd: self.pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        if unsafe { libc::poll(&mut poll, 1, 0) } != 0 {
            return Err(refused());
        }
        Ok(())
    }
    fn namespace(&self) -> io::Result<File> {
        // This is the kernel namespace handle under the pinned proc directory.
        open_at(self.proc.as_raw_fd(), "ns/pid", libc::O_RDONLY)
    }
    fn cgroup(&self, worker: &str) -> io::Result<File> {
        let text = bounded(open_at(
            self.proc.as_raw_fd(),
            "cgroup",
            libc::O_RDONLY | libc::O_NOFOLLOW,
        )?)?;
        cgroup_file(&cgroup_path(&text, worker)?)
    }
}
/// Construct only from the full Docker container ID and running init PID obtained
/// by Host inspection. Keeps the original process and cgroup object pinned.
pub struct ContainerPeer {
    worker: String,
    init: Process,
    namespace: File,
    cgroup: File,
}
pub struct ConnectionPeer {
    process: Process,
}
impl ContainerPeer {
    pub fn inspect(worker: &str, init_pid: i32) -> io::Result<Self> {
        if unsafe { libc::geteuid() } != 0 || !worker_id(worker) {
            return Err(refused());
        }
        let init = Process::open(init_pid)?;
        let namespace = init.namespace()?;
        let own = File::open("/proc/self/ns/pid")?;
        if same(&namespace, &own)? {
            return Err(refused());
        }
        let cgroup = init.cgroup(worker)?;
        let result = Self {
            worker: worker.into(),
            init,
            namespace,
            cgroup,
        };
        result.check(&result.init)?;
        Ok(result)
    }
    fn check(&self, process: &Process) -> io::Result<()> {
        self.init.live()?;
        process.live()?;
        if !same(&self.namespace, &self.init.namespace()?)?
            || !same(&self.cgroup, &self.init.cgroup(&self.worker)?)?
            || !same(&self.namespace, &process.namespace()?)?
            || !same(&self.cgroup, &process.cgroup(&self.worker)?)?
        {
            return Err(refused());
        }
        process.live()?;
        self.init.live()
    }
    pub fn accept(&self, stream: &UnixStream) -> io::Result<ConnectionPeer> {
        let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut cred as *mut libc::ucred).cast(),
                &mut len,
            )
        } != 0
            || len as usize != std::mem::size_of::<libc::ucred>()
            || cred.uid != 0
        {
            return Err(refused());
        }
        let peer = ConnectionPeer {
            process: Process::open(cred.pid)?,
        };
        self.check(&peer.process)?;
        Ok(peer)
    }
    pub fn recheck(&self, peer: &ConnectionPeer) -> io::Result<&str> {
        self.check(&peer.process)?;
        Ok(&self.worker)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_cgroup_v2_worker_only() {
        let id = "a1".repeat(32);
        for path in [
            format!("/docker/{id}"),
            format!("/system.slice/docker-{id}.scope"),
        ] {
            assert_eq!(
                cgroup_path(&format!("0::{path}\n"), &id).unwrap(),
                PathBuf::from(path)
            );
        }
        for text in [
            format!("0::/docker/{id}/child"),
            format!("0::/docker/{id}x"),
            format!("0::/../{id}"),
            format!("0:://{id}"),
            format!("1:cpu:/docker/{id}"),
            format!("0::/docker/{id}\n1:cpu:/foo"),
            "0::/".into(),
        ] {
            assert!(cgroup_path(&text, &id).is_err(), "{text}");
        }
        assert!(cgroup_path("0::/docker/anything", "anything").is_err());
    }
    #[test]
    fn pinned_process_refuses_after_exit() {
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let process = Process::open(child.id() as i32).unwrap();
        process.live().unwrap();
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(process.live().is_err());
    }
    #[test]
    fn host_namespace_and_invalid_process_are_not_containers() {
        assert!(ContainerPeer::inspect(&"a1".repeat(32), std::process::id() as i32).is_err());
        assert!(Process::open(0).is_err());
        assert!(Process::open(-1).is_err());
        assert!(ContainerPeer::inspect("short", 2).is_err());
    }
}

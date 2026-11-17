//! Private pipe protocol between the Host agent and its installed helper.
#[cfg(target_os = "linux")]
fn run() -> std::io::Result<()> {
    use hypermesh_host_crash_adapter::container_run::Run;
    use serde::Deserialize;
    use std::{
        io::{self, Write},
        path::PathBuf,
        time::{Duration, Instant},
    };
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() == 2 && args[0] == "purge" {
        let id = uuid::Uuid::parse_str(&args[1]).map_err(|_| io::Error::other("invalid run"))?;
        if id.is_nil() || id.to_string() != args[1] {
            return Err(io::Error::other("invalid run"));
        }
        return hypermesh_crash_retention::raw_mount_linux::remove(
            &hypermesh_crash_retention::root()?
                .join("config/crash-runs")
                .join(&args[1]),
        );
    }
    if !args.is_empty() {
        return Err(io::Error::other("invalid operation"));
    }
    fn refused() -> io::Error {
        io::Error::other("Host container cleanup unavailable")
    }
    fn input(timeout: Duration) -> io::Result<Vec<u8>> {
        let start = Instant::now();
        let mut bytes = Vec::new();
        loop {
            let left = timeout.checked_sub(start.elapsed()).ok_or_else(refused)?;
            let mut poll = libc::pollfd {
                fd: 0,
                events: libc::POLLIN,
                revents: 0,
            };
            if unsafe { libc::poll(&mut poll, 1, left.as_millis().min(i32::MAX as u128) as _) } != 1
            {
                return Err(refused());
            }
            let mut byte = [0];
            if unsafe { libc::read(0, byte.as_mut_ptr().cast(), 1) } != 1 {
                return Err(refused());
            }
            if byte[0] == b'\n' {
                return Ok(bytes);
            }
            bytes.push(byte[0]);
            if bytes.len() > 4096 {
                return Err(refused());
            }
        }
    }
    fn output(value: &impl serde::Serialize) -> io::Result<()> {
        let mut out = io::stdout().lock();
        serde_json::to_writer(&mut out, value)?;
        out.write_all(b"\n")?;
        out.flush()
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Setup {
        state_path: PathBuf,
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Binding {
        worker: String,
        init_pid: i32,
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Stop {
        stopped: bool,
    }
    let setup: Setup = serde_json::from_slice(&input(Duration::from_secs(10))?)?;
    let mut run = Run::prepare(&setup.state_path)?;
    output(&run.mounts()?)?;
    let binding: Binding = serde_json::from_slice(&input(Duration::from_secs(30))?)?;
    run.bind(&binding.worker, binding.init_pid)?;
    output(&serde_json::json!({"ready":true}))?;
    loop {
        let mut poll = libc::pollfd {
            fd: 0,
            events: libc::POLLIN,
            revents: 0,
        };
        if unsafe { libc::poll(&mut poll, 1, 0) } != 0 {
            let stop: Stop = serde_json::from_slice(&input(Duration::from_secs(1))?)?;
            if !stop.stopped {
                return Err(refused());
            }
            run.handoff()?;
            return Ok(());
        }
        if !run.serve_once()? {
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}
fn main() {
    #[cfg(target_os = "linux")]
    if run().is_ok() {
        return;
    }
    eprintln!("Host container cleanup unavailable");
    std::process::exit(1);
}

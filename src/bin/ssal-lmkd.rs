//! Guest-scoped lightweight LMKD for shared-PID-namespace (`CONFIG_PID_NS=n`) + `hidepid=2` environments.
//!
//! Only operates on PIDs verified to belong to the Guest `ssal_guest` cgroup subtree.
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::io;
use std::os::fd::RawFd;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const LMK_TARGET: i32 = 0;
const LMK_PROCPRIO: i32 = 1;
const LMK_PROCREMOVE: i32 = 2;
const LMK_PROCPURGE: i32 = 3;
const LMK_GETKILLCNT: i32 = 4;
const LMK_SUBSCRIBE: i32 = 5;
const LMK_PROCKILL: i32 = 6;
const LMK_UPDATE_PROPS: i32 = 7;

const LMK_ASYNC_EVENT_KILL: i32 = 0;

const CGROUP_UNLIMITED_V1: u64 = 1 << 60;
const PRESSURE_POLL_INTERVAL: Duration = Duration::from_millis(250);
const KILL_COOLDOWN: Duration = Duration::from_millis(250);
const HIGH_WATERMARK_PCT: u64 = 90;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CgroupBackend {
    V1,
    V2,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct TrackedProc {
    pid: i32,
    uid: i32,
    oom_adj: i32,
    starttime: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ClientState {
    fd: RawFd,
    subscribed_kill: bool,
}

#[derive(Default, Debug)]
struct LmkdState {
    targets: Vec<(i32, i32)>,
    procs: BTreeMap<i32, TrackedProc>,
    kill_counts: BTreeMap<i32, i32>,
    last_high_events: u64,
    last_max_events: u64,
    last_kill: Option<Instant>,
}

fn parse_i32_words(bytes: &[u8]) -> Option<Vec<i32>> {
    if bytes.is_empty() || bytes.len() % 4 != 0 {
        return None;
    }
    Some(
        bytes
            .chunks_exact(4)
            .map(|c| i32::from_be_bytes([c[0], c[1], c[2], c[3]]))
            .collect(),
    )
}

fn encode_i32_words(words: &[i32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(words.len() * 4);
    for &w in words {
        out.extend_from_slice(&w.to_be_bytes());
    }
    out
}

fn read_proc_starttime(proc_root: &Path, pid: i32) -> Option<u64> {
    let stat = fs::read_to_string(proc_root.join(pid.to_string()).join("stat")).ok()?;
    let rparen = stat.rfind(')')?;
    let after = stat.get(rparen + 2..)?;
    // Field 22 in /proc/[pid]/stat is starttime (index 19 after comm + ') ').
    after.split_whitespace().nth(19)?.parse::<u64>().ok()
}

fn read_proc_rss_pages(proc_root: &Path, pid: i32) -> u64 {
    let Ok(statm) = fs::read_to_string(proc_root.join(pid.to_string()).join("statm")) else {
        return 0;
    };
    statm
        .split_whitespace()
        .nth(1)
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0)
}

fn write_oom_score_adj(proc_root: &Path, pid: i32, oom_adj: i32) {
    let path = proc_root.join(pid.to_string()).join("oom_score_adj");
    let _ = fs::write(path, format!("{oom_adj}\n"));
}

fn collect_cgroup_pids(cgroup_root: &Path) -> BTreeSet<i32> {
    let mut pids = BTreeSet::new();
    let mut stack = vec![cgroup_root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        if let Ok(text) = fs::read_to_string(dir.join("cgroup.procs")) {
            for line in text.lines() {
                if let Ok(pid) = line.trim().parse::<i32>() {
                    if pid > 1 {
                        pids.insert(pid);
                    }
                }
            }
        }
        if let Ok(entries) = fs::read_dir(&dir) {
            for entry in entries.flatten() {
                if entry.file_type().is_ok_and(|t| t.is_dir()) {
                    stack.push(entry.path());
                }
            }
        }
    }
    pids
}

fn detect_cgroup(explicit: Option<&Path>) -> io::Result<(PathBuf, CgroupBackend)> {
    if let Some(path) = explicit {
        if path.join("memory.usage_in_bytes").is_file() {
            return Ok((path.to_path_buf(), CgroupBackend::V1));
        }
        if path.join("memory.current").is_file() {
            return Ok((path.to_path_buf(), CgroupBackend::V2));
        }
        return Err(io::Error::other(format!(
            "unsupported cgroup dir: {}",
            path.display()
        )));
    }
    let v1 = Path::new("/dev/memcg");
    if v1.join("memory.usage_in_bytes").is_file() {
        return Ok((v1.to_path_buf(), CgroupBackend::V1));
    }
    let v2 = Path::new("/sys/fs/cgroup");
    if v2.join("memory.current").is_file() {
        return Ok((v2.to_path_buf(), CgroupBackend::V2));
    }
    Err(io::Error::other(
        "no Guest memory cgroup found (/dev/memcg or /sys/fs/cgroup)",
    ))
}

fn parse_u64_trimmed(path: &Path) -> Option<u64> {
    fs::read_to_string(path).ok()?.trim().parse::<u64>().ok()
}

fn parse_v2_events(path: &Path) -> (u64, u64) {
    let Ok(text) = fs::read_to_string(path) else {
        return (0, 0);
    };
    let mut high = 0u64;
    let mut max = 0u64;
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        match (parts.next(), parts.next().and_then(|v| v.parse::<u64>().ok())) {
            (Some("high"), Some(v)) => high = v,
            (Some("max"), Some(v)) => max = v,
            _ => {}
        }
    }
    (high, max)
}

fn check_memory_pressure(
    cgroup_root: &Path,
    backend: CgroupBackend,
    state: &mut LmkdState,
) -> bool {
    match backend {
        CgroupBackend::V2 => {
            let Some(current) = parse_u64_trimmed(&cgroup_root.join("memory.current")) else {
                return false;
            };
            let high = parse_u64_trimmed(&cgroup_root.join("memory.high"));
            let max = parse_u64_trimmed(&cgroup_root.join("memory.max"));
            let (ev_high, ev_max) = parse_v2_events(&cgroup_root.join("memory.events"));
            let event_tripped = ev_high > state.last_high_events || ev_max > state.last_max_events;
            state.last_high_events = ev_high;
            state.last_max_events = ev_max;

            let over_high = high.is_some_and(|h| h > 0 && current >= h);
            let near_max = max.is_some_and(|m| m > 0 && current.saturating_mul(100) >= m.saturating_mul(HIGH_WATERMARK_PCT));
            event_tripped || over_high || near_max
        }
        CgroupBackend::V1 => {
            let Some(usage) = parse_u64_trimmed(&cgroup_root.join("memory.usage_in_bytes")) else {
                return false;
            };
            let limit = parse_u64_trimmed(&cgroup_root.join("memory.limit_in_bytes"))
                .filter(|&v| v > 0 && v < CGROUP_UNLIMITED_V1);
            let soft = parse_u64_trimmed(&cgroup_root.join("memory.soft_limit_in_bytes"))
                .filter(|&v| v > 0 && v < CGROUP_UNLIMITED_V1);
            let over_soft = soft.is_some_and(|s| usage >= s);
            let near_limit = limit.is_some_and(|l| usage.saturating_mul(100) >= l.saturating_mul(HIGH_WATERMARK_PCT));
            over_soft || near_limit
        }
    }
}

fn select_victim(
    state: &mut LmkdState,
    guest_pids: &BTreeSet<i32>,
    proc_root: &Path,
) -> Option<TrackedProc> {
    // Prune exited or reused PIDs before selecting a victim.
    state.procs.retain(|&pid, entry| {
        guest_pids.contains(&pid)
            && read_proc_starttime(proc_root, pid).is_some_and(|st| st == entry.starttime)
    });

    state
        .procs
        .values()
        .filter(|p| p.oom_adj > 0)
        .max_by_key(|p| (p.oom_adj, read_proc_rss_pages(proc_root, p.pid)))
        .cloned()
}

fn send_packet(fd: RawFd, words: &[i32]) {
    let bytes = encode_i32_words(words);
    unsafe {
        let _ = libc::send(fd, bytes.as_ptr().cast(), bytes.len(), libc::MSG_NOSIGNAL);
    }
}

fn handle_command(
    words: &[i32],
    client: &mut ClientState,
    state: &mut LmkdState,
    cgroup_root: &Path,
    proc_root: &Path,
) {
    let Some(&cmd) = words.first() else {
        return;
    };
    match cmd {
        LMK_TARGET => {
            let mut targets = Vec::new();
            for pair in words[1..].chunks_exact(2) {
                targets.push((pair[0], pair[1]));
            }
            state.targets = targets;
        }
        LMK_PROCPRIO if words.len() >= 4 => {
            let pid = words[1];
            let uid = words[2];
            let oom_adj = words[3];
            if pid <= 1 {
                return;
            }
            let guest_pids = collect_cgroup_pids(cgroup_root);
            if !guest_pids.contains(&pid) {
                eprintln!("ssal-lmkd: ignoring LMK_PROCPRIO for non-guest pid={pid}");
                return;
            }
            let Some(starttime) = read_proc_starttime(proc_root, pid) else {
                return;
            };
            write_oom_score_adj(proc_root, pid, oom_adj);
            state.procs.insert(
                pid,
                TrackedProc {
                    pid,
                    uid,
                    oom_adj,
                    starttime,
                },
            );
        }
        LMK_PROCREMOVE if words.len() >= 2 => {
            state.procs.remove(&words[1]);
        }
        LMK_PROCPURGE => {
            state.procs.clear();
        }
        LMK_GETKILLCNT if words.len() >= 3 => {
            let min_adj = words[1];
            let max_adj = words[2];
            let count: i32 = state
                .kill_counts
                .range(min_adj..=max_adj)
                .map(|(_, &c)| c)
                .sum();
            send_packet(client.fd, &[LMK_GETKILLCNT, count]);
        }
        LMK_SUBSCRIBE if words.len() >= 2 => {
            if words[1] == LMK_ASYNC_EVENT_KILL {
                client.subscribed_kill = true;
            }
        }
        LMK_UPDATE_PROPS => {
            send_packet(client.fd, &[LMK_UPDATE_PROPS, 1]);
        }
        _ => {}
    }
}

fn try_reclaim(
    state: &mut LmkdState,
    clients: &[ClientState],
    cgroup_root: &Path,
    backend: CgroupBackend,
    proc_root: &Path,
) {
    if state
        .last_kill
        .is_some_and(|t| t.elapsed() < KILL_COOLDOWN)
    {
        return;
    }
    if !check_memory_pressure(cgroup_root, backend, state) {
        return;
    }
    let guest_pids = collect_cgroup_pids(cgroup_root);
    let Some(victim) = select_victim(state, &guest_pids, proc_root) else {
        return;
    };
    // Final verification immediately before SIGKILL.
    let current_pids = collect_cgroup_pids(cgroup_root);
    if !current_pids.contains(&victim.pid)
        || read_proc_starttime(proc_root, victim.pid) != Some(victim.starttime)
    {
        state.procs.remove(&victim.pid);
        return;
    }
    if unsafe { libc::kill(victim.pid, libc::SIGKILL) } == 0 {
        eprintln!(
            "ssal-lmkd: killed guest pid={} uid={} oom_adj={}",
            victim.pid, victim.uid, victim.oom_adj
        );
        state.procs.remove(&victim.pid);
        *state.kill_counts.entry(victim.oom_adj).or_insert(0) += 1;
        state.last_kill = Some(Instant::now());
        for client in clients {
            if client.subscribed_kill {
                send_packet(client.fd, &[LMK_PROCKILL, victim.pid, victim.uid]);
            }
        }
    }
}

fn open_listener(socket_path: Option<&Path>) -> io::Result<RawFd> {
    if let Ok(fd_str) = env::var("ANDROID_SOCKET_lmkd") {
        let fd: RawFd = fd_str
            .parse()
            .map_err(|_| io::Error::other("invalid ANDROID_SOCKET_lmkd"))?;
        if unsafe { libc::listen(fd, 8) } != 0 {
            return Err(io::Error::last_os_error());
        }
        return Ok(fd);
    }
    let path = socket_path.ok_or_else(|| {
        io::Error::other("ANDROID_SOCKET_lmkd or --socket <path> is required")
    })?;
    let _ = fs::remove_file(path);
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let cpath = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())?;
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let bytes = cpath.as_bytes_with_nul();
    if bytes.len() > addr.sun_path.len() {
        unsafe { libc::close(fd) };
        return Err(io::Error::other("socket path too long"));
    }
    for (dst, &src) in addr.sun_path.iter_mut().zip(bytes.iter()) {
        *dst = src as libc::c_char;
    }
    let addr_len = (std::mem::size_of::<libc::sa_family_t>() + bytes.len()) as libc::socklen_t;
    if unsafe { libc::bind(fd, (&raw const addr).cast(), addr_len) } != 0
        || unsafe { libc::listen(fd, 8) } != 0
    {
        let err = io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(err);
    }
    Ok(fd)
}

fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn main() -> io::Result<()> {
    eprintln!("ssal-lmkd: main entered");
    let mut socket_path: Option<PathBuf> = None;
    let mut cgroup_arg: Option<PathBuf> = None;
    let mut args = env::args_os().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--socket" {
            socket_path = args.next().map(PathBuf::from);
        } else if arg == "--cgroup-dir" {
            cgroup_arg = args.next().map(PathBuf::from);
        }
    }

    let (cgroup_root, backend) = detect_cgroup(cgroup_arg.as_deref())?;
    let listener_fd = open_listener(socket_path.as_deref())?;
    set_nonblocking(listener_fd)?;

    let proc_root = Path::new("/proc");
    let mut state = LmkdState::default();
    let mut clients: Vec<ClientState> = Vec::new();
    let mut last_pressure_check = Instant::now();

    println!(
        "guest_lmkd_ready=1 backend={backend:?} cgroup={}",
        cgroup_root.display()
    );

    let mut buf = [0u8; 4096];
    loop {
        let mut pollfds = Vec::with_capacity(1 + clients.len());
        pollfds.push(libc::pollfd {
            fd: listener_fd,
            events: libc::POLLIN,
            revents: 0,
        });
        for client in &clients {
            pollfds.push(libc::pollfd {
                fd: client.fd,
                events: libc::POLLIN,
                revents: 0,
            });
        }

        let rc = unsafe {
            libc::poll(
                pollfds.as_mut_ptr(),
                pollfds.len() as libc::nfds_t,
                PRESSURE_POLL_INTERVAL.as_millis() as libc::c_int,
            )
        };
        if rc < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }

        if pollfds[0].revents & libc::POLLIN != 0 {
            loop {
                let cfd = unsafe {
                    libc::accept4(
                        listener_fd,
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                        libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                    )
                };
                if cfd < 0 {
                    let err = io::Error::last_os_error();
                    if err.kind() == io::ErrorKind::WouldBlock {
                        break;
                    }
                    break;
                }
                clients.push(ClientState {
                    fd: cfd,
                    subscribed_kill: false,
                });
            }
        }

        let mut closed = Vec::new();
        for (idx, pfd) in pollfds.iter().skip(1).enumerate() {
            if pfd.revents & libc::POLLIN != 0 {
                loop {
                    let n = unsafe {
                        libc::recv(pfd.fd, buf.as_mut_ptr().cast(), buf.len(), 0)
                    };
                    if n < 0 {
                        let err = io::Error::last_os_error();
                        if err.kind() == io::ErrorKind::WouldBlock {
                            break;
                        }
                        closed.push(idx);
                        break;
                    }
                    if n == 0 {
                        closed.push(idx);
                        break;
                    }
                    if let Some(words) = parse_i32_words(&buf[..n as usize]) {
                        handle_command(&words, &mut clients[idx], &mut state, &cgroup_root, proc_root);
                    }
                }
            } else if pfd.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
                closed.push(idx);
            }
        }

        for idx in closed.into_iter().rev() {
            let removed = clients.remove(idx);
            unsafe {
                libc::close(removed.fd);
            }
        }

        if last_pressure_check.elapsed() >= PRESSURE_POLL_INTERVAL {
            try_reclaim(&mut state, &clients, &cgroup_root, backend, proc_root);
            last_pressure_check = Instant::now();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = env::temp_dir().join(format!("ssal-lmkd-test-{name}-{nanos}"));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn wire_roundtrip_big_endian() {
        let encoded = encode_i32_words(&[LMK_PROCPRIO, 1234, 10123, 900]);
        assert_eq!(
            parse_i32_words(&encoded),
            Some(vec![LMK_PROCPRIO, 1234, 10123, 900])
        );
        assert_eq!(parse_i32_words(&[1, 2, 3]), None);
    }

    #[test]
    fn rejects_non_guest_pid_and_accepts_guest_pid() {
        let root = temp_dir("cgroup-filter");
        let cg = root.join("cg");
        let proc_dir = root.join("proc");
        fs::create_dir_all(cg.join("apps/uid_10001/pid_222")).unwrap();
        fs::write(cg.join("cgroup.procs"), "100\n").unwrap();
        fs::write(cg.join("apps/uid_10001/pid_222/cgroup.procs"), "222\n").unwrap();

        fs::create_dir_all(proc_dir.join("222")).unwrap();
        fs::create_dir_all(proc_dir.join("999")).unwrap();
        // 22 fields after ') ' -> index 19 is starttime
        let fake_stat = "222 (app) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 55555 0 0";
        fs::write(proc_dir.join("222/stat"), fake_stat).unwrap();
        fs::write(proc_dir.join("999/stat"), fake_stat).unwrap();

        let mut state = LmkdState::default();
        let mut client = ClientState {
            fd: -1,
            subscribed_kill: false,
        };

        // Host PID 999 not in cgroup.procs -> must be ignored.
        handle_command(&[LMK_PROCPRIO, 999, 1000, 900], &mut client, &mut state, &cg, &proc_dir);
        assert!(!state.procs.contains_key(&999));

        // Guest PID 222 in nested cgroup -> must be registered and oom_score_adj written.
        handle_command(&[LMK_PROCPRIO, 222, 10001, 900], &mut client, &mut state, &cg, &proc_dir);
        assert_eq!(state.procs.get(&222).unwrap().starttime, 55555);
        assert_eq!(
            fs::read_to_string(proc_dir.join("222/oom_score_adj")).unwrap(),
            "900\n"
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn victim_selection_protects_non_positive_adj_and_checks_starttime() {
        let root = temp_dir("victim");
        let cg = root.join("cg");
        let proc_dir = root.join("proc");
        fs::create_dir_all(&cg).unwrap();
        fs::write(cg.join("cgroup.procs"), "10\n20\n30\n").unwrap();

        for (pid, st, rss) in [(10, 100, 5000), (20, 200, 1000), (30, 300, 4000)] {
            fs::create_dir_all(proc_dir.join(pid.to_string())).unwrap();
            fs::write(
                proc_dir.join(format!("{pid}/stat")),
                format!("{pid} (p) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 {st} 0 0"),
            )
            .unwrap();
            fs::write(
                proc_dir.join(format!("{pid}/statm")),
                format!("10000 {rss} 0 0 0 0 0"),
            )
            .unwrap();
        }

        let mut state = LmkdState::default();
        state.procs.insert(
            10,
            TrackedProc {
                pid: 10,
                uid: 1000,
                oom_adj: -900,
                starttime: 100,
            },
        );
        state.procs.insert(
            20,
            TrackedProc {
                pid: 20,
                uid: 10020,
                oom_adj: 900,
                starttime: 200,
            },
        );
        state.procs.insert(
            30,
            TrackedProc {
                pid: 30,
                uid: 10030,
                oom_adj: 900,
                starttime: 999, // Mismatched starttime -> PID reused, must be pruned!
            },
        );

        let guest_pids = collect_cgroup_pids(&cg);
        let victim = select_victim(&mut state, &guest_pids, &proc_dir).unwrap();
        assert_eq!(victim.pid, 20);
        assert!(!state.procs.contains_key(&30));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn pressure_detection_v2_and_v1() {
        let root = temp_dir("pressure");
        let v2 = root.join("v2");
        fs::create_dir_all(&v2).unwrap();
        fs::write(v2.join("memory.current"), "950\n").unwrap();
        fs::write(v2.join("memory.high"), "max\n").unwrap();
        fs::write(v2.join("memory.max"), "1000\n").unwrap();
        fs::write(v2.join("memory.events"), "low 0\nhigh 0\nmax 0\noom 0\n").unwrap();

        let mut state = LmkdState::default();
        assert!(check_memory_pressure(&v2, CgroupBackend::V2, &mut state));

        fs::write(v2.join("memory.current"), "500\n").unwrap();
        assert!(!check_memory_pressure(&v2, CgroupBackend::V2, &mut state));

        let v1 = root.join("v1");
        fs::create_dir_all(&v1).unwrap();
        fs::write(v1.join("memory.usage_in_bytes"), "910\n").unwrap();
        fs::write(v1.join("memory.limit_in_bytes"), "1000\n").unwrap();
        assert!(check_memory_pressure(&v1, CgroupBackend::V1, &mut state));

        let _ = fs::remove_dir_all(root);
    }
}

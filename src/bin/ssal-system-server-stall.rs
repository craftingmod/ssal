//! External, bounded snapshots: never ask the stalled ART thread to unwind itself.
use std::env;
use std::fs::{self, File};
use std::io;
use std::os::unix::fs::FileExt;
use std::process::ExitCode;

const NT_PRSTATUS: usize = 1;
const PTRACE_EVENT_STOP: u32 = 128;
const PTRACE_SEIZE: libc::c_int = 0x4206;
const PTRACE_INTERRUPT: libc::c_int = 0x4207;

fn wait_stopped(tid: libc::pid_t) -> Option<libc::c_int> {
    let mut status: libc::c_int = 0;
    loop {
        let waited = unsafe { libc::waitpid(tid, &mut status, libc::__WALL) };
        if waited < 0 {
            if io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return None;
        }
        return (waited == tid && libc::WIFSTOPPED(status)).then_some(status);
    }
}

fn snapshot(pid: libc::pid_t) -> ExitCode {
    let context = match fs::read_to_string(format!("/proc/{pid}/attr/current")) {
        Ok(s) => s.trim_end_matches('\0').to_owned(),
        Err(_) => return ExitCode::from(1),
    };
    if context != "u:r:ssal_p0001_system_server:s0" {
        eprintln!("refusing non-Guest SystemServer pid={pid} context={context}");
        return ExitCode::from(2);
    }
    let memory = match File::open(format!("/proc/{pid}/mem")) {
        Ok(file) => file,
        Err(e) => {
            eprintln!("mem: {e}");
            return ExitCode::from(3);
        }
    };
    let tasks = match fs::read_dir(format!("/proc/{pid}/task")) {
        Ok(dir) => dir,
        Err(_) => return ExitCode::from(4),
    };

    let mut captured = 0u32;
    for entry in tasks.flatten() {
        if captured >= 64 {
            break;
        }
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        let Ok(tid) = name.parse::<libc::pid_t>() else {
            continue;
        };
        if tid <= 1 {
            continue;
        }
        if unsafe { libc::ptrace(PTRACE_SEIZE, tid, 0, 0) } != 0 {
            eprintln!("seize: {}", io::Error::last_os_error());
            continue;
        }
        if unsafe { libc::ptrace(PTRACE_INTERRUPT, tid, 0, 0) } != 0 {
            eprintln!("interrupt: {}", io::Error::last_os_error());
            unsafe { libc::ptrace(libc::PTRACE_DETACH, tid, 0, 0) };
            continue;
        }
        if let Some(status) = wait_stopped(tid) {
            let mut regs = [0u64; 34];
            let mut iov = libc::iovec {
                iov_base: regs.as_mut_ptr().cast(),
                iov_len: std::mem::size_of_val(&regs),
            };
            if unsafe {
                libc::ptrace(
                    libc::PTRACE_GETREGSET,
                    tid,
                    NT_PRSTATUS as *mut libc::c_void,
                    &mut iov as *mut _ as *mut libc::c_void,
                )
            } == 0
            {
                println!(
                    "THREAD tid={tid} pc={:#x} lr={:#x} fp={:#x} sp={:#x}",
                    regs[32], regs[30], regs[29], regs[31]
                );
                for (i, reg) in regs.iter().take(9).enumerate() {
                    println!("REG tid={tid} x{i}={reg:#x}");
                }
                let mut lock = [0u8; 16];
                if memory
                    .read_exact_at(&mut lock, regs[0] & 0x00ff_ffff_ffff_ffff)
                    .is_ok()
                {
                    let w = [
                        u32::from_ne_bytes(lock[0..4].try_into().unwrap()),
                        u32::from_ne_bytes(lock[4..8].try_into().unwrap()),
                        u32::from_ne_bytes(lock[8..12].try_into().unwrap()),
                        u32::from_ne_bytes(lock[12..16].try_into().unwrap()),
                    ];
                    println!(
                        "WAIT_WORDS tid={tid} addr={:#x} words={:08x},{:08x},{:08x},{:08x}",
                        regs[0], w[0], w[1], w[2], w[3]
                    );
                }
                let mut fp = regs[29];
                // shortcut: FP and raw stack only; use offline CFI for omitted frames.
                for i in 0..40 {
                    if fp < regs[31] || fp - regs[31] >= 8 * 1024 * 1024 || (fp & 15) != 0 {
                        break;
                    }
                    let mut pair = [0u8; 16];
                    if memory.read_exact_at(&mut pair, fp).is_err() {
                        break;
                    }
                    let next_fp = u64::from_ne_bytes(pair[0..8].try_into().unwrap());
                    let next_pc = u64::from_ne_bytes(pair[8..16].try_into().unwrap());
                    println!(
                        "FRAME tid={tid} index={i} fp={fp:#x} pc={:#x}",
                        next_pc & 0x0000_ffff_ffff_ffff
                    );
                    if next_fp <= fp {
                        break;
                    }
                    fp = next_fp;
                }
                let mut stack = [0u8; 1024];
                if let Ok(n) = memory.read_at(&mut stack, regs[31]) {
                    for (i, chunk) in stack[..n].chunks_exact(8).enumerate() {
                        let val = u64::from_ne_bytes(chunk.try_into().unwrap());
                        println!("STACK tid={tid} offset={} value={val:#x}", i * 8);
                    }
                }
                captured += 1;
            } else {
                eprintln!("getregset: {}", io::Error::last_os_error());
            }
            // Preserve a genuine signal-delivery stop, suppress our synthetic event stop.
            let sig = if ((status as u32) >> 16) == PTRACE_EVENT_STOP {
                0
            } else {
                libc::WSTOPSIG(status)
            };
            if unsafe { libc::ptrace(libc::PTRACE_DETACH, tid, 0, sig as *mut libc::c_void) } != 0 {
                eprintln!("detach: {}", io::Error::last_os_error());
            }
        }
    }
    println!("CAPTURED={captured}");
    if captured > 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(5)
    }
}

fn main() -> ExitCode {
    let args: Vec<_> = env::args().collect();
    if args.len() != 2 {
        return ExitCode::from(64);
    }
    let Ok(pid) = args[1].parse::<libc::pid_t>() else {
        return ExitCode::from(64);
    };
    if pid <= 1 {
        return ExitCode::from(64);
    }
    snapshot(pid)
}

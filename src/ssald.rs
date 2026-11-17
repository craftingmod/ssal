#[cfg(unix)]
mod binder_probe;
#[cfg(unix)]
mod daemon;
#[cfg(unix)]
mod diagnostics;
#[cfg(unix)]
#[path = "guest/mod.rs"]
mod guest;
#[cfg(unix)]
mod service_contract;

#[cfg(unix)]
fn main() {
    let args: Vec<_> = std::env::args_os().collect();
    if args.get(1).is_some_and(|arg| {
        arg == "--shell-session" || arg == "--shell-enter" || arg == "--shell-fork"
    }) {
        // Daemon restart detection must not mistake independent Shell workers for ssald.
        if unsafe { libc::prctl(libc::PR_SET_NAME, c"ssal-shell".as_ptr()) } != 0 {
            eprintln!(
                "cannot name Shell worker: {}",
                std::io::Error::last_os_error()
            );
            std::process::exit(1);
        }
        if args.len() < 4 || args[3] != "--" {
            eprintln!("invalid Shell worker invocation");
            std::process::exit(2);
        }
        let words = args[4..]
            .iter()
            .map(|word| {
                word.clone()
                    .into_string()
                    .map_err(|_| std::io::Error::other("command must be UTF-8"))
            })
            .collect::<std::io::Result<Vec<_>>>();
        let result = words.and_then(|words| {
            if args[1] == "--shell-session" {
                guest::shell::session(args[2].to_str().unwrap_or("/"), &words)
            } else if args[1] == "--shell-fork" {
                guest::shell::fork(std::path::Path::new(&args[2]), &words)
            } else {
                guest::shell::enter(std::path::Path::new(&args[2]), &words)
            }
        });
        match result {
            Ok(code) => std::process::exit(code),
            Err(error) => {
                eprintln!("ssal shell: {error}");
                std::process::exit(1);
            }
        }
    }
    if args
        .get(1)
        .is_some_and(|arg| arg == "--zygote-readiness-client" || arg == "--zygote-fork-client")
    {
        if args.len() != 2 {
            eprintln!("invalid readiness client invocation");
            std::process::exit(1);
        }
        let result = if args[1] == "--zygote-fork-client" {
            guest::launcher::fork_client()
        } else {
            guest::launcher::readiness_client()
        };
        if let Err(e) = result {
            eprintln!("{e}");
            std::process::exit(1);
        }
        return;
    }
    #[cfg(feature = "phase2c-diagnostic")]
    if args
        .get(1)
        .is_some_and(|arg| arg == "--phase2c-rsbinder-runner")
    {
        if args.len() != 4 || unsafe { libc::geteuid() } != 0 {
            eprintln!("invalid Phase 2C diagnostic runner invocation");
            std::process::exit(1);
        }
        let root = std::path::PathBuf::from(ssal::unix::ROOT);
        let result = daemon::run_phase2c_diagnostic(
            &root,
            args[2].to_str().unwrap_or(""),
            std::path::Path::new(&args[3]),
        );
        match result {
            Ok(output) => println!("{output}"),
            Err(error) => {
                eprintln!("Phase 2C diagnostic: {error}");
                std::process::exit(1);
            }
        }
        return;
    }
    #[cfg(feature = "phase3-diagnostic")]
    if args
        .get(1)
        .is_some_and(|arg| arg == "--phase3-rsbinder-runner")
    {
        if args.len() != 5 || unsafe { libc::geteuid() } != 0 {
            eprintln!("invalid Phase 3 diagnostic runner invocation");
            std::process::exit(1);
        }
        let result = daemon::run_phase3_diagnostic(
            &std::path::PathBuf::from(ssal::unix::ROOT),
            args[2].to_str().unwrap_or(""),
            std::path::Path::new(&args[3]),
            std::path::Path::new(&args[4]),
        );
        match result {
            Ok(output) => println!("{output}"),
            Err(error) => {
                eprintln!("Phase 3 diagnostic: {error}");
                std::process::exit(1);
            }
        }
        return;
    }
    if args
        .get(1)
        .is_some_and(|a| a == "--runtime-credentials-worker")
    {
        if args.len() != 5 || unsafe { libc::geteuid() } != 0 {
            eprintln!("invalid runtime credentials worker");
            std::process::exit(1);
        }
        let result = diagnostics::selinux::runtime_preflight::environment::identity_worker(
            std::path::Path::new(&args[2]),
            args[3].to_str().unwrap_or(""),
            args[4].to_str().unwrap_or(""),
        );
        match result {
            Ok(v) => println!("{v}"),
            Err(e) => {
                eprintln!("runtime credentials: {e}");
                std::process::exit(1);
            }
        }
        return;
    }
    if args.get(1).is_some_and(|arg| {
        arg == "--prepare-worker"
            || arg == "--binder-probe-worker"
            || arg == "--selinux-probe-worker"
            || arg == "--servicemanager-preflight-worker"
            || arg == "--servicemanager-runtime-preflight-worker"
            || arg == "--enforcing-binder-worker"
            || arg == "--servicemanager-worker"
            || arg == "--guest-data-worker"
            || arg == "--guest-child-worker"
            || arg == "--guest-cgroup-worker"
            || arg == "--guest-processgroup-worker"
            || arg == "--guest-memory-worker"
            || arg == "--guest-service-worker"
            || arg == "--guest-services-6a-worker"
            || arg == "--guest-services-6b-worker"
            || arg == "--guest-zygote-7a-worker"
    }) {
        let force_regen = args.len() == 6 && args[5] == "--regen";
        if (args.len() != 5 && !force_regen)
            || (force_regen && args[1] != "--prepare-worker")
            || unsafe { libc::geteuid() } != 0
        {
            eprintln!("invalid prepare worker invocation");
            std::process::exit(1);
        }
        if let Err(e) = guest::prepare::worker(
            std::path::Path::new(&args[2]),
            std::path::Path::new(&args[3]),
            std::path::Path::new(&args[4]),
            args[1].to_str().unwrap_or(""),
            force_regen,
        ) {
            eprintln!("prepare worker: {e}");
            std::process::exit(1);
        }
        return;
    }
    if let Err(e) = daemon::run() {
        eprintln!("ssald: {e}");
        std::process::exit(1);
    }
}
#[cfg(not(unix))]
fn main() {
    eprintln!("ssald requires Android/Linux");
    std::process::exit(1);
}

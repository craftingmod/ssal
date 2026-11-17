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

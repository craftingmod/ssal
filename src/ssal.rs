#[cfg(unix)]
fn main() {
    use ssal::unix::{send, valid_image_name, Request, Response, ROOT, VERSION};
    use std::io::BufRead;
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let native_sepolicy =
        args.first().is_some_and(|a| a == "prepare") && args.iter().any(|a| a == "--native");
    if native_sepolicy {
        args.retain(|a| a != "--native");
    }
    if args
        .first()
        .is_some_and(|a| a == "probe" || a == "--lock-probe-child")
    {
        let internal = args[0] == "--lock-probe-child";
        match ssal::lock_namespace_probe::cli(&args[1..], internal) {
            Ok(true) => return,
            Ok(false) => std::process::exit(1),
            Err(e) => {
                eprintln!("lock probe: {e}");
                std::process::exit(1);
            }
        }
    }
    let (command, image_name, profile_name, file, force_regen) = match args.as_slice() {
        [a] if ["status", "doctor", "return", "logs", "stop-for-restart"].contains(&a.as_str()) => {
            (a.clone(), None, None, None, false)
        }
        [a, name] if a == "switch" && valid_image_name(name) => {
            ("switch".into(), Some(name.clone()), None, None, false)
        }
        [a, flag, profile] if a == "prepare" && flag == "--regen" && valid_image_name(profile) => {
            ("prepare".into(), None, Some(profile.clone()), None, true)
        }
        [a, profile]
            if [
                "doctor",
                "prepare",
                "probe-binder",
                "probe-selinux-transition",
                "probe-servicemanager-preflight",
                "probe-servicemanager-runtime-preflight",
                "probe-servicemanager",
                "probe-guest-data",
                "remove",
            ]
            .contains(&a.as_str())
                && valid_image_name(profile) =>
        {
            (a.clone(), None, Some(profile.clone()), None, false)
        }
        [a, image] if a == "create" && valid_image_name(image) => {
            ("create".into(), Some(image.clone()), None, None, false)
        }
        [a, image, profile]
            if a == "create" && valid_image_name(image) && valid_image_name(profile) =>
        {
            (
                "create".into(),
                Some(image.clone()),
                Some(profile.clone()),
                None,
                false,
            )
        }
        [a, name, path] if a == "add" && valid_image_name(name) => {
            match std::fs::File::open(path) {
                Ok(f) => ("add".into(), Some(name.clone()), None, Some(f), false),
                Err(e) => {
                    eprintln!("{e}");
                    std::process::exit(1)
                }
            }
        }
        _ => {
            eprintln!(
                "usage: ssal doctor [PROFILE_NAME] | prepare [--regen] [--native] PROFILE_NAME | probe-binder PROFILE_NAME | probe-selinux-transition PROFILE_NAME | probe-servicemanager-preflight PROFILE_NAME | probe-servicemanager-runtime-preflight PROFILE_NAME | probe-servicemanager PROFILE_NAME | probe-guest-data PROFILE_NAME | remove PROFILE_NAME | status | logs | add IMAGE_NAME PATH | create IMAGE_NAME [PROFILE_NAME] | switch IMAGE_NAME | return\nNames: 1-64 ASCII letters, digits, underscores or hyphens"
            );
            std::process::exit(2)
        }
    };
    let result = (|| -> Result<Response, Box<dyn std::error::Error>> {
        let mut stream = UnixStream::connect(format!("{ROOT}/run/ssald.sock"))?;
        send(
            &mut stream,
            &Request {
                version: VERSION,
                command,
                image_name,
                profile_name,
                force_regen,
                native_sepolicy,
            },
            file.as_ref().map(AsRawFd::as_raw_fd),
        )?;
        let mut line = String::new();
        std::io::BufReader::new(stream).read_line(&mut line)?;
        Ok(serde_json::from_str(&line)?)
    })();
    match result {
        Ok(r) => {
            println!("{}", r.message);
            if !r.ok {
                std::process::exit(1)
            }
        }
        Err(e) => {
            eprintln!("ssal: {e}");
            std::process::exit(1)
        }
    }
}
#[cfg(not(unix))]
fn main() {
    eprintln!("ssal requires Android/Linux");
    std::process::exit(1);
}

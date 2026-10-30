#[cfg(unix)]
fn main() {
    use ssal::unix::{send, valid_image_name, Request, Response, ROOT, VERSION};
    use std::io::BufRead;
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (command, image_name, profile_name, file) = match args.as_slice() {
        [a] if ["status", "doctor", "return", "logs", "stop-for-restart"].contains(&a.as_str()) => {
            (a.clone(), None, None, None)
        }
        [a, name] if a == "switch" && valid_image_name(name) => {
            ("switch".into(), Some(name.clone()), None, None)
        }
        [a, profile]
            if ["doctor", "prepare", "probe-binder", "remove"].contains(&a.as_str())
                && valid_image_name(profile) =>
        {
            (a.clone(), None, Some(profile.clone()), None)
        }
        [a, image] if a == "create" && valid_image_name(image) => {
            ("create".into(), Some(image.clone()), None, None)
        }
        [a, image, profile]
            if a == "create" && valid_image_name(image) && valid_image_name(profile) =>
        {
            (
                "create".into(),
                Some(image.clone()),
                Some(profile.clone()),
                None,
            )
        }
        [a, name, path] if a == "add" && valid_image_name(name) => {
            match std::fs::File::open(path) {
                Ok(f) => ("add".into(), Some(name.clone()), None, Some(f)),
                Err(e) => {
                    eprintln!("{e}");
                    std::process::exit(1)
                }
            }
        }
        _ => {
            eprintln!(
                "usage: ssal doctor [PROFILE_NAME] | prepare PROFILE_NAME | probe-binder PROFILE_NAME | remove PROFILE_NAME | status | logs | add IMAGE_NAME PATH | create IMAGE_NAME [PROFILE_NAME] | switch IMAGE_NAME | return\nNames: 1-64 ASCII letters, digits, underscores or hyphens"
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

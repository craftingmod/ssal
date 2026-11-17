#[cfg(unix)]
mod cli;

#[cfg(unix)]
fn main() {
    use ssal::unix::{send, Response, ROOT};
    use std::io::{self, BufRead, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;

    let args: Vec<String> = std::env::args().skip(1).collect();
    let action = match cli::parse(&args) {
        Ok(action) => action,
        Err(e) => {
            eprintln!("ssal: {e}\nTry 'ssal --help' for more information.");
            std::process::exit(2);
        }
    };
    let result = (|| -> Result<(), Box<dyn std::error::Error>> {
        let output = match action {
            cli::Action::Help(command) => cli::help(command.as_deref()),
            cli::Action::Version => format!("ssal {}", env!("CARGO_PKG_VERSION")),
            cli::Action::Probe => {
                let internal = args[0] == "--lock-probe-child";
                if !ssal::lock_namespace_probe::cli(&args[1..], internal)? {
                    std::process::exit(1);
                }
                return Ok(());
            }
            cli::Action::Request(request, path) => {
                let file = path
                    .map(|path| {
                        std::fs::File::open(&path).map_err(|e| format!("cannot open '{path}': {e}"))
                    })
                    .transpose()?;
                let mut stream = UnixStream::connect(format!("{ROOT}/run/ssald.sock"))
                    .map_err(|e| format!("cannot connect to ssald: {e}"))?;
                send(&mut stream, &request, file.as_ref().map(AsRawFd::as_raw_fd))?;
                let mut line = String::new();
                io::BufReader::new(stream).read_line(&mut line)?;
                let response: Response = serde_json::from_str(&line)?;
                if !response.ok {
                    return Err(response.message.into());
                }
                response.message
            }
        };
        writeln!(io::stdout().lock(), "{output}")?;
        Ok(())
    })();
    if let Err(e) = result {
        if e.downcast_ref::<io::Error>()
            .is_some_and(|e| e.kind() == io::ErrorKind::BrokenPipe)
        {
            return;
        }
        eprintln!("ssal: {e}");
        std::process::exit(1);
    }
}
#[cfg(not(unix))]
fn main() {
    eprintln!("ssal: requires Android/Linux");
    std::process::exit(1);
}

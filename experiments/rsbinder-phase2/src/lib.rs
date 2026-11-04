#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProbeKind {
    Host,
    Guest,
}

impl ProbeKind {
    #[cfg(target_os = "android")]
    fn name(self) -> &'static str {
        match self {
            Self::Host => "host",
            Self::Guest => "guest",
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Args {
    device: String,
    service: String,
    expected_descriptor: String,
}

fn parse_args(args: &[String]) -> Result<Args, &'static str> {
    if args.len() != 6
        || args[0] != "--device"
        || args[2] != "--service"
        || args[4] != "--expected-descriptor"
        || !args[1].starts_with('/')
        || args[3].is_empty()
    {
        return Err(
            "usage: probe --device ABSOLUTE_PATH --service NAME --expected-descriptor DESCRIPTOR",
        );
    }
    Ok(Args {
        device: args[1].clone(),
        service: args[3].clone(),
        expected_descriptor: args[5].clone(),
    })
}

pub fn run(kind: ProbeKind) {
    let args: Vec<_> = std::env::args().skip(1).collect();
    #[cfg(target_os = "android")]
    if kind == ProbeKind::Guest
        && args
            .first()
            .is_some_and(|arg| arg == "--initialize-private-properties")
    {
        if args.len() != 2 {
            eprintln!("usage: guest_probe --initialize-private-properties ABSOLUTE_PATH");
            std::process::exit(2);
        }
        match android_probe::initialize_private_properties(std::path::Path::new(&args[1])) {
            Ok(result) => println!("{result}"),
            Err(error) => {
                eprintln!("Guest property initialization: {error}");
                std::process::exit(1);
            }
        }
        return;
    }
    let args = match parse_args(&args) {
        Ok(args) => args,
        Err(message) => {
            eprintln!("{message}");
            std::process::exit(2);
        }
    };
    if let Err(message) = validate_kind_path(kind, &args) {
        eprintln!("{message}");
        std::process::exit(2);
    }

    #[cfg(target_os = "android")]
    android_probe::run(kind, args);

    #[cfg(not(target_os = "android"))]
    {
        let _ = (kind, args);
        eprintln!("rsbinder-phase2 probes must run on Android");
        std::process::exit(2);
    }
}

fn validate_kind_path(kind: ProbeKind, args: &Args) -> Result<(), &'static str> {
    if kind == ProbeKind::Host && args.device != "/dev/binder" {
        Err("host_probe requires the explicit Host path /dev/binder")
    } else {
        Ok(())
    }
}

#[cfg(target_os = "android")]
mod android_probe;

#[cfg(test)]
mod tests {
    use super::{parse_args, validate_kind_path, ProbeKind};

    #[test]
    fn device_service_and_descriptor_must_be_explicit() {
        let valid = [
            "--device",
            "/dev/binder",
            "--service",
            "package",
            "--expected-descriptor",
            "android.content.pm.IPackageManager",
        ]
        .map(str::to_owned);
        assert!(parse_args(&valid).is_ok());
        assert!(parse_args(&Vec::new()).is_err());
        assert!(validate_kind_path(ProbeKind::Host, &parse_args(&valid).unwrap()).is_ok());

        let relative = [
            "--device",
            "dev/binder",
            "--service",
            "package",
            "--expected-descriptor",
            "android.content.pm.IPackageManager",
        ]
        .map(str::to_owned);
        assert!(parse_args(&relative).is_err());

        let guest_path = [
            "--device",
            "/private/binder",
            "--service",
            "aidl_lazy_test_1",
            "--expected-descriptor",
            "BBinder",
        ]
        .map(str::to_owned);
        assert_eq!(
            parse_args(&guest_path).unwrap().expected_descriptor,
            "BBinder"
        );
        assert!(validate_kind_path(ProbeKind::Guest, &parse_args(&guest_path).unwrap()).is_ok());
        assert!(validate_kind_path(ProbeKind::Host, &parse_args(&guest_path).unwrap()).is_err());
    }
}

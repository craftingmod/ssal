use ssal::unix::{valid_image_name, Request, VERSION};

const COMMANDS: &[(&str, &str, &str)] = &[
    (
        "shell",
        "[PROFILE_NAME]",
        "Open an independent Guest shell with a PTY",
    ),
    (
        "exec",
        "[PROFILE_NAME] -- COMMAND [ARG]...",
        "Execute a command in the Guest environment",
    ),
    ("status", "", "Show images, profiles and background jobs"),
    ("logs", "", "Show daemon logs"),
    (
        "logcat",
        "[-d]",
        "Stream the running Guest profile's captured Android logs",
    ),
    (
        "doctor",
        "[PROFILE_NAME]",
        "Check the daemon or a guest profile",
    ),
    (
        "add",
        "IMAGE_NAME PATH",
        "Copy and register a raw ext4 system image",
    ),
    (
        "allow",
        "PACKAGE_NAME",
        "Allow a Host package UID for presenter socket access",
    ),
    (
        "create",
        "IMAGE_NAME [PROFILE_NAME]",
        "Create a profile with independent userdata",
    ),
    (
        "remove",
        "PROFILE_NAME",
        "Permanently delete a profile and its userdata",
    ),
    (
        "prepare",
        "[OPTION]... PROFILE_NAME",
        "Validate guest mounts without starting Android",
    ),
    (
        "start",
        "PROFILE_NAME",
        "Start the prepared Guest Android session",
    ),
    (
        "stop",
        "[PROFILE_NAME]",
        "Stop the running Guest Android session",
    ),
    (
        "switch",
        "IMAGE_NAME",
        "Switch systems (currently unavailable)",
    ),
    ("return", "", "Return to One UI (currently unavailable)"),
    (
        "probe-binder",
        "PROFILE_NAME",
        "Run the isolated Binder probe",
    ),
    (
        "probe-selinux-transition",
        "PROFILE_NAME",
        "Check SELinux transitions",
    ),
    (
        "probe-servicemanager-preflight",
        "PROFILE_NAME",
        "Check servicemanager prerequisites",
    ),
    (
        "probe-servicemanager-runtime-preflight",
        "PROFILE_NAME",
        "Check the private Binder runtime environment",
    ),
    (
        "probe-servicemanager",
        "PROFILE_NAME",
        "Run the servicemanager probe",
    ),
    (
        "probe-guest-data",
        "PROFILE_NAME",
        "Run the guest data isolation probe",
    ),
    (
        "probe",
        "KIND [OPTION]...",
        "Run an opt-in lock namespace probe",
    ),
    ("stop-for-restart", "", "Stop the daemon for module restart"),
];

pub enum Action {
    Shell {
        profile: Option<String>,
        command: Vec<String>,
    },
    Help(Option<String>),
    Version,
    Probe,
    Request(Request, Option<String>),
}

pub fn help(command: Option<&str>) -> String {
    let mut text = if let Some(command) = command {
        let (_, operands, description) = COMMANDS.iter().find(|c| c.0 == command).unwrap();
        format!("Usage: ssal {command} {operands}\n{description}\n")
    } else {
        let mut text = String::from("Usage: ssal [OPTION] COMMAND [ARG]...\nSSAL - System Switching Abstraction Layer\n\nCommands:\n");
        for (name, _, description) in COMMANDS.iter().filter(|c| c.0 != "stop-for-restart") {
            text.push_str(&format!("  {name:<40} {description}\n"));
        }
        text
    };
    text.push_str("\nOptions:\n  -h, --help       Display this help and exit\n");
    if command.is_none() {
        text.push_str("  -V, --version    Display version and exit\n\nUse 'ssal COMMAND --help' for command usage.\n");
    }
    if command == Some("prepare") {
        text.push_str("      --regen      Regenerate guest preparation artifacts\n      --native     Use the native KernelSU SELinux backend\n");
    }
    if command == Some("logcat") {
        text.push_str("  -d               Dump captured logs and exit\n");
    }
    if command == Some("probe") {
        text.push_str("\nKinds: lock-sysconfig, lock-rro, lock-mount-plain, lock-mount-context,\n       lock-mount-relabel, lock-target-plain, lock-target-context\nOptions: --dry-run, --execute --acknowledge-risk, --image PATH,\n         --guest-root PATH, --apk PATH, --method METHOD,\n         --sysconfig-image PATH, --sysconfig-sha256 HASH, --fail-at STAGE\n");
    } else {
        text.push_str("\nOptions may precede or follow operands. Use '--' to end option parsing.\nNames: 1-64 ASCII letters, digits, underscores or hyphens.\n");
    }
    text
}

pub fn parse(args: &[String]) -> Result<Action, String> {
    let Some(first) = args.first() else {
        return Err("missing command".into());
    };
    if first == "--lock-probe-child" {
        return Ok(Action::Probe);
    }
    if first == "--help" || first == "-h" {
        return Ok(Action::Help(None));
    }
    if first == "--version" || first == "-V" {
        return Ok(Action::Version);
    }
    if first == "help" {
        return match &args[1..] {
            [] => Ok(Action::Help(None)),
            [name] if COMMANDS.iter().any(|c| c.0 == name) => Ok(Action::Help(Some(name.clone()))),
            _ => Err("expected 'help [COMMAND]' with a known command".into()),
        };
    }
    let (command, usage, _) = COMMANDS.iter().find(|c| c.0 == first).ok_or_else(|| {
        if first.starts_with('-') {
            format!("unrecognized option '{first}'")
        } else {
            format!("unknown command '{first}'")
        }
    })?;
    if matches!(*command, "shell" | "exec") {
        let tail = &args[1..];
        if matches!(tail.first().map(String::as_str), Some("-h" | "--help")) {
            return Ok(Action::Help(Some(first.clone())));
        }
        let separator = tail.iter().position(|arg| arg == "--");
        let names = &tail[..separator.unwrap_or(tail.len())];
        if names.len() > 1
            || names
                .first()
                .is_some_and(|name| !valid_image_name(name) || name.starts_with('-'))
        {
            return Err(format!(
                "{command}: expected at most one valid profile name"
            ));
        }
        let words = separator
            .map(|index| tail[index + 1..].to_vec())
            .unwrap_or_default();
        if (*command == "exec" && words.is_empty()) || (*command == "shell" && !words.is_empty()) {
            return Err(format!("Usage: ssal {command} {usage}"));
        }
        return Ok(Action::Shell {
            profile: names.first().cloned(),
            command: words,
        });
    }
    // The probe has its own value-taking parser and execution safety checks.
    if *command == "probe" {
        return if matches!(args.get(1).map(String::as_str), Some("-h" | "--help")) {
            Ok(Action::Help(Some(first.clone())))
        } else {
            Ok(Action::Probe)
        };
    }
    let mut operands = Vec::new();
    let mut options = true;
    let mut force_regen = false;
    let mut native_sepolicy = false;
    let mut dump_logs = false;
    for arg in &args[1..] {
        match arg.as_str() {
            "--" if options => options = false,
            "-h" | "--help" if options => return Ok(Action::Help(Some(first.clone()))),
            "--regen" if options && *command == "prepare" => force_regen = true,
            "--native" if options && *command == "prepare" => native_sepolicy = true,
            "-d" if options && *command == "logcat" => dump_logs = true,
            _ if options && arg.starts_with('-') && arg != "-" => {
                return Err(format!("{command}: unrecognized option '{arg}'"));
            }
            _ => operands.push(arg.clone()),
        }
    }
    let (minimum, maximum) = match *command {
        "doctor" | "stop" => (0, 1),
        "create" => (1, 2),
        "add" => (2, 2),
        "status" | "logs" | "logcat" | "return" | "stop-for-restart" => (0, 0),
        _ => (1, 1),
    };
    if operands.len() < minimum || operands.len() > maximum {
        return Err(format!(
            "{command}: {} operand\nUsage: ssal {command} {usage}",
            if operands.len() < minimum {
                "missing"
            } else {
                "unexpected"
            }
        ));
    }
    if *command == "allow" {
        let name = &operands[0];
        if name.is_empty()
            || name.len() > 128
            || !name.contains('.')
            || name.starts_with('.')
            || name.ends_with('.')
            || name.contains("..")
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.' || b == b'-')
        {
            return Err(format!("allow: invalid package name '{name}'"));
        }
    } else {
        for name in operands
            .iter()
            .take(if *command == "add" { 1 } else { operands.len() })
        {
            if !valid_image_name(name) {
                return Err(format!("{command}: invalid name '{name}' (expected 1-64 ASCII letters, digits, '_' or '-')"));
            }
        }
    }
    let mut request = Request {
        version: VERSION,
        command: if dump_logs {
            "logcat-dump".into()
        } else {
            first.clone()
        },
        image_name: None,
        profile_name: None,
        force_regen,
        native_sepolicy,
    };
    let mut path = None;
    match *command {
        "add" => {
            request.image_name = Some(operands[0].clone());
            path = Some(operands[1].clone());
        }
        "create" | "switch" => {
            request.image_name = Some(operands[0].clone());
            request.profile_name = operands.get(1).cloned();
        }
        _ => request.profile_name = operands.first().cloned(),
    }
    Ok(Action::Request(request, path))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_words(args: &[&str]) -> Result<Action, String> {
        parse(&args.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn shell_and_exec_preserve_command_arguments() {
        let Action::Shell { profile, command } = parse_words(&[
            "exec",
            "one",
            "--",
            "/system/bin/sh",
            "-c",
            "printf '%s' 'a b'",
            "--help",
        ])
        .unwrap() else {
            panic!()
        };
        assert_eq!(profile.as_deref(), Some("one"));
        assert_eq!(
            command,
            ["/system/bin/sh", "-c", "printf '%s' 'a b'", "--help"]
        );
        assert!(matches!(
            parse_words(&["shell"]),
            Ok(Action::Shell { profile: None, .. })
        ));
        for args in [
            vec!["exec"],
            vec!["exec", "--"],
            vec!["exec", "one", "id"],
            vec!["shell", "../host"],
            vec!["shell", "--", "id"],
        ] {
            assert!(parse_words(&args).is_err(), "{args:?}");
        }
    }

    #[test]
    fn help_and_version_do_not_need_daemon() {
        for args in [
            vec!["--help"],
            vec!["-h"],
            vec!["help"],
            vec!["prepare", "--help"],
            vec!["help", "prepare"],
            vec!["probe", "--help"],
        ] {
            assert!(matches!(parse_words(&args), Ok(Action::Help(_))));
        }
        assert!(matches!(parse_words(&["--version"]), Ok(Action::Version)));
        for (command, _, _) in COMMANDS {
            assert!(help(Some(command)).contains(&format!("Usage: ssal {command}")));
        }
    }

    #[test]
    fn prepare_options_can_follow_operands() {
        for args in [
            vec!["prepare", "--regen", "--native", "profile1"],
            vec!["prepare", "profile1", "--native", "--regen"],
        ] {
            let Action::Request(r, _) = parse_words(&args).unwrap() else {
                panic!()
            };
            assert!(r.force_regen && r.native_sepolicy);
            assert_eq!(r.profile_name.as_deref(), Some("profile1"));
        }
    }

    #[test]
    fn separator_preserves_names_and_paths() {
        let Action::Request(r, path) = parse_words(&["add", "--", "-image", "--help"]).unwrap()
        else {
            panic!()
        };
        assert_eq!(r.image_name.as_deref(), Some("-image"));
        assert_eq!(path.as_deref(), Some("--help"));
        assert!(parse_words(&["prepare", "--", "--native"]).is_ok());
    }

    #[test]
    fn reject_bad_input_before_connecting() {
        for args in [
            vec![],
            vec!["unknown"],
            vec!["--bad"],
            vec!["status", "extra"],
            vec!["add", "image"],
            vec!["create", "../image"],
            vec!["remove", "bad/name"],
            vec!["status", "--native"],
            vec!["logcat", "profile1"],
            vec!["logs", "-d"],
            vec!["prepare", "--regen"],
        ] {
            assert!(parse_words(&args).is_err(), "{args:?}");
        }
    }

    #[test]
    fn logcat_defaults_to_following_the_active_profile() {
        for (args, expected) in [
            (&["logcat"][..], "logcat"),
            (&["logcat", "-d"][..], "logcat-dump"),
        ] {
            let Action::Request(request, None) = parse_words(args).unwrap() else {
                panic!()
            };
            assert_eq!(request.command, expected);
            assert_eq!(request.profile_name, None);
        }
    }

    #[test]
    fn existing_requests_and_internal_commands_are_preserved() {
        for (command, _, _) in COMMANDS
            .iter()
            .filter(|c| !matches!(c.0, "probe" | "shell" | "exec"))
        {
            let args = match *command {
                "add" => vec![*command, "image", "/tmp/image.img"],
                "allow" => vec![*command, "alyac.android.ssalsurface"],
                "create" | "switch" => vec![*command, "image"],
                "status" | "logs" | "logcat" | "return" | "stop-for-restart" => vec![*command],
                _ => vec![*command, "profile1"],
            };
            let Action::Request(r, _) = parse_words(&args).unwrap() else {
                panic!()
            };
            assert_eq!(r.command, *command);
            assert_eq!(r.version, VERSION);
        }
        assert!(matches!(
            parse_words(&["--lock-probe-child"]),
            Ok(Action::Probe)
        ));
    }
}

#![cfg(unix)]

use std::process::Command;

#[test]
fn help_and_version_use_stdout_and_succeed() {
    for args in [
        vec!["--help"],
        vec!["prepare", "--help"],
        vec!["help", "remove"],
        vec!["--version"],
        vec!["-V"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_ssal"))
            .args(&args)
            .output()
            .unwrap();
        assert!(output.status.success(), "{args:?}");
        assert!(output.stderr.is_empty(), "{args:?}");
        let text = String::from_utf8(output.stdout).unwrap();
        assert!(
            text.starts_with("Usage: ssal")
                || text == format!("ssal {}\n", env!("CARGO_PKG_VERSION"))
        );
    }
}

#[test]
fn usage_errors_use_stderr_and_exit_two() {
    for args in [
        vec![],
        vec!["unknown"],
        vec!["prepare"],
        vec!["status", "--regen"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_ssal"))
            .args(&args)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        assert!(output.stdout.is_empty(), "{args:?}");
        let text = String::from_utf8(output.stderr).unwrap();
        assert!(text.starts_with("ssal: "));
        assert!(text.contains("Try 'ssal --help'"));
    }
}

#[test]
fn file_errors_use_stderr_and_exit_one() {
    // A child of a regular file cannot be opened, regardless of daemon state.
    let path = format!("{}/image.img", env!("CARGO_BIN_EXE_ssal"));
    let output = Command::new(env!("CARGO_BIN_EXE_ssal"))
        .args(["add", "image", &path])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let text = String::from_utf8(output.stderr).unwrap();
    assert!(text.starts_with("ssal: cannot open '"));
    assert!(text.contains(&path));
}

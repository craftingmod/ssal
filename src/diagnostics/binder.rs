//! Reports private Binder validation without sending transactions to host Binder.
use crate::guest::binder::Session;
use serde::Serialize;
use std::fs;
use std::io;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::Path;

#[derive(Serialize, Clone, Copy)]
#[serde(rename_all = "snake_case")]
enum Status {
    NotRun,
    Passed,
    Failed,
    Unavailable,
}

#[derive(Serialize)]
struct Report {
    device_created: Status,
    device_opened: Status,
    driver_protocol: Option<i32>,
    context_manager: Status,
    ipc: Status,
    servicemanager: Status,
    android_service_selinux: Status,
    host_registry_isolation: Status,
    cleanup: Status,
    validation_scope: &'static str,
    failure: Option<String>,
}

pub(crate) fn verify(root: &Path) -> io::Result<()> {
    let mut report = Report {
        device_created: Status::NotRun,
        device_opened: Status::NotRun,
        driver_protocol: None,
        context_manager: Status::NotRun,
        ipc: Status::NotRun,
        servicemanager: Status::NotRun,
        android_service_selinux: Status::NotRun,
        host_registry_isolation: Status::NotRun,
        cleanup: Status::NotRun,
        validation_scope: "private_device_only",
        failure: None,
    };
    let host = fs::metadata("/dev/binder")?;
    if !host.file_type().is_char_device() {
        return Err(io::Error::other(
            "host /dev/binder is not a character device",
        ));
    }
    let mut session = Session::new();
    let result = (|| -> io::Result<()> {
        report.device_created = Status::Failed;
        let (major, minor, protocol) = session.provision(root)?;
        report.device_created = Status::Passed;
        report.device_opened = Status::Passed;
        report.driver_protocol = Some(protocol);
        // A fresh exec is mandatory: no inherited libbinder ProcessState/FDs.
        // The helper is only admitted after exact private device identity checks.
        crate::diagnostics::guest::binder_ipc(root, major, minor, &mut |stage| {
            if stage == "context_manager_attempt" {
                report.context_manager = Status::Failed;
            }
            if stage == "ipc_attempt" {
                report.ipc = Status::Failed;
            }
            if stage == "context_manager" {
                report.context_manager = Status::Passed;
            }
            if stage == "ipc" {
                report.ipc = Status::Passed;
                report.validation_scope = "management_domain_ipc_only";
            }
            if stage == "unavailable" {
                report.context_manager = Status::Unavailable;
                report.ipc = Status::Unavailable;
            }
        })?;
        Ok(())
    })();
    if let Err(e) = &result {
        report.failure = Some(e.to_string());
    }
    let cleanup = session.cleanup();
    if let Err(e) = &cleanup {
        report.failure = Some(match report.failure.take() {
            Some(previous) => format!("{previous}; {e}"),
            None => e.to_string(),
        });
    }
    report.cleanup = if cleanup.is_ok() {
        Status::Passed
    } else {
        Status::Failed
    };
    let current = fs::metadata("/dev/binder")?;
    let host_unchanged =
        (host.dev(), host.ino(), host.rdev()) == (current.dev(), current.ino(), current.rdev());
    println!(
        "host Binder path identity unchanged={host_unchanged}; this probe issued no transactions to the host Binder device"
    );
    println!("Binder probe summary: {}", serde_json::to_string(&report)?);
    if !host_unchanged {
        return Err(io::Error::other(
            "host Binder identity changed during probe",
        ));
    }
    match (result, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(e), Ok(())) | (Ok(()), Err(e)) => Err(e),
        (Err(e), Err(cleanup)) => Err(io::Error::other(format!("{e}; {cleanup}"))),
    }
}

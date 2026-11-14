//! Fixed-target Guest child probe. It never changes SELinux policy or labels.
const TARGET: &str = "u:r:ssal_guest_probe:s0";
const KSU: &str = "u:r:ksu:s0";
const PROPERTY_AREA_CONTEXT: &str = "u:object_r:ssal_guest_property_area:s0";
const PROPERTY_AREA_DIR_CONTEXT: &str = "u:object_r:ssal_guest_property_dir:s0";
const PROPERTY_AREA_FS_CONTEXT: &str = "u:object_r:tmpfs:s0";
const PROC_CONTEXT: &str = "u:object_r:proc:s0";
const SYSFS_CONTEXT: &str = "u:object_r:sysfs:s0";
const SELINUXFS_CONTEXT: &str = "u:object_r:selinuxfs:s0";
const GUEST_DIAG_UID: u32 = 1000;
const GUEST_DIAG_GID: u32 = 1000;
#[cfg(unix)]
const PROPERTY_AREA_PATH: &str = "/dev/__properties__";

#[cfg(unix)]
#[derive(Clone, Debug, PartialEq, Eq)]
struct HostPropertySnapshot {
    mount_namespace: String,
    dir_dev: u64,
    dir_ino: u64,
    mount_id: u32,
    entries: Vec<HostPropertyEntry>,
}

#[cfg(unix)]
#[derive(Clone, Debug, PartialEq, Eq)]
struct HostPropertyEntry {
    name: String,
    dev: u64,
    ino: u64,
    size: u64,
    mode: u32,
    mtime: i64,
    mtime_nsec: i64,
    ctime: i64,
    ctime_nsec: i64,
    label: String,
}

fn host_process_kind(pid: u32, comm: &str, argv0: &str, exe: &str) -> Option<&'static str> {
    if pid == 1 && comm == "init" {
        Some("init")
    } else if comm == "system_server" {
        Some("system_server")
    } else if matches!(comm, "installd" | "netd" | "adbd" | "artd") {
        Some(match comm {
            "installd" => "installd",
            "netd" => "netd",
            "adbd" => "adbd",
            _ => "artd",
        })
    } else if comm == "surfaceflinger" {
        Some("surfaceflinger")
    } else if comm == "servicemanager" {
        Some("servicemanager")
    } else if matches!(
        (argv0, exe),
        ("zygote", "/system/bin/app_process32") | ("zygote64", "/system/bin/app_process64")
    ) {
        Some("zygote")
    } else {
        None
    }
}

fn argv0(cmdline: &[u8]) -> Result<&str, std::str::Utf8Error> {
    std::str::from_utf8(cmdline.split(|&b| b == 0).next().unwrap_or_default())
}

fn is_aarch64_elf64(header: &[u8]) -> bool {
    header.len() >= 20
        && &header[..4] == b"\x7fELF"
        && header[4] == 2
        && header[5] == 1
        && u16::from_le_bytes([header[18], header[19]]) == 183
}

fn has_executable_mode(mode: u32) -> bool {
    mode & 0o111 != 0
}

fn host_process_snapshots_match<T: PartialEq>(before: &[T], after: &[T]) -> bool {
    before == after
}

fn permission_mask(permission_bit: u32) -> Option<u32> {
    permission_bit
        .checked_sub(1)
        .and_then(|bit| 1u32.checked_shl(bit))
}

#[derive(Debug, PartialEq, Eq)]
struct ProcessCredentialStatus {
    uid: [u32; 4],
    gid: [u32; 4],
    groups: Vec<u32>,
    capabilities: [u64; 5],
    no_new_privs: u32,
}

fn parse_process_credential_status(status: &str) -> Option<ProcessCredentialStatus> {
    fn field<'a>(status: &'a str, name: &str) -> Option<&'a str> {
        let mut values = status
            .lines()
            .filter_map(|line| line.strip_prefix(name)?.strip_prefix(':'))
            .map(str::trim);
        let value = values.next()?;
        values.next().is_none().then_some(value)
    }
    fn decimal_values<T: std::str::FromStr>(value: &str) -> Option<Vec<T>> {
        value
            .split_whitespace()
            .map(str::parse)
            .collect::<Result<_, _>>()
            .ok()
    }
    fn fixed<T, const N: usize>(values: Vec<T>) -> Option<[T; N]> {
        values.try_into().ok()
    }

    let uid = fixed(decimal_values(field(status, "Uid")?)?)?;
    let gid = fixed(decimal_values(field(status, "Gid")?)?)?;
    let groups = decimal_values(field(status, "Groups")?)?;
    let capability = |name| u64::from_str_radix(field(status, name)?, 16).ok();
    Some(ProcessCredentialStatus {
        uid,
        gid,
        groups,
        capabilities: [
            capability("CapInh")?,
            capability("CapPrm")?,
            capability("CapEff")?,
            capability("CapBnd")?,
            capability("CapAmb")?,
        ],
        no_new_privs: field(status, "NoNewPrivs")?.parse().ok()?,
    })
}

fn process_credentials_restricted(status: &str) -> bool {
    parse_process_credential_status(status).is_some_and(|identity| {
        identity.uid == [GUEST_DIAG_UID; 4]
            && identity.gid == [GUEST_DIAG_GID; 4]
            && identity.groups.is_empty()
            && identity.capabilities == [0; 5]
            && identity.no_new_privs == 1
    })
}

#[cfg(test)]
mod credential_status_tests {
    use super::*;

    const STATUS: &str = "Uid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\nGroups:\nCapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapBnd:\t0000000000000000\nCapAmb:\t0000000000000000\nNoNewPrivs:\t1\n";

    #[test]
    fn child_credential_status_must_match_the_full_allowlist() {
        assert!(process_credentials_restricted(STATUS));
        for (before, after) in [
            ("Uid:\t1000", "Uid:\t0"),
            ("Gid:\t1000", "Gid:\t0"),
            ("Groups:\nCapInh:", "Groups:\t1000\nCapInh:"),
            ("CapEff:\t0000000000000000", "CapEff:\t0000000000000001"),
            ("CapBnd:\t0000000000000000", "CapBnd:\t0000000000000001"),
            ("NoNewPrivs:\t1", "NoNewPrivs:\t0"),
        ] {
            assert!(!process_credentials_restricted(
                &STATUS.replacen(before, after, 1)
            ));
        }
        assert!(!process_credentials_restricted("Uid:\t29999\n"));
    }

    #[test]
    fn selinux_permission_numbers_are_one_based_bit_positions() {
        assert_eq!(permission_mask(1), Some(0x1));
        assert_eq!(permission_mask(2), Some(0x2));
        assert_eq!(permission_mask(32), Some(0x8000_0000));
        assert_eq!(permission_mask(0), None);
        assert_eq!(permission_mask(33), None);
    }

    #[test]
    fn host_signal_and_ptrace_require_conclusive_enforcing_denials() {
        let query = |status, permissive| AvQuery {
            status,
            permissive,
            sequence: Some(1),
            query_errno: None,
            permission_bit: Some(1),
            allowed_mask: Some(0),
            raw_response: None,
        };
        assert!(host_access_denied_in_enforcing_domain(&query(
            AvStatus::Denied,
            Some(false)
        )));
        assert!(!host_access_denied_in_enforcing_domain(&query(
            AvStatus::Allowed,
            Some(false)
        )));
        assert!(!host_access_denied_in_enforcing_domain(&query(
            AvStatus::QueryError,
            None
        )));
        assert!(!host_access_denied_in_enforcing_domain(&query(
            AvStatus::Denied,
            Some(true)
        )));
    }
}

#[derive(Debug, PartialEq)]
enum Mode<'a> {
    DryRun,
    HostSnapshot,
    Control { helper: &'a str, sha256: &'a str },
    Run { helper: &'a str, sha256: &'a str },
    PropertyAreaPreflight { helper: &'a str, sha256: &'a str },
    PropertyAreaRun { helper: &'a str, sha256: &'a str },
    ProcOnlyPreflight { helper: &'a str, sha256: &'a str },
    ProcOnlyRun { helper: &'a str, sha256: &'a str },
    BareControl { helper: &'a str, sha256: &'a str },
    BareRun { helper: &'a str, sha256: &'a str },
    BarePtraceControl { helper: &'a str, sha256: &'a str },
    BarePtraceRun { helper: &'a str, sha256: &'a str },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ExecutionPlan {
    transition: bool,
    identity_report: bool,
    ptrace: bool,
    property_area: bool,
    proc_only: bool,
    preflight_only: bool,
    guest_permissive_ok: bool,
}

fn execution_plan<'a>(mode: &Mode<'a>) -> Option<(&'a str, &'a str, ExecutionPlan)> {
    let (helper, sha256, plan) = match mode {
        Mode::Control { helper, sha256 } => {
            (*helper, *sha256, (false, true, false, false, false, false))
        }
        Mode::Run { helper, sha256 } => {
            (*helper, *sha256, (true, true, false, false, false, false))
        }
        Mode::PropertyAreaPreflight { helper, sha256 } => {
            (*helper, *sha256, (true, true, false, true, false, true))
        }
        Mode::PropertyAreaRun { helper, sha256 } => {
            (*helper, *sha256, (true, true, true, true, false, false))
        }
        Mode::ProcOnlyPreflight { helper, sha256 } => {
            (*helper, *sha256, (true, true, true, false, true, true))
        }
        Mode::ProcOnlyRun { helper, sha256 } => {
            (*helper, *sha256, (true, true, true, false, true, false))
        }
        Mode::BareControl { helper, sha256 } => {
            (*helper, *sha256, (false, false, false, false, false, false))
        }
        Mode::BareRun { helper, sha256 } => {
            (*helper, *sha256, (true, false, false, false, false, false))
        }
        Mode::BarePtraceControl { helper, sha256 } => {
            (*helper, *sha256, (false, false, true, false, false, false))
        }
        Mode::BarePtraceRun { helper, sha256 } => {
            (*helper, *sha256, (true, false, true, false, false, false))
        }
        Mode::DryRun | Mode::HostSnapshot => return None,
    };
    Some((
        helper,
        sha256,
        ExecutionPlan {
            transition: plan.0,
            identity_report: plan.1,
            ptrace: plan.2,
            property_area: plan.3,
            proc_only: plan.4,
            preflight_only: plan.5,
            guest_permissive_ok: plan.3 || plan.4,
        },
    ))
}

fn parse_args(args: &[String]) -> Result<Mode<'_>, &'static str> {
    if args.is_empty() || args == ["--dry-run"] {
        return Ok(Mode::DryRun);
    }
    if args == ["--host-snapshot"] {
        return Ok(Mode::HostSnapshot);
    }
    if args.len() == 4
        && [
            "--run-after-approval",
            "--property-area-preflight",
            "--property-area-live-after-approval",
            "--proc-only-preflight",
            "--proc-only-after-approval",
            "--control",
            "--bare-transition",
            "--bare-control",
            "--bare-ptrace-transition",
            "--bare-ptrace-control",
        ]
        .contains(&args[0].as_str())
        && !args[1].starts_with('-')
        && args[2] == "--sha256"
        && args[3].len() == 64
        && args[3].bytes().all(|b| b.is_ascii_hexdigit())
    {
        let mode = match args[0].as_str() {
            "--control" => Mode::Control {
                helper: &args[1],
                sha256: &args[3],
            },
            "--run-after-approval" => Mode::Run {
                helper: &args[1],
                sha256: &args[3],
            },
            "--property-area-preflight" => Mode::PropertyAreaPreflight {
                helper: &args[1],
                sha256: &args[3],
            },
            "--property-area-live-after-approval" => Mode::PropertyAreaRun {
                helper: &args[1],
                sha256: &args[3],
            },
            "--proc-only-preflight" => Mode::ProcOnlyPreflight {
                helper: &args[1],
                sha256: &args[3],
            },
            "--proc-only-after-approval" => Mode::ProcOnlyRun {
                helper: &args[1],
                sha256: &args[3],
            },
            "--bare-control" => Mode::BareControl {
                helper: &args[1],
                sha256: &args[3],
            },
            "--bare-ptrace-control" => Mode::BarePtraceControl {
                helper: &args[1],
                sha256: &args[3],
            },
            "--bare-ptrace-transition" => Mode::BarePtraceRun {
                helper: &args[1],
                sha256: &args[3],
            },
            _ => Mode::BareRun {
                helper: &args[1],
                sha256: &args[3],
            },
        };
        return Ok(mode);
    }
    Err("usage: --dry-run | --host-snapshot | --control|--run-after-approval|--property-area-preflight|--property-area-live-after-approval|--proc-only-preflight|--proc-only-after-approval|--bare-control|--bare-transition|--bare-ptrace-control|--bare-ptrace-transition /path --sha256 HASH")
}
#[cfg(any(unix, test))]
fn target_state_allowed(permissive: bool, guest_permissive_ok: bool) -> bool {
    guest_permissive_ok || !permissive
}

type AvRequest<'a> = (&'a str, &'a str, &'static str, &'static str, bool);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AvStatus {
    Allowed,
    Denied,
    QueryError,
}

#[cfg_attr(not(unix), allow(dead_code))]
#[derive(Debug)]
struct AvQuery {
    status: AvStatus,
    permissive: Option<bool>,
    sequence: Option<u32>,
    query_errno: Option<i32>,
    permission_bit: Option<u32>,
    allowed_mask: Option<u32>,
    raw_response: Option<String>,
}

fn host_access_denied_in_enforcing_domain(query: &AvQuery) -> bool {
    query.status == AvStatus::Denied && query.permissive == Some(false)
}

fn record_required_issue(issues: &mut Vec<String>, request: AvRequest<'_>, query: &AvQuery) {
    let (source, target, class, permission, required) = request;
    if required {
        match query.status {
            AvStatus::Allowed => {}
            AvStatus::Denied if query.permissive == Some(true) => println!(
                "SELINUX_STATIC_WARNING source={source} target={target} {class}:{permission} decision=DENIED domain_permissive=true runtime_gate=not_applicable"
            ),
            AvStatus::Denied => issues.push(format!(
                "{source} {target} {class}:{permission} decision=DENIED"
            )),
            AvStatus::QueryError => issues.push(format!(
                "{source} {target} {class}:{permission} decision=QUERY_ERROR query_errno={}",
                query
                    .query_errno
                    .map_or_else(|| "none".into(), |errno| errno.to_string())
            )),
        }
    }
}

fn required_av_block_message(issues: &[String]) -> Option<String> {
    (!issues.is_empty()).then(|| {
        format!(
            "required AV blocked before child creation: {}",
            issues.join(", ")
        )
    })
}

#[cfg(unix)]
fn record_av_crosscheck(name: &str, expected: AvStatus, query: &AvQuery) {
    println!(
        "AV_CROSSCHECK name={name} expected={expected:?} actual={:?} match={} permission_bit={} allowed_mask={} raw_response={:?}",
        query.status,
        query.status == expected,
        query.permission_bit.map_or_else(|| "unknown".into(), |bit| format!("0x{bit:x}")),
        query.allowed_mask.map_or_else(|| "unknown".into(), |mask| format!("0x{mask:x}")),
        query.raw_response
    );
}

#[cfg(any(unix, test))]
// The selinuxfs transaction takes context, context, and a u16 class; it returns the full AV.
fn write_access_request<W: std::io::Write>(
    writer: &mut W,
    source: &str,
    target: &str,
    index: u16,
) -> std::io::Result<()> {
    let request = format!("{source} {target} {index}");
    let n = writer.write(request.as_bytes())?;
    if n != request.len() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::WriteZero,
            "short SELinux access transaction",
        ));
    }
    Ok(())
}

fn parse_access_response(
    response: &str,
    permission_bit: u32,
) -> std::io::Result<(bool, bool, u32, u32)> {
    let fields: Vec<_> = response.split_whitespace().collect();
    if fields.len() != 6 {
        return Err(std::io::Error::other("invalid AV response field count"));
    }
    let hex = |value: &str| u32::from_str_radix(value, 16).map_err(std::io::Error::other);
    let allowed_mask = hex(fields[0])?;
    if hex(fields[1])? & permission_bit != permission_bit {
        return Err(std::io::Error::other("undecided AV"));
    }
    let flags = hex(fields[5])?;
    let sequence = fields[4].parse().map_err(std::io::Error::other)?;
    Ok((
        allowed_mask & permission_bit == permission_bit,
        flags & 1 != 0,
        sequence,
        allowed_mask,
    ))
}

fn expected_property_creation_context(response: &str) -> bool {
    response.trim_end_matches('\0').trim_end_matches('\n') == PROPERTY_AREA_CONTEXT
}

fn property_area_av_requests<'a>(
    root: &'a str,
    dev: &'a str,
    mountpoint: &'a str,
) -> Vec<AvRequest<'a>> {
    let tmpfs = PROPERTY_AREA_FS_CONTEXT;
    let area = PROPERTY_AREA_CONTEXT;
    let dir = PROPERTY_AREA_DIR_CONTEXT;
    vec![
        (KSU, root, "dir", "search", false),
        (KSU, dev, "dir", "search", false),
        (KSU, root, "dir", "mounton", false),
        (KSU, KSU, "capability", "sys_admin", false),
        (KSU, tmpfs, "filesystem", "relabelfrom", false),
        (KSU, tmpfs, "filesystem", "relabelto", false),
        (KSU, mountpoint, "dir", "mounton", false),
        (KSU, tmpfs, "filesystem", "mount", false),
        (TARGET, root, "dir", "search", true),
        (TARGET, dev, "dir", "search", true),
        (TARGET, SYSFS_CONTEXT, "dir", "search", true),
        (TARGET, SELINUXFS_CONTEXT, "dir", "search", true),
        (TARGET, SELINUXFS_CONTEXT, "file", "open", true),
        (TARGET, SELINUXFS_CONTEXT, "file", "read", true),
        (TARGET, dir, "dir", "search", true),
        (TARGET, dir, "dir", "write", true),
        (TARGET, dir, "dir", "add_name", true),
        (TARGET, dir, "dir", "getattr", true),
        (TARGET, area, "file", "create", true),
        (TARGET, area, "file", "relabelfrom", true),
        (TARGET, area, "file", "relabelto", true),
        (TARGET, area, "file", "open", true),
        (TARGET, area, "file", "read", true),
        (TARGET, area, "file", "write", true),
        (TARGET, area, "file", "map", true),
        (TARGET, area, "file", "getattr", true),
        (dir, tmpfs, "filesystem", "associate", true),
        (area, tmpfs, "filesystem", "associate", true),
        (KSU, PROC_CONTEXT, "dir", "search", false),
        (KSU, TARGET, "dir", "search", false),
        (KSU, TARGET, "file", "open", false),
        (KSU, TARGET, "file", "read", false),
        (KSU, TARGET, "process", "getattr", false),
        (TARGET, PROC_CONTEXT, "dir", "search", true),
        (TARGET, PROC_CONTEXT, "filesystem", "getattr", true),
        (TARGET, PROC_CONTEXT, "lnk_file", "read", false),
        (TARGET, TARGET, "dir", "search", true),
        (TARGET, TARGET, "dir", "open", false),
        (TARGET, TARGET, "dir", "read", false),
        (TARGET, TARGET, "lnk_file", "read", true),
        (TARGET, TARGET, "file", "open", true),
        (TARGET, TARGET, "file", "read", true),
        (TARGET, TARGET, "file", "getattr", false),
        (TARGET, KSU, "fd", "use", true),
        (TARGET, KSU, "fifo_file", "getattr", true),
        (
            TARGET,
            "u:object_r:null_device:s0",
            "chr_file",
            "getattr",
            true,
        ),
        (
            TARGET,
            "u:object_r:ssal_guest_probe_exec:s0",
            "file",
            "getattr",
            true,
        ),
    ]
}

#[cfg(unix)]
fn transition_av_requests<'a>(source: &'a str, helper_label: &'a str) -> Vec<AvRequest<'a>> {
    let mut requests = vec![
        (source, source, "process", "setexec", true),
        (source, TARGET, "process", "transition", true),
        (TARGET, helper_label, "file", "entrypoint", true),
    ];
    requests.extend(
        ["open", "read", "getattr", "execute", "map"]
            .into_iter()
            .map(|permission| (source, helper_label, "file", permission, true)),
    );
    requests
}

fn proc_only_av_requests() -> Vec<AvRequest<'static>> {
    [
        (TARGET, PROC_CONTEXT, "dir", "search", false),
        (TARGET, PROC_CONTEXT, "lnk_file", "read", false),
        (TARGET, TARGET, "dir", "search", false),
        (TARGET, TARGET, "file", "open", false),
        (TARGET, TARGET, "file", "read", false),
        (TARGET, TARGET, "file", "getattr", false),
    ]
    .into()
}

fn proc_failure_class(
    selinux_avc_confirmed: bool,
    dac_confirmed: bool,
    path_resolution_confirmed: bool,
) -> &'static str {
    if selinux_avc_confirmed {
        "SELINUX_DENIAL_CONFIRMED"
    } else if dac_confirmed {
        "DAC_DENIAL_CONFIRMED"
    } else if path_resolution_confirmed {
        "PATH_RESOLUTION_FAILURE"
    } else {
        "UNDETERMINED"
    }
}

fn avc_confirms_proc_denial(log: &str, pid: u32) -> bool {
    let expected_pid = format!("pid={pid}");
    let expected_sid = format!("scontext={TARGET}");
    log.lines().any(|line| {
        let body = line.split_once(';').map_or(line, |(_, body)| body);
        let fields: Vec<_> = body.split_whitespace().collect();
        let has = |field: &str| fields.contains(&field);
        let denied = body
            .split_once("avc: denied {")
            .and_then(|(_, tail)| tail.split_once('}'))
            .is_some_and(|(permissions, _)| {
                permissions
                    .split_whitespace()
                    .any(|permission| matches!(permission, "search" | "open" | "read" | "getattr"))
            });
        has(&expected_pid)
            && has(&expected_sid)
            && has("permissive=0")
            && denied
            && (has("tclass=dir") || has("tclass=file") || has("tclass=lnk_file"))
    })
}

fn parent_exec_valid(
    expected_sid: &str,
    process_sid: Option<&str>,
    task_sid: Option<&str>,
    process_attr_label: Option<&str>,
    task_attr_label: Option<&str>,
    starttime_before: Option<u64>,
    starttime_after: Option<u64>,
    expected_exe: (u64, u64),
    actual_exe: Option<(u64, u64)>,
    expected_mount_namespace: Option<&str>,
    actual_mount_namespace: Option<&str>,
    global_enforcing: bool,
    target_permissive: Option<bool>,
    guest_permissive_ok: bool,
) -> bool {
    process_sid == Some(expected_sid)
        && task_sid == Some(expected_sid)
        && process_attr_label.is_some_and(|label| !label.is_empty())
        && task_attr_label.is_some_and(|label| !label.is_empty())
        && process_attr_label == task_attr_label
        && starttime_before.is_some()
        && starttime_before == starttime_after
        && actual_exe == Some(expected_exe)
        && actual_mount_namespace.is_some()
        && expected_mount_namespace
            .map_or(true, |expected| actual_mount_namespace == Some(expected))
        && global_enforcing
        && (expected_sid != TARGET || guest_permissive_ok || target_permissive == Some(false))
}

fn proc_report_valid(report: &serde_json::Value, pid: u32, host_pids: &[u32]) -> bool {
    let Some(results) = report["proc_only"]["results"].as_array() else {
        return false;
    };
    let Some(components) = report["proc_only"]["components"].as_array() else {
        return false;
    };
    let Some(host_paths) = report["proc_only"]["host_paths"].as_array() else {
        return false;
    };
    let runtime = &report["proc_only"]["runtime"];
    if report["protocol"] != 1
        || report["pid"] != pid
        || report["proc_only"]["status"] != "complete"
        || results.len() != 3
        || components.len() != 11
        || host_paths.len() != host_pids.len()
        || report["context"] != TARGET
        || runtime["guest_data"]["matches_profile"] != true
        || runtime["guest_data"]["differs_host_data"] != true
        || runtime["guest_data"]["write_read_unlink"] != true
        || runtime["guest_binder"]["private"] != true
        || runtime["guest_binder"]["opened"] != true
        || runtime["guest_binder"]["rdev"] == runtime["guest_binder"]["host_rdev"]
        || runtime["guest_property_area_differs_host"] != true
        || runtime["guest_property_socket_absent"] != true
    {
        return false;
    }
    results.iter().enumerate().all(|(index, result)| {
        let path = result["requested_path"].as_str().unwrap_or_default();
        let expected = match index {
            0 => path == "/proc/thread-self/attr/current",
            1 => path == "/proc/self/attr/current",
            2 => path.starts_with("/proc/self/task/") && path.ends_with("/attr/current"),
            _ => false,
        };
        expected
            && result["open_errno"].as_i64().is_some()
            && result["read_errno"].as_i64().is_some()
            && result["close_errno"].as_i64().is_some()
    }) && components.iter().all(|component| {
        component["requested_path"].as_str().is_some()
            && component["stat_errno"].as_i64().is_some()
            && component["readlink_errno"].as_i64().is_some()
    }) && host_paths
        .iter()
        .zip(host_pids)
        .all(|(path, expected_pid)| {
            path["pid"] == *expected_pid
                && path["root_open_errno"].as_i64().is_some()
                && path["root_opened"].as_bool().is_some()
                && path["fd_dir_open_errno"].as_i64().is_some()
                && path["fd_dir_opened"].as_bool().is_some()
                && path["fd_read_errno"].as_i64().is_some()
                && path["fd_read_succeeded"].as_bool().is_some()
                && path["signal_zero_errno"].as_i64() == Some(1)
                && path["signal_zero_allowed"] == false
        })
        && report["proc_only"]["first_open_errno"] == results[0]["open_errno"]
}

fn host_proc_paths_denied(report: &serde_json::Value, host_pids: &[u32]) -> bool {
    let Some(host_paths) = report["proc_only"]["host_paths"].as_array() else {
        return false;
    };
    if host_paths.len() != host_pids.len() {
        return false;
    }
    let permission_denied = |error: i64| matches!(error, 1 | 2 | 13 | 20 | 40);
    host_paths
        .iter()
        .zip(host_pids)
        .all(|(path, expected_pid)| {
            path["pid"] == *expected_pid
                && path["root_opened"] == false
                && path["root_open_errno"]
                    .as_i64()
                    .is_some_and(permission_denied)
                && path["fd_dir_opened"] == false
                && path["fd_dir_open_errno"]
                    .as_i64()
                    .is_some_and(permission_denied)
                && path["fd_read_succeeded"] == false
                && path["signal_zero_errno"].as_i64() == Some(1)
                && path["signal_zero_allowed"] == false
        })
}

const TRACE_CHILD: u32 = 1;
const TRACE_STDIN_OPEN: u32 = 2;
const TRACE_STDOUT: u32 = 3;
const TRACE_STDERR: u32 = 4;
const TRACE_FD_FLAGS: u32 = 5;
const TRACE_SETEXEC_OPEN: u32 = 6;
const TRACE_SETEXEC_WRITE: u32 = 7;
const TRACE_EXECVEAT_ENTERED: u32 = 8;
const TRACE_EXECVEAT_RETURNED: u32 = 9;
const TRACE_REPORTER_MAIN: u32 = 10;
const TRACE_STDIN_DUP: u32 = 11;
const TRACE_PTRACE_TRACEME: u32 = 12;
const TRACE_PTRACE_STOP: u32 = 13;
const TRACE_MOUNT_NS_UNSHARE: u32 = 14;
const TRACE_MOUNT_PRIVATE: u32 = 15;
const TRACE_MOUNT_TMPFS: u32 = 16;
const TRACE_CAP_AMBIENT: u32 = 17;
const TRACE_CAPBSET_DROP: u32 = 18;
const TRACE_SETGROUPS: u32 = 19;
const TRACE_SETRESGID: u32 = 20;
const TRACE_SETRESUID: u32 = 21;
const TRACE_CAPSET: u32 = 22;
const TRACE_NO_NEW_PRIVS: u32 = 23;
const TRACE_CREDENTIAL_VERIFY: u32 = 24;
const TRACE_GUEST_CHROOT: u32 = 25;

#[repr(C)]
#[derive(Clone, Copy)]
struct TraceEvent {
    stage: u32,
    errno: i32,
}

fn trace_stage_name(stage: u32) -> &'static str {
    match stage {
        TRACE_CHILD => "child_started",
        TRACE_STDIN_OPEN => "open_stdin",
        TRACE_STDIN_DUP => "dup2_stdin",
        TRACE_STDOUT => "dup2_stdout",
        TRACE_STDERR => "dup2_stderr",
        TRACE_FD_FLAGS => "fcntl_cloexec",
        TRACE_SETEXEC_OPEN => "setexec_open",
        TRACE_SETEXEC_WRITE => "setexec_write",
        TRACE_EXECVEAT_ENTERED => "execveat_entered",
        TRACE_EXECVEAT_RETURNED => "execveat_returned",
        TRACE_REPORTER_MAIN => "reporter_main",
        TRACE_PTRACE_TRACEME => "ptrace_traceme",
        TRACE_PTRACE_STOP => "ptrace_initial_stop",
        TRACE_MOUNT_NS_UNSHARE => "mount_namespace_unshare",
        TRACE_MOUNT_PRIVATE => "mount_propagation_private",
        TRACE_MOUNT_TMPFS => "mount_property_tmpfs",
        TRACE_CAP_AMBIENT => "ambient_capabilities_clear",
        TRACE_CAPBSET_DROP => "capability_bounding_drop",
        TRACE_SETGROUPS => "setgroups",
        TRACE_SETRESGID => "setresgid",
        TRACE_SETRESUID => "setresuid",
        TRACE_CAPSET => "capset_zero",
        TRACE_NO_NEW_PRIVS => "no_new_privs",
        TRACE_CREDENTIAL_VERIFY => "credentials_verified",
        TRACE_GUEST_CHROOT => "guest_chroot",
        _ => "unknown",
    }
}

fn trace_syscall_name(stage: u32) -> &'static str {
    match stage {
        TRACE_STDIN_OPEN => "open",
        TRACE_STDIN_DUP => "dup2",
        TRACE_STDOUT | TRACE_STDERR => "dup2",
        TRACE_FD_FLAGS => "fcntl",
        TRACE_SETEXEC_OPEN => "open",
        TRACE_SETEXEC_WRITE => "write",
        TRACE_PTRACE_TRACEME => "ptrace",
        TRACE_PTRACE_STOP => "kill",
        TRACE_MOUNT_NS_UNSHARE => "unshare",
        TRACE_MOUNT_PRIVATE | TRACE_MOUNT_TMPFS => "mount",
        TRACE_CAP_AMBIENT | TRACE_CAPBSET_DROP | TRACE_NO_NEW_PRIVS => "prctl",
        TRACE_SETGROUPS => "setgroups",
        TRACE_SETRESGID => "setresgid",
        TRACE_SETRESUID => "setresuid",
        TRACE_CAPSET => "capset",
        TRACE_EXECVEAT_RETURNED => "execveat",
        TRACE_GUEST_CHROOT => "chroot",
        _ => "none",
    }
}

fn decode_trace_events(bytes: &[u8]) -> Result<Vec<TraceEvent>, &'static str> {
    if bytes.len() % std::mem::size_of::<TraceEvent>() != 0 {
        return Err("truncated child trace record");
    }
    Ok(bytes
        .chunks_exact(std::mem::size_of::<TraceEvent>())
        .map(|chunk| TraceEvent {
            stage: u32::from_ne_bytes(chunk[..4].try_into().unwrap()),
            errno: i32::from_ne_bytes(chunk[4..8].try_into().unwrap()),
        })
        .collect())
}

fn bare_output_matches_context(output: &str, context: &str) -> bool {
    output == format!("BARE_ENTRY\ncontext={context}\0\n")
}

fn bare_exit_probe_succeeded(status: i32, output: &str) -> bool {
    status == (42 << 8) && output.is_empty()
}

fn ptrace_wait_stop(status: i32) -> Option<(i32, u32)> {
    (status & 0xff == 0x7f).then_some(((status >> 8) & 0xff, (status as u32) >> 16))
}

fn decode_siginfo(raw: &[u8; 128]) -> (i32, u64) {
    (
        i32::from_ne_bytes(raw[8..12].try_into().unwrap()),
        u64::from_ne_bytes(raw[16..24].try_into().unwrap()),
    )
}

fn proc_stat_starttime(stat: &str) -> Option<u64> {
    stat.rsplit_once(')')?
        .1
        .split_whitespace()
        .nth(19)?
        .parse()
        .ok()
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    #[cfg(unix)]
    if args
        .first()
        .is_some_and(|arg| arg == "--cgroup-mount-check")
    {
        if let Err(error) = cgroup_mount_check(&args) {
            eprintln!("cgroup mount check failed: {error}");
            std::process::exit(1);
        }
        return;
    }
    match parse_args(&args) {
        Ok(Mode::DryRun) => {
            println!("dry-run: target={TARGET}; policy=unchanged; exec=not_run; default=enforcing; diagnostic=off");
            return;
        }
        Ok(Mode::HostSnapshot) => {
            #[cfg(unix)]
            if let Err(e) = unix::print_host_snapshot() {
                eprintln!("blocked or failed: {e}");
                std::process::exit(1);
            }
            #[cfg(not(unix))]
            std::process::exit(2);
            #[cfg(unix)]
            return;
        }
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(2);
        }
        Ok(
            Mode::Control { .. }
            | Mode::Run { .. }
            | Mode::PropertyAreaPreflight { .. }
            | Mode::PropertyAreaRun { .. }
            | Mode::ProcOnlyPreflight { .. }
            | Mode::ProcOnlyRun { .. }
            | Mode::BareControl { .. }
            | Mode::BareRun { .. }
            | Mode::BarePtraceControl { .. }
            | Mode::BarePtraceRun { .. },
        ) => {}
    }
    #[cfg(unix)]
    if let Err(e) = unix::run(&args) {
        eprintln!("blocked or failed: {e}");
        std::process::exit(1);
    }
    #[cfg(not(unix))]
    {
        eprintln!("device execution requires Android/Linux; no action performed");
        std::process::exit(2);
    }
}

#[cfg(unix)]
fn cgroup_mount_check(args: &[String]) -> std::io::Result<()> {
    use std::{ffi::CString, fs, io};
    if args.len() != 2 {
        return Err(io::Error::other("usage: --cgroup-mount-check GUEST_ROOT"));
    }
    let membership = fs::read_to_string("/proc/self/cgroup")?;
    let namespace = fs::read_link("/proc/self/ns/mnt")?;
    let root = CString::new(args[1].as_str()).map_err(io::Error::other)?;
    if unsafe { libc::chroot(root.as_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    std::env::set_current_dir("/")?;
    let info = fs::read_to_string("/proc/self/mountinfo")?;
    ssal::namespace_mounts::require_private_mounts(&info)?;
    let v1_memory = info.lines().any(|line| {
        line.split_once(" - ").is_some_and(|(_, tail)| {
            let fields: Vec<_> = tail.split_whitespace().collect();
            fields.first() == Some(&"cgroup")
                && line.split_whitespace().nth(4) == Some("/dev/memcg")
                && fields
                    .get(2..)
                    .unwrap_or_default()
                    .iter()
                    .flat_map(|value| value.split(','))
                    .any(|value| value == "memory")
        })
    });
    if info
        .lines()
        .filter(|line| {
            line.split_once(" - ").is_some_and(|(_, tail)| {
                matches!(tail.split_whitespace().next(), Some("cgroup" | "cgroup2"))
            })
        })
        .count()
        != if v1_memory { 5 } else { 4 }
    {
        return Err(io::Error::other(
            "unexpected extra/missing Guest cgroup mount",
        ));
    }
    let mut expected = vec![
        (
            "/sys/fs/cgroup",
            if v1_memory {
                "/ssal_guest"
            } else {
                "/apps/ssal_guest"
            },
            "cgroup2",
        ),
        ("/dev/cpuctl", "/ssal_guest", "cgroup"),
        ("/dev/cpuset", "/ssal_guest", "cgroup"),
        ("/dev/blkio", "/ssal_guest", "cgroup"),
    ];
    if v1_memory {
        expected.push(("/dev/memcg", "/ssal_guest", "cgroup"));
    }
    for (target, expected_root, kind) in expected {
        let entries: Vec<_> = info
            .lines()
            .filter(|line| line.split_whitespace().nth(4) == Some(target))
            .collect();
        if entries.len() != 1 {
            return Err(io::Error::other(format!(
                "expected one Guest mount: {target}"
            )));
        }
        let line = entries[0];
        if line.split_whitespace().nth(3) != Some(expected_root)
            || line
                .split_once(" - ")
                .and_then(|(_, tail)| tail.split_whitespace().next())
                != Some(kind)
        {
            return Err(io::Error::other(format!(
                "unexpected Guest cgroup backing: {line}"
            )));
        }
        let members = fs::read_to_string(format!("{target}/cgroup.procs"))?;
        if !members.trim().is_empty() {
            return Err(io::Error::other(format!(
                "new Guest subtree is occupied: {target}"
            )));
        }
        println!("guest_cgroup_mount=PASS {line} members={members:?}");
    }
    let after = fs::read_to_string("/proc/self/cgroup")?;
    for name in ["cpus", "mems"] {
        let value = fs::read_to_string(format!("/dev/cpuset/{name}"))?;
        if value.trim().is_empty() {
            return Err(io::Error::other("Guest cpuset is uninitialized"));
        }
        println!("guest_cpuset_{name}={value:?}");
    }
    if after != membership || fs::read_link("/proc/self/ns/mnt")? != namespace {
        return Err(io::Error::other(
            "read-only probe membership/namespace changed",
        ));
    }
    println!("guest_cgroup_membership_read_only={after:?}");
    println!("guest_cgroup_mount_check=PASS namespace={} root=/ membership=inherited_unchanged no_cgroup_writes=true", namespace.display());
    Ok(())
}

#[cfg(unix)]
mod unix {
    use super::{
        argv0, avc_confirms_proc_denial, bare_exit_probe_succeeded, bare_output_matches_context,
        decode_siginfo, decode_trace_events, execution_plan, expected_property_creation_context,
        has_executable_mode, host_access_denied_in_enforcing_domain, host_proc_paths_denied,
        host_process_kind, host_process_snapshots_match, is_aarch64_elf64, parent_exec_valid,
        parse_access_response, parse_args, parse_process_credential_status, permission_mask,
        proc_failure_class, proc_only_av_requests, proc_report_valid, proc_stat_starttime,
        process_credentials_restricted, property_area_av_requests, ptrace_wait_stop,
        record_av_crosscheck, record_required_issue, required_av_block_message,
        target_state_allowed, trace_stage_name, trace_syscall_name, transition_av_requests,
        write_access_request, AvQuery, AvStatus, ExecutionPlan, HostPropertyEntry,
        HostPropertySnapshot, TraceEvent, GUEST_DIAG_GID, GUEST_DIAG_UID, KSU,
        PROPERTY_AREA_CONTEXT, PROPERTY_AREA_DIR_CONTEXT, PROPERTY_AREA_FS_CONTEXT,
        PROPERTY_AREA_PATH, SELINUXFS_CONTEXT, SYSFS_CONTEXT, TARGET, TRACE_CAPBSET_DROP,
        TRACE_CAPSET, TRACE_CAP_AMBIENT, TRACE_CHILD, TRACE_CREDENTIAL_VERIFY,
        TRACE_EXECVEAT_ENTERED, TRACE_EXECVEAT_RETURNED, TRACE_FD_FLAGS, TRACE_GUEST_CHROOT,
        TRACE_MOUNT_NS_UNSHARE, TRACE_MOUNT_PRIVATE, TRACE_MOUNT_TMPFS, TRACE_NO_NEW_PRIVS,
        TRACE_PTRACE_STOP, TRACE_PTRACE_TRACEME, TRACE_REPORTER_MAIN, TRACE_SETEXEC_OPEN,
        TRACE_SETEXEC_WRITE, TRACE_SETGROUPS, TRACE_SETRESGID, TRACE_SETRESUID, TRACE_STDERR,
        TRACE_STDIN_DUP, TRACE_STDIN_OPEN, TRACE_STDOUT,
    };
    use std::{
        ffi::CString,
        fs::{self, File, OpenOptions},
        io::{self, Read, Seek, SeekFrom, Write},
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::fs::{FileExt, MetadataExt, OpenOptionsExt},
        },
        time::{Duration, Instant},
    };

    #[cfg(target_os = "android")]
    type PtraceRequest = libc::c_int;
    #[cfg(not(target_os = "android"))]
    type PtraceRequest = libc::c_uint;

    const PTRACE_TRACEME: PtraceRequest = 0;
    const PTRACE_CONT: PtraceRequest = 7;
    const PTRACE_SETOPTIONS: PtraceRequest = 0x4200;
    const PTRACE_GETSIGINFO: PtraceRequest = 0x4202;
    #[cfg(target_arch = "aarch64")]
    const PTRACE_GETREGSET: PtraceRequest = 0x4204;
    const PTRACE_O_TRACEEXEC: usize = 0x10;
    const PTRACE_EVENT_EXEC: u32 = 4;
    const PTRACE_O_TRACEEXIT: usize = 0x40;
    const PTRACE_EVENT_EXIT: u32 = 6;
    #[cfg(target_arch = "aarch64")]
    const NT_PRSTATUS: usize = 1;

    fn read(path: &str) -> io::Result<String> {
        Ok(fs::read_to_string(path)?.trim_matches('\0').trim().into())
    }
    fn fd_mount_id(file: &File) -> io::Result<u32> {
        let info = fs::read_to_string(format!("/proc/self/fdinfo/{}", file.as_raw_fd()))?;
        info.lines()
            .find_map(|line| line.strip_prefix("mnt_id:").map(str::trim))
            .ok_or_else(|| io::Error::other("fdinfo has no mnt_id"))?
            .parse()
            .map_err(io::Error::other)
    }
    fn host_property_snapshot() -> io::Result<HostPropertySnapshot> {
        let mount_namespace = fs::read_link("/proc/thread-self/ns/mnt")?
            .to_string_lossy()
            .into_owned();
        let directory = File::open(PROPERTY_AREA_PATH).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!(
                    "openat {PROPERTY_AREA_PATH} errno={:?}: {e}",
                    e.raw_os_error()
                ),
            )
        })?;
        let metadata = directory.metadata()?;
        let mut entries = Vec::new();
        for entry in fs::read_dir(PROPERTY_AREA_PATH)? {
            let entry = entry?;
            let entry_metadata = fs::symlink_metadata(entry.path())?;
            let file_label = if entry_metadata.is_file() && !entry_metadata.file_type().is_symlink()
            {
                label(&File::open(entry.path())?)?
            } else {
                "not_regular_file".to_owned()
            };
            entries.push(HostPropertyEntry {
                name: entry.file_name().to_string_lossy().into_owned(),
                dev: entry_metadata.dev(),
                ino: entry_metadata.ino(),
                size: entry_metadata.size(),
                mode: entry_metadata.mode(),
                mtime: entry_metadata.mtime(),
                mtime_nsec: entry_metadata.mtime_nsec(),
                ctime: entry_metadata.ctime(),
                ctime_nsec: entry_metadata.ctime_nsec(),
                label: file_label,
            });
        }
        entries.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(HostPropertySnapshot {
            mount_namespace,
            dir_dev: metadata.dev(),
            dir_ino: metadata.ino(),
            mount_id: fd_mount_id(&directory)?,
            entries,
        })
    }
    type HostProcess = (String, u32, u64, String, String);

    fn host_process_snapshot() -> io::Result<Vec<HostProcess>> {
        let mut processes = Vec::new();
        let mut zygote_names = Vec::new();
        for entry in fs::read_dir("/proc")? {
            let entry = entry?;
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|s| s.parse::<u32>().ok())
            else {
                continue;
            };
            let process_dir = entry.path();
            let comm = fs::read_to_string(process_dir.join("comm"))
                .unwrap_or_default()
                .trim()
                .to_owned();
            let candidate = matches!(
                comm.as_str(),
                "app_process" | "app_process32" | "app_process64" | "main" | "zygote" | "zygote64"
            );
            let cmdline = if candidate {
                fs::read(process_dir.join("cmdline"))?
            } else {
                Vec::new()
            };
            let argv0 = argv0(&cmdline).map_err(io::Error::other)?;
            let zygote_candidate = matches!(argv0, "zygote" | "zygote64")
                || matches!(comm.as_str(), "zygote" | "zygote64");
            let exe = if zygote_candidate || host_process_kind(pid, &comm, "", "").is_some() {
                fs::read_link(process_dir.join("exe"))?
                    .to_string_lossy()
                    .into_owned()
            } else {
                String::new()
            };
            let kind = host_process_kind(pid, &comm, argv0, &exe);
            if zygote_candidate && kind != Some("zygote") {
                return Err(io::Error::other(format!(
                    "ambiguous zygote pid={pid} comm={comm} argv0={argv0} exe={exe}"
                )));
            }
            if let Some(kind) = kind {
                if kind == "zygote" {
                    if zygote_names.contains(&argv0.to_owned()) {
                        return Err(io::Error::other(format!(
                            "ambiguous duplicate zygote argv0={argv0}"
                        )));
                    }
                    zygote_names.push(argv0.to_owned());
                }
                let stat = fs::read_to_string(process_dir.join("stat"))?;
                let starttime = stat
                    .rsplit_once(')')
                    .and_then(|(_, fields)| fields.split_whitespace().nth(19))
                    .ok_or_else(|| io::Error::other(format!("invalid stat pid={pid}")))?
                    .parse()
                    .map_err(io::Error::other)?;
                let context = fs::read_to_string(process_dir.join("attr/current"))?
                    .trim_matches('\0')
                    .trim()
                    .to_owned();
                if context.is_empty() {
                    return Err(io::Error::other(format!("empty SELinux context pid={pid}")));
                }
                processes.push((kind.to_owned(), pid, starttime, context, exe));
            }
        }
        processes.sort();
        // shortcut: checks five stable Android core process names; extend if this device reports different names.
        for required in [
            "init",
            "zygote",
            "system_server",
            "surfaceflinger",
            "servicemanager",
        ] {
            if !processes.iter().any(|(kind, ..)| kind == required) {
                return Err(io::Error::other(format!(
                    "Host process snapshot missing {required}"
                )));
            }
        }
        for optional in ["installd", "netd", "adbd", "artd"] {
            println!(
                "host_process_optional name={optional} present={}",
                processes.iter().any(|(kind, ..)| kind == optional)
            );
        }
        Ok(processes)
    }
    pub fn print_host_snapshot() -> io::Result<()> {
        println!("host_processes={:?}", host_process_snapshot()?);
        println!("host_property={:?}", host_property_snapshot()?);
        Ok(())
    }
    fn validate_context(context: &str) -> io::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .open("/sys/fs/selinux/context")
            .map_err(|e| io::Error::new(e.kind(), format!("openat selinuxfs/context: {e}")))?;
        let mut request = context.as_bytes().to_vec();
        request.push(0);
        let written = file
            .write(&request)
            .map_err(|e| io::Error::new(e.kind(), format!("validate context {context}: {e}")))?;
        if written != request.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "short SELinux context validation request",
            ));
        }
        Ok(())
    }
    fn property_area_preflight(
        sequence: &mut Option<u32>,
        required_issues: &mut Vec<String>,
    ) -> io::Result<(HostPropertySnapshot, Vec<HostProcess>)> {
        validate_context(PROPERTY_AREA_DIR_CONTEXT)?;
        validate_context(PROPERTY_AREA_CONTEXT)?;
        validate_context(PROPERTY_AREA_FS_CONTEXT)?;
        if label(&File::open("/dev/null")?)? != "u:object_r:null_device:s0" {
            return Err(io::Error::other("unexpected /dev/null label"));
        }
        for (path, expected) in [
            ("/sys", SYSFS_CONTEXT),
            ("/sys/fs", SYSFS_CONTEXT),
            ("/sys/fs/selinux", SELINUXFS_CONTEXT),
            ("/sys/fs/selinux/enforce", SELINUXFS_CONTEXT),
        ] {
            if label(&File::open(path)?)? != expected {
                return Err(io::Error::other(format!("unexpected label for {path}")));
            }
        }
        let class: u16 = read("/sys/fs/selinux/class/file/index")?
            .parse()
            .map_err(io::Error::other)?;
        let mut create = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/sys/fs/selinux/create")?;
        write_access_request(&mut create, TARGET, PROPERTY_AREA_DIR_CONTEXT, class)?;
        let mut created = String::new();
        create.read_to_string(&mut created)?;
        println!("property_file_creation_context={created:?}");
        if !expected_property_creation_context(&created) {
            return Err(io::Error::other(
                "unexpected property file creation context",
            ));
        }
        let host = host_property_snapshot()?;
        let processes = host_process_snapshot()?;
        let mountpoint = File::open(PROPERTY_AREA_PATH)?;
        let mountpoint_label = label(&mountpoint)
            .map_err(|e| io::Error::new(e.kind(), format!("fgetxattr /dev/__properties__: {e}")))?;
        let root_label = label(&File::open("/")?)?;
        let dev_label = label(&File::open("/dev")?)?;
        println!(
            "host_mount_namespace={} host_property_dir_dev={} host_property_dir_ino={} host_mount_id={} property_mountpoint_label={mountpoint_label}",
            host.mount_namespace, host.dir_dev, host.dir_ino, host.mount_id
        );
        println!("host_processes_before={processes:?}");
        for request @ (source, target, class, permission, required) in
            property_area_av_requests(&root_label, &dev_label, &mountpoint_label)
        {
            let query = decision(
                source,
                target,
                class,
                permission,
                if required { "required" } else { "reference" },
            );
            if source == TARGET
                && target == PROPERTY_AREA_FS_CONTEXT
                && class == "file"
                && permission == "write"
            {
                record_av_crosscheck("guest_tmpfs_file_write", AvStatus::Denied, &query);
            }
            record_required_issue(required_issues, request, &query);
            if let Some(seq) = query.sequence {
                if sequence.replace(seq).is_some_and(|old| old != seq) {
                    return Err(io::Error::other(
                        "policy sequence changed during property-area AV checks",
                    ));
                }
            }
        }
        let ksu_query = decision(KSU, KSU, "process", "getattr", "reference");
        if let Some(seq) = ksu_query.sequence {
            if sequence.replace(seq).is_some_and(|old| old != seq) {
                return Err(io::Error::other(
                    "policy sequence changed during KSU mode check",
                ));
            }
        }
        println!(
            "ksu_permissive={}",
            ksu_query
                .permissive
                .map_or_else(|| "unknown".into(), |value| value.to_string())
        );
        Ok((host, processes))
    }

    fn proc_only_preflight(
        sequence: &mut Option<u32>,
        required_issues: &mut Vec<String>,
    ) -> io::Result<(HostPropertySnapshot, Vec<HostProcess>)> {
        let host = host_property_snapshot()?;
        let processes = host_process_snapshot()?;
        println!(
            "proc_only_host_mount_namespace={} host_property_dir_dev={} host_property_dir_ino={} host_mount_id={} property_entries={:?}",
            host.mount_namespace, host.dir_dev, host.dir_ino, host.mount_id, host.entries
        );
        println!("host_processes_before={processes:?}");

        for request @ (av_source, target, class, permission, required) in proc_only_av_requests() {
            let query = decision(
                av_source,
                target,
                class,
                permission,
                if required { "required" } else { "diagnostic" },
            );
            record_required_issue(required_issues, request, &query);
            if let Some(seq) = query.sequence {
                if sequence.replace(seq).is_some_and(|old| old != seq) {
                    return Err(io::Error::other(
                        "policy sequence changed during Proc-Only AV checks",
                    ));
                }
            }
        }

        let property_write = decision(
            TARGET,
            PROPERTY_AREA_FS_CONTEXT,
            "file",
            "write",
            "calibration_reference",
        );
        record_av_crosscheck("guest_tmpfs_file_write", AvStatus::Denied, &property_write);
        if let Some(seq) = property_write.sequence {
            if sequence.replace(seq).is_some_and(|old| old != seq) {
                return Err(io::Error::other(
                    "policy sequence changed during AV calibration",
                ));
            }
        }

        let target_state = decision(TARGET, TARGET, "process", "getattr", "reference");
        if target_state.permissive.is_none() {
            return Err(io::Error::other("Guest domain SELinux state is unknown"));
        }
        println!(
            "guest_selinux_state={:?}; SELinux is diagnostic for this boundary run",
            target_state.permissive
        );
        if let Some(seq) = target_state.sequence {
            if sequence.replace(seq).is_some_and(|old| old != seq) {
                return Err(io::Error::other(
                    "policy sequence changed during Guest state check",
                ));
            }
        }
        let mut host_access_issues = Vec::new();
        for (kind, pid, _, context, _) in &processes {
            for permission in ["signal", "ptrace"] {
                let query = decision(TARGET, context, "process", permission, "host_boundary");
                let denied_in_enforcing_guest = host_access_denied_in_enforcing_domain(&query);
                println!(
                    "host_process_access kind={kind} pid={pid} target_context={context} permission={permission} selinux_decision={:?} guest_domain_enforcing={:?} check=selinuxfs_AV_only host_signal_or_ptrace_performed=false",
                    query.status, query.permissive
                );
                if !denied_in_enforcing_guest && query.permissive != Some(true) {
                    host_access_issues.push(format!(
                        "{kind}[{pid}] process:{permission} decision={:?} guest_domain_enforcing={:?}",
                        query.status, query.permissive
                    ));
                }
                if query.permissive == Some(true) {
                    println!("host_process_access_selinux_scope=diagnostic_only guest_domain_permissive=true structural_probe=proc_root_fd_and_signal_zero");
                }
                if let Some(seq) = query.sequence {
                    if sequence.replace(seq).is_some_and(|old| old != seq) {
                        return Err(io::Error::other(
                            "policy sequence changed during Host signal/ptrace AV checks",
                        ));
                    }
                }
            }
        }
        if !host_access_issues.is_empty() {
            return Err(io::Error::other(format!(
                "Host process signal/ptrace boundary is not proven; child execution blocked: {}",
                host_access_issues.join(", ")
            )));
        }
        println!(
            "host_signal_ptrace_selinux_scope={} host_signal_delivered=false host_ptrace_attached=false",
            if target_state.permissive == Some(false) { "enforcing_AV" } else { "diagnostic_only_guest_permissive" }
        );
        Ok((host, processes))
    }
    fn decision(
        source: &str,
        target: &str,
        class: &str,
        permission: &str,
        requirement: &str,
    ) -> AvQuery {
        let mut permission_bit = None;
        let mut allowed_mask = None;
        let mut raw_response = String::new();
        let result = (|| -> io::Result<(bool, bool, u32)> {
            let base = format!("/sys/fs/selinux/class/{class}");
            let idx: u16 = read(&format!("{base}/index"))?
                .parse()
                .map_err(io::Error::other)?;
            let bit: u32 = read(&format!("{base}/perms/{permission}"))?
                .parse()
                .map_err(io::Error::other)?;
            let mask =
                permission_mask(bit).ok_or_else(|| io::Error::other("invalid permission bit"))?;
            permission_bit = Some(mask);
            let mut f = OpenOptions::new()
                .read(true)
                .write(true)
                .open("/sys/fs/selinux/access")?;
            write_access_request(&mut f, source, target, idx)?;
            f.read_to_string(&mut raw_response)?;
            let (allowed, permissive, sequence, mask) = parse_access_response(&raw_response, mask)?;
            allowed_mask = Some(mask);
            Ok((allowed, permissive, sequence))
        })();

        match result {
            Ok((allowed, permissive, sequence)) => {
                let status = if allowed {
                    AvStatus::Allowed
                } else {
                    AvStatus::Denied
                };
                let decision = if allowed { "ALLOWED" } else { "DENIED" };
                println!(
                    "AV source_context={source} target_context={target} class={class} permission={permission} permission_bit={} allowed_mask={} decision={decision} requirement={requirement} query_errno=0 policy_sequence={sequence} raw_response={raw_response:?}",
                    permission_bit.map_or_else(|| "unknown".into(), |bit| format!("0x{bit:x}")),
                    allowed_mask.map_or_else(|| "unknown".into(), |mask| format!("0x{mask:x}")),
                );
                AvQuery {
                    status,
                    permissive: Some(permissive),
                    sequence: Some(sequence),
                    query_errno: None,
                    permission_bit,
                    allowed_mask,
                    raw_response: Some(raw_response),
                }
            }
            Err(error) => {
                let query_errno = error.raw_os_error();
                println!(
                    "AV source_context={source} target_context={target} class={class} permission={permission} permission_bit={} allowed_mask={} decision=QUERY_ERROR requirement={requirement} query_errno={} policy_sequence=unknown raw_response={raw_response:?} parse_error={error}",
                    permission_bit.map_or_else(|| "unknown".into(), |bit| format!("0x{bit:x}")),
                    allowed_mask.map_or_else(|| "unknown".into(), |mask| format!("0x{mask:x}")),
                    query_errno.map_or_else(|| "none".into(), |errno| errno.to_string()),
                );
                AvQuery {
                    status: AvStatus::QueryError,
                    permissive: None,
                    sequence: None,
                    query_errno,
                    permission_bit,
                    allowed_mask,
                    raw_response: Some(raw_response),
                }
            }
        }
    }

    fn kernel_log_cursor() -> Option<File> {
        let result = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open("/dev/kmsg")
            .and_then(|mut file| {
                file.seek(SeekFrom::End(0))?;
                Ok(file)
            });
        match result {
            Ok(file) => Some(file),
            Err(error) => {
                println!(
                    "proc_avc_capture=unavailable syscall=openat path=/dev/kmsg errno={:?} error={error}",
                    error.raw_os_error()
                );
                None
            }
        }
    }

    fn read_kernel_log_updates(file: &mut File) -> io::Result<(String, bool)> {
        let mut output = Vec::new();
        let mut record = [0u8; 8192];
        let mut overrun = false;
        loop {
            match file.read(&mut record) {
                Ok(0) => break,
                Ok(size) => {
                    output.extend_from_slice(&record[..size]);
                    if output.len() >= 1024 * 1024 {
                        break;
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) if error.raw_os_error() == Some(libc::EPIPE) => overrun = true,
                Err(error) => return Err(error),
            }
            if overrun {
                break;
            }
        }
        Ok((String::from_utf8_lossy(&output).into_owned(), overrun))
    }

    fn label(f: &File) -> io::Result<String> {
        let mut b = [0u8; 512];
        let n = unsafe {
            libc::fgetxattr(
                f.as_raw_fd(),
                c"security.selinux".as_ptr(),
                b.as_mut_ptr().cast(),
                b.len(),
            )
        };
        if n <= 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(std::str::from_utf8(&b[..n as usize])
            .map_err(io::Error::other)?
            .trim_matches('\0')
            .into())
    }
    fn file_hash(f: &File) -> io::Result<String> {
        use sha2::{Digest, Sha256};
        let mut digest = Sha256::new();
        let mut buf = [0u8; 65536];
        let mut offset = 0u64;
        loop {
            let n = f.read_at(&mut buf, offset)?;
            if n == 0 {
                break;
            }
            digest.update(&buf[..n]);
            offset += n as u64;
        }
        Ok(digest
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect())
    }

    fn verify_aarch64_executable(file: &File, metadata: &fs::Metadata) -> io::Result<()> {
        let mut header = [0u8; 20];
        if file.read_at(&mut header, 0)? != header.len() || !is_aarch64_elf64(&header) {
            return Err(io::Error::other(
                "expected an ELF64 little-endian AArch64 file",
            ));
        }
        if !has_executable_mode(metadata.mode()) {
            return Err(io::Error::other("ELF has no executable mode bit"));
        }
        Ok(())
    }

    fn pipe_pair() -> io::Result<(File, File)> {
        let mut fds = [-1; 2];
        if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(unsafe { (File::from_raw_fd(fds[0]), File::from_raw_fd(fds[1])) })
    }

    #[cfg(target_os = "android")]
    unsafe fn errno() -> i32 {
        *libc::__errno()
    }
    #[cfg(target_os = "linux")]
    unsafe fn errno() -> i32 {
        *libc::__errno_location()
    }

    unsafe fn record(fd: i32, stage: u32, error: i32) {
        let event = TraceEvent {
            stage,
            errno: error,
        };
        let mut offset = 0;
        let bytes = (&event as *const TraceEvent).cast::<u8>();
        while offset < std::mem::size_of::<TraceEvent>() {
            let result = libc::write(
                fd,
                bytes.add(offset).cast(),
                std::mem::size_of::<TraceEvent>() - offset,
            );
            if result > 0 {
                offset += result as usize;
            } else if result < 0 && errno() == libc::EINTR {
                continue;
            } else {
                break;
            }
        }
    }

    unsafe fn child_fail(trace_fd: i32, stage: u32, error: i32) -> ! {
        record(trace_fd, stage, error);
        libc::_exit(126)
    }

    #[repr(C)]
    struct CapHeader {
        version: u32,
        pid: i32,
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct CapData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }

    unsafe fn child_credentials_are_restricted(cap_last: u32) -> bool {
        let (mut ruid, mut euid, mut suid) = (0, 0, 0);
        let (mut rgid, mut egid, mut sgid) = (0, 0, 0);
        if libc::getresuid(&mut ruid, &mut euid, &mut suid) != 0
            || libc::getresgid(&mut rgid, &mut egid, &mut sgid) != 0
            || [ruid, euid, suid] != [GUEST_DIAG_UID; 3]
            || [rgid, egid, sgid] != [GUEST_DIAG_GID; 3]
        {
            return false;
        }
        if libc::getgroups(0, std::ptr::null_mut()) != 0 {
            return false;
        }
        let mut header = CapHeader {
            version: 0x20080522,
            pid: 0,
        };
        let mut capabilities = [CapData::default(); 2];
        if libc::syscall(
            libc::SYS_capget,
            &mut header as *mut CapHeader,
            capabilities.as_mut_ptr(),
        ) != 0
            || capabilities
                .iter()
                .any(|cap| cap.effective != 0 || cap.permitted != 0 || cap.inheritable != 0)
            || libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1
        {
            return false;
        }
        (0..=cap_last).all(|cap| {
            libc::prctl(libc::PR_CAPBSET_READ, cap as libc::c_int, 0, 0, 0) == 0
                && libc::prctl(
                    libc::PR_CAP_AMBIENT,
                    libc::PR_CAP_AMBIENT_IS_SET,
                    cap as libc::c_int,
                    0,
                    0,
                ) == 0
        })
    }

    unsafe fn child_prepare_proc_credentials(trace_fd: i32, cap_last: u32) {
        if libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL,
            0,
            0,
            0,
        ) != 0
        {
            child_fail(trace_fd, TRACE_CAP_AMBIENT, errno());
        }
        record(trace_fd, TRACE_CAP_AMBIENT, 0);
        for cap in 0..=cap_last {
            if libc::prctl(libc::PR_CAPBSET_DROP, cap as libc::c_int, 0, 0, 0) != 0
                || libc::prctl(libc::PR_CAPBSET_READ, cap as libc::c_int, 0, 0, 0) != 0
            {
                child_fail(trace_fd, TRACE_CAPBSET_DROP, errno());
            }
        }
        record(trace_fd, TRACE_CAPBSET_DROP, 0);
        if libc::prctl(libc::PR_SET_KEEPCAPS, 0, 0, 0, 0) != 0 {
            child_fail(trace_fd, TRACE_CAPSET, errno());
        }
        if libc::setgroups(0, std::ptr::null()) != 0 {
            child_fail(trace_fd, TRACE_SETGROUPS, errno());
        }
        record(trace_fd, TRACE_SETGROUPS, 0);
        if libc::setresgid(GUEST_DIAG_GID, GUEST_DIAG_GID, GUEST_DIAG_GID) != 0 {
            child_fail(trace_fd, TRACE_SETRESGID, errno());
        }
        record(trace_fd, TRACE_SETRESGID, 0);
        if libc::setresuid(GUEST_DIAG_UID, GUEST_DIAG_UID, GUEST_DIAG_UID) != 0 {
            child_fail(trace_fd, TRACE_SETRESUID, errno());
        }
        record(trace_fd, TRACE_SETRESUID, 0);
        let header = CapHeader {
            version: 0x20080522,
            pid: 0,
        };
        if libc::syscall(
            libc::SYS_capset,
            &header as *const CapHeader,
            [CapData::default(); 2].as_ptr(),
        ) != 0
            || libc::prctl(
                libc::PR_CAP_AMBIENT,
                libc::PR_CAP_AMBIENT_CLEAR_ALL,
                0,
                0,
                0,
            ) != 0
        {
            child_fail(trace_fd, TRACE_CAPSET, errno());
        }
        record(trace_fd, TRACE_CAPSET, 0);
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            child_fail(trace_fd, TRACE_NO_NEW_PRIVS, errno());
        }
        record(trace_fd, TRACE_NO_NEW_PRIVS, 0);
        if !child_credentials_are_restricted(cap_last) {
            child_fail(trace_fd, TRACE_CREDENTIAL_VERIFY, libc::EPERM);
        }
        record(trace_fd, TRACE_CREDENTIAL_VERIFY, 0);
    }

    unsafe fn prepare_property_mount(trace_fd: i32) {
        if libc::unshare(libc::CLONE_NEWNS) != 0 {
            child_fail(trace_fd, TRACE_MOUNT_NS_UNSHARE, errno());
        }
        record(trace_fd, TRACE_MOUNT_NS_UNSHARE, 0);
        if libc::mount(
            std::ptr::null(),
            c"/".as_ptr(),
            std::ptr::null(),
            (libc::MS_REC | libc::MS_PRIVATE) as libc::c_ulong,
            std::ptr::null(),
        ) != 0
        {
            child_fail(trace_fd, TRACE_MOUNT_PRIVATE, errno());
        }
        record(trace_fd, TRACE_MOUNT_PRIVATE, 0);
        if libc::mount(
            c"tmpfs".as_ptr(),
            c"/dev/__properties__".as_ptr(),
            c"tmpfs".as_ptr(),
            (libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC) as libc::c_ulong,
            c"size=1m,mode=0700,uid=1000,gid=1000,fscontext=u:object_r:tmpfs:s0,rootcontext=u:object_r:ssal_guest_property_dir:s0"
                .as_ptr()
                .cast(),
        ) != 0
        {
            child_fail(trace_fd, TRACE_MOUNT_TMPFS, errno());
        }
        record(trace_fd, TRACE_MOUNT_TMPFS, 0);
    }

    unsafe fn child_exec(
        helper_fd: i32,
        argv0: *const libc::c_char,
        env: *const *const libc::c_char,
        transition: bool,
        ptrace: bool,
        property_area: bool,
        proc_only: bool,
        cap_last: u32,
        stdout_read: i32,
        stdout_write: i32,
        stderr_read: i32,
        stderr_write: i32,
        trace_read: i32,
        trace_write: i32,
        guest_root: Option<&std::ffi::CStr>,
    ) -> ! {
        libc::close(stdout_read);
        libc::close(stderr_read);
        libc::close(trace_read);
        record(trace_write, TRACE_CHILD, 0);

        if let Some(root) = guest_root {
            if libc::chdir(root.as_ptr()) != 0
                || libc::chroot(c".".as_ptr()) != 0
                || libc::chdir(c"/".as_ptr()) != 0
            {
                child_fail(trace_write, TRACE_GUEST_CHROOT, errno());
            }
            record(trace_write, TRACE_GUEST_CHROOT, 0);
        }

        let null_fd = libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC);
        if null_fd < 0 {
            child_fail(trace_write, TRACE_STDIN_OPEN, errno());
        }
        record(trace_write, TRACE_STDIN_OPEN, 0);
        if null_fd != libc::STDIN_FILENO && libc::dup2(null_fd, libc::STDIN_FILENO) < 0 {
            child_fail(trace_write, TRACE_STDIN_DUP, errno());
        }
        if null_fd != libc::STDIN_FILENO {
            libc::close(null_fd);
        }
        record(trace_write, TRACE_STDIN_DUP, 0);

        if stdout_write != libc::STDOUT_FILENO && libc::dup2(stdout_write, libc::STDOUT_FILENO) < 0
        {
            child_fail(trace_write, TRACE_STDOUT, errno());
        }
        record(trace_write, TRACE_STDOUT, 0);
        if stderr_write != libc::STDERR_FILENO && libc::dup2(stderr_write, libc::STDERR_FILENO) < 0
        {
            child_fail(trace_write, TRACE_STDERR, errno());
        }
        record(trace_write, TRACE_STDERR, 0);

        // Mark the entire table, including descriptors absent from a procfs snapshot.
        if libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 4u32) < 0 {
            child_fail(trace_write, TRACE_FD_FLAGS, errno());
        }
        let trace_flags = libc::fcntl(trace_write, libc::F_GETFD);
        if trace_flags < 0
            || libc::fcntl(trace_write, libc::F_SETFD, trace_flags & !libc::FD_CLOEXEC) < 0
        {
            child_fail(trace_write, TRACE_FD_FLAGS, errno());
        }
        record(trace_write, TRACE_FD_FLAGS, 0);

        if property_area {
            prepare_property_mount(trace_write);
        }

        if proc_only || property_area {
            child_prepare_proc_credentials(trace_write, cap_last);
        }

        if transition {
            let fd = libc::open(
                c"/proc/thread-self/attr/exec".as_ptr(),
                libc::O_WRONLY | libc::O_CLOEXEC,
            );
            if fd < 0 {
                child_fail(trace_write, TRACE_SETEXEC_OPEN, errno());
            }
            record(trace_write, TRACE_SETEXEC_OPEN, 0);
            let n = libc::write(
                fd,
                c"u:r:ssal_guest_probe:s0".as_ptr().cast(),
                TARGET.len() + 1,
            );
            let error = if n < 0 {
                errno()
            } else if n != (TARGET.len() + 1) as isize {
                libc::EIO
            } else {
                0
            };
            libc::close(fd);
            record(trace_write, TRACE_SETEXEC_WRITE, error);
            if error != 0 {
                libc::_exit(126);
            }
        }

        if ptrace {
            if libc::ptrace(
                PTRACE_TRACEME,
                0,
                std::ptr::null_mut::<libc::c_void>(),
                std::ptr::null_mut::<libc::c_void>(),
            ) < 0
            {
                child_fail(trace_write, TRACE_PTRACE_TRACEME, errno());
            }
            record(trace_write, TRACE_PTRACE_TRACEME, 0);
            if libc::kill(libc::getpid(), libc::SIGSTOP) < 0 {
                child_fail(trace_write, TRACE_PTRACE_STOP, errno());
            }
        }

        record(trace_write, TRACE_EXECVEAT_ENTERED, 0);
        libc::syscall(
            libc::SYS_execveat,
            helper_fd as libc::c_long,
            c"".as_ptr(),
            [argv0, std::ptr::null()].as_ptr(),
            env,
            libc::AT_EMPTY_PATH as libc::c_long,
        );
        let error = errno();
        record(trace_write, TRACE_EXECVEAT_RETURNED, error);
        libc::_exit(127)
    }

    fn collect_pipe(file: File) -> io::Result<Vec<u8>> {
        let mut bytes = Vec::new();
        file.take(16384).read_to_end(&mut bytes)?;
        Ok(bytes)
    }

    fn ptrace_request(
        request: PtraceRequest,
        pid: libc::pid_t,
        addr: *mut libc::c_void,
        data: *mut libc::c_void,
    ) -> io::Result<()> {
        if unsafe { libc::ptrace(request, pid, addr, data) } == -1 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    fn stop_and_reap(pid: libc::pid_t, status: &mut i32) {
        unsafe {
            libc::kill(pid, libc::SIGKILL);
            while libc::waitpid(pid, status, 0) < 0 && errno() == libc::EINTR {}
        }
    }

    fn read_siginfo(pid: libc::pid_t) -> io::Result<(i32, u64)> {
        #[repr(align(8))]
        struct AlignedSiginfo([u8; 128]);
        let mut raw = AlignedSiginfo([0; 128]);
        ptrace_request(
            PTRACE_GETSIGINFO,
            pid,
            std::ptr::null_mut(),
            raw.0.as_mut_ptr().cast(),
        )?;
        Ok(decode_siginfo(&raw.0))
    }

    #[cfg(target_arch = "aarch64")]
    fn read_aarch64_pc(pid: libc::pid_t) -> io::Result<u64> {
        let mut regs = [0u64; 34];
        let mut iov = libc::iovec {
            iov_base: regs.as_mut_ptr().cast(),
            iov_len: std::mem::size_of_val(&regs),
        };
        ptrace_request(
            PTRACE_GETREGSET,
            pid,
            NT_PRSTATUS as *mut libc::c_void,
            (&mut iov as *mut libc::iovec).cast(),
        )?;
        if iov.iov_len < 33 * std::mem::size_of::<u64>() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "short AArch64 NT_PRSTATUS regset",
            ));
        }
        Ok(regs[32])
    }

    #[cfg(not(target_arch = "aarch64"))]
    fn read_aarch64_pc(_pid: libc::pid_t) -> io::Result<u64> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "PTRACE_GETREGSET PC decode requires AArch64",
        ))
    }

    fn proc_error(syscall: &str, path: &str, error: io::Error) -> String {
        format!(
            "syscall={syscall} pathname={path} errno={} error={error}",
            error
                .raw_os_error()
                .map_or_else(|| "none".into(), |errno| errno.to_string())
        )
    }

    fn proc_text(path: &str) -> Result<String, String> {
        let mut file = File::open(path).map_err(|error| proc_error("openat", path, error))?;
        let mut value = String::new();
        file.read_to_string(&mut value)
            .map_err(|error| proc_error("read", path, error))?;
        Ok(value.trim_matches('\0').trim().to_owned())
    }

    fn proc_link(path: &str) -> Result<String, String> {
        fs::read_link(path)
            .map(|target| target.to_string_lossy().into_owned())
            .map_err(|error| proc_error("readlinkat", path, error))
    }

    fn proc_file_context(path: &str) -> Result<String, String> {
        let file = File::open(path).map_err(|error| proc_error("openat", path, error))?;
        label(&file).map_err(|error| proc_error("fgetxattr", path, error))
    }

    fn proc_starttime(pid: libc::pid_t) -> Result<u64, String> {
        let path = format!("/proc/{pid}/stat");
        let stat = proc_text(&path)?;
        proc_stat_starttime(&stat).ok_or_else(|| {
            format!("syscall=parse_proc_stat pathname={path} errno=none error=invalid starttime")
        })
    }

    fn proc_executable_identity(pid: libc::pid_t) -> Result<(u64, u64), String> {
        let path = format!("/proc/{pid}/exe");
        let file = File::open(&path).map_err(|error| proc_error("openat", &path, error))?;
        let metadata = file
            .metadata()
            .map_err(|error| proc_error("fstat", &path, error))?;
        Ok((metadata.dev(), metadata.ino()))
    }

    fn observation_field<T: std::fmt::Debug>(name: &str, value: Result<T, String>) -> String {
        match value {
            Ok(value) => format!("{name}={value:?}"),
            Err(error) => format!("{name}_error={error:?}"),
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct FdIdentity {
        device: u64,
        inode: u64,
        mode: u32,
        rdev: u64,
        mount_id: u32,
        flags: u32,
    }

    fn fdinfo_number(info: &str, key: &str, radix: u32) -> io::Result<u32> {
        let mut values = info.lines().filter_map(|line| line.strip_prefix(key));
        let value = values
            .next()
            .ok_or_else(|| io::Error::other("missing fdinfo field"))?;
        let number = u32::from_str_radix(value.trim(), radix).map_err(io::Error::other)?;
        if values.next().is_some() {
            return Err(io::Error::other("duplicate fdinfo field"));
        }
        Ok(number)
    }

    fn fd_identity(pid: u32, fd: i32) -> io::Result<FdIdentity> {
        // stat follows the proc magic link without opening pipes/devices in the parent.
        let metadata = fs::metadata(format!("/proc/{pid}/fd/{fd}"))?;
        let info = fs::read_to_string(format!("/proc/{pid}/fdinfo/{fd}"))?;
        let mount_id = fdinfo_number(&info, "mnt_id:", 10)?;
        if mount_id == 0 {
            return Err(io::Error::other("invalid FD mount ID"));
        }
        Ok(FdIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
            mode: metadata.mode(),
            rdev: metadata.rdev(),
            mount_id,
            flags: fdinfo_number(&info, "flags:", 8)? & !(libc::O_CLOEXEC as u32),
        })
    }

    struct FdGuard {
        expected: Vec<(i32, FdIdentity)>,
        host_mount_id: u32,
        host_objects: Vec<(u64, u64)>,
    }

    fn verify_child_fds(pid: u32, guard: &FdGuard) -> io::Result<()> {
        let mut actual = Vec::new();
        // This enumeration FD belongs to the parent, never to the stopped child.
        for entry in fs::read_dir(format!("/proc/{pid}/fd"))? {
            let name = entry?.file_name();
            let fd = name
                .to_str()
                .and_then(|name| name.parse::<i32>().ok())
                .filter(|fd| *fd >= 0)
                .ok_or_else(|| io::Error::other("invalid child FD entry"))?;
            let identity = fd_identity(pid, fd)?;
            let path = fs::read_link(format!("/proc/{pid}/fd/{fd}"))?;
            println!("parent_fd pid={pid} fd={fd} identity={identity:?} target={path:?} shares_host_mount={}", identity.mount_id == guard.host_mount_id);
            if guard
                .host_objects
                .contains(&(identity.device, identity.inode))
                || path.starts_with(PROPERTY_AREA_PATH)
            {
                return Err(io::Error::other(
                    "Host property FD inherited; child was not resumed",
                ));
            }
            actual.push((fd, identity));
        }
        actual.sort_by_key(|(fd, _)| *fd);
        let mut expected = guard.expected.clone();
        expected.sort_by_key(|(fd, _)| *fd);
        if actual != expected {
            return Err(io::Error::other(format!(
                "child FD whitelist mismatch: expected={expected:?} actual={actual:?}"
            )));
        }
        Ok(())
    }

    #[cfg(test)]
    mod fd_tests {
        use super::*;
        use std::os::unix::process::CommandExt;
        use std::process::{Command, Stdio};

        #[test]
        fn fdinfo_is_strict_and_flags_are_octal() {
            assert_eq!(
                fdinfo_number("flags:\t0100002\n", "flags:", 8).unwrap(),
                0o100002
            );
            for info in [
                "",
                "mnt_id: x",
                "mnt_id: 1\nmnt_id: 2",
                "mnt_id: 4294967296",
            ] {
                assert!(fdinfo_number(info, "mnt_id:", 10).is_err());
            }
        }

        #[test]
        fn ptrace_exit_stop_keeps_fd_table_available() {
            let null = OpenOptions::new()
                .read(true)
                .write(true)
                .open("/dev/null")
                .unwrap();
            let identity = fd_identity(std::process::id(), null.as_raw_fd()).unwrap();
            let guard = FdGuard {
                expected: (0..=2).map(|fd| (fd, identity.clone())).collect(),
                host_mount_id: u32::MAX,
                host_objects: Vec::new(),
            };
            let mut command = Command::new("/bin/true");
            command
                .stdin(Stdio::from(null.try_clone().unwrap()))
                .stdout(Stdio::from(null.try_clone().unwrap()))
                .stderr(Stdio::from(null.try_clone().unwrap()));
            unsafe {
                command.pre_exec(|| {
                    if libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 4u32) < 0
                        || libc::ptrace(
                            PTRACE_TRACEME,
                            0,
                            std::ptr::null_mut::<libc::c_void>(),
                            std::ptr::null_mut::<libc::c_void>(),
                        ) < 0
                    {
                        return Err(io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            let mut child = command.spawn().unwrap();
            let pid = child.id() as i32;
            let mut status = 0;
            let result = (|| -> io::Result<()> {
                if unsafe { libc::waitpid(pid, &mut status, 0) } != pid || !libc::WIFSTOPPED(status)
                {
                    return Err(io::Error::other("missing exec stop"));
                }
                verify_child_fds(pid as u32, &guard)?;
                ptrace_request(
                    PTRACE_SETOPTIONS,
                    pid,
                    std::ptr::null_mut(),
                    PTRACE_O_TRACEEXIT as *mut libc::c_void,
                )?;
                ptrace_request(PTRACE_CONT, pid, std::ptr::null_mut(), std::ptr::null_mut())?;
                if unsafe { libc::waitpid(pid, &mut status, 0) } != pid
                    || ptrace_wait_stop(status) != Some((libc::SIGTRAP, PTRACE_EVENT_EXIT))
                {
                    return Err(io::Error::other("missing exit stop"));
                }
                verify_child_fds(pid as u32, &guard)?;
                ptrace_request(PTRACE_CONT, pid, std::ptr::null_mut(), std::ptr::null_mut())?;
                Ok(())
            })();
            if result.is_err() {
                child.kill().unwrap();
            }
            child.wait().unwrap();
            result.unwrap();
        }

        #[test]
        fn stopped_child_fd_guard_rejects_leaks_and_identity_mismatches() {
            let null = OpenOptions::new()
                .read(true)
                .write(true)
                .open("/dev/null")
                .unwrap();
            let identity = fd_identity(std::process::id(), null.as_raw_fd()).unwrap();
            let mut guard = FdGuard {
                expected: (0..=2).map(|fd| (fd, identity.clone())).collect(),
                host_mount_id: u32::MAX,
                host_objects: Vec::new(),
            };
            for leak in [false, true] {
                let mut child = Command::new("/bin/sh")
                    .args([
                        "-c",
                        if leak {
                            "exec 9</dev/null; kill -STOP $$; exit 0"
                        } else {
                            "kill -STOP $$; exit 0"
                        },
                    ])
                    .stdin(Stdio::from(null.try_clone().unwrap()))
                    .stdout(Stdio::from(null.try_clone().unwrap()))
                    .stderr(Stdio::from(null.try_clone().unwrap()))
                    .spawn()
                    .unwrap();
                let pid = child.id();
                let mut status = 0;
                assert_eq!(
                    unsafe { libc::waitpid(pid as i32, &mut status, libc::WUNTRACED) },
                    pid as i32
                );
                let result = (|| -> io::Result<()> {
                    if !libc::WIFSTOPPED(status) {
                        return Err(io::Error::other("fixture did not stop"));
                    }
                    assert_eq!(verify_child_fds(pid, &guard).is_ok(), !leak);
                    if !leak {
                        guard.expected[0].1.flags ^= libc::O_NONBLOCK as u32;
                        assert!(verify_child_fds(pid, &guard).is_err());
                        guard.expected[0].1.flags ^= libc::O_NONBLOCK as u32;
                        guard.host_mount_id = identity.mount_id;
                        assert!(verify_child_fds(pid, &guard).is_ok());
                        guard.host_mount_id = u32::MAX;
                        // A different mount ID must not hide a bind alias of the Host device.
                        guard.host_objects.push((identity.device, identity.inode));
                        assert!(verify_child_fds(pid, &guard).is_err());
                        guard.host_objects.clear();
                        let missing = guard.expected.pop().unwrap();
                        assert!(verify_child_fds(pid, &guard).is_err());
                        guard.expected.push(missing);
                    }
                    Ok(())
                })();
                child.kill().unwrap();
                child.wait().unwrap();
                result.unwrap();
                assert!(verify_child_fds(pid, &guard).is_err());
            }
        }
    }

    struct ExecStopGuard<'a> {
        expected_context: &'a str,
        expected_exe: (u64, u64),
        expected_mount_namespace: Option<&'a str>,
        expected_sequence: Option<u32>,
        fds: Option<&'a FdGuard>,
        check_credentials: bool,
        guest_permissive_ok: bool,
        guest_root_identity: Option<(u64, u64)>,
        post_fd_verified: std::cell::Cell<bool>,
    }

    fn observe_exec_stop(
        pid: libc::pid_t,
        starttime_before: u64,
        guard: &ExecStopGuard<'_>,
    ) -> io::Result<()> {
        let tid = pid;
        let process_attr = format!("/proc/{pid}/attr/current");
        let task_attr = format!("/proc/{pid}/task/{tid}/attr/current");
        let starttime = proc_starttime(pid);
        let executable = proc_link(&format!("/proc/{pid}/exe"));
        let executable_identity = proc_executable_identity(pid);
        let mount_namespace = proc_link(&format!("/proc/{pid}/ns/mnt"));
        let process_context = proc_text(&process_attr);
        let process_attr_label = proc_file_context(&process_attr);
        let task_context = proc_text(&task_attr);
        let task_attr_label = proc_file_context(&task_attr);
        let global_enforcing = read("/sys/fs/selinux/enforce").is_ok_and(|value| value == "1");
        let target_permissive = if guard.expected_context == TARGET {
            let state = decision(TARGET, TARGET, "process", "getattr", "reference");
            if state.sequence == guard.expected_sequence {
                state.permissive
            } else {
                None
            }
        } else {
            None
        };
        println!(
            "ptrace_exec_observation pid={pid} tid={tid} starttime_before={starttime_before} global_enforcing={global_enforcing} target_permissive={target_permissive:?} {} {} {} {} {} {} {} {}",
            observation_field("starttime", starttime.clone()),
            observation_field("executable", executable),
            observation_field("executable_dev_ino", executable_identity.clone()),
            observation_field("mount_namespace", mount_namespace.clone()),
            observation_field("process_context", process_context.clone()),
            observation_field("process_attr_file_context", process_attr_label.clone()),
            observation_field("task_context", task_context.clone()),
            observation_field("task_attr_file_context", task_attr_label.clone()),
        );
        let starttime_after = starttime.ok();
        let process_sid = process_context.ok();
        let process_label = process_attr_label.ok();
        let task_sid = task_context.ok();
        let task_label = task_attr_label.ok();
        let actual_exe = executable_identity.ok();
        let actual_namespace = mount_namespace.ok();
        if let Some(expected) = guard.guest_root_identity {
            let actual = fs::metadata(format!("/proc/{pid}/root"))
                .ok()
                .map(|root| (root.dev(), root.ino()));
            println!("guest_root_identity expected={expected:?} actual={actual:?}");
            if actual != Some(expected) {
                return Err(io::Error::other(
                    "child root is not the mounted Guest rootfs",
                ));
            }
        }
        if !parent_exec_valid(
            guard.expected_context,
            process_sid.as_deref(),
            task_sid.as_deref(),
            process_label.as_deref(),
            task_label.as_deref(),
            Some(starttime_before),
            starttime_after,
            guard.expected_exe,
            actual_exe,
            guard.expected_mount_namespace,
            actual_namespace.as_deref(),
            global_enforcing,
            target_permissive,
            guard.guest_permissive_ok,
        ) {
            return Err(io::Error::other(
                "parent-side PTRACE_EVENT_EXEC validation failed; child was not resumed",
            ));
        }
        if let Some(fds) = guard.fds {
            let exe_label =
                proc_file_context(&format!("/proc/{pid}/exe")).map_err(io::Error::other)?;
            if exe_label != "u:object_r:ssal_guest_probe_exec:s0" {
                return Err(io::Error::other("unexpected exec-stop executable label"));
            }
            verify_child_fds(pid as u32, fds)?;
            println!("inherited_fd_isolation=PASS scope=ptrace_exec_stop");
        }
        if guard.check_credentials {
            let status_path = format!("/proc/{pid}/status");
            let status = proc_text(&status_path).map_err(io::Error::other)?;
            let observed = parse_process_credential_status(&status)
                .ok_or_else(|| io::Error::other("incomplete child credential status"))?;
            println!("diagnostic_child_credentials={observed:?}");
            if !process_credentials_restricted(&status) {
                return Err(io::Error::other(
                    "diagnostic child credentials do not match the fixed allowlist",
                ));
            }
            println!("diagnostic_child_credentials=PASS scope=ptrace_exec_stop");
        }
        Ok(())
    }

    fn wait_ptraced(
        pid: libc::pid_t,
        deadline: Instant,
        guard: &ExecStopGuard<'_>,
    ) -> io::Result<(i32, bool, bool)> {
        let mut status = 0;
        let mut options_set = false;
        let mut exec_event = false;
        let mut starttime_before = None;
        loop {
            let result =
                unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG | libc::WUNTRACED) };
            if result == pid {
                let Some((signal, event)) = ptrace_wait_stop(status) else {
                    return Ok((status, false, exec_event));
                };
                if !options_set {
                    if signal != libc::SIGSTOP || event != 0 {
                        stop_and_reap(pid, &mut status);
                        return Err(io::Error::other(format!(
                            "unexpected initial ptrace stop: signal={signal} event={event}"
                        )));
                    }
                    starttime_before = match proc_starttime(pid) {
                        Ok(starttime) => Some(starttime),
                        Err(error) => {
                            stop_and_reap(pid, &mut status);
                            return Err(io::Error::other(format!(
                                "cannot identify child before exec: {error}"
                            )));
                        }
                    };
                    if let Err(error) = ptrace_request(
                        PTRACE_SETOPTIONS,
                        pid,
                        std::ptr::null_mut(),
                        (PTRACE_O_TRACEEXEC
                            | if guard.fds.is_some() {
                                PTRACE_O_TRACEEXIT
                            } else {
                                0
                            }) as *mut libc::c_void,
                    ) {
                        stop_and_reap(pid, &mut status);
                        return Err(io::Error::other(format!(
                            "PTRACE_SETOPTIONS(PTRACE_O_TRACEEXEC): {error}"
                        )));
                    }
                    options_set = true;
                    if let Err(error) =
                        ptrace_request(PTRACE_CONT, pid, std::ptr::null_mut(), std::ptr::null_mut())
                    {
                        stop_and_reap(pid, &mut status);
                        return Err(io::Error::other(format!("PTRACE_CONT: {error}")));
                    }
                    continue;
                }

                if event == PTRACE_EVENT_EXEC {
                    exec_event = true;
                    let Some(starttime_before) = starttime_before else {
                        stop_and_reap(pid, &mut status);
                        return Err(io::Error::other(
                            "child starttime was not captured before exec",
                        ));
                    };
                    if let Err(error) = observe_exec_stop(pid, starttime_before, guard) {
                        stop_and_reap(pid, &mut status);
                        return Err(error);
                    }
                    match read_aarch64_pc(pid) {
                        Ok(pc) => println!("ptrace_event=EXEC pid={pid} pc=0x{pc:x}"),
                        Err(error) => {
                            println!("ptrace_event=EXEC pid={pid} getregset=failed error={error}")
                        }
                    }
                } else if event == PTRACE_EVENT_EXIT && exec_event && guard.fds.is_some() {
                    if guard.post_fd_verified.get() {
                        stop_and_reap(pid, &mut status);
                        return Err(io::Error::other("duplicate child FD checkpoint"));
                    }
                    if let Err(error) = verify_child_fds(pid as u32, guard.fds.unwrap()) {
                        stop_and_reap(pid, &mut status);
                        return Err(error);
                    }
                    guard.post_fd_verified.set(true);
                    println!("child_fd_checkpoint=PASS scope=ptrace_exit_stop");
                } else if signal == libc::SIGSEGV {
                    println!("ptrace_signal=SIGSEGV pid={pid}");
                    match read_siginfo(pid) {
                        Ok((si_code, fault_addr)) => {
                            println!(
                                "ptrace_siginfo si_code={si_code} fault_addr=0x{fault_addr:x}"
                            );
                        }
                        Err(error) => println!("ptrace_getsiginfo=failed error={error}"),
                    }
                    match read_aarch64_pc(pid) {
                        Ok(pc) => println!("ptrace_sigsegv_pc=0x{pc:x}"),
                        Err(error) => println!("ptrace_sigsegv_getregset=failed error={error}"),
                    }
                }

                let deliver = if event != 0 || signal == libc::SIGTRAP {
                    0
                } else {
                    signal
                };
                if let Err(error) = ptrace_request(
                    PTRACE_CONT,
                    pid,
                    std::ptr::null_mut(),
                    deliver as usize as *mut libc::c_void,
                ) {
                    stop_and_reap(pid, &mut status);
                    return Err(io::Error::other(format!("PTRACE_CONT: {error}")));
                }
                continue;
            }
            if result < 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                stop_and_reap(pid, &mut status);
                return Err(error);
            }
            if Instant::now() >= deadline {
                stop_and_reap(pid, &mut status);
                return Ok((status, true, exec_event));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    pub fn run(args: &[String]) -> io::Result<()> {
        let mode = parse_args(args).map_err(io::Error::other)?;
        let (helper_path, sha256, plan) = execution_plan(&mode)
            .ok_or_else(|| io::Error::other("read-only mode cannot execute"))?;
        let ExecutionPlan {
            transition,
            identity_report,
            ptrace,
            property_area,
            proc_only,
            preflight_only,
            guest_permissive_ok,
        } = plan;
        let guest_root_path = if proc_only || property_area {
            Some(
                std::env::var("SSAL_GUEST_ROOT")
                    .map_err(|_| io::Error::other("Guest root is required for this mode"))?,
            )
        } else {
            None
        };
        let guest_root = guest_root_path
            .as_ref()
            .map(|path| CString::new(path.as_bytes()).map_err(io::Error::other))
            .transpose()?;
        let guest_root_identity = guest_root_path
            .as_ref()
            .map(|root| {
                let metadata = fs::metadata(root)?;
                if !metadata.is_dir() {
                    return Err(io::Error::other("Guest root is not a directory"));
                }
                Ok((metadata.dev(), metadata.ino()))
            })
            .transpose()?;
        if read("/sys/fs/selinux/enforce")? != "1" {
            return Err(io::Error::other("global Enforcing required"));
        }
        println!("global_enforcing=true selinuxfs_enforce=1");
        let source = read("/proc/thread-self/attr/current")?;
        if source != "u:r:ksu:s0" {
            return Err(io::Error::other("expected ksu source"));
        }
        let launcher = File::open("/proc/self/exe")?;
        let launcher_meta = launcher.metadata()?;
        verify_aarch64_executable(&launcher, &launcher_meta)?;
        println!(
            "launcher_path={:?} launcher_context={} launcher_sha256={} launcher_mode=0{:o} launcher_elf=ELF64_AArch64",
            fs::read_link("/proc/self/exe")?,
            label(&launcher)?,
            file_hash(&launcher)?,
            launcher_meta.mode() & 0o7777
        );
        let helper = File::open(helper_path)?;
        let meta = helper.metadata()?;
        if !meta.is_file() {
            return Err(io::Error::other("helper must be a regular file"));
        }
        verify_aarch64_executable(&helper, &meta)?;
        println!(
            "helper_path={helper_path:?} helper_context={} helper_mode=0{:o} helper_elf=ELF64_AArch64",
            label(&helper)?,
            meta.mode() & 0o7777
        );
        if file_hash(&helper)? != sha256.to_ascii_lowercase() {
            return Err(io::Error::other("helper SHA-256 mismatch"));
        }
        let cap_last = if proc_only || property_area {
            let last: u32 = read("/proc/sys/kernel/cap_last_cap")?
                .parse()
                .map_err(io::Error::other)?;
            if last > 63 {
                return Err(io::Error::other(format!(
                    "unsupported cap_last_cap={last}; cannot verify all capability sets"
                )));
            }
            println!("proc_child_capability_range=0..={last}");
            last
        } else {
            0
        };
        let mut sequence = None;
        let mut required_issues = Vec::new();
        let permissive = if transition {
            let file_label = label(&helper)?;
            if file_label != "u:object_r:ssal_guest_probe_exec:s0" {
                return Err(io::Error::other(format!(
                    "unexpected helper label: {file_label}"
                )));
            }
            for context in [source.as_str(), TARGET, file_label.as_str()] {
                validate_context(context).map_err(|error| {
                    io::Error::new(
                        error.kind(),
                        format!("SELinux context-to-SID validation failed for {context}: {error}"),
                    )
                })?;
                println!("selinux_context_to_sid context={context} result=valid");
            }
            println!(
                "helper_context={} known_successful_guest_context=u:object_r:ssal_guest_probe_exec:s0 helper_context_match=true",
                file_label
            );
            for request @ (s, t, class, permission, _) in
                transition_av_requests(&source, &file_label)
            {
                let query = decision(s, t, class, permission, "required");
                if class == "file" && permission == "execute" {
                    record_av_crosscheck("known_guest_helper_execute", AvStatus::Allowed, &query);
                }
                record_required_issue(&mut required_issues, request, &query);
                if let Some(seq) = query.sequence {
                    if sequence.replace(seq).is_some_and(|old| old != seq) {
                        return Err(io::Error::other("policy sequence changed"));
                    }
                }
            }
            let target_state = decision(TARGET, TARGET, "process", "getattr", "reference");
            if let Some(seq) = target_state.sequence {
                if sequence.replace(seq).is_some_and(|old| old != seq) {
                    return Err(io::Error::other("policy sequence changed"));
                }
            }
            let permissive = target_state
                .permissive
                .ok_or_else(|| io::Error::other("target Enforcing state query failed"))?;
            if !target_state_allowed(permissive, guest_permissive_ok) {
                return Err(io::Error::other("target domain is permissive"));
            }
            println!("guest_domain_permissive={permissive} guest_permissive_accepted={guest_permissive_ok}");
            Some(permissive)
        } else {
            None
        };
        let (host_property_before, host_processes_before) = if property_area {
            let (host, processes) = property_area_preflight(&mut sequence, &mut required_issues)?;
            let after = decision(TARGET, TARGET, "process", "getattr", "reference");
            if let Some(seq) = after.sequence {
                if sequence.replace(seq).is_some_and(|old| old != seq) {
                    return Err(io::Error::other(
                        "policy sequence changed during property-area checks",
                    ));
                }
            }
            if after.permissive != permissive {
                return Err(io::Error::other(
                    "target Enforcing state query failed or changed during property-area checks",
                ));
            }
            (Some(host), Some(processes))
        } else if proc_only {
            let (host, processes) = proc_only_preflight(&mut sequence, &mut required_issues)?;
            let after = decision(TARGET, TARGET, "process", "getattr", "reference");
            if let Some(seq) = after.sequence {
                if sequence.replace(seq).is_some_and(|old| old != seq) {
                    return Err(io::Error::other(
                        "policy sequence changed during Proc-Only preflight",
                    ));
                }
            }
            if after.permissive != permissive {
                return Err(io::Error::other(
                    "target Enforcing state query failed or changed during Proc-Only preflight",
                ));
            }
            (Some(host), Some(processes))
        } else {
            (None, None)
        };
        if let Some(message) = required_av_block_message(&required_issues) {
            return Err(io::Error::other(message));
        }
        println!(
            "mode={}; transition={}; reporter={}; property_area_live_poc={}; proc_only={}; helper_dev={} helper_ino={}",
            if proc_only && preflight_only { "proc-only-preflight" } else if proc_only { "proc-only" } else if preflight_only { "property-area-preflight" } else if property_area { "property-area-live" } else if transition { "transition" } else { "control" },
            if transition { "requested" } else { "not_run" },
            if identity_report { "identity" } else { "bare" },
            if preflight_only { "read_only" } else if property_area { "approved" } else { "not_run" },
            if proc_only { "enabled" } else { "not_run" },
            meta.dev(),
            meta.ino()
        );
        if transition && !preflight_only {
            println!("reporter_paths=/proc/self/exe,/proc/self/ns,/proc/self/attr/current,/proc/self/status; proc_attr_label=observed_at_ptrace_exec_stop");
        }

        if preflight_only {
            let host_after = host_property_snapshot()?;
            let processes_after = host_process_snapshot()?;
            let host_path_unchanged = host_property_before.as_ref() == Some(&host_after);
            let host_processes_unchanged = host_processes_before
                .as_ref()
                .is_some_and(|before| host_process_snapshots_match(before, &processes_after));
            println!(
                "host_path_unchanged={host_path_unchanged} host_property_files_unchanged={host_path_unchanged} host_property_file_contents=not_checked host_processes_unchanged={host_processes_unchanged}"
            );
            if !host_path_unchanged || !host_processes_unchanged {
                return Err(io::Error::other(
                    "read-only preflight Host identity changed during its snapshot",
                ));
            }
            println!(
                "PASS: read-only preflight; child=not_created; mount=not_attempted; mode={}",
                if proc_only {
                    "proc-only"
                } else {
                    "property-area"
                }
            );
            return Ok(());
        }

        let argv0 = CString::new(helper_path.as_bytes()).map_err(io::Error::other)?;
        let (stdout_read, stdout_write) = pipe_pair()?;
        let (stderr_read, stderr_write) = pipe_pair()?;
        let (trace_read, trace_write) = pipe_pair()?;
        let stage_env = CString::new(format!("SSAL_STAGE_FD={}", trace_write.as_raw_fd()))
            .map_err(io::Error::other)?;
        let approved_env = CString::new("SSAL_PROPERTY_AREA_APPROVED=1").unwrap();
        let proc_only_env = CString::new("SSAL_PROC_ONLY=1").unwrap();
        let host_pids_env = host_processes_before
            .as_ref()
            .map(|processes| {
                CString::new(format!(
                    "SSAL_HOST_CORE_PIDS={}",
                    processes
                        .iter()
                        .map(|(_, pid, ..)| pid.to_string())
                        .collect::<Vec<_>>()
                        .join(",")
                ))
                .map_err(io::Error::other)
            })
            .transpose()?;
        let property_env = host_property_before
            .as_ref()
            .map(|host| -> io::Result<Vec<CString>> {
                Ok(vec![
                    CString::new(format!("SSAL_HOST_MNT_NS={}", host.mount_namespace))
                        .map_err(io::Error::other)?,
                    CString::new(format!("SSAL_HOST_DIR_DEV={}", host.dir_dev))
                        .map_err(io::Error::other)?,
                    CString::new(format!("SSAL_HOST_DIR_INO={}", host.dir_ino))
                        .map_err(io::Error::other)?,
                    CString::new(format!("SSAL_HOST_MOUNT_ID={}", host.mount_id))
                        .map_err(io::Error::other)?,
                ])
            })
            .transpose()
            .map_err(io::Error::other)?;
        let mut env = vec![stage_env.as_ptr()];
        if property_area {
            env.push(approved_env.as_ptr());
        }
        if property_area || proc_only {
            env.extend(
                property_env
                    .as_ref()
                    .expect("Guest run has Host snapshot")
                    .iter()
                    .map(|value| value.as_ptr()),
            );
        }
        if proc_only {
            env.push(proc_only_env.as_ptr());
            env.push(
                host_pids_env
                    .as_ref()
                    .ok_or_else(|| io::Error::other("missing Host process snapshot"))?
                    .as_ptr(),
            );
        }
        let guest_boundary_env = if guest_root.is_some() {
            [
                "SSAL_GUEST_DATA_DEV",
                "SSAL_GUEST_DATA_INO",
                "SSAL_HOST_DATA_DEV",
                "SSAL_HOST_DATA_INO",
                "SSAL_HOST_BINDER_RDEV",
            ]
            .into_iter()
            .map(|name| {
                let value = std::env::var(name)
                    .map_err(|_| io::Error::other(format!("missing {name} environment")))?;
                CString::new(format!("{name}={value}")).map_err(io::Error::other)
            })
            .collect::<io::Result<Vec<_>>>()?
        } else {
            Vec::new()
        };
        env.extend(guest_boundary_env.iter().map(|value| value.as_ptr()));
        env.push(std::ptr::null());
        let mut kmsg_cursor = if proc_only { kernel_log_cursor() } else { None };
        let null_input = if let Some(root) = &guest_root_path {
            File::open(std::path::Path::new(root).join("dev/null"))?
        } else {
            File::open("/dev/null")?
        };
        let fd_guard = if property_area || proc_only {
            Some(FdGuard {
                expected: vec![
                    (0, fd_identity(std::process::id(), null_input.as_raw_fd())?),
                    (
                        1,
                        fd_identity(std::process::id(), stdout_write.as_raw_fd())?,
                    ),
                    (
                        2,
                        fd_identity(std::process::id(), stderr_write.as_raw_fd())?,
                    ),
                    (
                        trace_write.as_raw_fd(),
                        fd_identity(std::process::id(), trace_write.as_raw_fd())?,
                    ),
                ],
                host_mount_id: host_property_before.as_ref().unwrap().mount_id,
                host_objects: {
                    let host = host_property_before.as_ref().unwrap();
                    std::iter::once((host.dir_dev, host.dir_ino))
                        .chain(host.entries.iter().map(|entry| (entry.dev, entry.ino)))
                        .collect()
                },
            })
        } else {
            None
        };
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            let error = io::Error::last_os_error();
            println!(
                "syscall=fork errno={}",
                error.raw_os_error().unwrap_or_default()
            );
            return Err(error);
        }
        if pid == 0 {
            unsafe {
                child_exec(
                    helper.as_raw_fd(),
                    argv0.as_ptr(),
                    env.as_ptr(),
                    transition,
                    ptrace,
                    property_area,
                    proc_only,
                    cap_last,
                    stdout_read.as_raw_fd(),
                    stdout_write.as_raw_fd(),
                    stderr_read.as_raw_fd(),
                    stderr_write.as_raw_fd(),
                    trace_read.as_raw_fd(),
                    trace_write.as_raw_fd(),
                    guest_root.as_deref(),
                )
            }
        }
        drop(stdout_write);
        drop(stderr_write);
        drop(trace_write);
        println!("child_pid={pid}; fork=ok");
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut status = 0;
        let expected_context = if transition { TARGET } else { source.as_str() };
        let expected_mount_namespace = if proc_only {
            host_property_before
                .as_ref()
                .map(|host| host.mount_namespace.as_str())
        } else {
            None
        };
        let exec_guard = ExecStopGuard {
            expected_context,
            expected_exe: (meta.dev(), meta.ino()),
            expected_mount_namespace,
            expected_sequence: sequence,
            fds: fd_guard.as_ref(),
            check_credentials: proc_only || property_area,
            guest_permissive_ok,
            guest_root_identity,
            post_fd_verified: std::cell::Cell::new(false),
        };
        let (status, timed_out, exec_event_seen) = if ptrace {
            match wait_ptraced(pid, deadline, &exec_guard) {
                Ok(result) => result,
                Err(error) => {
                    // wait_ptraced kills and reaps on failure; still report Host checks.
                    if let Some(before) = &host_property_before {
                        println!(
                            "host_path_unchanged={} host_property_file_contents=not_checked",
                            host_property_snapshot().is_ok_and(|after| *before == after)
                        );
                    }
                    if let Some(before) = &host_processes_before {
                        println!(
                            "host_processes_unchanged={}",
                            host_process_snapshot()
                                .is_ok_and(|after| host_process_snapshots_match(before, &after))
                        );
                    }
                    println!(
                        "global_enforcing_after={} namespace_cleanup=UNVERIFIED",
                        read("/sys/fs/selinux/enforce").is_ok_and(|value| value == "1")
                    );
                    return Err(error);
                }
            }
        } else {
            let mut timed_out = false;
            loop {
                let result = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
                if result == pid {
                    break;
                }
                if result < 0 {
                    let error = io::Error::last_os_error();
                    if error.raw_os_error() == Some(libc::EINTR) {
                        continue;
                    }
                    return Err(error);
                }
                if Instant::now() >= deadline {
                    timed_out = true;
                    unsafe {
                        libc::kill(pid, libc::SIGKILL);
                        while libc::waitpid(pid, &mut status, 0) < 0 && errno() == libc::EINTR {}
                    }
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            (status, timed_out, false)
        };
        println!("child_wait_status=0x{status:04x}; timed_out={timed_out}");
        let (host_path_unchanged, host_processes_unchanged) = if let Some(host_before) =
            &host_property_before
        {
            let path_unchanged = match host_property_snapshot() {
                Ok(host_after) => {
                    let unchanged = host_before == &host_after;
                    println!(
                            "host_mount_namespace_after={} host_property_dir_dev_after={} host_property_dir_ino_after={} host_mount_id_after={} host_property_entries_after={} host_path_unchanged={unchanged} host_property_files_unchanged={unchanged} host_property_file_contents=not_checked",
                            host_after.mount_namespace,
                            host_after.dir_dev,
                            host_after.dir_ino,
                            host_after.mount_id,
                            host_after.entries.len()
                        );
                    unchanged
                }
                Err(error) => {
                    println!("host_path_check=failed error={error}");
                    false
                }
            };
            let processes_unchanged = match host_process_snapshot() {
                Ok(processes_after) => {
                    let unchanged = host_processes_before.as_ref().is_some_and(|before| {
                        host_process_snapshots_match(before, &processes_after)
                    });
                    println!(
                            "host_processes_after={processes_after:?} host_processes_unchanged={unchanged}"
                        );
                    unchanged
                }
                Err(error) => {
                    println!("host_process_check=failed error={error}");
                    false
                }
            };
            (path_unchanged, processes_unchanged)
        } else {
            (true, true)
        };
        if ptrace {
            println!(
                "ptrace_exec_event={}",
                if exec_event_seen { "seen" } else { "not_seen" }
            );
        }
        let trace = collect_pipe(trace_read)?;
        let events = decode_trace_events(&trace).map_err(io::Error::other)?;
        let mut reporter_main = false;
        for event in events {
            println!(
                "child_stage={} syscall={} errno={}",
                trace_stage_name(event.stage),
                trace_syscall_name(event.stage),
                event.errno
            );
            reporter_main |= event.stage == TRACE_REPORTER_MAIN;
            if event.stage == TRACE_EXECVEAT_RETURNED {
                println!("syscall=execveat errno={}", event.errno);
            }
        }
        println!(
            "reporter_main={}",
            if reporter_main { "seen" } else { "not_seen" }
        );

        let (kernel_log, kmsg_overrun, kmsg_readable) = match kmsg_cursor.as_mut() {
            Some(cursor) => match read_kernel_log_updates(cursor) {
                Ok((log, overrun)) => {
                    println!("proc_avc_capture=available overrun={overrun}");
                    (log, overrun, true)
                }
                Err(error) => {
                    println!("proc_avc_capture=read_failed error={error}");
                    (String::new(), false, false)
                }
            },
            None => (String::new(), false, false),
        };

        let mut output = String::new();
        stdout_read.take(16384).read_to_string(&mut output)?;
        let reporter_valid = if identity_report {
            let mut identity: serde_json::Value = match serde_json::from_str(&output) {
                Ok(identity) => identity,
                Err(error) => {
                    let stderr = String::from_utf8_lossy(&collect_pipe(stderr_read)?).into_owned();
                    let outcome = if status & 0x7f != 0 {
                        format!("signal={}", status & 0x7f)
                    } else {
                        format!("exit={}", (status >> 8) & 0xff)
                    };
                    return Err(io::Error::other(format!(
                        "child pid={pid} {outcome}; reporter_main={reporter_main}; invalid identity output ({error}); stderr={stderr:?}"
                    )));
                }
            };
            let proc_identity_valid = if proc_only {
                let avc_confirmed = avc_confirms_proc_denial(&kernel_log, pid as u32);
                let path_failure = identity["proc_only"]["path_resolution_failure"]
                    .as_bool()
                    .unwrap_or(false);
                let failed = identity["proc_only"]["results"]
                    .as_array()
                    .is_some_and(|results| {
                        results.iter().any(|result| {
                            result["open_succeeded"] == false || result["read_succeeded"] == false
                        })
                    });
                let failure_class = if failed {
                    proc_failure_class(avc_confirmed, false, path_failure)
                } else {
                    "NO_FAILURE"
                };
                let matching_avcs = kernel_log
                    .lines()
                    .filter(|line| avc_confirms_proc_denial(line, pid as u32))
                    .collect::<Vec<_>>();
                let binder_avcs = kernel_log
                    .lines()
                    .filter(|line| {
                        line.contains("avc: denied")
                            && line.contains(&format!("pid={pid} "))
                            && (line.contains("binder") || line.contains("chr_file"))
                    })
                    .collect::<Vec<_>>();
                println!("guest_binder_avc available={kmsg_readable} overrun={kmsg_overrun} matching={binder_avcs:?}");
                println!(
                    "proc_failure_class={failure_class} selinux_avc_confirmed={avc_confirmed} dac_denial_confirmed=false avc_log_available={kmsg_readable} avc_log_overrun={kmsg_overrun} matching_avc={matching_avcs:?}"
                );
                identity["proc_only"]["failure_class"] =
                    serde_json::Value::String(failure_class.to_owned());
                identity["proc_only"]["selinux_avc_confirmed"] =
                    serde_json::Value::Bool(avc_confirmed);
                identity["proc_only"]["dac_denial_confirmed"] = serde_json::Value::Bool(false);
                identity["proc_only"]["avc_log_available"] = serde_json::Value::Bool(kmsg_readable);
                let host_pids = host_processes_before
                    .as_ref()
                    .map(|processes| {
                        processes
                            .iter()
                            .map(|(_, pid, ..)| *pid)
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                let host_proc_denied = host_proc_paths_denied(&identity, &host_pids);
                println!("proc_report_valid={} expected=true host_proc_denied={} expected=true guest_binder_opened={} expected=true guest_binder_errno={}", proc_report_valid(&identity, pid as u32, &host_pids), host_proc_denied, identity["proc_only"]["runtime"]["guest_binder"]["opened"], identity["proc_only"]["runtime"]["guest_binder"]["errno"]);
                println!(
                    "host_proc_root_fd_boundary={} scope=read_only_open_and_fd_directory_listing host_fd_targets_opened=false",
                    if host_proc_denied { "PASS" } else { "FAIL_OR_UNKNOWN" }
                );
                identity["proc_only"]["host_proc_root_fd_boundary"] = serde_json::Value::String(
                    if host_proc_denied {
                        "PASS"
                    } else {
                        "FAIL_OR_UNKNOWN"
                    }
                    .into(),
                );
                proc_report_valid(&identity, pid as u32, &host_pids) && host_proc_denied
            } else {
                true
            };
            if property_area {
                // This field is parent evidence, never a claim trusted from Guest JSON.
                identity["property_area_live_poc"]["host_fd_separated"] =
                    serde_json::Value::Bool(exec_event_seen && exec_guard.post_fd_verified.get());
                identity["property_area_live_poc"]["host_fd_scope"] =
                    serde_json::Value::String("exec_and_exit_stop".into());
            }
            println!("child={identity}");
            let identity_valid = identity["protocol"] == 1
                && identity["pid"] == pid as u32
                && if proc_only {
                    proc_identity_valid
                } else {
                    identity["context"] == expected_context
                        && identity["executable_dev"] == meta.dev()
                        && identity["executable_ino"] == meta.ino()
                };
            identity_valid
                && (!property_area || {
                    let area = &identity["property_area_live_poc"];
                    let host = host_property_before.as_ref().unwrap();
                    area["status"] == "passed"
                        && area["mount_namespace_before"] == host.mount_namespace
                        && area["mount_namespace_after"] != host.mount_namespace
                        && area["host_dir_dev"] == host.dir_dev
                        && area["host_dir_ino"] == host.dir_ino
                        && area["host_mount_id"] == host.mount_id
                        && area["area_size"] == 128 * 1024
                        && area["property_label"] == PROPERTY_AREA_CONTEXT
                        && area["property"] == "ssal.guest.poc"
                        && area["value"] == "guest-area-ok"
                        && area["fsetxattr_attempted"] == true
                        && area["fsetxattr_succeeded"] == true
                        && area["fsetxattr_errno"] == 0
                        && area["writer_mapped"] == true
                        && area["property_added"] == true
                        && area["reader_mapped"] == true
                        && area["property_found"] == true
                        && area["readonly_value_match"] == true
                        && area["separate_mapping"] == true
                        && area["host_area_separated"] == true
                        && area["host_fd_separated"] == true
                        && exec_guard.post_fd_verified.get()
                        && area["cleanup"] == "namespace_teardown_after_child_exit"
                })
        } else {
            let exit_probe = bare_exit_probe_succeeded(status, &output);
            let entered = exit_probe || bare_output_matches_context(&output, expected_context);
            println!(
                "bare_entry={}; proof={}; output={output:?}",
                if entered { "seen" } else { "not_seen" },
                if exit_probe {
                    "exit_42"
                } else {
                    "context_output"
                }
            );
            entered
        };
        let status_valid = (status & 0x7f == 0 && (status >> 8) & 0xff == 0)
            || bare_exit_probe_succeeded(status, &output);
        let valid = status_valid
            && !timed_out
            && reporter_valid
            && (!identity_report || reporter_main)
            && (!proc_only || exec_event_seen);
        let enforcing_after = read("/sys/fs/selinux/enforce")? == "1";
        let state_matches = if transition {
            let after = decision(TARGET, TARGET, "process", "getattr", "reference");
            after.permissive == permissive && after.sequence == sequence
        } else {
            true
        };
        println!("final_checks status_valid={status_valid} expected=true timed_out={timed_out} expected=false reporter_valid={reporter_valid} expected=true reporter_main={reporter_main} exec_event_seen={exec_event_seen} enforcing_after={enforcing_after} expected=true state_matches={state_matches} expected=true host_path_unchanged={host_path_unchanged} expected=true host_processes_unchanged={host_processes_unchanged} expected=true");
        let stderr = String::from_utf8_lossy(&collect_pipe(stderr_read)?).into_owned();
        if !stderr.is_empty() {
            println!("child_stderr={stderr:?}");
        }
        if !valid
            || !enforcing_after
            || !state_matches
            || !host_path_unchanged
            || !host_processes_unchanged
            || file_hash(&helper)? != sha256.to_ascii_lowercase()
        {
            if status & 0x7f != 0 || timed_out {
                let outcome = if timed_out {
                    "timed_out".to_string()
                } else {
                    format!("signal={}", status & 0x7f)
                };
                return Err(io::Error::other(format!(
                    "child pid={pid} {outcome}; reporter_main={reporter_main}; stderr={stderr:?}"
                )));
            }
            return Err(io::Error::other(
                format!("identity, process status, property-area result, or post-exec policy state mismatch; child_stderr={stderr:?}"),
            ));
        }
        if transition {
            if property_area {
                println!("PASS: Guest-permissive diagnostic property area; Bionic write/read mapping, label, inode/mount separation, Host process snapshot, and cleanup verified");
            } else if identity_report {
                println!("PASS: child reaped; actual target SID confirmed; global Enforcing retained; target_permissive={}", permissive.unwrap_or(false));
            } else if bare_exit_probe_succeeded(status, &output) {
                println!(
                    "PASS: bare ELF entry confirmed by exit code 42; global Enforcing retained"
                );
            } else {
                println!(
                    "PASS: bare ELF entry and target context confirmed; global Enforcing retained"
                );
            }
        } else if identity_report {
            println!("PASS: no-transition control; child reaped in source SID; global Enforcing retained");
        } else if bare_exit_probe_succeeded(status, &output) {
            println!("PASS: bare ELF entry confirmed by exit code 42; source SID retained; global Enforcing retained");
        } else {
            println!(
                "PASS: bare ELF entry and source context confirmed; global Enforcing retained"
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args(xs: &[&str]) -> Vec<String> {
        xs.iter().map(|x| x.to_string()).collect()
    }
    #[test]
    fn access_query_is_one_complete_transaction_and_rejects_short_write() {
        struct Writer {
            chunks: Vec<Vec<u8>>,
            short: bool,
        }
        impl std::io::Write for Writer {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.chunks.push(buf.to_vec());
                Ok(if self.short { buf.len() - 1 } else { buf.len() })
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut good = Writer {
            chunks: vec![],
            short: false,
        };
        write_access_request(&mut good, "u:r:ksu:s0", "u:r:ksu:s0", 1).unwrap();
        assert_eq!(good.chunks, vec![b"u:r:ksu:s0 u:r:ksu:s0 1".to_vec()]);
        let mut short = Writer {
            chunks: vec![],
            short: true,
        };
        assert!(write_access_request(&mut short, "a", "b", 1).is_err());
        assert_eq!(short.chunks.len(), 1);
    }
    #[test]
    fn defaults_are_dry_and_diagnostic_alone_never_executes() {
        assert_eq!(parse_args(&args(&[])), Ok(Mode::DryRun));
        assert_eq!(parse_args(&args(&["--dry-run"])), Ok(Mode::DryRun));
        for a in [
            &["--diagnostic-permissive"][..],
            &["--run-after-approval"][..],
            &["--run-after-approval", "--diagnostic-permissive"][..],
            &["--run-after-approval", "/x", "--sha256", "abc"][..],
            &["--run-after-approval", "/x"][..],
            &["--property-area-preflight", "/x"][..],
            &["--property-area-live-after-approval", "/x"][..],
            &["--proc-only-preflight", "/x"][..],
            &["--proc-only-after-approval", "/x"][..],
            &["--dry-run", "x"][..],
        ] {
            assert!(parse_args(&args(a)).is_err());
        }
    }

    #[test]
    fn property_area_mode_has_an_explicit_gate_and_exact_av_scope() {
        let hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        assert_eq!(
            parse_args(&args(&[
                "--property-area-live-after-approval",
                "/area-poc",
                "--sha256",
                hash
            ])),
            Ok(Mode::PropertyAreaRun {
                helper: "/area-poc",
                sha256: hash
            })
        );
        let requests = property_area_av_requests(
            "u:object_r:rootfs:s0",
            "u:object_r:device:s0",
            "u:object_r:properties_device:s0",
        );
        assert_eq!(requests.len(), 47);
        assert!(requests.contains(&(KSU, "u:object_r:rootfs:s0", "dir", "search", false)));
        assert!(requests.contains(&(KSU, "u:object_r:device:s0", "dir", "search", false)));
        assert!(requests.contains(&(KSU, KSU, "capability", "sys_admin", false)));
        assert!(requests.contains(&(
            KSU,
            PROPERTY_AREA_FS_CONTEXT,
            "filesystem",
            "relabelfrom",
            false
        )));
        assert!(requests.contains(&(
            KSU,
            PROPERTY_AREA_FS_CONTEXT,
            "filesystem",
            "relabelto",
            false
        )));
        assert!(requests.contains(&(KSU, PROPERTY_AREA_FS_CONTEXT, "filesystem", "mount", false)));
        assert!(requests.contains(&(KSU, "u:object_r:rootfs:s0", "dir", "mounton", false)));
        assert!(requests.contains(&(
            KSU,
            "u:object_r:properties_device:s0",
            "dir",
            "mounton",
            false
        )));
        assert!(requests.contains(&(
            PROPERTY_AREA_CONTEXT,
            PROPERTY_AREA_FS_CONTEXT,
            "filesystem",
            "associate",
            true
        )));
        assert!(requests.contains(&(TARGET, PROPERTY_AREA_CONTEXT, "file", "map", true)));
        assert!(requests.contains(&(TARGET, PROPERTY_AREA_DIR_CONTEXT, "dir", "write", true)));
        assert!(requests.contains(&(
            PROPERTY_AREA_DIR_CONTEXT,
            PROPERTY_AREA_FS_CONTEXT,
            "filesystem",
            "associate",
            true
        )));
        assert!(!requests
            .iter()
            .any(|(source, target, class, permission, _)| {
                *source == TARGET
                    && *target == PROPERTY_AREA_FS_CONTEXT
                    && matches!(
                        (*class, *permission),
                        ("dir", "write") | ("file", "create" | "write")
                    )
            }));
        assert!(requests.contains(&(TARGET, PROC_CONTEXT, "lnk_file", "read", false)));
        assert!(requests.contains(&(KSU, TARGET, "process", "getattr", false)));
        assert!(requests.contains(&(KSU, TARGET, "file", "open", false)));
        assert!(requests.contains(&(TARGET, TARGET, "file", "open", true)));
        assert!(requests.contains(&(TARGET, TARGET, "file", "read", true)));
        assert!(requests.contains(&(TARGET, TARGET, "dir", "open", false)));
        assert!(requests.contains(&(TARGET, TARGET, "dir", "read", false)));
        assert!(requests.contains(&(TARGET, PROC_CONTEXT, "filesystem", "getattr", true)));
        assert!(requests.contains(&(TARGET, TARGET, "lnk_file", "read", true)));
        assert!(requests.contains(&(TARGET, KSU, "fd", "use", true)));
        assert!(requests.contains(&(TARGET, SYSFS_CONTEXT, "dir", "search", true)));
        assert!(requests.contains(&(TARGET, SELINUXFS_CONTEXT, "dir", "search", true)));
        assert!(requests.contains(&(TARGET, SELINUXFS_CONTEXT, "file", "open", true)));
        assert!(requests.contains(&(TARGET, SELINUXFS_CONTEXT, "file", "read", true)));
        assert!(requests.contains(&(TARGET, KSU, "fifo_file", "getattr", true)));
        assert!(requests.contains(&(
            TARGET,
            "u:object_r:null_device:s0",
            "chr_file",
            "getattr",
            true
        )));
        assert!(requests.contains(&(
            TARGET,
            "u:object_r:ssal_guest_probe_exec:s0",
            "file",
            "getattr",
            true
        )));
        assert!(!requests.iter().any(|(source, _, class, permission, _)| {
            *source == TARGET
                && ((*class == "capability" && *permission == "sys_admin")
                    || (*class == "filesystem" && *permission == "mount"))
        }));
        assert!(requests.iter().all(|(_, _, class, permission, _)| {
            matches!(
                *class,
                "capability"
                    | "dir"
                    | "file"
                    | "filesystem"
                    | "lnk_file"
                    | "process"
                    | "fd"
                    | "fifo_file"
                    | "chr_file"
            ) && !(*class == "file" && *permission == "execute")
        }));
    }

    #[test]
    fn property_area_preflight_requires_an_explicit_helper_hash() {
        let hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        assert_eq!(
            parse_args(&args(&[
                "--property-area-preflight",
                "/area-poc",
                "--sha256",
                hash
            ])),
            Ok(Mode::PropertyAreaPreflight {
                helper: "/area-poc",
                sha256: hash
            })
        );
    }

    #[test]
    fn property_creation_context_requires_the_dedicated_label() {
        assert!(expected_property_creation_context(PROPERTY_AREA_CONTEXT));
        assert!(expected_property_creation_context(&format!(
            "{PROPERTY_AREA_CONTEXT}\0"
        )));
        assert!(!expected_property_creation_context(
            PROPERTY_AREA_FS_CONTEXT
        ));
        assert!(!expected_property_creation_context(""));
        assert!(!expected_property_creation_context(&format!(
            "{PROPERTY_AREA_CONTEXT}x"
        )));
    }

    #[test]
    fn proc_only_modes_are_mount_free_and_separately_approved() {
        let hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let preflight_args = args(&["--proc-only-preflight", "/proc-helper", "--sha256", hash]);
        let preflight = parse_args(&preflight_args).unwrap();
        let (_, _, preflight_plan) = execution_plan(&preflight).unwrap();
        assert_eq!(
            preflight_plan,
            ExecutionPlan {
                transition: true,
                identity_report: true,
                ptrace: true,
                property_area: false,
                proc_only: true,
                preflight_only: true,
                guest_permissive_ok: true,
            }
        );

        let approved_args = args(&[
            "--proc-only-after-approval",
            "/proc-helper",
            "--sha256",
            hash,
        ]);
        let approved = parse_args(&approved_args).unwrap();
        let (_, _, approved_plan) = execution_plan(&approved).unwrap();
        assert_eq!(
            approved_plan,
            ExecutionPlan {
                transition: true,
                identity_report: true,
                ptrace: true,
                property_area: false,
                proc_only: true,
                preflight_only: false,
                guest_permissive_ok: true,
            }
        );
        assert!(!approved_plan.property_area);
    }

    #[test]
    fn proc_only_av_scope_never_gates_on_property_denials_but_live_still_does() {
        let proc_requests = proc_only_av_requests();
        assert!(proc_requests.iter().all(|(_, _, _, _, required)| !required));
        assert!(proc_requests.contains(&(TARGET, PROC_CONTEXT, "dir", "search", false)));
        assert!(proc_requests.contains(&(TARGET, TARGET, "file", "open", false)));
        assert!(!proc_requests.iter().any(|(_, _, class, permission, _)| {
            *class == "filesystem" || *permission == "create" || *permission == "write"
        }));

        let denied = AvQuery {
            status: AvStatus::Denied,
            permissive: Some(false),
            sequence: Some(7),
            query_errno: None,
            permission_bit: Some(2),
            allowed_mask: Some(0),
            raw_response: Some("0 3 0 0 7 0".into()),
        };
        let mut issues = Vec::new();
        record_required_issue(
            &mut issues,
            (TARGET, PROPERTY_AREA_FS_CONTEXT, "file", "write", false),
            &denied,
        );
        assert_eq!(required_av_block_message(&issues), None);
        record_required_issue(
            &mut issues,
            (TARGET, PROPERTY_AREA_FS_CONTEXT, "file", "write", true),
            &denied,
        );
        assert!(required_av_block_message(&issues).is_some());
    }

    #[test]
    fn selinux_access_response_uses_allowed_mask_and_preserves_query_errors() {
        assert_eq!(
            parse_access_response("7 7 0 0 19 0", 0x4).unwrap(),
            (true, false, 19, 7)
        );
        assert_eq!(
            parse_access_response("3 7 0 0 19 0", 0x4).unwrap(),
            (false, false, 19, 3)
        );
        assert!(parse_access_response("0 0 0 0", 0x1).is_err());
        assert!(parse_access_response("0 0 0 0 19 0", 0x1).is_err());
    }

    #[test]
    fn proc_report_keeps_paths_and_initial_errno_independent() {
        let report = serde_json::json!({
            "protocol": 1,
            "pid": 44,
            "context": TARGET,
            "proc_only": {
                "status": "complete",
                "first_open_errno": 13,
                "results": [
                    {"requested_path":"/proc/thread-self/attr/current", "open_errno":13, "read_errno":-1, "close_errno":-1},
                    {"requested_path":"/proc/self/attr/current", "open_errno":0, "read_errno":0, "close_errno":0},
                    {"requested_path":"/proc/self/task/44/attr/current", "open_errno":2, "read_errno":-1, "close_errno":-1}
                ],
                "components": [
                    {"requested_path":"/proc", "stat_errno":0, "readlink_errno":-1},
                    {"requested_path":"/proc/thread-self", "stat_errno":0, "readlink_errno":0},
                    {"requested_path":"/proc/thread-self/attr", "stat_errno":0, "readlink_errno":-1},
                    {"requested_path":"/proc/thread-self/attr/current", "stat_errno":0, "readlink_errno":-1},
                    {"requested_path":"/proc/self", "stat_errno":0, "readlink_errno":0},
                    {"requested_path":"/proc/self/attr", "stat_errno":0, "readlink_errno":-1},
                    {"requested_path":"/proc/self/attr/current", "stat_errno":0, "readlink_errno":-1},
                    {"requested_path":"/proc/self/task", "stat_errno":0, "readlink_errno":-1},
                    {"requested_path":"/proc/self/task/44", "stat_errno":0, "readlink_errno":-1},
                    {"requested_path":"/proc/self/task/44/attr", "stat_errno":0, "readlink_errno":-1},
                    {"requested_path":"/proc/self/task/44/attr/current", "stat_errno":0, "readlink_errno":-1}
                ],
                "host_paths": [
                    {"pid":1,"root_open_errno":13,"root_opened":false,"fd_dir_open_errno":13,"fd_dir_opened":false,"fd_read_errno":-1,"fd_read_succeeded":false,"signal_zero_errno":1,"signal_zero_allowed":false},
                    {"pid":55,"root_open_errno":13,"root_opened":false,"fd_dir_open_errno":13,"fd_dir_opened":false,"fd_read_errno":-1,"fd_read_succeeded":false,"signal_zero_errno":1,"signal_zero_allowed":false}
                ],
                "runtime": {
                    "guest_data":{"matches_profile":true,"differs_host_data":true,"write_read_unlink":true},
                    "guest_binder":{"rdev":517,"host_rdev":513,"private":true,"opened":true},
                    "guest_property_area_differs_host":true,
                    "guest_property_socket_absent":true
                }
            }
        });
        let host_pids = [1, 55];
        assert!(proc_report_valid(&report, 44, &host_pids));
        assert!(host_proc_paths_denied(&report, &host_pids));
        let mut overwritten = report.clone();
        overwritten["proc_only"]["first_open_errno"] = serde_json::json!(0);
        assert!(!proc_report_valid(&overwritten, 44, &host_pids));
        overwritten = report.clone();
        overwritten["proc_only"]["host_paths"][0]["root_opened"] = serde_json::json!(true);
        assert!(proc_report_valid(&overwritten, 44, &host_pids));
        assert!(!host_proc_paths_denied(&overwritten, &host_pids));
        overwritten = report.clone();
        overwritten["proc_only"]["runtime"]["guest_data"]["write_read_unlink"] =
            serde_json::json!(false);
        assert!(!proc_report_valid(&overwritten, 44, &host_pids));
        assert_eq!(
            proc_failure_class(false, false, true),
            "PATH_RESOLUTION_FAILURE"
        );
        assert_eq!(
            proc_failure_class(true, false, false),
            "SELINUX_DENIAL_CONFIRMED"
        );
        assert_eq!(
            proc_failure_class(false, true, false),
            "DAC_DENIAL_CONFIRMED"
        );
        assert_eq!(proc_failure_class(false, false, false), "UNDETERMINED");
    }

    #[test]
    fn staged_helper_must_be_executable_aarch64_elf64() {
        let mut header = [0u8; 20];
        header[..4].copy_from_slice(b"\x7fELF");
        header[4] = 2;
        header[5] = 1;
        header[18..20].copy_from_slice(&183u16.to_le_bytes());
        assert!(is_aarch64_elf64(&header));
        header[5] = 2;
        assert!(!is_aarch64_elf64(&header));
        assert!(has_executable_mode(0o755));
        assert!(!has_executable_mode(0o644));
    }

    #[test]
    fn parent_exec_validation_rejects_sid_mismatch_and_allows_same_mount_namespace() {
        let valid = parent_exec_valid(
            TARGET,
            Some(TARGET),
            Some(TARGET),
            Some("u:object_r:proc_attr:s0"),
            Some("u:object_r:proc_attr:s0"),
            Some(500),
            Some(500),
            (8, 9),
            Some((8, 9)),
            Some("mnt:[4026531840]"),
            Some("mnt:[4026531840]"),
            true,
            Some(false),
            false,
        );
        assert!(valid);
        assert!(!parent_exec_valid(
            TARGET,
            Some(TARGET),
            Some("u:r:ksu:s0"),
            Some("u:object_r:proc_attr:s0"),
            Some("u:object_r:proc_attr:s0"),
            Some(500),
            Some(500),
            (8, 9),
            Some((8, 9)),
            Some("mnt:[4026531840]"),
            Some("mnt:[4026531840]"),
            true,
            Some(false),
            false,
        ));
        assert!(parent_exec_valid(
            TARGET,
            Some(TARGET),
            Some(TARGET),
            Some("u:object_r:proc_attr:s0"),
            Some("u:object_r:proc_attr:s0"),
            Some(500),
            Some(500),
            (8, 9),
            Some((8, 9)),
            None,
            Some("mnt:[4026531840]"),
            true,
            Some(true),
            true,
        ));
        assert!(!parent_exec_valid(
            TARGET,
            Some(TARGET),
            Some(TARGET),
            Some("u:object_r:proc_attr:s0"),
            Some("u:object_r:proc_attr:s0"),
            Some(500),
            Some(500),
            (8, 9),
            Some((8, 9)),
            None,
            Some("mnt:[4026531840]"),
            true,
            Some(true),
            false,
        ));
    }

    #[test]
    fn avc_correlation_requires_child_sid_permission_and_enforcing_mode() {
        let line = "6,400,1,-;avc: denied { open } for pid=44 comm=ssal-probe name=current dev=proc ino=1 scontext=u:r:ssal_guest_probe:s0 tcontext=u:object_r:proc:s0 tclass=file permissive=0";
        assert!(avc_confirms_proc_denial(line, 44));
        assert!(!avc_confirms_proc_denial(line, 45));
        assert!(!avc_confirms_proc_denial(
            &line.replace("permissive=0", "permissive=1"),
            44
        ));
        assert!(!avc_confirms_proc_denial(
            &line.replace("open", "write"),
            44
        ));
    }

    #[test]
    fn host_process_snapshot_comparison_includes_every_identity_field() {
        let before = vec![(
            "zygote",
            1765,
            627,
            "u:r:zygote:s0",
            "/system/bin/app_process64",
        )];
        assert!(host_process_snapshots_match(&before, &before.clone()));
        let mut after = before.clone();
        after[0].2 += 1;
        assert!(!host_process_snapshots_match(&before, &after));
        after = before.clone();
        after[0].3 = "u:r:other:s0";
        assert!(!host_process_snapshots_match(&before, &after));
    }

    #[test]
    fn required_av_denials_and_query_errors_block_but_references_do_not() {
        let mut issues = Vec::new();
        let allowed = AvQuery {
            status: AvStatus::Allowed,
            permissive: Some(false),
            sequence: Some(1),
            query_errno: None,
            permission_bit: Some(1),
            allowed_mask: Some(1),
            raw_response: Some("1 1 0 0 1 0".into()),
        };
        record_required_issue(
            &mut issues,
            (TARGET, PROPERTY_AREA_FS_CONTEXT, "dir", "search", true),
            &allowed,
        );
        let denied = AvQuery {
            status: AvStatus::Denied,
            permissive: Some(false),
            sequence: Some(1),
            query_errno: None,
            permission_bit: Some(1),
            allowed_mask: Some(0),
            raw_response: Some("0 1 0 0 1 0".into()),
        };
        record_required_issue(
            &mut issues,
            (TARGET, PROPERTY_AREA_FS_CONTEXT, "dir", "write", true),
            &denied,
        );
        let query_error = AvQuery {
            status: AvStatus::QueryError,
            permissive: None,
            sequence: None,
            query_errno: Some(libc::EINVAL),
            permission_bit: Some(1),
            allowed_mask: None,
            raw_response: Some("bad response".into()),
        };
        record_required_issue(
            &mut issues,
            (TARGET, PROPERTY_AREA_FS_CONTEXT, "dir", "add_name", true),
            &query_error,
        );
        record_required_issue(
            &mut issues,
            (TARGET, TARGET, "process", "getattr", false),
            &denied,
        );
        record_required_issue(
            &mut issues,
            (TARGET, TARGET, "process", "getattr", false),
            &query_error,
        );
        assert_eq!(
            required_av_block_message(&issues).as_deref(),
            Some("required AV blocked before child creation: u:r:ssal_guest_probe:s0 u:object_r:tmpfs:s0 dir:write decision=DENIED, u:r:ssal_guest_probe:s0 u:object_r:tmpfs:s0 dir:add_name decision=QUERY_ERROR query_errno=22")
        );
        assert_eq!(required_av_block_message(&[]), None);
    }

    #[test]
    fn host_process_snapshot_only_selects_known_android_core_processes() {
        assert_eq!(argv0(b"zygote64\0--zygote\0"), Ok("zygote64"));
        assert_eq!(host_process_kind(1, "init", "", ""), Some("init"));
        assert_eq!(
            host_process_kind(55, "system_server", "", ""),
            Some("system_server")
        );
        assert_eq!(
            host_process_kind(88, "app_process64", "zygote64", "/system/bin/app_process64"),
            Some("zygote")
        );
        assert_eq!(
            host_process_kind(89, "main", "zygote64", "/system/bin/app_process64"),
            Some("zygote")
        );
        assert_eq!(
            host_process_kind(99, "surfaceflinger", "", ""),
            Some("surfaceflinger")
        );
        for (name, kind) in [
            ("installd", "installd"),
            ("netd", "netd"),
            ("adbd", "adbd"),
            ("artd", "artd"),
        ] {
            assert_eq!(host_process_kind(101, name, "", ""), Some(kind));
        }
        assert_eq!(
            host_process_kind(100, "main", "zygote64", "/system/bin/other"),
            None
        );
        assert_eq!(
            host_process_kind(100, "main", "other", "/system/bin/app_process64"),
            None
        );
    }

    #[test]
    fn proc_starttime_parser_handles_spaces_and_parentheses_in_comm() {
        let mut fields = vec!["0"; 20];
        fields[0] = "S";
        fields[19] = "627";
        let stat = format!("15448 (main ) worker) {}", fields.join(" "));
        assert_eq!(proc_stat_starttime(&stat), Some(627));
    }

    #[test]
    fn control_mode_is_explicit_and_trace_records_are_checked() {
        let hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        assert_eq!(
            parse_args(&args(&["--control", "/x", "--sha256", hash])),
            Ok(Mode::Control {
                helper: "/x",
                sha256: hash
            })
        );
        assert_eq!(
            parse_args(&args(&["--bare-control", "/x", "--sha256", hash])),
            Ok(Mode::BareControl {
                helper: "/x",
                sha256: hash
            })
        );
        assert_eq!(
            parse_args(&args(&["--bare-ptrace-control", "/x", "--sha256", hash])),
            Ok(Mode::BarePtraceControl {
                helper: "/x",
                sha256: hash
            })
        );
        assert_eq!(
            parse_args(&args(&["--bare-ptrace-transition", "/x", "--sha256", hash])),
            Ok(Mode::BarePtraceRun {
                helper: "/x",
                sha256: hash
            })
        );
        assert_eq!(
            parse_args(&args(&["--bare-transition", "/x", "--sha256", hash])),
            Ok(Mode::BareRun {
                helper: "/x",
                sha256: hash
            })
        );
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&TRACE_SETEXEC_WRITE.to_ne_bytes());
        bytes.extend_from_slice(&libc::EACCES.to_ne_bytes());
        let events = decode_trace_events(&bytes).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(trace_stage_name(events[0].stage), "setexec_write");
        assert_eq!(trace_syscall_name(events[0].stage), "write");
        assert_eq!(events[0].errno, libc::EACCES);
        assert!(decode_trace_events(&bytes[..bytes.len() - 1]).is_err());
    }

    #[test]
    fn bare_reporter_requires_entry_marker_and_exact_context() {
        assert!(bare_output_matches_context(
            "BARE_ENTRY\ncontext=u:r:ksu:s0\0\n",
            "u:r:ksu:s0"
        ));
        assert!(!bare_output_matches_context(
            "BARE_ENTRY\ncontext=u:r:other:s0\0\n",
            "u:r:ksu:s0"
        ));
        assert!(!bare_output_matches_context("", "u:r:ksu:s0"));
    }

    #[test]
    fn exit_probe_requires_expected_status_and_no_output() {
        assert!(bare_exit_probe_succeeded(42 << 8, ""));
        assert!(!bare_exit_probe_succeeded(0, ""));
        assert!(!bare_exit_probe_succeeded(42 << 8, "unexpected"));
        assert!(!bare_exit_probe_succeeded(0x000b, ""));
    }

    #[test]
    fn ptrace_wait_status_and_siginfo_fields_are_decoded() {
        assert_eq!(ptrace_wait_stop((4 << 16) | (5 << 8) | 0x7f), Some((5, 4)));
        assert_eq!(ptrace_wait_stop(0x000b), None);

        let mut raw = [0u8; 128];
        raw[8..12].copy_from_slice(&1i32.to_ne_bytes());
        raw[16..24].copy_from_slice(&0x1234u64.to_ne_bytes());
        assert_eq!(decode_siginfo(&raw), (1, 0x1234));
    }

    #[test]
    fn guest_permissive_is_allowed_only_for_diagnostic_children() {
        assert!(target_state_allowed(false, false));
        assert!(!target_state_allowed(true, false));
        assert!(target_state_allowed(true, true));
        assert_eq!(
            parse_args(&args(&[
                "--run-after-approval",
                "/x",
                "--sha256",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            ])),
            Ok(Mode::Run {
                helper: "/x",
                sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            })
        );
        assert!(parse_args(&args(&[
            "--run-after-approval",
            "/x",
            "--sha256",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--diagnostic-permissive"
        ]))
        .is_err());
    }
}

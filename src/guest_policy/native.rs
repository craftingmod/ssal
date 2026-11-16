//! KernelSU UAPI 5, from uapi/{supercall,selinux}.h and userspace/ksud/src/sepolicy.rs.
//! No KernelSU text parser is used: the CIL generator records the argument vectors.
use super::*;

pub const UAPI_VERSION: u32 = 5;
// Limit symbol growth between clones; KernelSU's clone buffer has limited growth headroom.
pub const BATCH_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyCommand {
    pub cmd: u32,
    pub subcmd: u32,
    pub args: Vec<String>,
}

pub(super) fn record(
    rules: &mut BTreeMap<String, Vec<PolicyCommand>>,
    text: String,
    cmd: u32,
    subcmd: u32,
    args: &[&str],
) {
    let command = PolicyCommand {
        cmd,
        subcmd,
        args: args.iter().map(|s| (*s).into()).collect(),
    };
    let commands = rules.entry(text).or_default();
    if !commands.contains(&command) {
        commands.push(command);
    }
}

impl PolicyCommand {
    pub fn encode(&self) -> io::Result<Vec<u8>> {
        let valid = match self.cmd {
            1 => self.args.len() == 4 && matches!(self.subcmd, 1 | 3 | 4),
            2 => self.args.len() == 5 && (1..=3).contains(&self.subcmd),
            4 | 5 => self.args.len() == 2 && self.subcmd == 0,
            6 => self.args.len() == 1 && self.subcmd == 0,
            7 => self.args.len() == 5 && self.subcmd == 0,
            8 => self.args.len() == 4 && matches!(self.subcmd, 1 | 2),
            _ => false,
        };
        if !valid {
            return Err(invalid("unsupported command/subcommand or argument count"));
        }
        if matches!(self.cmd, 1 | 2) && self.args[1] == "self" {
            return Err(invalid("unexpanded self target; regenerate the plan"));
        }
        let mut bytes = Vec::new();
        bytes.extend(self.cmd.to_le_bytes());
        bytes.extend(self.subcmd.to_le_bytes());
        for (i, arg) in self.args.iter().enumerate() {
            // Only the optional transition object can encode ALL/NULL in SSAL plans.
            if arg.as_bytes().contains(&0)
                || arg.len() > 255
                || (arg.is_empty() && !(self.cmd == 7 && i == 4))
                || arg == "*"
            {
                return Err(invalid(format!("invalid policy argument #{i}: {arg:?}")));
            }
            let valid_arg = (self.cmd == 7 && i == 4)
                || symbol(arg)
                || (self.cmd == 2 && i == 4 && valid_range(arg));
            if !valid_arg {
                return Err(invalid(format!("invalid policy symbol #{i}: {arg:?}")));
            }
            bytes.extend((arg.len() as u32).to_le_bytes());
            bytes.extend(arg.as_bytes());
            bytes.push(0);
        }
        if self.cmd == 2 && (self.args[3] != "ioctl" || !valid_range(&self.args[4])) {
            return Err(invalid("only validated u16 ioctl ranges are supported"));
        }
        Ok(bytes)
    }

    fn owned(&self, prefix: &str) -> bool {
        let guest = |i: usize| self.args[i].starts_with(prefix);
        match self.cmd {
            1 | 2 => guest(0),
            4 => guest(0) && guest(1),
            5 => guest(1), // Shared Host labels may join a Guest target attribute.
            6 => guest(0),
            7 => {
                guest(0)
                    && guest(3)
                    && (guest(1) || (self.args[1] == "tmpfs" && self.args[2] == "file"))
            }
            8 => guest(0) && guest(1) && guest(3),
            _ => false,
        }
    }
}

fn valid_range(s: &str) -> bool {
    let parse = |s: &str| {
        s.strip_prefix("0x")
            .and_then(|s| u16::from_str_radix(s, 16).ok())
    };
    match s.split_once('-') {
        Some((a, b)) => matches!((parse(a), parse(b)), (Some(a), Some(b)) if a <= b),
        None => parse(s).is_some(),
    }
}

fn statement_text(commands: &[PolicyCommand]) -> io::Result<String> {
    let first = &commands[0];
    let a = &first.args;
    let text = if first.cmd == 1 {
        if commands
            .iter()
            .any(|c| c.cmd != 1 || c.subcmd != first.subcmd || c.args[..3] != a[..3])
        {
            return Err(invalid("mixed permission statement"));
        }
        let op = match first.subcmd {
            1 => "allow",
            3 => "auditallow",
            _ => "dontaudit",
        };
        format!(
            "{op} {} {} {} {{ {} }}",
            a[0],
            a[1],
            a[2],
            commands
                .iter()
                .map(|c| c.args[3].as_str())
                .collect::<Vec<_>>()
                .join(" ")
        )
    } else {
        if commands.len() != 1 {
            return Err(invalid("non-AV statement must have one command"));
        }
        let op = match first.cmd {
            2 => match first.subcmd {
                1 => "allowxperm",
                2 => "auditallowxperm",
                _ => "dontauditxperm",
            },
            4 => "type",
            5 => "typeattribute",
            6 => "attribute",
            7 => "type_transition",
            8 => {
                if first.subcmd == 1 {
                    "type_change"
                } else {
                    "type_member"
                }
            }
            _ => return Err(invalid("unsupported command")),
        };
        format!(
            "{op} {}",
            a.iter()
                .filter(|a| !a.is_empty())
                .cloned()
                .collect::<Vec<_>>()
                .join(" ")
        )
    };
    Ok(text)
}

#[derive(Debug)]
pub struct EncodedBatch {
    pub payload: Vec<u8>,
    pub commands: usize,
    pub statements: Vec<String>,
}

/// Validate and encode every delta statement before opening a driver or changing policy.
pub fn encode(plan: &Plan, ordered: &[String]) -> io::Result<Vec<EncodedBatch>> {
    plan.usable()?;
    if plan.version < 5 {
        return Err(invalid(
            "native plan predates explicit self expansion; regenerate the plan",
        ));
    }
    let prefix = format!("ssal_{}_", plan.id);
    if !valid_id(&plan.id) {
        return Err(invalid("invalid profile policy ID"));
    }
    let mut batches = Vec::new();
    let mut batch = EncodedBatch {
        payload: Vec::new(),
        commands: 0,
        statements: Vec::new(),
    };
    let mut issues = Vec::new();
    let mut phase = 0;
    for text in ordered {
        let result = (|| -> io::Result<(Vec<u8>, usize)> {
            let commands = plan
                .native_rules
                .get(text)
                .filter(|c| !c.is_empty())
                .ok_or_else(|| {
                    invalid("no structured command; regenerate plan (rule was not omitted)")
                })?;
            let mut payload = Vec::new();
            for command in commands {
                let bytes = command.encode()?;
                let placeholder = command.cmd == 4
                    && plan.placeholders.contains(&command.args[0])
                    && plan.shared_types.contains(&command.args[0])
                    && !command.args[0].starts_with(&prefix)
                    && command.args[1] == format!("{prefix}placeholders");
                if !placeholder
                    && command.args.iter().enumerate().any(|(i, a)| {
                        (i < 2 || (matches!(command.cmd, 7 | 8) && i == 3))
                            && plan.placeholders.contains(a)
                    })
                {
                    return Err(invalid(
                        "placeholder may only appear in its type declaration",
                    ));
                }
                if !placeholder && !command.owned(&prefix) {
                    return Err(invalid("command modifies non-Guest policy"));
                }
                let next_phase = match command.cmd {
                    6 => 0,
                    4 => 1,
                    5 => 2,
                    _ => 3,
                };
                if next_phase < phase {
                    return Err(invalid("declaration/dependency ordering violation"));
                }
                phase = next_phase;
                payload.extend(bytes);
            }
            if statement_text(commands)? != *text {
                return Err(invalid(
                    "structured command differs from delta ledger statement",
                ));
            }
            Ok((payload, commands.len()))
        })();
        match result {
            Err(e) => issues.push(format!("{text}: {e}")),
            Ok((payload, count)) => {
                if payload.len() > BATCH_BYTES {
                    issues.push(format!("{text}: statement exceeds native batch limit"));
                    continue;
                }
                if !batch.payload.is_empty() && batch.payload.len() + payload.len() > BATCH_BYTES {
                    batches.push(batch);
                    batch = EncodedBatch {
                        payload: Vec::new(),
                        commands: 0,
                        statements: Vec::new(),
                    };
                }
                batch.payload.extend(payload);
                batch.commands += count;
                batch.statements.push(text.clone());
            }
        }
    }
    if !issues.is_empty() {
        return Err(invalid(issues.join("\n")));
    }
    if !batch.payload.is_empty() {
        batches.push(batch);
    }
    Ok(batches)
}

#[cfg(unix)]
mod driver {
    use super::*;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    pub const GET_INFO: u32 = 0x80104b02;
    const GET_INFO_LEGACY: u32 = 0x80004b02;
    pub const SET_SEPOLICY: u32 = 0xc0004b04;

    #[repr(C)]
    #[derive(Default, Debug, Serialize)]
    pub struct KernelSuInfo {
        pub version: u32,
        pub flags: u32,
        pub features: u32,
        pub uapi_version: u32,
    }

    #[repr(C, align(8))]
    struct SetSepolicy {
        data_len: u64,
        data: u64,
    }

    pub struct KernelSuNative {
        fd: OwnedFd,
        pub info: KernelSuInfo,
    }

    impl KernelSuNative {
        pub fn open() -> io::Result<Self> {
            let mut inherited = None;
            for entry in fs::read_dir("/proc/self/fd")? {
                let entry = entry?;
                let Ok(fd) = entry.file_name().to_string_lossy().parse::<i32>() else {
                    continue;
                };
                let Ok(target) = fs::read_link(entry.path()) else {
                    continue;
                };
                if target == Path::new("anon_inode:[ksu_driver_su]") {
                    inherited = Some(fd);
                    break;
                }
                if target == Path::new("anon_inode:[ksu_driver]") {
                    inherited = Some(fd);
                }
            }
            let fd = if let Some(fd) = inherited {
                unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) }
            } else {
                let mut fd: i32 = -1;
                // KernelSU reboot hook installs an anon-inode FD; cmd=0 is not a reboot operation.
                unsafe {
                    libc::syscall(libc::SYS_reboot, 0xDEADBEEFu32, 0xCAFEBABEu32, 0, &mut fd);
                }
                if fd >= 0 && unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
                    let error = io::Error::last_os_error();
                    unsafe {
                        libc::close(fd);
                    }
                    return Err(error);
                }
                fd
            };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            let fd = unsafe { OwnedFd::from_raw_fd(fd) };
            let mut info = KernelSuInfo::default();
            if unsafe { libc::ioctl(fd.as_raw_fd(), GET_INFO as _, &mut info) } < 0 {
                info = KernelSuInfo::default();
                if unsafe { libc::ioctl(fd.as_raw_fd(), GET_INFO_LEGACY as _, &mut info) } < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(Self { fd, info })
        }

        pub fn validate_uapi(&self) -> io::Result<()> {
            if self.info.uapi_version != UAPI_VERSION {
                return Err(invalid(format!("native UAPI mismatch: installed={}, encoder={UAPI_VERSION}; no injection attempted", self.info.uapi_version)));
            }
            Ok(())
        }

        pub fn inject(&self, batch: &EncodedBatch) -> io::Result<usize> {
            self.validate_uapi()?;
            let request = SetSepolicy {
                data_len: batch.payload.len() as u64,
                data: batch.payload.as_ptr() as u64,
            };
            let ret = unsafe { libc::ioctl(self.fd.as_raw_fd(), SET_SEPOLICY as _, &request) };
            if ret < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(ret as usize)
        }
    }
}

#[cfg(unix)]
pub use driver::{KernelSuInfo, KernelSuNative};

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn shared_tmpfs_transition_still_requires_guest_source_and_output() {
        let command = PolicyCommand {
            cmd: 7,
            subcmd: 0,
            args: [
                "ssal_p0001_zygote",
                "tmpfs",
                "file",
                "ssal_p0001_zygote_tmpfs",
                "",
            ]
            .map(String::from)
            .to_vec(),
        };
        assert!(command.owned("ssal_p0001_"));
        for (index, value) in [
            (0, "zygote"),
            (1, "rootfs"),
            (2, "dir"),
            (3, "zygote_tmpfs"),
        ] {
            let mut denied = command.clone();
            denied.args[index] = value.into();
            assert!(!denied.owned("ssal_p0001_"));
        }
    }
    #[test]
    fn binary_layout_and_special_objects() -> io::Result<()> {
        let command = PolicyCommand {
            cmd: 7,
            subcmd: 0,
            args: ["a", "b", "anon_inode", "c", "[userfaultfd]"]
                .map(String::from)
                .to_vec(),
        };
        let bytes = command.encode()?;
        assert_eq!(&bytes[..8], &[7, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(&bytes[8..14], &[1, 0, 0, 0, b'a', 0]);
        assert!(bytes.ends_with(b"[userfaultfd]\0"));
        let mut command = command;
        command.args[4] = "[io_uring]".into();
        assert!(command.encode()?.ends_with(b"[io_uring]\0"));
        command.args[4].clear();
        assert!(command.encode()?.ends_with(&[0; 5]));
        command.args[0] = "a\0b".into();
        assert!(command.encode().is_err());
        assert!(valid_range("0x0000-0xffff"));
        assert!(!valid_range("0xffff-0x0000"));
        Ok(())
    }
}

use super::server::PeerCredentials;

pub(super) fn valid_powerctl(command: &str) -> bool {
    if command.bytes().any(|byte| byte.is_ascii_whitespace()) || command == "reboot,userspace" {
        return false;
    }
    match command.split_once(',') {
        Some((action, reason)) => matches!(action, "shutdown" | "reboot") && !reason.is_empty(),
        None => matches!(command, "shutdown" | "reboot"),
    }
}

pub(super) fn powerctl(command: &str, peer: PeerCredentials, session_owner_pid: i32) -> bool {
    if !valid_powerctl(command) || unsafe { libc::getppid() } != session_owner_pid {
        eprintln!(
            "Guest powerctl ignored: command={command:?} pid={} uid={} gid={}",
            peer.pid, peer.uid, peer.gid
        );
        return false;
    }
    // shortcut: reboot tears down this Guest session; request relaunch when a Guest restart coordinator exists.
    if unsafe { libc::kill(session_owner_pid, libc::SIGTERM) } != 0 {
        eprintln!(
            "Guest powerctl could not stop session owner pid={session_owner_pid}: {}",
            std::io::Error::last_os_error()
        );
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn powerctl_only_requests_guest_session_shutdown_or_restart() {
        let peer = PeerCredentials {
            pid: 1,
            uid: 0,
            gid: 0,
        };
        for command in [
            "shutdown",
            "shutdown,userrequested",
            "reboot",
            "reboot,recovery",
        ] {
            assert!(valid_powerctl(command));
        }
        for command in [
            "",
            "halt",
            "reboot,userspace",
            "reboot,",
            "shutdown,user requested",
        ] {
            assert!(!valid_powerctl(command));
        }
        assert!(!powerctl("reboot", peer, unsafe { libc::getpid() }));
    }
}

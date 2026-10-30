//! arm64 Binder UAPI, fixed integer/name payloads, no FD or object transfer.
use serde_json::json;
use std::fs::{self, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
const WRITE_READ: u32 = 0xc0306201;
const TRANSACTION: u32 = 0x80407202;
const REPLY: u32 = 0x80407203;
const NAME: &[u8] = b"ssal.enforcing.private.echo";
pub fn reject_default(identity: [u64; 4]) -> io::Result<()> {
    match fs::metadata("/dev/binder") {
        Ok(meta) if meta.is_file() && meta.mode() & 0o777 == 0 && !matches(&meta, identity) => (),
        Err(e) if [Some(libc::EACCES), Some(libc::EPERM)].contains(&e.raw_os_error()) => (),
        _ => return Err(io::Error::other("negative control object mismatch")),
    }
    let error = Driver::open(identity)
        .err()
        .ok_or_else(|| io::Error::other("negative control unexpectedly opened"))?;
    println!(
        "{}",
        json!({"event":"negative_default_driver","status":"passed","syscall":"stat default path before open","errno":error.raw_os_error(),"reason":error.to_string(),"host_open_attempted":false,"binder_ioctl_attempted":false})
    );
    Ok(())
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Tx {
    target: u64,
    cookie: u64,
    code: u32,
    flags: u32,
    sender_pid: i32,
    sender_euid: u32,
    data_size: u64,
    offsets_size: u64,
    buffer: u64,
    offsets: u64,
}
struct Driver {
    file: fs::File,
    mapping: *mut libc::c_void,
}
impl Drop for Driver {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.mapping, 131072);
        }
    }
}
fn ioctl(fd: i32, name: &str, command: u32, data: *mut libc::c_void) -> io::Result<()> {
    let rc = unsafe { libc::ioctl(fd, command as _, data) };
    let error = if rc != 0 {
        Some(io::Error::last_os_error())
    } else {
        None
    };
    println!(
        "{}",
        json!({"event":"ioctl","pid":std::process::id(),"ioctl":name,"command":format!("0x{command:08x}"),"rc":rc,"errno":error.as_ref().and_then(io::Error::raw_os_error),"xperm_scope":"actual command result; AV ioctl alone is not xperm proof"})
    );
    match error {
        Some(e) => Err(e),
        None => Ok(()),
    }
}
fn matches(meta: &fs::Metadata, identity: [u64; 4]) -> bool {
    meta.file_type().is_char_device()
        && [meta.dev(), meta.ino(), meta.rdev()] == identity[..3]
        && meta.rdev() != identity[3]
}
impl Driver {
    fn open(identity: [u64; 4]) -> io::Result<Self> {
        if !matches(&fs::metadata("/dev/binder")?, identity) {
            return Err(io::Error::other(
                "default driver identity mismatch; no fallback",
            ));
        }
        let file = match OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open("/dev/binder")
        {
            Ok(f) => f,
            Err(e) => {
                println!(
                    "{}",
                    json!({"event":"open","syscall":"open(/dev/binder)","errno":e.raw_os_error(),"fallback":false})
                );
                return Err(e);
            }
        };
        if !matches(&file.metadata()?, identity) {
            return Err(io::Error::other("opened driver identity mismatch"));
        }
        let label = ssal::unix::image_context(&file)?;
        println!(
            "{}",
            json!({"event":"open","pid":std::process::id(),"syscall":"open(/dev/binder)","errno":null,"label":label,"identity":identity,"fallback":false})
        );
        if label != "u:object_r:binder_device:s0" {
            return Err(io::Error::other("driver label mismatch"));
        }
        let mut protocol: i32 = 0;
        ioctl(
            file.as_raw_fd(),
            "BINDER_VERSION",
            0xc0046209,
            (&mut protocol as *mut i32).cast(),
        )?;
        if protocol != 8 {
            return Err(io::Error::other("Binder protocol != 8"));
        }
        let mapping = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                131072,
                libc::PROT_READ,
                libc::MAP_PRIVATE,
                file.as_raw_fd(),
                0,
            )
        };
        if mapping == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { file, mapping })
    }
    fn exchange(&self, write: &[u8], read: bool) -> io::Result<Vec<(u32, Option<Tx>)>> {
        let mut buffer = [0u8; 4096];
        let mut bwr = [
            write.len() as u64,
            0,
            write.as_ptr() as u64,
            if read { buffer.len() as u64 } else { 0 },
            0,
            buffer.as_mut_ptr() as u64,
        ];
        let result = ioctl(
            self.file.as_raw_fd(),
            "BINDER_WRITE_READ",
            WRITE_READ,
            bwr.as_mut_ptr().cast(),
        );
        println!(
            "{}",
            json!({"event":"write_read","pid":std::process::id(),"write_size":bwr[0],"write_consumed":bwr[1],"read_consumed":bwr[4]})
        );
        if let Err(e) = result {
            if e.raw_os_error() != Some(libc::EAGAIN) {
                return Err(e);
            }
        }
        if bwr[1] != write.len() as u64 || bwr[4] > buffer.len() as u64 {
            return Err(io::Error::other("Binder consumed size mismatch"));
        }
        parse(&buffer[..bwr[4] as usize])
    }
    fn wait(&self) -> io::Result<Vec<(u32, Option<Tx>)>> {
        let mut poll = libc::pollfd {
            fd: self.file.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        if unsafe { libc::poll(&mut poll, 1, 3000) } <= 0 {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "Binder poll"));
        }
        self.exchange(&[], true)
    }
    fn data(&self, tx: Tx) -> io::Result<Vec<u8>> {
        if tx.data_size == 0 && tx.offsets_size == 0 {
            return Ok(Vec::new());
        }
        let start = self.mapping as u64;
        if tx.offsets_size != 0
            || tx.data_size > 256
            || tx.buffer < start
            || tx
                .buffer
                .checked_add(tx.data_size)
                .is_none_or(|e| e > start + 131072)
        {
            return Err(io::Error::other("unexpected Binder payload bounds/objects"));
        }
        Ok(
            unsafe { std::slice::from_raw_parts(tx.buffer as *const u8, tx.data_size as usize) }
                .to_vec(),
        )
    }
    fn free(&self, tx: Tx) -> io::Result<()> {
        let mut bytes = 0x40086303u32.to_ne_bytes().to_vec();
        bytes.extend_from_slice(&tx.buffer.to_ne_bytes());
        self.exchange(&bytes, false)?;
        Ok(())
    }
}
fn parse(bytes: &[u8]) -> io::Result<Vec<(u32, Option<Tx>)>> {
    let mut offset = 0;
    let mut events = Vec::new();
    while offset < bytes.len() {
        if offset + 4 > bytes.len() {
            return Err(io::Error::other("truncated Binder command"));
        }
        let command = u32::from_ne_bytes(bytes[offset..offset + 4].try_into().unwrap());
        offset += 4;
        let size = ((command >> 16) & 0x3fff) as usize;
        if offset + size > bytes.len() {
            return Err(io::Error::other("truncated Binder response"));
        }
        let tx = if command == TRANSACTION || command == REPLY {
            if size != 64 {
                return Err(io::Error::other("Binder transaction ABI"));
            }
            Some(unsafe { std::ptr::read_unaligned(bytes[offset..].as_ptr().cast::<Tx>()) })
        } else {
            None
        };
        println!(
            "{}",
            json!({"event":"binder_return","pid":std::process::id(),"command":format!("0x{command:08x}"),"transaction":command==TRANSACTION,"reply":command==REPLY,"raw":&bytes[offset..offset+size]})
        );
        events.push((command, tx));
        offset += size;
    }
    Ok(events)
}
fn command(command: u32, tx: &Tx) -> Vec<u8> {
    let mut out = command.to_ne_bytes().to_vec();
    out.extend_from_slice(unsafe {
        std::slice::from_raw_parts((tx as *const Tx).cast::<u8>(), 64)
    });
    out
}
pub fn serve(identity: [u64; 4]) -> io::Result<()> {
    server(identity, None)
}
pub fn request(identity: [u64; 4]) -> io::Result<()> {
    client(identity)
}
fn server(identity: [u64; 4], ready: Option<i32>) -> io::Result<()> {
    let driver = Driver::open(identity)?;
    driver.exchange(&[], false)?; // Empty dispatch is recorded separately from IPC.
    let mut object = [0u64; 3];
    ioctl(
        driver.file.as_raw_fd(),
        "BINDER_SET_CONTEXT_MGR_EXT",
        0x4018620d,
        object.as_mut_ptr().cast(),
    )?;
    println!(
        "{}",
        json!({"event":"private_context_manager","status":"passed","pid":std::process::id()})
    );
    driver.exchange(&0x630cu32.to_ne_bytes(), false)?;
    if let Some(ready) = ready {
        if unsafe { libc::write(ready, b"R".as_ptr().cast(), 1) } != 1 {
            return Err(io::Error::last_os_error());
        }
        unsafe {
            libc::close(ready);
        }
    }
    let mut registered = false;
    loop {
        for (code, tx) in driver.wait()? {
            if code == TRANSACTION {
                let tx = tx.unwrap();
                let request = driver.data(tx)?;
                if tx.sender_euid != 1000 {
                    return Err(io::Error::other("unexpected Binder sender UID"));
                }
                println!(
                    "{}",
                    json!({"event":"binder_transaction_received","code":tx.code,"sender_pid":tx.sender_pid,"sender_uid":tx.sender_euid,"data_size":tx.data_size})
                );
                // A fixed in-memory test registry. No IServiceManager implementation.
                let response = match (tx.code, request.as_slice()) {
                    (0, []) => b"".as_slice(),
                    (1, NAME) => {
                        registered = true;
                        b"registered".as_slice()
                    }
                    (2, NAME) if registered => b"found:ssal.enforcing.private.echo".as_slice(),
                    (3, b"ssal-missing") => b"not_found".as_slice(),
                    (4, b"SSAL-echo-nonce") => b"SSAL-echo-nonce".as_slice(),
                    _ => b"denied_invalid_request".as_slice(),
                };
                let reply = Tx {
                    data_size: response.len() as u64,
                    buffer: response.as_ptr() as u64,
                    ..Tx::default()
                };
                driver.exchange(&command(0x40406301, &reply), false)?;
                driver.free(tx)?;
            }
        }
    }
}
fn client(identity: [u64; 4]) -> io::Result<()> {
    let driver = Driver::open(identity)?;
    for (code, request, expected) in [
        (0, b"".as_slice(), b"".as_slice()),
        (1, NAME, b"registered".as_slice()),
        (2, NAME, b"found:ssal.enforcing.private.echo".as_slice()),
        (3, b"ssal-missing".as_slice(), b"not_found".as_slice()),
        (
            4,
            b"SSAL-echo-nonce".as_slice(),
            b"SSAL-echo-nonce".as_slice(),
        ),
    ] {
        let tx = Tx {
            code,
            data_size: request.len() as u64,
            buffer: request.as_ptr() as u64,
            ..Tx::default()
        };
        let mut events = driver.exchange(&command(0x40406300, &tx), true)?;
        let mut replied = false;
        for _ in 0..16 {
            for (command, tx) in events {
                if [0x7205, 0x7211, 0x80047200].contains(&command) {
                    let mut extended = [0u32; 3];
                    let result = ioctl(
                        driver.file.as_raw_fd(),
                        "BINDER_GET_EXTENDED_ERROR",
                        0xc00c6211,
                        extended.as_mut_ptr().cast(),
                    );
                    println!(
                        "{}",
                        json!({"event":"extended_error","ioctl_available":result.is_ok(),"id":extended[0],"command":format!("0x{:08x}",extended[1]),"param":extended[2] as i32,"errno":result.err().and_then(|e|e.raw_os_error())})
                    );
                    return Err(io::Error::other(format!(
                        "Binder transaction result 0x{command:08x}; not success"
                    )));
                }
                if command == REPLY {
                    let tx = tx.unwrap();
                    let response = driver.data(tx)?;
                    if tx.flags & 8 != 0 || response != expected {
                        return Err(io::Error::other("Binder reply status/payload mismatch"));
                    }
                    driver.free(tx)?;
                    replied = true;
                    println!(
                        "{}",
                        json!({"event":"private_registry_transaction","code":code,"status":"passed","negative_lookup":code==3,"scope":"fixed test registry only; no AOSP servicemanager or Host registry observation"})
                    );
                }
            }
            if replied {
                break;
            }
            events = driver.wait()?;
        }
        if !replied {
            return Err(io::Error::other("no Binder reply"));
        }
    }
    Ok(())
}
pub fn selftest(identity: [u64; 4]) -> io::Result<()> {
    let mut pipe = [0; 2];
    if unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let parent = unsafe { libc::getpid() };
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        unsafe {
            libc::close(pipe[0]);
            libc::close(pipe[1]);
        }
        return Err(io::Error::last_os_error());
    }
    if pid == 0 {
        unsafe {
            libc::close(pipe[0]);
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
        }
        if unsafe { libc::getppid() } != parent {
            unsafe { libc::_exit(1) }
        }
        let result = server(identity, Some(pipe[1]));
        if let Err(e) = &result {
            println!(
                "{}",
                json!({"event":"server_blocked","errno":e.raw_os_error(),"error":e.to_string()})
            );
        }
        unsafe { libc::_exit(i32::from(result.is_err())) }
    }
    unsafe {
        libc::close(pipe[1]);
    }
    let result = (|| {
        let mut p = libc::pollfd {
            fd: pipe[0],
            events: libc::POLLIN,
            revents: 0,
        };
        let mut byte = 0u8;
        if unsafe { libc::poll(&mut p, 1, 4000) } <= 0
            || unsafe { libc::read(pipe[0], (&mut byte as *mut u8).cast(), 1) } != 1
            || byte != b'R'
        {
            return Err(io::Error::other("private manager not ready"));
        }
        client(identity)
    })();
    unsafe {
        libc::close(pipe[0]);
        libc::kill(pid, libc::SIGKILL);
    }
    let mut status = 0;
    while unsafe { libc::waitpid(pid, &mut status, 0) } < 0 {
        if io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            return Err(io::Error::last_os_error());
        }
    }
    println!(
        "{}",
        json!({"event":"raw_ipc_complete","status":if result.is_ok(){"passed"}else{"blocked"},"server_reaped":true,"server_pid":pid})
    );
    result
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_truncated_responses_and_preserves_failure_commands() {
        assert_eq!(std::mem::size_of::<Tx>(), 64);
        assert!(parse(&[1, 2, 3]).is_err());
        assert!(parse(&TRANSACTION.to_ne_bytes()).is_err());
        assert_eq!(parse(&0x7211u32.to_ne_bytes()).unwrap()[0].0, 0x7211);
    }
}

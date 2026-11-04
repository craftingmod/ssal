use std::io::{self, Write};

fn main() -> io::Result<()> {
    unsafe {
        libc::raise(libc::SIGSTOP);
    }
    if std::env::args().any(|arg| arg == "--oom") {
        let mut chunks = Vec::new();
        for _ in 0..96 {
            let mut chunk = vec![0u8; 1024 * 1024];
            for i in (0..chunk.len()).step_by(4096) {
                chunk[i] = 1;
            }
            chunks.push(chunk);
            std::hint::black_box(&chunks);
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        return Err(io::Error::other("memory.max did not stop allocator"));
    }
    let mut bytes = vec![0u8; 16 * 1024 * 1024];
    for i in (0..bytes.len()).step_by(4096) {
        bytes[i] = 1;
    }
    let normal = unsafe { libc::fork() };
    if normal < 0 {
        return Err(io::Error::last_os_error());
    }
    if normal == 0 {
        loop {
            unsafe {
                libc::pause();
            }
        }
    }
    let detached = unsafe { libc::fork() };
    if detached < 0 {
        return Err(io::Error::last_os_error());
    }
    if detached == 0 {
        if unsafe { libc::setsid() } < 0 {
            std::process::exit(2);
        }
        loop {
            unsafe {
                libc::pause();
            }
        }
    }
    println!("normal={normal} detached={detached}");
    io::stdout().flush()?;
    std::hint::black_box(&bytes);
    loop {
        unsafe {
            libc::pause();
        }
    }
}

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

mod images;
mod profiles;
mod session;

pub(crate) use session::run;
#[cfg(feature = "phase2c-diagnostic")]
pub(crate) use session::run_phase2c_diagnostic;
#[cfg(feature = "phase3-diagnostic")]
pub(crate) use session::run_phase3_diagnostic;

fn atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let temp = path.with_extension("tmp");
    let mut f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&temp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    fs::rename(&temp, path)?;
    File::open(path.parent().unwrap())?.sync_all()
}

fn now() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

use prost::Message;
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

#[cfg(test)]
const FILENAME: &str = "persistent_properties";
const MAX_FILE_SIZE: u64 = 4 * 1024 * 1024;

// Android 16 init/persistent_properties.proto (proto2 optional fields).
#[derive(Clone, PartialEq, Message)]
struct PersistentProperties {
    #[prost(message, repeated, tag = "1")]
    properties: Vec<Record>,
}

#[derive(Clone, PartialEq, Message)]
struct Record {
    #[prost(string, optional, tag = "1")]
    name: Option<String>,
    #[prost(string, optional, tag = "2")]
    value: Option<String>,
}

pub(super) struct Store {
    directory: File,
    _lock: File,
    pub values: BTreeMap<String, String>,
}

impl Store {
    pub fn open(path: &Path) -> io::Result<Self> {
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        check_file(&directory, true)?;
        let lock = open_at(
            &directory,
            c".ssal-writer-lock",
            libc::O_RDWR | libc::O_CREAT,
            0o600,
        )?;
        check_file(&lock, false)?;
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let values = match open_at(&directory, c"persistent_properties", libc::O_RDONLY, 0) {
            Ok(file) => {
                check_file(&file, false)?;
                let mut data = Vec::new();
                file.take(MAX_FILE_SIZE + 1).read_to_end(&mut data)?;
                if data.len() as u64 > MAX_FILE_SIZE {
                    return Err(io::Error::other("persistent property file too large"));
                }
                decode(&data)?
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => BTreeMap::new(),
            Err(e) => return Err(e),
        };
        // An interrupted pre-rename write is never newer than the committed file.
        if unsafe {
            libc::unlinkat(
                directory.as_raw_fd(),
                c"persistent_properties.tmp".as_ptr(),
                0,
            )
        } != 0
            && io::Error::last_os_error().kind() != io::ErrorKind::NotFound
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            directory,
            _lock: lock,
            values,
        })
    }

    pub fn commit(&mut self, name: &str, value: &str) -> io::Result<()> {
        validate_record(name, value)?;
        let mut values = self.values.clone();
        values.insert(name.into(), value.into());
        self.write(values)
    }

    pub fn apply_staged(&mut self) -> io::Result<()> {
        let mut values = self.values.clone();
        for (name, value) in &self.values {
            if let Some(actual) = name.strip_prefix("next_boot.") {
                values.insert(actual.into(), value.clone());
                values.remove(name);
            }
        }
        self.write(values)
    }

    fn write(&mut self, values: BTreeMap<String, String>) -> io::Result<()> {
        let bytes = encode(&values);
        if bytes.len() as u64 > MAX_FILE_SIZE {
            return Err(io::Error::other("persistent property file too large"));
        }
        let mut file = open_at(
            &self.directory,
            c"persistent_properties.tmp",
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            0o600,
        )?;
        let result = (|| {
            file.write_all(&bytes)?;
            file.sync_all()?;
            if unsafe {
                libc::renameat(
                    self.directory.as_raw_fd(),
                    c"persistent_properties.tmp".as_ptr(),
                    self.directory.as_raw_fd(),
                    c"persistent_properties".as_ptr(),
                )
            } != 0
            {
                return Err(io::Error::last_os_error());
            }
            self.directory.sync_all()
        })();
        if result.is_err() {
            unsafe {
                libc::unlinkat(
                    self.directory.as_raw_fd(),
                    c"persistent_properties.tmp".as_ptr(),
                    0,
                );
            }
        }
        result?;
        self.values = values;
        Ok(())
    }
}

fn open_at(directory: &File, name: &std::ffi::CStr, flags: i32, mode: u32) -> io::Result<File> {
    use std::os::fd::FromRawFd;
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            mode as libc::mode_t,
        )
    };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}

fn check_file(file: &File, directory: bool) -> io::Result<()> {
    let m = file.metadata()?;
    if m.uid() != unsafe { libc::geteuid() }
        || m.mode() & 0o7777 != if directory { 0o700 } else { 0o600 }
        || if directory {
            !m.is_dir()
        } else {
            !m.is_file() || m.nlink() != 1
        }
    {
        return Err(io::Error::other(
            "unsafe persistent property file owner/type/mode",
        ));
    }
    Ok(())
}

fn validate_record(name: &str, value: &str) -> io::Result<()> {
    if !name.starts_with("persist.") && !name.starts_with("next_boot.persist.") {
        return Err(io::Error::other(
            "non-persistent record in persistent property file",
        ));
    }
    rsproperties::wire::validate_property_name(name).map_err(io::Error::other)?;
    rsproperties::wire::validate_value_len(name, value).map_err(io::Error::other)
}

fn decode(bytes: &[u8]) -> io::Result<BTreeMap<String, String>> {
    let message = PersistentProperties::decode(bytes).map_err(io::Error::other)?;
    let mut values = BTreeMap::new();
    for record in message.properties {
        let name = record
            .name
            .ok_or_else(|| io::Error::other("persistent record has no name"))?;
        let value = record.value.unwrap_or_default();
        validate_record(&name, &value)?;
        if values.insert(name, value).is_some() {
            return Err(io::Error::other("duplicate persistent record"));
        }
    }
    Ok(values)
}

fn encode(values: &BTreeMap<String, String>) -> Vec<u8> {
    PersistentProperties {
        properties: values
            .iter()
            .map(|(name, value)| Record {
                name: Some(name.clone()),
                value: Some(value.clone()),
            })
            .collect(),
    }
    .encode_to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};
    #[test]
    fn aosp_wire_fixture_and_malformed_input() {
        let bytes = b"\x0a\x0f\x0a\x09persist.x\x12\x02ok";
        let values = BTreeMap::from([("persist.x".into(), "ok".into())]);
        assert_eq!(decode(bytes).unwrap(), values);
        assert_eq!(encode(&values), bytes);
        assert!(decode(&bytes[..bytes.len() - 1]).is_err());
        let mut duplicate = bytes.to_vec();
        duplicate.extend(bytes);
        assert!(decode(&duplicate).is_err());
        assert!(validate_record("sys.powerctl", "reboot").is_err());
    }

    #[test]
    fn restart_atomic_failure_lock_and_symlink() {
        let path = super::super::tests::temp_dir("persistent");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut store = Store::open(&path).unwrap();
        assert!(Store::open(&path).is_err());
        store.commit("persist.x", "old").unwrap();
        let committed = std::fs::read(path.join(FILENAME)).unwrap();
        std::fs::create_dir(path.join("persistent_properties.tmp")).unwrap();
        assert!(store.commit("persist.x", "lost").is_err());
        assert_eq!(store.values["persist.x"], "old");
        assert_eq!(std::fs::read(path.join(FILENAME)).unwrap(), committed);
        std::fs::remove_dir(path.join("persistent_properties.tmp")).unwrap();
        drop(store);
        std::fs::write(path.join("persistent_properties.tmp"), b"interrupted").unwrap();
        let store = Store::open(&path).unwrap();
        assert_eq!(store.values["persist.x"], "old");
        assert!(!path.join("persistent_properties.tmp").exists());
        drop(store);
        std::fs::rename(path.join(FILENAME), path.join("sentinel")).unwrap();
        symlink("sentinel", path.join(FILENAME)).unwrap();
        assert!(Store::open(&path).is_err());
        assert_eq!(std::fs::read(path.join("sentinel")).unwrap(), committed);
        std::fs::remove_dir_all(path).unwrap();
    }
}

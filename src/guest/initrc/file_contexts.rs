//! Android `file_contexts` parser and directory label lookup for Guest `init.rc`.
use crate::platform::mount::guest_path;
use regex::Regex;
use std::fs;
use std::io;
use std::path::Path;

#[derive(Clone, Copy, Eq, PartialEq)]
enum FileKind {
    Dir,
    Other,
}

struct Entry {
    regex: Regex,
    kind: Option<FileKind>,
    context: Option<String>,
}

/// Parsed Android `file_contexts` entries using last-match-wins precedence.
#[derive(Default)]
pub struct FileContexts {
    entries: Vec<Entry>,
}

impl FileContexts {
    /// Parses one or more `file_contexts` text files in priority order (later entries override earlier ones).
    pub fn parse(texts: &[&str]) -> Self {
        let mut entries = Vec::new();
        for text in texts {
            for raw_line in text.lines() {
                let line = raw_line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                let fields: Vec<&str> = line.split_whitespace().collect();
                let (pattern, kind, context) = match fields.as_slice() {
                    [pattern, context] => (*pattern, None, *context),
                    [pattern, kind_flag, context] => {
                        let kind = match *kind_flag {
                            "-d" => Some(FileKind::Dir),
                            "--" | "-l" | "-c" | "-b" | "-s" | "-p" => Some(FileKind::Other),
                            _ => continue,
                        };
                        (*pattern, kind, *context)
                    }
                    _ => continue,
                };
                let Ok(regex) = Regex::new(&format!("^(?:{pattern})$")) else {
                    continue;
                };
                entries.push(Entry {
                    regex,
                    kind,
                    context: (context != "<<none>>").then(|| context.to_owned()),
                });
            }
        }
        Self { entries }
    }

    /// Loads mapped Guest `file_contexts` files directly from the mounted Guest root.
    pub fn load_from_guest_root(root: &Path) -> io::Result<Self> {
        let candidates: &[&[&str]] = &[
            &["system/etc/selinux/plat_file_contexts"],
            &[
                "system_ext/etc/selinux/system_ext_file_contexts",
                "system/system_ext/etc/selinux/system_ext_file_contexts",
            ],
            &[
                "product/etc/selinux/product_file_contexts",
                "system/product/etc/selinux/product_file_contexts",
            ],
        ];
        let mut texts = Vec::new();
        for group in candidates {
            for rel in *group {
                match guest_path(root, rel) {
                    Ok(resolved) => {
                        texts.push(fs::read_to_string(resolved)?);
                        break;
                    }
                    Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
                    Err(err) => return Err(err),
                }
            }
        }
        let refs: Vec<&str> = texts.iter().map(String::as_str).collect();
        Ok(Self::parse(&refs))
    }

    /// Returns the SELinux context matching directory `path` (last match wins).
    pub fn lookup_dir(&self, path: &str) -> Option<&str> {
        self.entries
            .iter()
            .rev()
            .find(|entry| {
                matches!(entry.kind, None | Some(FileKind::Dir)) && entry.regex.is_match(path)
            })
            .and_then(|entry| entry.context.as_deref())
    }
}

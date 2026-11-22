//! Tokenizer, property expansion, and `.rc` file loader for Guest `init.rc`.
use super::{Action, Line, Plan, Properties, Service};
use crate::platform::mount::guest_path;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Component, Path};

pub(super) const PRIMARY: &str = "/system/etc/init/hw/init.rc";
const DIRECTORIES: &[&str] = &[
    "/system/etc/init",
    "/system_ext/etc/init",
    "/product/etc/init",
];
const RESOLVED_DIRECTORIES: &[&str] = &["/system/system_ext/etc/init", "/system/product/etc/init"];

fn is_allowed_init_path(path: &Path) -> bool {
    if DIRECTORIES
        .iter()
        .chain(RESOLVED_DIRECTORIES)
        .any(|prefix| path.starts_with(prefix))
    {
        return true;
    }
    let components: Vec<_> = path.components().collect();
    matches!(
        components.as_slice(),
        [
            Component::RootDir,
            Component::Normal(apex_root),
            Component::Normal(_apex_name),
            Component::Normal(etc),
            rest @ ..
        ] if *apex_root == "apex"
            && *etc == "etc"
            && rest.iter().all(|part| matches!(part, Component::Normal(_)))
    )
}

fn is_optional_init_dir(path: &str) -> bool {
    if DIRECTORIES.contains(&path) {
        return true;
    }
    let parts: Vec<_> = path.split('/').collect();
    matches!(
        parts.as_slice(),
        ["", "apex", name, "etc"] | ["", "apex", name, "etc", "init"] if !name.is_empty()
    )
}

impl Plan {
    pub fn load(root: &Path, properties: &Properties) -> io::Result<Self> {
        let mut plan = Self::default();
        plan.load_path(root, PRIMARY, properties)?;
        for directory in DIRECTORIES {
            plan.load_path(root, directory, properties)?;
        }
        let apex_dir = root.join("apex");
        if fs::symlink_metadata(&apex_dir).is_ok_and(|meta| meta.is_dir()) {
            let mut entries = fs::read_dir(&apex_dir)?.collect::<io::Result<Vec<_>>>()?;
            entries.sort_by_key(|entry| entry.file_name());
            for entry in entries {
                let file_name = entry.file_name();
                let Some(name) = file_name.to_str() else {
                    continue;
                };
                if name.contains('@') {
                    continue;
                }
                if entry.file_type()?.is_dir() {
                    plan.load_path(root, &format!("/apex/{name}/etc"), properties)?;
                    plan.load_path(root, &format!("/apex/{name}/etc/init"), properties)?;
                }
            }
        }
        Ok(plan)
    }

    fn load_path(&mut self, root: &Path, path: &str, properties: &Properties) -> io::Result<()> {
        if !is_allowed_init_path(Path::new(path)) {
            return Err(io::Error::other("outside Guest system init directories"));
        }
        let resolved = match guest_path(root, path.trim_start_matches('/')) {
            Ok(resolved) => resolved,
            Err(error)
                if error.kind() == io::ErrorKind::NotFound && is_optional_init_dir(path) =>
            {
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        let relative = resolved.strip_prefix(root).map_err(io::Error::other)?;
        if !is_allowed_init_path(&Path::new("/").join(relative)) {
            return Err(io::Error::other(
                "resolved outside Guest system init directories",
            ));
        }
        if !self.loaded.insert(resolved.clone()) {
            return Ok(());
        }
        if self.loaded.len() > 1024 {
            return Err(io::Error::other("too many Guest initrc inputs"));
        }
        let metadata = fs::metadata(&resolved)?;
        if metadata.is_dir() {
            let mut files = fs::read_dir(resolved)?.collect::<io::Result<Vec<_>>>()?;
            files.sort_by_key(|file| file.file_name());
            for file in files {
                if file
                    .path()
                    .extension()
                    .is_some_and(|extension| extension == "rc")
                {
                    let name = file.file_name();
                    let name = name
                        .to_str()
                        .ok_or_else(|| io::Error::other("non-UTF-8 rc filename"))?;
                    self.load_path(root, &format!("{path}/{name}"), properties)?;
                }
            }
            return Ok(());
        }
        const MAX_RC_SIZE: u64 = 1024 * 1024;
        if !metadata.is_file() {
            return Err(io::Error::other(
                "Guest initrc input must be a regular file",
            ));
        }
        let mut source = String::new();
        File::open(resolved)?
            .take(MAX_RC_SIZE + 1)
            .read_to_string(&mut source)?;
        if source.len() as u64 > MAX_RC_SIZE {
            return Err(io::Error::other("Guest initrc input exceeds 1 MiB"));
        }
        for import in self.parse(path, &source)? {
            let Some(path) = import
                .words
                .get(1)
                .filter(|_| import.words.len() == 2)
                .and_then(|path| expand(path, properties))
            else {
                import.skip("invalid import or missing Guest property");
                continue;
            };
            if !is_allowed_init_path(Path::new(&path)) {
                import.skip("outside Guest system init directories");
                continue;
            }
            match self.load_path(root, &path, properties) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    import.skip("import missing")
                }
                result => result.map_err(|error| {
                    io::Error::other(format!("{} import {path}: {error}", import.source))
                })?,
            }
        }
        Ok(())
    }

    pub(super) fn parse(&mut self, path: &str, source: &str) -> io::Result<Vec<Line>> {
        let mut service: Option<Service> = None;
        let mut action = None;
        let mut imports = Vec::new();
        for line in tokenize(path, source)? {
            let words = &line.words;
            let Some(keyword) = words.first().map(String::as_str) else {
                continue;
            };
            if matches!(keyword, "on" | "service" | "import") {
                if let Some(service) = service.take() {
                    self.register(service);
                }
                action = None;
            }
            match keyword {
                "on" if words.len() >= 2 => {
                    action = Some(self.actions.len());
                    self.actions.push(Action {
                        trigger: line,
                        commands: Vec::new(),
                    });
                }
                "import" => imports.push(line),
                "service" if words.len() >= 3 => {
                    service = Some(Service {
                        declaration: line,
                        classes: vec!["default".into()],
                        disabled: false,
                        overrides: false,
                        oneshot: false,
                        restart_period: None,
                    });
                }
                "on" | "service" => line.skip("invalid declaration"),
                _ => {
                    if let Some(service) = &mut service {
                        match keyword {
                            "class" if words.len() > 1 => service.classes = words[1..].to_vec(),
                            "disabled" if words.len() == 1 => service.disabled = true,
                            "override" if words.len() == 1 => service.overrides = true,
                            "oneshot" if words.len() == 1 => service.oneshot = true,
                            "restart_period" if words.len() == 2 => match words[1].parse() {
                                Ok(seconds) => service.restart_period = Some(seconds),
                                Err(_) => line.skip("invalid restart_period"),
                            },
                            _ if matches!(
                                service.declaration.words[1].as_str(),
                                "servicemanager" | "zygote"
                            ) =>
                            {
                                line.skip("service credentials, sockets and runtime options use the Guest launcher contract");
                            }
                            _ => {}
                        }
                    } else if let Some(index) = action {
                        self.actions[index].commands.push(line);
                    }
                }
            }
        }
        if let Some(service) = service {
            self.register(service);
        }
        Ok(imports)
    }
}

pub(crate) fn expand(value: &str, properties: &Properties) -> Option<String> {
    let mut remaining = value;
    let mut result = String::new();
    while let Some((prefix, substitution)) = remaining.split_once("${") {
        let (expression, suffix) = substitution.split_once('}')?;
        let (key, default) = expression.split_once(":-").unwrap_or((expression, ""));
        result.push_str(prefix);
        result.push_str(
            match properties.get(key).filter(|value| !value.is_empty()) {
                Some(value) => value,
                None if !default.is_empty() => default,
                None => return None,
            },
        );
        remaining = suffix;
    }
    result.push_str(remaining);
    Some(result)
}

fn tokenize(path: &str, source: &str) -> io::Result<Vec<Line>> {
    let mut lines = Vec::new();
    let mut words = Vec::new();
    let source = source.replace("\r\n", "\n");
    let mut chars = source.chars().peekable();
    let mut word = None;
    let mut quoted = false;
    let mut physical_line = 1;
    let mut logical_line = 1;
    let malformed = |line| io::Error::other(format!("{path}:{line} malformed initrc token"));
    while let Some(ch) = chars.next() {
        match ch {
            '"' => {
                quoted = !quoted;
                word.get_or_insert_with(String::new);
            }
            '\\' if chars.next_if_eq(&'\n').is_some() => {
                physical_line += 1;
                while chars.next_if(|ch| matches!(ch, ' ' | '\t')).is_some() {}
            }
            '\\' => word.get_or_insert_with(String::new).push(
                match chars.next().ok_or_else(|| malformed(logical_line))? {
                    'n' => '\n',
                    'r' => '\r',
                    't' => '\t',
                    ch => ch,
                },
            ),
            '#' if !quoted && word.is_none() && words.is_empty() => {
                while chars.next_if(|ch| *ch != '\n').is_some() {}
            }
            '\n' => {
                physical_line += 1;
                if quoted {
                    word.get_or_insert_with(String::new).push(ch);
                } else {
                    words.extend(word.take());
                    if !words.is_empty() {
                        lines.push(Line {
                            source: format!("{path}:{logical_line}"),
                            words: std::mem::take(&mut words),
                        });
                    }
                    logical_line = physical_line;
                }
            }
            ch if ch.is_ascii_whitespace() && !quoted => {
                words.extend(word.take());
            }
            ch => word.get_or_insert_with(String::new).push(ch),
        }
    }
    words.extend(word);
    if quoted {
        return Err(malformed(logical_line));
    }
    if !words.is_empty() {
        lines.push(Line {
            source: format!("{path}:{logical_line}"),
            words,
        });
    }
    Ok(lines)
}

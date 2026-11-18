//! Executes the service-start subset of Android init through the Guest launcher.
use crate::platform::mount::guest_path;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::Path;

const PRIMARY: &str = "/system/etc/init/hw/init.rc";
const DIRECTORIES: &[&str] = &[
    "/system/etc/init",
    "/system_ext/etc/init",
    "/product/etc/init",
];
const RESOLVED_DIRECTORIES: &[&str] = &["/system/system_ext/etc/init", "/system/product/etc/init"];

pub type Properties = BTreeMap<String, String>;

#[derive(Clone)]
pub(crate) struct Line {
    pub(crate) source: String,
    pub(crate) words: Vec<String>,
}

impl Line {
    pub(crate) fn skip(&self, reason: &str) {
        println!(
            "Guest initrc skip {} {}: {reason}",
            self.source,
            self.words.join(" ")
        );
    }
}

struct Service {
    declaration: Line,
    classes: Vec<String>,
    disabled: bool,
    overrides: bool,
    oneshot: bool,
    restart_period: Option<u32>,
}

struct Action {
    trigger: Line,
    commands: Vec<Line>,
}

impl Action {
    fn matches(&self, event: Option<&str>, changed: Option<&str>, properties: &Properties) -> bool {
        let mut trigger_event = None;
        let mut relevant = changed.is_none();
        for (index, word) in self.trigger.words[1..].iter().enumerate() {
            if index % 2 == 1 {
                if word != "&&" {
                    return false;
                }
            } else if let Some(condition) = word.strip_prefix("property:") {
                let Some((key, expected)) = condition.split_once('=') else {
                    return false;
                };
                relevant |= changed == Some(key);
                let actual = properties.get(key).map(String::as_str).unwrap_or_default();
                if if expected == "*" {
                    actual.is_empty()
                } else {
                    actual != expected
                } {
                    return false;
                }
            } else if trigger_event.replace(word.as_str()).is_some() {
                return false;
            }
        }
        relevant && self.trigger.words.len() % 2 == 0 && trigger_event == event
    }
}

#[derive(Default)]
pub struct Plan {
    services: BTreeMap<String, Service>,
    service_order: Vec<String>,
    actions: Vec<Action>,
    loaded: BTreeSet<std::path::PathBuf>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum BootService {
    Servicemanager,
    Apexd,
    Zygote,
}

impl BootService {
    fn named(name: &str) -> Option<Self> {
        match name {
            "servicemanager" => Some(Self::Servicemanager),
            "apexd" => Some(Self::Apexd),
            "zygote" => Some(Self::Zygote),
            _ => None,
        }
    }

    pub fn executable(self) -> &'static str {
        match self {
            Self::Servicemanager => "/system/bin/servicemanager",
            Self::Apexd => "/system/bin/apexd",
            Self::Zygote => "/system/bin/app_process64",
        }
    }
}

enum BootItem<'a> {
    Event(Option<String>),
    Command(&'a Line),
    Start(&'a str, &'a Line),
}

pub struct BootQueue<'a> {
    plan: &'a Plan,
    pending: VecDeque<BootItem<'a>>,
    events: BTreeSet<Option<String>>,
    started: BTreeSet<BootService>,
    apex_enabled: bool,
}

impl Plan {
    pub fn load(root: &Path, properties: &Properties) -> io::Result<Self> {
        let mut plan = Self::default();
        plan.load_path(root, PRIMARY, properties)?;
        for directory in DIRECTORIES {
            plan.load_path(root, directory, properties)?;
        }
        Ok(plan)
    }

    fn load_path(&mut self, root: &Path, path: &str, properties: &Properties) -> io::Result<()> {
        let allowed = |path: &Path| {
            DIRECTORIES
                .iter()
                .chain(RESOLVED_DIRECTORIES)
                .any(|prefix| path.starts_with(prefix))
        };
        if !allowed(Path::new(path)) {
            return Err(io::Error::other("outside Guest system init directories"));
        }
        let resolved = match guest_path(root, path.trim_start_matches('/')) {
            Ok(resolved) => resolved,
            Err(error)
                if error.kind() == io::ErrorKind::NotFound && DIRECTORIES.contains(&path) =>
            {
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        let relative = resolved.strip_prefix(root).map_err(io::Error::other)?;
        if !allowed(&Path::new("/").join(relative)) {
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
            if !allowed(Path::new(&path)) {
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

    fn parse(&mut self, path: &str, source: &str) -> io::Result<Vec<Line>> {
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

    fn register(&mut self, service: Service) {
        let name = &service.declaration.words[1];
        if self.services.contains_key(name) {
            if !service.overrides {
                service.declaration.skip("duplicate service");
                return;
            }
            self.service_order.retain(|previous| previous != name);
        }
        self.service_order.push(name.clone());
        self.services.insert(name.clone(), service);
    }

    pub fn boot(&self, apex_enabled: bool) -> BootQueue<'_> {
        BootQueue {
            plan: self,
            pending: [Some("early-init"), Some("init"), Some("late-init"), None]
                .into_iter()
                .map(|event| BootItem::Event(event.map(str::to_owned)))
                .collect(),
            events: BTreeSet::new(),
            started: BTreeSet::new(),
            apex_enabled,
        }
    }

    fn class_members<'a>(&'a self, class: &'a str) -> impl Iterator<Item = &'a String> {
        self.service_order.iter().filter(move |name| {
            let service = &self.services[*name];
            !service.disabled && service.classes.iter().any(|candidate| candidate == class)
        })
    }

    pub(crate) fn restart_options(
        &self,
        name: &str,
        executable: &str,
        args: &[String],
    ) -> Option<(bool, Option<u32>)> {
        let service = self.services.get(name)?;
        let words = &service.declaration.words;
        (words[2] == executable && words[3..] == *args)
            .then_some((service.oneshot, service.restart_period))
    }
}

impl BootQueue<'_> {
    pub fn next_start(&mut self, properties: &Properties) -> io::Result<Option<BootService>> {
        while let Some(item) = self.pending.pop_front() {
            match item {
                BootItem::Event(event) => {
                    // shortcut: cold boot visits each event once, repeated events use live triggers
                    if self.events.insert(event.clone()) {
                        for action in self.plan.actions.iter().rev() {
                            if action.matches(event.as_deref(), None, properties) {
                                for line in action.commands.iter().rev() {
                                    self.pending.push_front(BootItem::Command(line));
                                }
                            }
                        }
                    }
                }
                BootItem::Command(line) => match line.words.as_slice() {
                    [command, event] if command == "trigger" => {
                        self.pending.push_back(BootItem::Event(Some(event.clone())));
                    }
                    [command, name] if command == "start" || (command == "restart" && name == "apexd") => {
                        self.pending.push_front(BootItem::Start(name, line));
                    }
                    [command, class] if command == "class_start" => {
                        let members: Vec<_> = self.plan.class_members(class).collect();
                        for name in members.into_iter().rev() {
                            self.pending.push_front(BootItem::Start(name, line));
                        }
                    }
                    [command, name, value]
                        if command == "wait_for_prop" && name == "apexd.status" && value == "activated" =>
                    {
                        if self.apex_enabled && properties.get(name) != Some(value) {
                            return Err(io::Error::other(format!(
                                "{}: Guest APEX activation has not completed",
                                line.source
                            )));
                        }
                    }
                    _ => line.skip("unsupported Guest init command"),
                },
                BootItem::Start(name, line) => {
                    let Some(service) = BootService::named(name) else {
                        line.skip("service has no Guest boot handler");
                        continue;
                    };
                    if (service == BootService::Apexd && !self.apex_enabled)
                        || self.started.contains(&service)
                    {
                        continue;
                    }
                    let declaration = &self.plan.services.get(name).ok_or_else(|| {
                        io::Error::other(format!("{}: missing Guest initrc service {name}", line.source))
                    })?.declaration;
                    let args: &[&str] = match service {
                        BootService::Zygote => &[
                            "-Xzygote", "/system/bin", "--zygote", "--start-system-server", "--socket-name=zygote",
                        ],
                        _ => &[],
                    };
                    if declaration.words[2] != service.executable() || declaration.words[3..] != *args {
                        return Err(io::Error::other(format!(
                            "{}: {name} executable or arguments differ from the Guest launcher contract",
                            declaration.source
                        )));
                    }
                    println!(
                        "Guest initrc start {name} trigger={} declaration={}",
                        line.source, declaration.source
                    );
                    self.started.insert(service);
                    return Ok(Some(service));
                }
            }
        }
        Ok(None)
    }
}

pub(crate) struct PropertyTriggers {
    plan: Plan,
    pub(crate) properties: Properties,
    pending: VecDeque<usize>,
    enabled: bool,
}

impl PropertyTriggers {
    pub(crate) fn new(plan: Plan, properties: Properties) -> Self {
        let mut triggers = Self {
            plan,
            properties,
            pending: VecDeque::new(),
            enabled: false,
        };
        triggers.enable_if_ready();
        triggers
    }

    fn enable_if_ready(&mut self) {
        if self
            .properties
            .get("servicemanager.ready")
            .is_some_and(|value| value == "true")
        {
            self.enabled = true;
            self.enqueue(None, None);
        }
    }

    pub(crate) fn changed(&mut self, name: &str, value: &str) {
        if self
            .properties
            .get(name)
            .is_some_and(|previous| previous == value)
        {
            return;
        }
        self.properties.insert(name.into(), value.into());
        if self.enabled {
            self.enqueue(None, Some(name));
        } else if name == "servicemanager.ready" {
            self.enable_if_ready();
        }
    }

    pub(crate) fn trigger(&mut self, event: &str) {
        self.enqueue(Some(event), None);
    }

    fn enqueue(&mut self, event: Option<&str>, changed: Option<&str>) {
        for (index, action) in self.plan.actions.iter().enumerate() {
            if action.matches(event, changed, &self.properties) && !self.pending.contains(&index) {
                self.pending.push_back(index);
            }
        }
    }

    pub(crate) fn next_action(&mut self) -> Option<(String, Vec<Line>)> {
        let action = &self.plan.actions[self.pending.pop_front()?];
        Some((action.trigger.source.clone(), action.commands.clone()))
    }

    pub(crate) fn clear(&mut self) {
        self.pending.clear();
    }

    pub(crate) fn class_members(&self, class: &str) -> Vec<String> {
        self.plan.class_members(class).cloned().collect()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boot_follows_guest_events_and_only_starts_reviewed_services() -> io::Result<()> {
        let mut plan = Plan::default();
        let imports = plan.parse(
            PRIMARY,
            r#"
import /system/etc/init/hw/init.${ro.zygote}.rc
service vendor-hal /vendor/bin/hw/hal
    class core
service servicemanager /system/bin/servicemanager
    class core
    disabled
on early-init
    class_start core
on init
    start servicemanager
on late-init
    trigger zygote-start
on zygote-start && \
    property:servicemanager.ready=true
    write /sys/power/state "multi
line"
    exec -- /system/bin/reboot
    start zygote
on property:servicemanager.ready=true
    class_start early_hal
"#,
        )?;
        let props = Properties::from([("ro.zygote".into(), "zygote64".into())]);
        let import = expand(&imports[0].words[1], &props).unwrap();
        assert_eq!(import, "/system/etc/init/hw/init.zygote64.rc");
        plan.parse(
            &import,
            "service zygote /system/bin/app_process64 \"-Xzygote\" /system/bin --zygote --start-system-server --socket-name=zygote\n",
        )?;
        let mut boot = plan.boot(false);
        assert_eq!(boot.next_start(&props)?, Some(BootService::Servicemanager));
        assert_eq!(boot.next_start(&props)?, None);
        let mut ready = props;
        ready.insert("servicemanager.ready".into(), "true".into());
        let mut boot = plan.boot(false);
        assert_eq!(boot.next_start(&Properties::new())?, Some(BootService::Servicemanager));
        assert_eq!(boot.next_start(&ready)?, Some(BootService::Zygote));
        assert_eq!(boot.next_start(&ready)?, None);
        Ok(())
    }

    #[test]
    fn apexd_mapping_requires_a_reachable_start_and_stock_declaration() -> io::Result<()> {
        for command in ["start", "restart"] {
            let mut plan = Plan::default();
            plan.parse(
                PRIMARY,
                &format!(
                    "service apexd /system/bin/apexd\n    disabled\n\
                     on late-init\n    trigger post-fs-data\n\
                     on post-fs-data && property:servicemanager.ready=true\n    {command} apexd\n"
                ),
            )?;
            assert_eq!(plan.boot(true).next_start(&Properties::new())?, None);
            let ready = Properties::from([("servicemanager.ready".into(), "true".into())]);
            assert_eq!(plan.boot(true).next_start(&ready)?, Some(BootService::Apexd));
            plan.parse(
                "/system/etc/init/apexd.rc",
                "service apexd /system/bin/apexd --bootstrap\n    override\n",
            )?;
            assert!(plan.boot(true).next_start(&ready).is_err());
        }
        Ok(())
    }

    #[test]
    #[ignore = "requires the read-only extracted LineageOS GSI init files"]
    fn boot_plan_for_extracted_gsi() -> io::Result<()> {
        let root = std::env::var_os("SSAL_INITRC_FIXTURE").expect("set SSAL_INITRC_FIXTURE");
        let mut props = Properties::from([("ro.zygote".into(), "zygote64".into())]);
        let plan = Plan::load(Path::new(&root), &props)?;
        let mut boot = plan.boot(true);
        assert_eq!(boot.next_start(&props)?, Some(BootService::Servicemanager));
        props.insert("servicemanager.ready".into(), "true".into());
        assert_eq!(boot.next_start(&props)?, Some(BootService::Apexd));
        let mut blocked = plan.boot(true);
        assert_eq!(blocked.next_start(&props)?, Some(BootService::Servicemanager));
        assert_eq!(blocked.next_start(&props)?, Some(BootService::Apexd));
        assert!(blocked.next_start(&props).is_err());
        props.insert("apexd.status".into(), "activated".into());
        assert_eq!(boot.next_start(&props)?, Some(BootService::Zygote));
        Ok(())
    }
}

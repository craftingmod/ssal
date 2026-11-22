//! Executes the service-start and directory-creation subset of Android init through the Guest launcher.
pub mod aid;
pub mod file_contexts;
pub mod fs;
mod parser;

pub(crate) use parser::expand;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::io;

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

pub(super) struct Service {
    pub(super) declaration: Line,
    pub(super) classes: Vec<String>,
    pub(super) disabled: bool,
    pub(super) overrides: bool,
    pub(super) oneshot: bool,
    pub(super) restart_period: Option<u32>,
}

pub(super) struct Action {
    pub(super) trigger: Line,
    pub(super) commands: Vec<Line>,
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
    pub(super) services: BTreeMap<String, Service>,
    pub(super) service_order: Vec<String>,
    pub(super) actions: Vec<Action>,
    pub(super) loaded: BTreeSet<std::path::PathBuf>,
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
    pub(super) fn register(&mut self, service: Service) {
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

    pub fn mkdir_specs(&self, triggers: &[&str], properties: &Properties) -> Vec<fs::MkdirSpec> {
        let mut specs = Vec::new();
        for event in triggers {
            for action in &self.actions {
                if action.matches(Some(event), None, properties) {
                    for line in &action.commands {
                        if let Some(spec) = fs::parse_mkdir(line, properties) {
                            specs.push(spec);
                        }
                    }
                }
            }
        }
        specs
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

#[cfg(test)]
mod tests {
    use super::file_contexts::FileContexts;
    use super::parser::PRIMARY;
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::path::Path;

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
        assert_eq!(
            boot.next_start(&Properties::new())?,
            Some(BootService::Servicemanager)
        );
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
        assert_eq!(
            blocked.next_start(&props)?,
            Some(BootService::Servicemanager)
        );
        assert_eq!(blocked.next_start(&props)?, Some(BootService::Apexd));
        assert!(blocked.next_start(&props).is_err());
        props.insert("apexd.status".into(), "activated".into());
        assert_eq!(boot.next_start(&props)?, Some(BootService::Zygote));
        Ok(())
    }

    #[test]
    fn aid_lookup_resolves_names_and_numeric_ids() {
        assert_eq!(aid::lookup("root"), Some(0));
        assert_eq!(aid::lookup("system"), Some(1000));
        assert_eq!(aid::lookup("shared_relro"), Some(1037));
        assert_eq!(aid::lookup("statsd"), Some(1066));
        assert_eq!(aid::lookup("shell"), Some(2000));
        assert_eq!(aid::lookup("1037"), Some(1037));
        assert_eq!(aid::lookup("0"), Some(0));
        assert_eq!(aid::lookup("nonexistent_aid"), None);
        assert_eq!(aid::lookup(""), None);
    }

    #[test]
    fn file_contexts_lookup_respects_kind_and_last_match_wins() {
        let plat = r#"
# comment
/data/misc(/.*)?               u:object_r:ssal_p0001_system_data_file:s0
/data/misc/installd(/.*)?      u:object_r:ssal_p0001_install_data_file:s0
/data/misc/installd/file   --  u:object_r:ssal_p0001_other_file:s0
/data/misc/shared_relro    -d  u:object_r:ssal_p0001_shared_relro_file:s0
/data/misc/shared_relro    --  u:object_r:ssal_p0001_wrong_file:s0
/data/misc/none            <<none>>
"#;
        let product = "/data/misc/installd(/.*)? u:object_r:ssal_p0001_product_override:s0\n";
        let fc = FileContexts::parse(&[plat, product]);
        assert_eq!(
            fc.lookup_dir("/data/misc/shared_relro"),
            Some("u:object_r:ssal_p0001_shared_relro_file:s0")
        );
        assert_eq!(
            fc.lookup_dir("/data/misc/installd"),
            Some("u:object_r:ssal_p0001_product_override:s0")
        );
        assert_eq!(
            fc.lookup_dir("/data/misc/other"),
            Some("u:object_r:ssal_p0001_system_data_file:s0")
        );
        assert_eq!(fc.lookup_dir("/data/misc/none"), None);
    }

    #[test]
    fn parse_mkdir_handles_defaults_options_and_expansion() {
        let props = Properties::from([("ro.user".into(), "0".into())]);
        let line = |words: &[&str]| Line {
            source: "init.rc:1".into(),
            words: words.iter().map(|s| (*s).to_owned()).collect(),
        };
        assert_eq!(
            fs::parse_mkdir(&line(&["mkdir", "/data/misc/user"]), &props),
            Some(fs::MkdirSpec {
                path: "/data/misc/user".into(),
                mode: 0o755,
                uid: 0,
                gid: 0,
                source: "init.rc:1".into(),
            })
        );
        assert_eq!(
            fs::parse_mkdir(
                &line(&[
                    "mkdir",
                    "/data/misc/profiles/cur/${ro.user}/",
                    "2750",
                    "system",
                    "shell",
                    "encryption=Require"
                ]),
                &props
            ),
            Some(fs::MkdirSpec {
                path: "/data/misc/profiles/cur/0".into(),
                mode: 0o2750,
                uid: 1000,
                gid: 2000,
                source: "init.rc:1".into(),
            })
        );
        assert_eq!(
            fs::parse_mkdir(
                &line(&["mkdir", "/data/misc/foo", "encryption=Require"]),
                &props
            ),
            Some(fs::MkdirSpec {
                path: "/data/misc/foo".into(),
                mode: 0o755,
                uid: 0,
                gid: 0,
                source: "init.rc:1".into(),
            })
        );
        assert_eq!(
            fs::parse_mkdir(&line(&["mkdir", "/data/misc/bad", "not_octal"]), &props),
            None
        );
        assert_eq!(
            fs::parse_mkdir(
                &line(&["mkdir", "/data/misc/bad", "0755", "unknown_user"]),
                &props
            ),
            None
        );
    }

    #[test]
    fn apply_mkdirs_filters_allowlist_preserves_modes_and_rejects_symlinks() -> io::Result<()> {
        let temp = std::env::temp_dir().join(format!("ssal-initrc-fs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp);
        std::fs::create_dir_all(temp.join("data/misc"))?;
        symlink("target", temp.join("data/misc/linkdir"))?;

        let mut plan = Plan::default();
        plan.parse(
            PRIMARY,
            r#"
on post-fs-data
    mkdir /data/misc/user 0755
    mkdir /data/misc/profiles 0711
    mkdir /data/misc/profiles/cur 0711
    mkdir /data/misc/linkdir/child 0755
    mkdir /dev/forbidden 0755
    mkdir /data/other/ignored 0755
"#,
        )?;
        let props = Properties::new();
        assert!(fs::apply_mkdirs(
            &temp,
            &plan,
            &["post-fs-data"],
            &props,
            &["/dev/"],
            false
        )
        .is_err());

        let count = fs::apply_mkdirs(
            &temp,
            &plan,
            &["post-fs-data"],
            &props,
            &["/data/misc/"],
            false,
        )?;
        assert_eq!(count, 3);
        assert_eq!(
            std::fs::metadata(temp.join("data/misc/user"))?
                .permissions()
                .mode()
                & 0o7777,
            0o755
        );
        assert_eq!(
            std::fs::metadata(temp.join("data/misc/profiles/cur"))?
                .permissions()
                .mode()
                & 0o7777,
            0o711
        );
        assert!(!temp.join("dev/forbidden").exists());
        assert!(!temp.join("data/other/ignored").exists());
        assert!(!temp.join("data/misc/linkdir/child").exists());

        std::fs::remove_dir_all(&temp)?;
        Ok(())
    }

    #[test]
    fn load_scans_apex_etc_rc_and_skips_versioned_dirs() -> io::Result<()> {
        let temp = std::env::temp_dir().join(format!("ssal-initrc-apex-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp);
        std::fs::create_dir_all(temp.join("system/etc/init/hw"))?;
        std::fs::write(temp.join("system/etc/init/hw/init.rc"), "")?;
        std::fs::create_dir_all(temp.join("apex/com.android.os.statsd/etc"))?;
        std::fs::write(
            temp.join("apex/com.android.os.statsd/etc/init.rc"),
            "on post-fs-data\n    mkdir /data/misc/stats-data 0770\n",
        )?;
        std::fs::create_dir_all(temp.join("apex/com.android.os.statsd@340000000/etc"))?;
        std::fs::write(
            temp.join("apex/com.android.os.statsd@340000000/etc/init.rc"),
            "on post-fs-data\n    mkdir /data/misc/should-skip 0700\n",
        )?;

        let props = Properties::new();
        let plan = Plan::load(&temp, &props)?;
        let specs = plan.mkdir_specs(&["post-fs-data"], &props);
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].path, "/data/misc/stats-data");

        std::fs::remove_dir_all(&temp)?;
        Ok(())
    }

    #[test]
    fn apply_mkdirs_preserves_existing_directory_mode() -> io::Result<()> {
        let temp = std::env::temp_dir().join(format!("ssal-initrc-eexist-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp);
        let existing = temp.join("data/local/tmp");
        std::fs::create_dir_all(&existing)?;
        std::fs::set_permissions(&existing, std::fs::Permissions::from_mode(0o1771))?;

        let mut plan = Plan::default();
        plan.parse(
            PRIMARY,
            r#"
on post-fs-data
    mkdir /data/local/tmp 0771 shell shell
    mkdir /data/local/newdir 0700
"#,
        )?;
        let props = Properties::new();
        let count = fs::apply_mkdirs(&temp, &plan, &["post-fs-data"], &props, &["/data/"], false)?;
        assert_eq!(count, 2);
        assert_eq!(
            std::fs::metadata(&existing)?.permissions().mode() & 0o7777,
            0o1771
        );
        assert_eq!(
            std::fs::metadata(temp.join("data/local/newdir"))?
                .permissions()
                .mode()
                & 0o7777,
            0o700
        );

        std::fs::remove_dir_all(&temp)?;
        Ok(())
    }
}

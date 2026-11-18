use super::{services::Registry, Properties};
use crate::guest_initrc::expand;
use std::io;

impl Properties {
    pub(super) fn run_initrc(
        &mut self,
        services: &mut Registry,
        authorize: impl Fn(&str) -> io::Result<()>,
    ) -> io::Result<()> {
        // Bound cycles caused by rc commands that write properties or trigger events.
        let mut remaining = 4096;
        while let Some((source, commands)) =
            self.initrc.as_mut().and_then(|initrc| initrc.next_action())
        {
            println!("Guest initrc live action {source}");
            for line in commands {
                if remaining == 0 {
                    self.initrc.as_mut().unwrap().clear();
                    line.skip("live trigger command limit exceeded");
                    return Ok(());
                }
                remaining -= 1;
                let initrc = self.initrc.as_mut().unwrap();
                match line.words.as_slice() {
                    [command, name] if command == "start" => {
                        if !services.dispatch("start", name, None, self)? {
                            line.skip("Guest service unavailable for live start");
                        }
                    }
                    [command, class] if command == "class_start" => {
                        for name in initrc.class_members(class) {
                            services.dispatch("start", &name, None, self)?;
                        }
                    }
                    [command, event] if command == "trigger" => initrc.trigger(event),
                    [command, name, raw_value] if command == "setprop" && volatile(name) => {
                        let Some(value) = expand(raw_value, &initrc.properties) else {
                            line.skip("missing Guest property in setprop argument");
                            continue;
                        };
                        let (context, _) = self.policy.resolve(name);
                        if self.policy.validate(name, &value).is_err()
                            || authorize(context).is_err()
                        {
                            line.skip("Guest setprop validation or authorization failed");
                            continue;
                        }
                        self.set(name, &value)?;
                    }
                    _ => line.skip("unsupported live Guest init command"),
                }
            }
        }
        Ok(())
    }
}

fn volatile(name: &str) -> bool {
    !matches!(
        name,
        "sys.powerctl" | "selinux.restorecon_recursive" | "servicemanager.ready"
    ) && !["ctl.", "ro.", "persist.", "next_boot.", "init.svc."]
        .iter()
        .any(|prefix| name.starts_with(prefix))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guest_initrc::{Plan, PropertyTriggers};
    use std::fs;

    #[test]
    fn committed_guest_updates_drive_property_actions() -> io::Result<()> {
        let root = super::super::tests::temp_dir("initrc-live");
        let rc = root.join("system/etc/init/hw");
        fs::create_dir_all(&rc)?;
        fs::write(
            rc.join("init.rc"),
            r#"
on property:sys.first=1 && property:sys.second=*
    setprop sys.result ${sys.second}
    setprop sys.powerctl reboot
    trigger downstream
on downstream && property:sys.result=on
    setprop sys.downstream yes
on boot && property:sys.second=after
    setprop sys.boot_event replayed
on property:sys.second=after
    setprop sys.unapproved yes
"#,
        )?;
        let mut properties = super::super::tests::fixture(&root);
        let mut services = Registry::new(Vec::new(), &Default::default())?;
        properties.initrc = Some(PropertyTriggers::new(
            Plan::load(&root, &Default::default())?,
            Default::default(),
        ));
        properties.set("sys.first", "1")?;
        properties.set("sys.second", "on")?;
        properties.run_initrc(&mut services, |_| Ok(()))?;
        assert!(properties.area.find("sys.result").unwrap().is_none());
        properties.set("servicemanager.ready", "true")?;
        properties.run_initrc(&mut services, |_| Ok(()))?;
        assert_eq!(properties.area.get("sys.result").unwrap(), "on");
        assert_eq!(properties.area.get("sys.downstream").unwrap(), "yes");
        assert!(properties.area.find("sys.powerctl").unwrap().is_none());
        properties.set("sys.result", "sentinel")?;
        properties.set("sys.second", "on")?;
        properties.set("sys.unrelated", "1")?;
        properties.run_initrc(&mut services, |_| Ok(()))?;
        assert_eq!(properties.area.get("sys.result").unwrap(), "sentinel");
        properties.set("sys.second", "after")?;
        properties.run_initrc(&mut services, |_| {
            Err(io::Error::from(io::ErrorKind::PermissionDenied))
        })?;
        assert_eq!(properties.area.get("sys.result").unwrap(), "sentinel");
        assert!(properties.area.find("sys.unapproved").unwrap().is_none());
        properties.set("sys.second", "off")?;
        properties.run_initrc(&mut services, |_| Ok(()))?;
        assert_eq!(properties.area.get("sys.result").unwrap(), "off");
        assert!(properties.area.find("sys.boot_event").unwrap().is_none());
        drop(properties);
        fs::remove_dir_all(root)
    }
}

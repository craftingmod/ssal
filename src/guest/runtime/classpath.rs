use crate::guest::launcher::{run, run_as};
use std::fs;
use std::io;
use std::path::Path;

pub(in crate::guest) const DERIVE_CLASSPATH_CONTEXT: &[u8] = b"u:r:derive_classpath:s0\0";

#[derive(Debug, PartialEq, Eq)]
pub(in crate::guest) struct GuestClasspaths {
    pub(in crate::guest) boot: String,
    pub(in crate::guest) dex2oat: Option<String>,
    pub(in crate::guest) system_server: String,
    pub(in crate::guest) standalone_system_server: Option<String>,
}

fn classpath_exports(content: &str) -> io::Result<GuestClasspaths> {
    let mut boot = None;
    let mut dex2oat = None;
    let mut system_server = None;
    let mut standalone_system_server = None;
    let mut standalone_seen = false;
    for line in content.lines() {
        let mut fields = line.split_whitespace();
        if fields.next() != Some("export") {
            continue;
        }
        let Some(name) = fields.next() else {
            continue;
        };
        let value = fields.next();
        if fields.next().is_some() {
            return Err(io::Error::other("invalid Guest classpath export"));
        }
        let destination = match name {
            "BOOTCLASSPATH" => &mut boot,
            "DEX2OATBOOTCLASSPATH" => &mut dex2oat,
            "SYSTEMSERVERCLASSPATH" => &mut system_server,
            "STANDALONE_SYSTEMSERVER_JARS" => {
                if standalone_seen {
                    return Err(io::Error::other(
                        "duplicate Guest STANDALONE_SYSTEMSERVER_JARS",
                    ));
                }
                standalone_seen = true;
                standalone_system_server =
                    value.filter(|value| !value.is_empty()).map(str::to_owned);
                continue;
            }
            _ => continue,
        };
        let value = value
            .filter(|value| !value.is_empty())
            .ok_or_else(|| io::Error::other(format!("Guest {name} missing")))?;
        if destination.replace(value.to_owned()).is_some() {
            return Err(io::Error::other(format!("duplicate Guest {name}")));
        }
    }
    Ok(GuestClasspaths {
        boot: boot.ok_or_else(|| io::Error::other("Guest BOOTCLASSPATH missing"))?,
        dex2oat,
        system_server: system_server
            .ok_or_else(|| io::Error::other("Guest SYSTEMSERVERCLASSPATH missing"))?,
        standalone_system_server,
    })
}

fn checked_guest_classpath_paths(classpaths: &GuestClasspaths) -> io::Result<Vec<String>> {
    let mut paths = Vec::new();
    for classpath in std::iter::once(classpaths.boot.as_str())
        .chain(classpaths.dex2oat.iter().map(String::as_str))
        .chain(std::iter::once(classpaths.system_server.as_str()))
        .chain(
            classpaths
                .standalone_system_server
                .iter()
                .map(String::as_str),
        )
    {
        for path in classpath.split(':') {
            if !["/apex/", "/product/", "/system/", "/system_ext/"]
                .iter()
                .any(|prefix| path.starts_with(prefix))
                || path
                    .split('/')
                    .skip(1)
                    .any(|part| part.is_empty() || part == "." || part == "..")
                || path
                    .bytes()
                    .any(|byte| byte.is_ascii_whitespace() || byte == b'\\' || byte == 0)
            {
                return Err(io::Error::other(format!(
                    "Guest classpath escaped system/APEX roots: {path}"
                )));
            }
            paths.push(path.to_owned());
        }
    }
    paths.extend([
        "/system/framework/services.jar".to_owned(),
        "/system/lib64/libandroid_servers.so".to_owned(),
    ]);
    Ok(paths)
}

pub(in crate::guest) fn guest_env_value<'a>(environ: &'a [u8], name: &str) -> Option<&'a [u8]> {
    let prefix = format!("{name}=");
    environ
        .split(|byte| *byte == 0)
        .find_map(|entry| entry.strip_prefix(prefix.as_bytes()))
}

pub(in crate::guest) fn derive_guest_classpath(root: &Path) -> io::Result<GuestClasspaths> {
    let output = format!(
        "/data/local/tmp/.ssal-phase7a-classpath-{}.env",
        std::process::id()
    );
    let linker_config = run(
        root,
        "/system/bin/sh",
        &[
            "-c",
            "set -eu; test -r /linkerconfig/ld.config.txt; stat -c '%n %s %a %u %g' /linkerconfig/ld.config.txt; sha256sum /linkerconfig/ld.config.txt; ls -lZ /linkerconfig/ld.config.txt; echo ro.build.type=$(getprop ro.build.type); echo ro.debuggable=$(getprop ro.debuggable); echo debug.ld.all=$(getprop debug.ld.all)",
        ],
        0,
    )?;
    println!("Guest linkerconfig preflight:\n{linker_config}");
    let dependencies = run_as(
        root,
        "/system/bin/bootstrap/linker64",
        &["--list", "/apex/com.android.sdkext/bin/derive_classpath"],
        0,
        DERIVE_CLASSPATH_CONTEXT,
    )?;
    println!("Guest derive_classpath linker dependency list:\n{dependencies}");
    let derive = run(
        root,
        "/apex/com.android.sdkext/bin/derive_classpath",
        &[
            "--override-device-sdk-version=36",
            "--override-device-codename=REL",
            &output,
        ],
        0,
    );
    if let Err(error) = derive {
        let diagnostic = format!(
            "for path in /data/local /data/local/tmp /system/etc/classpaths /apex/*/etc/classpaths /apex/*/etc/classpaths/bootclasspath.pb /apex/*/etc/classpaths/systemserverclasspath.pb {output} {output}.tmp; do if [ -e \"$path\" ]; then ls -ldZ \"$path\"; else echo missing=$path; fi; done"
        );
        match run(root, "/system/bin/sh", &["-c", &diagnostic], 0) {
            Ok(output) => println!("Guest derive_classpath failure inputs:\n{output}"),
            Err(diagnostic_error) => {
                println!("Guest derive_classpath input diagnostic failed: {diagnostic_error}")
            }
        }
        return Err(error);
    }
    let output_path = root.join(output.trim_start_matches('/'));
    let result = classpath_exports(&fs::read_to_string(&output_path)?);
    fs::remove_file(output_path)?;
    let classpaths = result?;
    let paths = checked_guest_classpath_paths(&classpaths)?;
    let mut args = vec![
        "-c",
        "set -eu; for path do test -f \"$path\" || { echo \"missing Guest classpath file: $path\" >&2; exit 1; }; done",
        "ssal-classpath-preflight",
    ];
    args.extend(paths.iter().map(String::as_str));
    run(root, "/system/bin/sh", &args, 0)?;
    println!(
        "Guest classpath source=derive_classpath(Guest SDK 36, REL) boot_entries={} dex2oat_entries={} system_server_entries={} standalone_system_server_entries={}",
        classpaths.boot.split(':').count(),
        classpaths.dex2oat.as_deref().map_or(0, |v| v.split(':').count()),
        classpaths.system_server.split(':').count(),
        classpaths
            .standalone_system_server
            .as_deref()
            .map_or(0, |v| v.split(':').count())
    );
    Ok(classpaths)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classpath_exports_include_guest_system_server_jars() -> io::Result<()> {
        let classpaths = classpath_exports(
            "export SYSTEMSERVERCLASSPATH /system/framework/services.jar\nexport BOOTCLASSPATH /apex/com.android.art/javalib/core-oj.jar:/system/framework/framework.jar\nexport DEX2OATBOOTCLASSPATH /apex/com.android.art/javalib/core-oj.jar\nexport STANDALONE_SYSTEMSERVER_JARS /apex/com.android.os.statsd/javalib/service-statsd.jar\n",
        )?;
        assert_eq!(
            classpaths.boot,
            "/apex/com.android.art/javalib/core-oj.jar:/system/framework/framework.jar"
        );
        assert_eq!(
            classpaths.dex2oat.as_deref(),
            Some("/apex/com.android.art/javalib/core-oj.jar")
        );
        assert_eq!(classpaths.system_server, "/system/framework/services.jar");
        assert_eq!(
            classpaths.standalone_system_server.as_deref(),
            Some("/apex/com.android.os.statsd/javalib/service-statsd.jar")
        );
        assert!(
            classpath_exports("export BOOTCLASSPATH /system/framework/framework.jar\n").is_err()
        );
        assert!(
            classpath_exports("export SYSTEMSERVERCLASSPATH /system/framework/services.jar\n")
                .is_err()
        );
        assert!(classpath_exports(
            "export BOOTCLASSPATH /system/framework/framework.jar\nexport BOOTCLASSPATH /system/framework/framework.jar\nexport SYSTEMSERVERCLASSPATH /system/framework/services.jar\n"
        )
        .is_err());

        let optional_standalone = classpath_exports(
            "export BOOTCLASSPATH /system/framework/framework.jar\nexport SYSTEMSERVERCLASSPATH /system/framework/services.jar\nexport STANDALONE_SYSTEMSERVER_JARS\n",
        )?;
        assert_eq!(optional_standalone.standalone_system_server, None);
        assert!(checked_guest_classpath_paths(&optional_standalone).is_ok());
        let escaped = classpath_exports(
            "export BOOTCLASSPATH /system/../data/host.jar\nexport SYSTEMSERVERCLASSPATH /system/framework/services.jar\n",
        )?;
        assert!(checked_guest_classpath_paths(&escaped).is_err());
        assert_eq!(
            guest_env_value(
                b"BOOTCLASSPATH=/guest.jar\0SYSTEMSERVERCLASSPATH=/guest/services.jar\0",
                "SYSTEMSERVERCLASSPATH"
            ),
            Some(b"/guest/services.jar".as_slice())
        );
        Ok(())
    }
}

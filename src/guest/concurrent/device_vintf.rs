//! Guest Device VINTF overlay for hiding selected Host HAL declarations.

use ssal::namespace_mounts::Mounts;
use std::fs::{self, File};
use std::io;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::Path;

const HIDDEN_HAL_TOKENS: &[&str] = &["weaver", "usb", "camera", "nfc", "radio", "fingerprint"];
const DEVICE_VINTF_PARTITIONS: &[&str] = &["vendor", "odm"];
const UNAVAILABLE_FEATURES_XML: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<permissions>
    <!-- Camera -->
    <unavailable-feature name="android.hardware.camera" />
    <unavailable-feature name="android.hardware.camera.any" />
    <unavailable-feature name="android.hardware.camera.front" />
    <unavailable-feature name="android.hardware.camera.autofocus" />
    <unavailable-feature name="android.hardware.camera.flash" />
    <unavailable-feature name="android.hardware.camera.capability.manual_sensor" />
    <unavailable-feature name="android.hardware.camera.capability.manual_post_processing" />
    <unavailable-feature name="android.hardware.camera.capability.raw" />
    <unavailable-feature name="android.hardware.camera.level.full" />
    <unavailable-feature name="android.hardware.camera.external" />

    <!-- NFC -->
    <unavailable-feature name="android.hardware.nfc" />
    <unavailable-feature name="android.hardware.nfc.any" />
    <unavailable-feature name="android.hardware.nfc.hce" />
    <unavailable-feature name="android.hardware.nfc.hcef" />
    <unavailable-feature name="android.hardware.nfc.uicc" />
    <unavailable-feature name="android.hardware.nfc.ese" />
    <unavailable-feature name="android.hardware.nfc.beam" />

    <!-- Telephony / Radio -->
    <unavailable-feature name="android.hardware.telephony" />
    <unavailable-feature name="android.hardware.telephony.gsm" />
    <unavailable-feature name="android.hardware.telephony.cdma" />
    <unavailable-feature name="android.hardware.telephony.ims" />
    <unavailable-feature name="android.hardware.telephony.calling" />
    <unavailable-feature name="android.hardware.telephony.data" />
    <unavailable-feature name="android.hardware.telephony.subscription" />
    <unavailable-feature name="android.hardware.telephony.messaging" />
    <unavailable-feature name="android.hardware.telephony.radio.access" />
    <unavailable-feature name="android.hardware.telephony.mbms" />

    <!-- Bluetooth -->
    <unavailable-feature name="android.hardware.bluetooth" />
    <unavailable-feature name="android.hardware.bluetooth_le" />

    <!-- USB -->
    <unavailable-feature name="android.hardware.usb.host" />
    <unavailable-feature name="android.hardware.usb.accessory" />

    <!-- Biometrics -->
    <unavailable-feature name="android.hardware.fingerprint" />
    <unavailable-feature name="android.hardware.biometrics.face" />

    <!-- Wi-Fi -->
    <unavailable-feature name="android.hardware.wifi" />
    <unavailable-feature name="android.hardware.wifi.direct" />
    <unavailable-feature name="android.hardware.wifi.passpoint" />
    <unavailable-feature name="android.hardware.wifi.aware" />
    <unavailable-feature name="android.hardware.wifi.rtt" />
</permissions>
"#;

#[derive(Default, Debug, PartialEq, Eq)]
struct OverlayStats {
    removed_hals: usize,
    skipped_fragments: usize,
}

#[derive(Debug, PartialEq, Eq)]
struct FilterResult {
    xml: String,
    removed_hals: usize,
    remaining_hals: usize,
}

/// Overlay Guest `/vendor/etc/vintf` and `/odm/etc/vintf` with filtered copies
/// that strip Weaver, USB, Camera, NFC, Radio, and Bluetooth HCI HAL declarations.
pub(in crate::guest) fn install_overlay(
    mounts: &mut Mounts,
    root: &Path,
    plan: &ssal::guest_policy::Plan,
) -> io::Result<()> {
    let parent = root
        .parent()
        .ok_or_else(|| io::Error::other("Guest root has no parent for VINTF overlay staging"))?;
    let fallback_label = plan.context("vendor_configs_file", false)?;

    for partition in DEVICE_VINTF_PARTITIONS {
        let target = root.join(partition).join("etc/vintf");
        if !target.is_dir() {
            continue;
        }
        let staging = parent.join(format!("{partition}-vintf-overlay"));
        if staging.exists() {
            fs::remove_dir_all(&staging)?;
        }
        let mut stats = OverlayStats::default();
        copy_and_filter_dir(&target, &staging, false, &fallback_label, &mut stats)?;
        mounts.bind(&staging, &target, true, true)?;
        println!(
            "Guest device VINTF overlay partition={partition} dir={} removed_hals={} skipped_fragments={}",
            target.display(),
            stats.removed_hals,
            stats.skipped_fragments
        );
    }
    Ok(())
}

/// Overlay Guest `/system_ext/etc/permissions` (falling back to `/system/etc/permissions`)
/// with `ssal_unavailable_features.xml` so PackageManager hides Camera, NFC, Radio/Telephony,
/// Bluetooth, and USB features.
pub(in crate::guest) fn install_unavailable_features(
    mounts: &mut Mounts,
    root: &Path,
    plan: &ssal::guest_policy::Plan,
) -> io::Result<()> {
    let permissions_dir = crate::guest::mount::guest_path(root, "system/system_ext/etc/permissions")
        .or_else(|_| crate::guest::mount::guest_path(root, "system/etc/permissions"))?;
    let parent = root
        .parent()
        .ok_or_else(|| io::Error::other("Guest root has no parent for permissions overlay"))?;
    let staging = parent.join("permissions-overlay");
    if staging.exists() {
        fs::remove_dir_all(&staging)?;
    }
    let file_context = plan.context("system_file", false)?;
    copy_dir_preserving_layout(&permissions_dir, &staging, &file_context)?;

    let fragment = staging.join("ssal_unavailable_features.xml");
    fs::write(&fragment, UNAVAILABLE_FEATURES_XML)?;
    fs::set_permissions(&fragment, fs::Permissions::from_mode(0o644))?;
    ssal::guest_policy::runtime::set_label(&fragment, &file_context)?;

    mounts.bind(&staging, &permissions_dir, true, true)?;
    println!(
        "Guest unavailable-features overlay dir={} file=ssal_unavailable_features.xml",
        permissions_dir.display()
    );
    Ok(())
}

fn copy_dir_preserving_layout(src_dir: &Path, dst_dir: &Path, label: &str) -> io::Result<()> {
    fs::create_dir_all(dst_dir)?;
    fs::set_permissions(dst_dir, fs::Permissions::from_mode(0o755))?;
    ssal::guest_policy::runtime::set_label(dst_dir, label)?;

    for entry in fs::read_dir(src_dir)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let src_path = entry.path();
        let dst_path = dst_dir.join(entry.file_name());
        if file_type.is_symlink() {
            symlink(&fs::read_link(&src_path)?, &dst_path)?;
        } else if file_type.is_dir() {
            copy_dir_preserving_layout(&src_path, &dst_path, label)?;
        } else if file_type.is_file() {
            fs::copy(&src_path, &dst_path)?;
            fs::set_permissions(&dst_path, fs::Permissions::from_mode(0o644))?;
            ssal::guest_policy::runtime::set_label(&dst_path, label)?;
        }
    }
    Ok(())
}

fn copy_and_filter_dir(
    src_dir: &Path,
    dst_dir: &Path,
    in_manifest_subdir: bool,
    fallback_label: &str,
    stats: &mut OverlayStats,
) -> io::Result<()> {
    fs::create_dir_all(dst_dir)?;
    fs::set_permissions(dst_dir, fs::Permissions::from_mode(0o755))?;
    let dir_label = read_context_or(src_dir, fallback_label);
    ssal::guest_policy::runtime::set_label(dst_dir, &dir_label)?;

    for entry in fs::read_dir(src_dir)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let src_path = entry.path();
        let dst_path = dst_dir.join(entry.file_name());

        if file_type.is_symlink() {
            let link_target = fs::read_link(&src_path)?;
            symlink(&link_target, &dst_path)?;
            continue;
        }
        if file_type.is_dir() {
            let is_manifest =
                in_manifest_subdir || entry.file_name().to_string_lossy() == "manifest";
            copy_and_filter_dir(&src_path, &dst_path, is_manifest, fallback_label, stats)?;
            continue;
        }
        if !file_type.is_file() {
            continue;
        }

        let is_xml = src_path
            .extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| ext.eq_ignore_ascii_case("xml"));

        if is_xml {
            if let Ok(content) = fs::read_to_string(&src_path) {
                let filtered = filter_manifest_xml(&content);
                stats.removed_hals += filtered.removed_hals;
                if in_manifest_subdir && filtered.removed_hals > 0 && filtered.remaining_hals == 0
                {
                    stats.skipped_fragments += 1;
                    continue;
                }
                fs::write(&dst_path, filtered.xml)?;
            } else {
                fs::copy(&src_path, &dst_path)?;
            }
        } else {
            fs::copy(&src_path, &dst_path)?;
        }

        fs::set_permissions(&dst_path, fs::Permissions::from_mode(0o644))?;
        let file_label = read_context_or(&src_path, fallback_label);
        ssal::guest_policy::runtime::set_label(&dst_path, &file_label)?;
    }
    Ok(())
}

fn read_context_or(path: &Path, fallback: &str) -> String {
    File::open(path)
        .and_then(|file| ssal::unix::image_context(&file))
        .unwrap_or_else(|_| fallback.to_string())
}

fn is_hidden_hal_name(hal_name: &str) -> bool {
    let trimmed = hal_name.trim();
    if trimmed.eq_ignore_ascii_case("android.hardware.bluetooth")
        || trimmed.eq_ignore_ascii_case("android.hardware.bluetooth.hci")
    {
        return true;
    }

    let mut has_bluetooth = false;
    let mut has_hci = false;
    for segment in trimmed.split('.') {
        let lower = segment.to_ascii_lowercase();
        if HIDDEN_HAL_TOKENS.iter().any(|token| {
            lower == *token
                || lower.starts_with(&format!("{token}_"))
                || lower.starts_with(&format!("{token}-"))
        }) {
            return true;
        }
        if lower == "bluetooth_hci" || lower == "bluetooth-hci" {
            return true;
        }
        if lower == "bluetooth" {
            has_bluetooth = true;
        } else if lower == "hci" {
            has_hci = true;
        }
    }
    has_bluetooth && has_hci
}

fn filter_manifest_xml(xml: &str) -> FilterResult {
    let mut out = String::with_capacity(xml.len());
    let mut cursor = 0;
    let mut removed_hals = 0;
    let mut remaining_hals = 0;

    while let Some(hal_start) = find_next_hal_open(xml, cursor) {
        let Some((hal_end, inner_start, inner_end)) = find_hal_bounds(xml, hal_start) else {
            break;
        };

        let hal_name = extract_hal_name(&xml[inner_start..inner_end]);
        if hal_name.is_some_and(is_hidden_hal_name) {
            // Trim leading horizontal whitespace on the removed <hal> line and trailing newline.
            let line_prefix_start = xml[cursor..hal_start]
                .rfind('\n')
                .map_or(cursor, |nl| cursor + nl + 1);
            let before = if xml[line_prefix_start..hal_start]
                .bytes()
                .all(|b| b == b' ' || b == b'\t')
            {
                &xml[cursor..line_prefix_start]
            } else {
                &xml[cursor..hal_start]
            };
            out.push_str(before);
            cursor = skip_trailing_newline(xml, hal_end);
            removed_hals += 1;
        } else {
            out.push_str(&xml[cursor..hal_end]);
            cursor = hal_end;
            remaining_hals += 1;
        }
    }

    out.push_str(&xml[cursor..]);
    FilterResult {
        xml: out,
        removed_hals,
        remaining_hals,
    }
}

fn skip_trailing_newline(xml: &str, pos: usize) -> usize {
    let rest = &xml[pos..];
    if rest.starts_with("\r\n") {
        pos + 2
    } else if rest.starts_with('\n') {
        pos + 1
    } else {
        pos
    }
}

fn find_next_hal_open(xml: &str, mut pos: usize) -> Option<usize> {
    let bytes = xml.as_bytes();
    while pos < bytes.len() {
        if xml[pos..].starts_with("<!--") {
            pos = xml[pos + 4..]
                .find("-->")
                .map_or(bytes.len(), |end| pos + 4 + end + 3);
            continue;
        }
        if xml[pos..].starts_with("<![CDATA[") {
            pos = xml[pos + 9..]
                .find("]]>")
                .map_or(bytes.len(), |end| pos + 9 + end + 3);
            continue;
        }
        if xml[pos..].starts_with("<hal") {
            let next = bytes.get(pos + 4).copied();
            if matches!(next, Some(b' ' | b'\t' | b'\r' | b'\n' | b'>' | b'/')) {
                return Some(pos);
            }
        }
        pos += 1;
    }
    None
}

fn find_hal_bounds(xml: &str, hal_start: usize) -> Option<(usize, usize, usize)> {
    let open_end = xml[hal_start..].find('>')? + hal_start;
    if open_end > hal_start && xml.as_bytes()[open_end - 1] == b'/' {
        return Some((open_end + 1, open_end, open_end));
    }
    let inner_start = open_end + 1;
    let mut pos = inner_start;
    let bytes = xml.as_bytes();
    while pos < bytes.len() {
        if xml[pos..].starts_with("<!--") {
            pos = xml[pos + 4..]
                .find("-->")
                .map_or(bytes.len(), |end| pos + 4 + end + 3);
            continue;
        }
        if xml[pos..].starts_with("</hal>") {
            return Some((pos + 6, inner_start, pos));
        }
        pos += 1;
    }
    None
}

fn extract_hal_name(hal_inner: &str) -> Option<&str> {
    let mut pos = 0;
    let bytes = hal_inner.as_bytes();
    while pos < bytes.len() {
        if hal_inner[pos..].starts_with("<!--") {
            pos = hal_inner[pos + 4..]
                .find("-->")
                .map_or(bytes.len(), |end| pos + 4 + end + 3);
            continue;
        }
        if hal_inner[pos..].starts_with("<name") {
            let next = bytes.get(pos + 5).copied();
            if matches!(next, Some(b' ' | b'\t' | b'\r' | b'\n' | b'>')) {
                let open_end = hal_inner[pos..].find('>')? + pos;
                let close_start = hal_inner[open_end + 1..].find("</name>")? + open_end + 1;
                return Some(hal_inner[open_end + 1..close_start].trim());
            }
        }
        pos += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hides_target_hals_only() {
        assert!(is_hidden_hal_name("android.hardware.weaver"));
        assert!(is_hidden_hal_name("android.hardware.usb"));
        assert!(is_hidden_hal_name("android.hardware.usb.gadget"));
        assert!(is_hidden_hal_name("android.hardware.camera.provider"));
        assert!(is_hidden_hal_name("android.hardware.nfc"));
        assert!(is_hidden_hal_name("android.hardware.radio.modem"));
        assert!(is_hidden_hal_name("android.hardware.radio.config"));
        assert!(is_hidden_hal_name("android.hardware.bluetooth"));
        assert!(is_hidden_hal_name("android.hardware.bluetooth.hci"));
        assert!(is_hidden_hal_name("vendor.qti.hardware.weaver"));
        assert!(is_hidden_hal_name("vendor.samsung.hardware.usb"));
        assert!(is_hidden_hal_name("vendor.samsung.hardware.usb_ext"));
        assert!(is_hidden_hal_name("vendor.qti.hardware.bluetooth_hci"));

        assert!(!is_hidden_hal_name("android.hardware.bluetooth.audio"));
        assert!(!is_hidden_hal_name("android.hardware.broadcastradio"));
        assert!(!is_hidden_hal_name("android.hardware.graphics.composer"));
        assert!(!is_hidden_hal_name("android.hardware.keymint"));
        assert!(!is_hidden_hal_name("android.hardware.gatekeeper"));
        assert!(!is_hidden_hal_name("vendor.example.busbar"));
    }

    #[test]
    fn filters_target_hals_and_preserves_comments_and_other_hals() {
        let input = r#"<manifest version="1.0" type="device">
    <!-- <hal format="aidl"><name>android.hardware.audio</name></hal> -->
    <hal format="aidl">
        <name>android.hardware.weaver</name>
        <version>2</version>
        <fqname>IWeaver/default</fqname>
    </hal>
    <hal format="hidl">
        <name>android.hardware.graphics.composer</name>
        <transport>hwbinder</transport>
        <fqname>@2.4::IComposer/default</fqname>
    </hal>
    <hal format="aidl">
        <name>android.hardware.usb</name>
        <fqname>IUsb/default</fqname>
    </hal>
    <hal format="aidl">
        <name>android.hardware.usb.gadget</name>
        <fqname>IUsbGadget/default</fqname>
    </hal>
</manifest>
"#;
        let result = filter_manifest_xml(input);
        assert_eq!(result.removed_hals, 3);
        assert_eq!(result.remaining_hals, 1);
        assert!(!result.xml.contains("android.hardware.weaver"));
        assert!(!result.xml.contains("android.hardware.usb"));
        assert!(result.xml.contains("android.hardware.graphics.composer"));
        assert!(result
            .xml
            .contains("<!-- <hal format=\"aidl\"><name>android.hardware.audio</name></hal> -->"));
    }

    #[test]
    fn reports_empty_fragment_after_filtering() {
        let fragment = r#"<manifest version="1.0" type="device">
    <hal format="aidl">
        <name>android.hardware.usb.gadget</name>
        <fqname>IUsbGadget/default</fqname>
    </hal>
</manifest>
"#;
        let result = filter_manifest_xml(fragment);
        assert_eq!(result.removed_hals, 1);
        assert_eq!(result.remaining_hals, 0);
    }
}

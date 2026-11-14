#!/usr/bin/env python3
"""Compare offline batches with the unmodified KernelSU Rust serializer (no ioctl)."""
import json
import pathlib
import re
import subprocess
import sys

repo = pathlib.Path(__file__).resolve().parent.parent
encoding = pathlib.Path(sys.argv[1]).resolve()
work = repo / "out/phase8c-native/upstream-comparison"
work.mkdir(parents=True, exist_ok=True)
source = repo / "vendor/KernelSU/userspace/ksud/src/sepolicy.rs"
header = (repo / "vendor/KernelSU/uapi/selinux.h").read_text()
constants = "\n".join(
    f"pub const {name}: u32 = {value};"
    for name, value in re.findall(r"static const __u32 (\w+) = (\d+);", header)
)
(work / "Cargo.toml").write_text('''[package]
name = "ssal-upstream-encoder-check"
version = "0.0.0"
edition = "2021"
[workspace]
[dependencies]
anyhow = "1"
nom = "8"
derive-new = "0.7"
log = "0.4"
serde_json = "1"
''')
(work / "src").mkdir(exist_ok=True)
harness = r'''
#![allow(dead_code)]
mod ksu_uapi { CONSTANTS }
mod ksucalls {
    pub fn set_sepolicy(_: *const u8, _: u64) -> anyhow::Result<i32> {
        anyhow::bail!("comparison harness never injects policy")
    }
}
mod sepolicy {
    include!(SOURCE);
    pub fn encode_text(text: &str) -> anyhow::Result<Vec<u8>> {
        let statements = parse_sepolicy(text, true)?;
        serialize_atomic_statements(&flatten_atomic_statements(&statements)?)
    }
    pub fn encode_commands(commands: &[serde_json::Value]) -> anyhow::Result<Vec<u8>> {
        let mut statements = Vec::new();
        for c in commands {
            let mut args = c["args"].as_array().unwrap().iter().map(|v| {
                let value = v.as_str().unwrap();
                if value.is_empty() { PolicyObject::None } else { PolicyObject::One(value.as_bytes().to_vec()) }
            });
            statements.push(AtomicStatement {
                cmd: c["cmd"].as_u64().unwrap() as u32,
                subcmd: c["subcmd"].as_u64().unwrap() as u32,
                sepol1: args.next().unwrap_or_default(), sepol2: args.next().unwrap_or_default(),
                sepol3: args.next().unwrap_or_default(), sepol4: args.next().unwrap_or_default(),
                sepol5: args.next().unwrap_or_default(), sepol6: PolicyObject::None, sepol7: PolicyObject::None,
            });
        }
        serialize_atomic_statements(&statements)
    }
}
fn main() -> anyhow::Result<()> {
    let root = std::path::PathBuf::from(std::env::args().nth(1).unwrap());
    let plan: serde_json::Value = serde_json::from_slice(&std::fs::read(root.join("plan.json"))?)?;
    let report: serde_json::Value = serde_json::from_slice(&std::fs::read(root.join("encoding.json"))?)?;
    let (mut bytes, mut commands, mut transitions, mut xperms, mut parser_rejected, mut rejected_transitions, mut rejected_xperms) = (0,0,0,0,0,0,0);
    for batch in report["batches"].as_array().unwrap() {
        let file = batch["file"].as_str().unwrap();
        let text = std::fs::read_to_string(root.join(file.replace(".bin", ".rule")))?;
        let mut payload = Vec::new();
        for statement in text.lines() {
            let cmds = plan["native_rules"][statement].as_array().unwrap();
            let atomic_bytes = sepolicy::encode_commands(cmds)?;
            if let Ok(parsed_bytes) = sepolicy::encode_text(statement) {
                anyhow::ensure!(parsed_bytes == atomic_bytes, "upstream parser/expansion mismatch: {statement}");
            }
            payload.extend(atomic_bytes);
            commands += cmds.len();
            transitions += usize::from(statement.starts_with("type_transition "));
            xperms += usize::from(statement.starts_with("allowxperm "));
            if sepolicy::check_rule(statement).is_err() {
                parser_rejected += 1;
                rejected_transitions += usize::from(statement.starts_with("type_transition "));
                rejected_xperms += usize::from(statement.starts_with("allowxperm "));
            }
        }
        anyhow::ensure!(payload == std::fs::read(root.join(file))?, "binary mismatch: {file}");
        bytes += payload.len();
    }
    let summary = serde_json::json!({"all_bytes_equal":true,"bytes":bytes,"atomic_commands":commands,"type_transition":transitions,"allowxperm_atomic_ranges":xperms,"upstream_text_parser_rejected":parser_rejected,"parser_rejected_transitions":rejected_transitions,"parser_rejected_xperms":rejected_xperms});
    std::fs::write(root.join("upstream-comparison.json"), serde_json::to_vec_pretty(&summary)?)?;
    println!("{summary}");
    Ok(())
}
'''.replace("CONSTANTS", constants).replace("SOURCE", json.dumps(str(source)))
(work / "src/main.rs").write_text(harness)
subprocess.run(["cargo", "run", "--quiet", "--manifest-path", str(work / "Cargo.toml"), "--", str(encoding)], check=True)

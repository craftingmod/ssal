//! Offline encoding and explicit injection; special transition names select Native.
#[cfg(unix)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use ssal::guest_policy::{
        self,
        native::KernelSuNative,
        runtime::{self, Backend},
        Plan,
    };
    use std::{fs, path::Path};
    let args: Vec<_> = std::env::args().skip(1).collect();
    match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["info"] => println!("{}", serde_json::to_string_pretty(&KernelSuNative::open()?.info)?),
        ["check", input] => {
            let plan: Plan = serde_json::from_slice(&fs::read(input)?)?;
            runtime::check_native(&plan)?;
            println!("Native policy check passed; no injection attempted");
        }
        [mode @ ("encode" | "generate-encode"), input, output] => {
            let plan: Plan = if *mode == "generate-encode" {
                guest_policy::generate("p0001", &guest_policy::inputs(Path::new(input))?)?
            } else { serde_json::from_slice(&fs::read(input)?)? };
            let batches = runtime::encode_native(&plan)?;
            fs::create_dir_all(output)?;
            let output = Path::new(output);
            guest_policy::atomic(&output.join("plan.json"), &serde_json::to_vec_pretty(&plan)?)?;
            let mut manifest = Vec::new();
            for (index, batch) in batches.iter().enumerate() {
                let file = format!("batch-{index:04}.bin");
                guest_policy::atomic(&output.join(&file), &batch.payload)?;
                guest_policy::atomic(&output.join(format!("batch-{index:04}.rule")), (batch.statements.join("\n") + "\n").as_bytes())?;
                manifest.push(serde_json::json!({"file":file,"bytes":batch.payload.len(),"commands":batch.commands,"statements":batch.statements.len()}));
            }
            let report = serde_json::json!({"uapi":5,"injected":false,"types":plan.types.len(),"rules":plan.rules.len(),"unsupported":plan.unsupported,"unsupported_source":plan.unsupported_source,"batches":manifest});
            guest_policy::atomic(&output.join("encoding.json"), &serde_json::to_vec_pretty(&report)?)?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        ["apply", backend @ ("--native" | "--ksud"), profile] => {
            let profile = Path::new(profile);
            let plan = serde_json::from_slice(&fs::read(profile.join("selinux/plan.json"))?)?;
            runtime::apply_with_backend(profile, &plan, if *backend == "--native" { Backend::KernelSuNative } else { Backend::Ksud })?;
        }
        _ => return Err("usage: ssal-sepolicy info | check PLAN_JSON | encode PLAN_JSON OUTPUT_DIR | generate-encode GSI_EXPORT OUTPUT_DIR | apply (--native|--ksud) PROFILE_DIR".into()),
    }
    Ok(())
}

#[cfg(not(unix))]
fn main() {
    eprintln!("ssal-sepolicy requires Android/Linux");
    std::process::exit(1);
}

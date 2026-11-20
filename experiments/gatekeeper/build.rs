use std::{fs, path::Path};

fn add_dir(
    mut builder: rsbinder_aidl::Builder,
    dir: &Path,
    version: i32,
    hash: &str,
) -> rsbinder_aidl::Builder {
    let mut files: Vec<_> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("aidl"))
        .collect();
    files.sort();
    for file in files {
        builder = builder.source(file).version(version).hash(hash);
    }
    builder
}

fn main() {
    println!("cargo:rerun-if-changed=gatekeeper-aidl");
    let root = Path::new("gatekeeper-aidl");
    let mut builder = rsbinder_aidl::Builder::new().include_dir(root);
    builder = add_dir(
        builder,
        &root.join("android/hardware/gatekeeper"),
        1,
        "d877e8a1608a00fd9068bcd7e69ea480a7ea17f0",
    );
    builder = add_dir(
        builder,
        &root.join("android/hardware/security/keymint"),
        4,
        "a05c8079586139db45b0762a528cdd9745ad15ce",
    );
    builder = add_dir(
        builder,
        &root.join("android/hardware/security/secureclock"),
        1,
        "cd55ca9963c6a57fa5f2f120a45c6e0c4fafb423",
    );
    builder
        .output("gatekeeper")
        .generate()
        .expect("generate GateKeeper AIDL");
}

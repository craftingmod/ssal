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
    println!("cargo:rerun-if-changed=sensors-aidl");
    let root = Path::new("sensors-aidl");
    let mut builder = rsbinder_aidl::Builder::new().include_dir(root);
    builder = add_dir(
        builder,
        &root.join("android/hardware/common"),
        2,
        "c32ddfdeb69c6e4a8a45519e6f9a39c4b66fd99f",
    );
    builder = add_dir(
        builder,
        &root.join("android/hardware/common/fmq"),
        1,
        "12cf0ce8614557cc0efe73bdf011f5193f7a8653",
    );
    builder = add_dir(
        builder,
        &root.join("android/hardware/sensors"),
        3,
        "b051523be857524c99057b69f253a7d0bd295400",
    );
    builder
        .output("sensors")
        .generate()
        .expect("generate Sensors AIDL");
}

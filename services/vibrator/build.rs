use std::{fs, path::Path};

fn main() {
    println!("cargo:rerun-if-changed=vibrator-aidl");
    let root = Path::new("vibrator-aidl");
    let mut files: Vec<_> = fs::read_dir(root.join("android/hardware/vibrator"))
        .unwrap()
        .map(|file| file.unwrap().path())
        .filter(|path| path.extension().and_then(|e| e.to_str()) == Some("aidl"))
        .collect();
    files.sort();
    let mut builder = rsbinder_aidl::Builder::new().include_dir(root);
    for file in files {
        builder = builder
            .source(file)
            .version(2)
            .hash("ea8742d6993e1a82917da38b9938e537aa7fcb54");
    }
    builder
        .output("vibrator")
        .generate()
        .expect("generate Vibrator AIDL");
}

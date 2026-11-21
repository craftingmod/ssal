use std::{fs, path::Path};

fn main() {
    println!("cargo:rerun-if-changed=thermal-aidl");
    let root = Path::new("thermal-aidl");
    let mut files: Vec<_> = fs::read_dir(root.join("android/hardware/thermal"))
        .unwrap()
        .map(|file| file.unwrap().path())
        .filter(|path| path.extension().and_then(|e| e.to_str()) == Some("aidl"))
        .collect();
    files.sort();
    let mut builder = rsbinder_aidl::Builder::new().include_dir(root);
    for file in files {
        builder = builder
            .source(file)
            .version(3)
            .hash("4c4fc474c40b64963eb8d78b713b1095fecd72f0");
    }
    builder
        .output("thermal")
        .generate()
        .expect("generate Thermal AIDL");
}

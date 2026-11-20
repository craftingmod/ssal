use std::{fs, path::Path};

fn main() {
    // Frozen AOSP V4 matches the GSI's getHingeInfo transaction and parcelables.
    println!("cargo:rerun-if-changed=health-aidl");
    let root = Path::new("health-aidl");
    let mut files: Vec<_> = fs::read_dir(root.join("android/hardware/health"))
        .unwrap()
        .map(|file| file.unwrap().path())
        .collect();
    files.sort();
    let mut builder = rsbinder_aidl::Builder::new().include_dir(root);
    for file in files {
        let interface = matches!(
            file.file_stem().unwrap().to_str().unwrap(),
            "IHealth" | "IHealthInfoCallback"
        );
        builder = builder.source(file);
        if interface {
            builder = builder
                .version(4)
                .hash("c8d014c7bb950af538396f3e5a409c69b7b9335c");
        }
    }
    builder
        .output("health")
        .generate()
        .expect("generate Health AIDL");
}

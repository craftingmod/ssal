use std::fs;
use std::path::Path;

fn main() {
    println!("cargo:rerun-if-changed=composer3-aidl");
    let root = Path::new("composer3-aidl");
    let composer3 = root.join("android/hardware/graphics/composer3");
    let interfaces = ["IComposer.aidl", "IComposerClient.aidl", "IComposerCallback.aidl"];

    let mut builder = rsbinder_aidl::Builder::new()
        .include_dir(root)
        .source(root.join("android/hardware/common"))
        .source(root.join("android/hardware/graphics/common"));

    for iface in interfaces {
        builder = builder
            .source(composer3.join(iface))
            .version(2)
            .hash("b6d53bcf537cbe89633b1622e2b065ea17291234");
    }

    let mut others: Vec<_> = fs::read_dir(&composer3)
        .expect("read composer3 aidl dir")
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension().and_then(|e| e.to_str()) == Some("aidl")
                && !interfaces.contains(&path.file_name().unwrap().to_str().unwrap())
        })
        .collect();
    others.sort();
    for path in others {
        builder = builder.source(path);
    }

    builder
        .output("composer3")
        .generate()
        .expect("generate Guest Virtual Composer3 interfaces");
}

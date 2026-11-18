fn main() {
    println!("cargo:rerun-if-changed=aidl");
    rsbinder_aidl::Builder::new()
        .source("aidl")
        .output("apex")
        .generate()
        .expect("generate Guest IApexService");
    println!("cargo:rerun-if-changed=suspend-aidl");
    let dir = std::path::Path::new("suspend-aidl/android/system/suspend");
    let mut suspend = rsbinder_aidl::Builder::new().include_dir("suspend-aidl");
    for file in ["ISystemSuspend", "IWakeLock"] {
        suspend = suspend
            .source(dir.join(format!("{file}.aidl")))
            .version(1)
            .hash("082a58c2505b703702f34ab8abcb1d1b5e890be4");
    }
    for file in [
        "ISuspendControlService",
        "ISuspendCallback",
        "IWakelockCallback",
    ] {
        suspend = suspend
            .source(dir.join(format!("{file}.aidl")))
            .version(1)
            .hash("34506b107801d68c881c2c7368ad4c676aed3e9b");
    }
    suspend
        .source(dir.join("WakeLockType.aidl"))
        .source(dir.join("internal"))
        .output("suspend")
        .generate()
        .expect("generate Guest SystemSuspend interfaces");
}

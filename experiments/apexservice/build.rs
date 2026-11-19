fn main() {
    println!("cargo:rerun-if-changed=aidl");
    rsbinder_aidl::Builder::new()
        .source("aidl")
        .output("apex")
        .generate()
        .expect("generate Guest IApexService");
}

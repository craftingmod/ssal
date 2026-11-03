use std::path::PathBuf;

fn main() {
    rsbinder_aidl::Builder::new()
        .source(PathBuf::from("aidl"))
        .output(PathBuf::from("phase3"))
        .generate()
        .unwrap_or_else(|error| {
            eprintln!("{error:?}");
            std::process::exit(1);
        });
}

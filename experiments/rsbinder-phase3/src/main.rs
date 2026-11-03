#[cfg(target_os = "android")]
mod android;

#[cfg(target_os = "android")]
fn main() {
    if let Err(error) = android::run() {
        eprintln!(
            "{}",
            serde_json::json!({"event":"phase3_error","message":error.to_string()})
        );
        std::process::exit(1);
    }
}

#[cfg(not(target_os = "android"))]
fn main() {
    eprintln!("phase3-ipc must run on Android");
    std::process::exit(2);
}

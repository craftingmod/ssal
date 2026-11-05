#[cfg(any(target_os = "linux", target_os = "android"))]
fn main() {
    if let Err(error) = ssal::guest_properties::main() {
        eprintln!("Guest property server stopped; terminate Guest session: {error}");
        std::process::exit(1);
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn main() {
    eprintln!("Guest property server requires Android/Linux");
    std::process::exit(1);
}

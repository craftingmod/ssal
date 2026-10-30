//! Fixed disposable probe; never accepts an arbitrary executable or driver path.
#[cfg(unix)]
#[path = "../enforcing_worker.rs"]
mod worker;
#[cfg(unix)]
fn main() {
    if let Err(e) = worker::main() {
        println!(
            "{}",
            serde_json::json!({"event":"blocked","syscall_or_gate":e.to_string(),"errno":e.raw_os_error()})
        );
        std::process::exit(1);
    }
}
#[cfg(not(unix))]
fn main() {
    std::process::exit(1);
}

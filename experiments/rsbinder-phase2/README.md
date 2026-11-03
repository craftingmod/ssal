# rsbinder Phase 2 probes

This standalone crate tests the pinned rsbinder 0.12.0 kernel-Binder path. It does not connect the Host and Guest processes, register a service, or call a service method. Both programs require an explicit absolute Binder path and issue only a ServiceManager lookup followed by INTERFACE_TRANSACTION.

host_probe accepts only /dev/binder. Run it in a fresh process:

    host_probe --device /dev/binder --service package --expected-descriptor android.content.pm.IPackageManager

guest_probe must run as a separate process inside the existing Guest Private Binder test namespace, where /dev/binder resolves to that session's private device:

    guest_probe --device /dev/binder --service aidl_lazy_test_1 --expected-descriptor BBinder

Do not run that Guest command in the ordinary Host namespace. The same /dev/binder spelling would select the Host device there. The Guest service is session-scoped and must already be registered by the existing C++ Test B harness; this crate never registers it.

The C++ Test B service is `Echo : BBinder`. The Guest `INTERFACE_TRANSACTION` returned `BBinder`; the earlier empty-string expectation was incorrect.

The android_16_plus feature is the narrowest feature covering the plan's Android 16 target and the connected Android 17 device. rsbinder 0.12.0 selects its Android 16 ServiceManager variant for SDK 37. The probe does not need generated AIDL, so rsbinder-aidl is not a direct dependency.

## Build

The repository's Rust toolchain pins Rust 1.90.0 and the Android target. The repository .cargo/config.toml points to the Linux NDK API 26 linker; use an API 29 linker explicitly for this experiment.

On Windows PowerShell with NDK r30:

    $env:CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER = "$env:ANDROID_NDK_HOME\toolchains\llvm\prebuilt\windows-x86_64\bin\aarch64-linux-android29-clang.cmd"
    cargo test --locked --manifest-path experiments/rsbinder-phase2/Cargo.toml
    cargo check --locked --manifest-path experiments/rsbinder-phase2/Cargo.toml --target aarch64-linux-android
    cargo build --release --locked --manifest-path experiments/rsbinder-phase2/Cargo.toml --target aarch64-linux-android

On the repository's Linux builder, point the same Cargo variable to toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android29-clang. cargo-ndk is optional; these commands use Cargo's target linker directly.

Each Android run prints one JSON record with separate results for Binder initialization, handle 0, SDK detection, ServiceManager construction, lookup, and the descriptor transaction. It compares `getprop`, Bionic `__system_property_get`, `rsproperties`, and rsbinder SDK values in the process's current mount namespace. The Guest probe requires all four to report SDK 36.

The lookup calls Android 16 `checkService2` directly, preserving its Binder status and avoiding lazy-service start behavior. A missing Binder, transaction error, and descriptor mismatch are reported at their respective stages.

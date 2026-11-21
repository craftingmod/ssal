# RSProperties 0.7.0 migration report

Date: 2026-11-18  
Scope: migrate SSAL's Guest Property Area and adapter from `rsproperties` 0.6.0 to 0.7.0. This report does not include the separate `apexservice` blocker.

## Decision

SSAL now pins `rsproperties = 0.7.0` and declares Rust 1.85 as its minimum. The core crate remains responsible for the Guest Property Area and its readers. SSAL retains the Android service adapter, SELinux peer authorization, persistent store, and process supervision.

`rsproperties-service` 0.7.0 was not added. Its source is Linux-only and rejects Android targets; its service API also does not provide SSAL's per-request `SO_PEERSEC` authorization and Host-isolation gates. Using it would require either bypassing security checks or maintaining a fork. SSAL's existing `Service` wrapper already supervises the adapter child.

## 0.6.0 to 0.7.0 matrix

| Upstream change | SSAL decision | Application and risk |
|---|---|---|
| MSRV is Rust 1.85 | Apply | `Cargo.toml` now declares `rust-version = "1.85"`. The available WSL compiler was 1.90; 1.85 itself was not installed for verification. |
| `PropertyConfig` is non-exhaustive and uses `new()` builders | Apply | The Guest-area test fixture now initializes with `PropertyConfig::new()`. |
| `init()` and `system_properties()` return `Result` | Apply | Callers now propagate or explicitly unwrap errors; no success fallback was introduced. |
| Waits use instance-bound `PropertyIndex` and serial values | Apply | The existing wait test finds the property, reads its serial, then calls `wait_timeout(index, serial, timeout)`. `PropertyWatcher` and `AreaWatcher` were not added because no runtime caller needs them. |
| `PropertyInfoEntry` constructors and context parser arguments changed | Apply | Fixtures use `exact`/`prefix`; the parser uses `MatchKeyword::Checked`. |
| Error and parser APIs changed; public `rustix` types were removed | Apply | SSAL uses the 0.7 wire validators and `parse_int`; no `rustix` type is used by SSAL source. `rustix` remains a transitive implementation dependency. |
| `rsproperties-service::run(config, ServiceOptions)` returns a `ServiceHandle` | Defer | The published service cannot compile for Android and does not match SSAL's authorization boundary. Existing child supervision and cleanup remain in SSAL. |
| Upstream service adds AOSP control, power, response-code, and persistence behavior | Adapter | The Guest-local adapter implements V1/V2 wire handling, AOSP V2 status codes, `ctl.*`, and `sys.powerctl`; SSAL's SELinux checks and persistence semantics remain in place. |

The upstream contract was checked against the [0.7.0 changelog](https://github.com/hiking90/rsproperties/blob/main/CHANGELOG.md), [core API](https://docs.rs/rsproperties/0.7.0/rsproperties/), and [service source](https://docs.rs/crate/rsproperties-service/0.7.0/source/src/lib.rs). AOSP comparisons used [`property_type.cpp`](https://android.googlesource.com/platform/system/core/%2B/73f5b65ed439a2484f408ee426dcdff3c538706b/init/property_type.cpp), [`property_service.cpp`](https://android.googlesource.com/platform/system/core/%2B/master/init/property_service.cpp), and Bionic's [`system_property_set.cpp`](https://android.googlesource.com/platform/bionic/%2B/main/libc/bionic/system_property_set.cpp).

## SSAL feature decisions

| Feature | Decision | Reason and regression risk |
|---|---|---|
| Guest Property Area creation, reads, writes, and wait | 0.7.0 core | The isolated `tmpfs` area continues to use RSProperties. Existing freshness, mount-namespace, SELinux-enforcing, and Host identity gates remain. Wait callers use 0.7's index API. |
| Property socket and protocol | Keep a narrow adapter | Android needs peer PID/UID/GID plus SELinux source-context checks. V1 remains supported with its no-ack response; V2 returns AOSP status values. Unknown commands and malformed frames are explicit errors. |
| Guest system property socket | AOSP DAC behavior | `property_service` is root:root 0666; `property_service_for_system` is root:system (GID 1000) 0660. Startup verifies both socket types, ownership, mode, Guest directory identity, and separation from any Host socket with the same name. |
| Context and type validation | Keep the Guest resolver; use 0.7 helpers | SSAL still resolves Guest `property_contexts` into target SELinux contexts and requires an explicit `property_service:set` allow. Shared wire name/value validation and AOSP integer parsing come from 0.7. The double validator follows AOSP's whole-value, range, and underflow behavior. |
| `build.prop` loading | Keep explicit Guest inputs | `import` expansion remains unsupported. Upstream expansion has no SSAL hook to confine imported paths to the Guest root; accepting it without such confinement could read Host files. |
| `persist.*` | Keep SSAL store | Its protobuf bytes match the AOSP `persistent_properties` fixture. SSAL writes a same-directory temporary file, fsyncs it, renames atomically, and fsyncs the directory before publishing the area update. Corrupt data and write failures fail closed. Upstream service persistence has different corruption/write-failure behavior, so replacement was not justified. |
| `ctl.*` | Guest-only handler, fail closed | Requests are authorized and sent only to SSAL's Guest handler; no Host init or Host Property Service forwarding exists. The handler reports `PROP_ERROR_HANDLE_CONTROL_MESSAGE` because SSAL has no Guest init service table yet. This preserves current denial behavior but does not provide `ctl.start` functionality. |
| `sys.powerctl` | Guest session teardown only | `shutdown` and `reboot` requests are validated, acknowledged, then signal the verified Guest session owner. The Guest service never calls Host reboot/poweroff and never stores `sys.powerctl`. `reboot,userspace` and malformed requests return invalid-value status. A reboot currently tears down the Guest session; SSAL has no automatic Guest relaunch coordinator. |
| Lifecycle | Keep SSAL supervision | The property service remains a supervised child. Its parent PID is passed in configuration and checked at service startup; socket cleanup covers both Guest endpoints. The upstream `ServiceHandle` is not used on Android. |

The principal remaining compatibility limits are the absent Guest init service table, lack of automatic Guest relaunch for `reboot`, and lack of confined `build.prop` import expansion. No KernelSU policy expansion or SELinux permissive change was made.

## Patch and duplicate-code summary

- Updated the lockfile and dependency pin; migrated RSProperties configuration, result handling, property reads, wait indices, context entries, and parser keywords.
- Removed SSAL's duplicate integer parsing and delegated it to `rsproperties::parse::parse_int`.
- Kept the Android socket/service adapter, Guest SELinux authorization, atomic persistence, and process lifecycle because upstream does not provide equivalent Android isolation.
- Added explicit V1/V2 response handling, Guest-only control routing, and AOSP-compatible permissions for the system property socket.
- Added tests for wait notification, persistence recovery and failure, context/type rejection, V1 no-ack behavior, V2 status codes, and control routing without property writes.
- No Host property area, init, service, persistent file, or SELinux state was changed. No device payload was installed.

## Verification

| Check | Result |
|---|---|
| WSL Host `cargo check --locked --all-targets` | Pass |
| WSL Host `cargo test --locked --lib --bin ssal-property-service -- --test-threads=1` | Pass: 57 passed, 0 failed, 2 ignored. Root execution was needed to preserve RSProperties' strict root-owned area checks. |
| Android Rust cross-check `cargo check --locked --target aarch64-linux-android --all-targets` | Pass, including Android-only test code. This is a Rust cross-check, not a linked Android binary. |
| Full `ssald` test binary | 63 passed, 2 failed, 5 ignored in WSL. The failures were outside the property modules: a pipe-size expectation (observed 768 KiB vs 1 MiB) and a userdata allocated-block assertion. They should be rerun on the project's supported Linux test host; they were not changed here. |
| Android link/build script | Blocked: `/opt/android-ndk` and `ANDROID_NDK_HOME` are absent; `aarch64-linux-android26-clang` is unavailable. |
| Device regression | Not run. The attached ADB device reports Lenovo TB320FC, not the target Samsung/One UI host. No Guest payload was applied. |
| Zygote fork and SystemServer entry after migration | Not verified on device. Host unit tests do not establish this boot milestone. |

## Safety, rollback, and remaining work

The migration leaves the user-facing boot incomplete until an Android NDK link and a target-device run pass. Before a device run, capture the Host socket/property/data identities and confirm the disposable Guest mount cleanup path. Apply only this migration build, then stop at the first regression; do not alter Host properties, init, services, persistent data, or SELinux mode.

Rollback is to restore the pre-migration versions of `Cargo.toml`, `Cargo.lock`, and the changed files under `src/guest/`, then remove `src/guest/properties/control.rs` and this report. The checkout was clean before this task, so restoring those files to the starting revision reverses this patch. No persisted Guest format was changed, so no data conversion is needed.

Do not widen this migration to the existing `apexservice` blocker. Full completion still requires an Android linked build and a successful target-device run through Guest Property Service readiness, Zygote fork, and SystemServer entry.

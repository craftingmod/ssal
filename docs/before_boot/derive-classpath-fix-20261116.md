# Guest derive_classpath output commit fix

`derive_classpath` now completes on the device with SELinux Enforcing. The
failure was the final rename of its populated temporary export file, after
classpath fragment parsing and output writes had already succeeded.

## Evidence and change

- Global attempt73 replayed version22 with a temporary Guest-only syscall logger.
  `out/guest-first-boot-20261116/attempt73/worker-progress.log:331` records
  `rename` of `.ssal-phase7a-classpath-30965.env.tmp` failing with errno 13.
  The temporary output contained 4,638 bytes. No corresponding enforcing helper
  AVC was captured; the syscall trace identifies the operation directly.
- [AOSP WriteClasspathExports](https://android.googlesource.com/platform/packages/modules/SdkExtensions/+/main/derive_classpath/derive_classpath.cpp)
  writes `/data/` exports to a `.tmp` file and then renames it to the final path.
- `src/guest_policy.rs` version23 extends only the Guest
  `derive_classpath -> shell_data_file` permissions with `dir remove_name` and
  `file rename`. It preserves the previous permissions and Host policy.
- A regression test checks the generated Guest rules and their native commands.
  The existing helper FD test fixture now declares the derive_classpath type
  that its assertions already expected.

## Validation

- `cargo fmt --check`: passed.
- `cargo test --locked --lib guest_policy::tests`: 12 passed; one saved-GSI
  fixture test ignored because its optional fixture was not supplied.
- `bash scripts/build-android.sh`: passed in the WSLc build container.
- Global attempt74 used the new `ssald`, the established production logger,
  and a fresh independent userdata copy. `device-stage/worker.log:275` records
  derive_classpath exit status 0; line334 records validated classpath counts:
  boot 46, dex2oat 14, system server 16, standalone system server 9.
- ServiceManager/AIDL and PHASE5B passed. The policy ledger gained exactly two
  statements and lost none; the symbols and placeholders were unchanged.
  The native backend reported all six commands in the widened statements
  successful. Kernel rule readback remains unverified.
- The same boot ID, Enforcing mode, Host system_server, PID1 mountinfo, Host
  cgroups, original userdata metadata, system image metadata, and production
  binary hashes were preserved. The active policy hash changed as expected
  for the additive Guest rules.

Evidence is under `out/guest-first-boot-20261116/attempt73` and `attempt74`.
Attempt74's aggregate script exits 1 because it also requires Zygote readiness
and unchanged policy hashes. Derive_classpath itself succeeds; the later
Guest Zygote process exits with SIGSEGV (`device-stage/worker.log:3188`).
The Zygote crash and full first boot are outside this fix's validation.

## Cleanup status

The worker released its mounts, all 46 loop allocations, and Guest cgroups.
After explicit user approval, Luna removed both attempts' stage directories,
temporary module bindirs, and independent userdata images/partials. Both
cleanup scripts reported `CLEANUP=PASS`, no remaining mount/loop/cgroup, and
unchanged policy, applied ledger, compatibility data, original userdata,
system image, production binaries, and Host core/cgroups.

Evidence: `attempt73/cleanup-attempt73.device.txt` and
`attempt74/cleanup-attempt74.device.txt` under the evidence root above.
The earlier automatic approval rejection is retained in each attempt's
`cleanup-blocked.txt` as history; cleanup is now complete.

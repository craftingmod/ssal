# Mapped Guest SystemServer bring-up — 2026-11-16

Device: Lenovo TB320FC (`HA1WAQ7P`), profile `y702`, Host Enforcing.
Continues global attempt74. Production binaries and original userdata are not replaced.
Each attempt uses an independent 8 GiB userdata copy and a temporary module bindir.

## Changes and evidence

- Attempt75 attached bounded stdout/stderr diagnostics before the early-exit and
  cgroup checks. The 45 ms SIGSEGV was recorded, but output remained empty.
  `attempt75/stdio-access-before.jsonl:2-3` reports Guest Zygote denial for the
  launcher's KSU-owned FD use and pipe write. This query alone does not prove the
  SIGSEGV cause.
- Policy version24 extends the established helper stdio rules to Guest Zygote.
  Attempt76's applied ledger added exactly those two statements and removed none
  (`attempt76/policy-rule-diff.txt`). Zygote now reports its actual linker error:
  `libnativeloader.so` missing (`device-stage/worker/phase7b/stderr.log:1-2`).
- Linkerconfig also uses the existing Guest stderr logger. Its generated config
  lacked ART namespaces. Guest `/apex` and `apex-info-list.xml` were left as
  `tmpfs`; the kernel denies linkerconfig reading that type but permits the
  existing mapped `apex_mnt_dir` and `apex_info_file` types
  (`attempt78/apex-access.jsonl`). New Guest objects receive those labels.
- Attempt78 generates the ART namespace and exports `libnativeloader.so`, then
  aborts on `/data/dalvik-cache/arm64`: its parent incorrectly inherited
  `system_data_root_file` (`device-stage/logcat-filtered.txt:187-188`). The
  launcher gives it the existing Guest `dalvikcache_data_file` label.
- Inherited Zygote/USAP sockets are created in the child with Guest Zygote socket
  credentials and the mapped `zygote_socket` file label. This prevents exec from
  replacing inaccessible KSU socket descriptions. Attempt78 socket probes report
  ENOTSOCK; attempt79 reports the correct path, type and listening state for both.
- Attempt79 passes Zygote readiness, private Binder/AIDL, five-second residence,
  root/SID/environment/cgroup checks and worker mount/loop/cgroup teardown.
  `attempt79/apex-labels.txt` records the actual Guest APEX labels.
- Generated root symlinks are given the Guest `system_file` label; they are on
  Guest tmpfs, outside the system overlay. This addresses observed `/product`
  and `/system_ext` symlink-read denials without changing Host symlinks or policy.
- `SSAL_START_SYSTEM_SERVER=1` opts the mapped Zygote worker into actual native
  `--start-system-server` startup, a private pivot root and the existing FD reopen
  helper. It rejects an unmapped/non-Zygote worker and the app-fork diagnostic.
  The supervisor requires a Zygote child with mapped SystemServer SID, UID/GID
  1000, Guest root/net namespace, Guest cgroup, the Framework entry log and five
  seconds residence. Existing subreaper cleanup covers owned descendants.
- Attempt80 exposed incorrect native/Java option ordering; native options now
  precede `--socket-name`, with a regression test.

Evidence root: `out/guest-first-boot-20261116/` (global attempt directories).
The old 8B-5 fixed-SID/bypass runtime remains disabled and is not used.

## Verification and remaining work

Policy/native/runtime tests with the saved GSI and Host fixtures: 28 passed. Current fixture encoding is
49,895 rules, 133,895 commands, 11,267,592 bytes, 703 batches. The old fixture
expectations predated several previous derive_classpath changes; this session's
version24 live delta is only the two Zygote stdio rules above. Version25 additionally adds the 60 Guest-source/Guest-output tmpfs file transitions described below.
Launcher tests: 13 passed. Mount tests: 12 passed, one privileged test ignored.
Android builds pass in WSLc outside the sandbox. The obsolete static test that
asserted the launcher can never request SystemServer was removed; the explicit
opt-in admission and option ordering are covered by Rust tests.

Full Framework boot, Guest `sys.boot_completed`, HAL/FBE and hard reboot recovery
remain unverified. Actual kernel rule readback remains unverified except the
explicit compute_av queries. This device is Lenovo, not the target Samsung.

Cleanup75–77 was refused twice by automatic approval review; temporary attempt
files remain and local `cleanup-status.txt` preserves those decisions. No policy
is removed or recreated. Later attempt cleanup is pending.

## Final attempt83 and stop point

User requested stopping after attempt83; no attempt84 was started.

- Attempt81 reaches `nativeForkSystemServer` but aborts on the unregistered
  `/memfd:jit-zygote-cache`. ART had failed to initialize that cache. The existing
  transition targeted `ssal_p0001_tmpfs`, while kernel memfd uses shared `tmpfs`.
  The read-only kernel create query returned `tmpfs` before the correction
  (`attempt81/memfd-create-before.txt`).
- Version25 preserves those original transitions and adds equivalent file
  transitions from shared `tmpfs`, keeping Guest sources and Guest outputs.
  Native encoding allows that exact shared target/class only; tests reject Host
  sources, Host outputs, other shared targets and other classes. Attempt82 ledger
  diff is exactly 60 added transitions, zero removals or unexpected statements
  (`attempt82/policy-rule-diff.txt`). Kernel create query now returns the mapped
  `ssal_p0001_zygote_tmpfs` (`attempt82/memfd-create-after.txt`).
- Attempt82 got beyond the failed JIT mapping but stalled during FD reattachment:
  the synchronous ABI query blocked the parent's stderr draining. The query
  timed out after 30 seconds, and the supervisor killed the Zygote. Its final
  captured stderr was about 63 KiB. The parent now drains bounded Zygote
  diagnostics while waiting on the query. A regression test writes 128 KiB before
  allowing the simulated ABI reply; it passes.
- Attempt83 captures 75,884 stderr bytes and ends after 3,053 ms with Zygote PID
  1321 SIGABRT. The first fatal is `JNI FatalError called: (system_server) Unable
  to stat 55` at stderr timestamp `10:03:02.095`, lines 399–400 in
  `attempt83/device-stage/worker/phase7b/stderr.log`. Existing native FD allowlist
  validation stopped the fork; FD55 identity/cause remains unresolved. No
  allowlist bypass or speculative permission was added.
- Guest ServiceManager readiness and PHASE5B/AIDL passed. SystemServer Framework
  entry and Zygote readiness did not pass. The worker exits 1.
- `attempt83/remote-run.log` reports Host core, active policy hash, applied ledger,
  original userdata metadata, system image metadata, production binary hashes
  and Host cgroups unchanged. Mount/cgroup teardown and 46 loop releases pass;
  `CLEANUP_OK=1` refers to runtime resources, not deletion of the trial files.
- Final read-only check: Host Enforcing, boot ID
  `187ab5ca-c953-4032-b5fb-38875175d198`, Host system_server PID2280; only production
  ssald PID7717 remains. No Guest worker was left running.

Trial stage directories, module bindirs and userdata copies remain on device;
local logs and payloads are preserved. The automatic cleanup reviewer rejected
attempt75–77 deletion again even after the user's approval, saying the trusted
messages did not clearly authorize its exact scope. No alternate deletion route
was used. Attempts78–83 have not been submitted for artifact deletion.

## Continuation from attempt84 (2026-11-16)

The user resumed from attempt84. Attempts84–95 are now recorded; attempt96 has
not started.

- Attempt84 still aborts in the SystemServer fork with `Unable to stat 55`
  (`attempt84/device-stage/worker/phase7b/stderr.log:400`). Attempts85–87 reach
  `selinux_android_setcontext`, which returns permission denied
  (`attempt85/device-stage/worker/phase7b/stderr.log:431-435`). Attempts88–90
  report `dyntransition` and `setcurrent` denials. Attempt90 reloads the saved
  kernel policy snapshot; the active hash changes after reloading, so semantic
  equality of the serialized policy was not established.
- Attempt91 separates the SELinux checks: libselinux's `selinux_check_access`
  reports EACCES while the direct selinuxfs access query allows the same
  permissions; both `validatetrans` queries pass. This points to a userspace AVC
  mismatch but does not prove its cause (`attempt91/access-query.tsv`,
  `attempt91/selinuxfs-access-query.jsonl`,
  `attempt91/device-stage/attempt91/worker/phase7b/stderr.log:429-432`). Attempt92's
  reset flag was cleared before worker launch. Attempt93 did not reach the
  context-map setter diagnostics, so it did not test reset behavior.
- Attempt94 forwards the opt-in reset flag to Guest Zygote. The call is reached,
  but `dlsym(RTLD_NEXT, "avc_reset")` finds no symbol: `avc_reset=-1`,
  `errno=38` (`attempt94/device-stage/attempt94/worker/phase7b/stderr.log:429-433`).
  Both libselinux permission checks still return EACCES, and no setter-result
  line is recorded. Guest ServiceManager and PHASE5B pass; Guest Zygote
  readiness fails. The worker exits at `prepare worker: No such file or
  directory` (`attempt94/device-stage/attempt94/worker.log:3192`).
- Attempt95 adds `RTLD_DEFAULT` as a fallback lookup for `avc_reset`. This run
  did not reach the context-map setter, so the fallback remains unverified.
  ServiceManager and PHASE5B pass, then the worker exits with the same prepare
  error; stderr records `libprocessgroup` failing to create
  `/sys/fs/cgroup/system/uid_1000`
  (`attempt95/device-stage/attempt95/worker/phase7b/stderr.log:404`).
- Attempts94–95 preserve Host Enforcing, boot ID, system_server, mountinfo,
  cgroups, active policy hash
  `4f492890e043043e804c0e4f2ab1f3fcda1497eca955e485dca12cad77a4bd7c`, original
  userdata, system image, production binaries, and applied Guest policy ledger.
  Runtime mount, loop, and cgroup teardown passes (`CLEANUP_OK=1`). Each attempt's
  independent 8 GiB userdata copy and evidence remain on the device and locally.
- The current AOSP libselinux symbol map exports `avc_reset`, but this does not
  establish what the test GSI library exports:
  [AOSP symbol map](https://android.googlesource.com/platform/external/selinux/%2B/refs/heads/main/libselinux/src/libselinux.map).

The next useful runtime check is whether the `RTLD_DEFAULT` fallback resolves
`avc_reset` and changes the permission result. Attempt95 did not reach that
check. It left 18 GiB free; another 8 GiB clone would leave about 10 GiB free.
The automatic reviewer rejected the retry to remove the attempt75–77 stage,
bindir, and userdata artifacts, saying the trusted user message did not
authorize that exact deletion scope; prior approval was reported but not
accepted by the reviewer. No files were deleted; an
explicit approval for that exact cleanup was requested. Attempt96 has not
started. The Lenovo test device is not the target Samsung. Full Framework boot,
Guest `sys.boot_completed`, and hard reboot recovery remain unverified.

## Continuation after attempt107 (2026-11-17)

Attempt108 was run with a fresh 8 GiB trial userdata copy and a separate module
bindir. The original userdata image and production files were unchanged.

- The worker now creates Guest-only cgroup2 `/sys/fs/cgroup/ssal_guest/system`
  for SystemServer, owned by uid/gid 1000, before binding the Guest cgroup root
  (`src/guest_mounts.rs`). The worker logged the prepared path. The previous
  `libprocessgroup` ENOENT for `/sys/fs/cgroup/system/uid_1000` did not recur.
- Guest SystemServer PID13920 appeared in the expected
  `ssal_p0001_system_server` domain (`worker.log:341-342`). Its v1 memory
  membership check did not fail; the worker instead ended with Zygote exit.
  Framework-entry readiness was not observed.
- At stderr lines 431-438, the procattr transition reaches
  `SSAL_PROCATTR_WRITE_BEGIN` but no write-return marker is captured. The child
  is later reported exiting with SIGKILL; the sender and reason are unknown.
  No OOM, fatal Java crash, SIGABRT, SIGSEGV, or kernel failure was found in the
  filtered evidence. The procattr write may be related, but this is unproven.
- The later `Zygote failed to write to system_server FD: No such file or
  directory` is emitted by AOSP's SIGCHLD handler while it sends a death notice
  to `/data/system/unsolzygotesocket`, after reaping the child; it does not
  identify the cause of the child's SIGKILL
  ([AOSP Zygote source](https://android.googlesource.com/platform/frameworks/base/%2B/master/core/jni/com_android_internal_os_Zygote.cpp#377)).
- Host stayed Enforcing with boot ID
  `187ab5ca-c953-4032-b5fb-38875175d198`, policy hash
  `4f492890e043043e804c0e4f2ab1f3fcda1497eca955e485dca12cad77a4bd7c`,
  system_server PID2280, and production ssald PID7717. The worker confirmed
  unchanged Host cgroups, original userdata, system image, Guest policy ledger,
  and production binaries. Mount, cgroup, and all 46 loop cleanups passed.
- The ATTEMPT108 trial clone and local/device evidence are preserved. The
  next attempt has not started; it should collect brief read-only
  SystemServer/cgroup samples during startup to identify the SIGKILL source.

The test device remains Lenovo TB320FC, not the target Samsung. Full Framework
boot, Guest `sys.boot_completed`, and hard reboot recovery remain unverified.

Attempt109 repeated the same startup with a read-only sampler (no code, policy,
or memory-limit change):

- PID16779 again reached the expected Guest SystemServer domain and remained in
  `/ssal_guest/system/uid_1000/pid_16779` for cgroup2 and `/ssal_guest` for v1
  memory (`worker.log:341-342`, `live-process-samples.txt:15`).
- Twenty-seven samples across 58 seconds showed the main thread in
  `futex_wait_queue_me`, 9 threads, RSS 79–82 MiB, memory use 91.8–92.3 MiB,
  `memory.failcnt=0`, and `oom_kill=0` (`live-process-samples.txt:1-729`). Host
  MemAvailable was about 13 GiB and memory PSI was low.
- It ended after 64.254 seconds with signal 9 and no core; no Framework entry,
  lmkd/OOM, Java fatal, or kernel kill record was found. As in attempt108, the
  direct SIGKILL sender remains unknown. `worker.log:3191-3193` confirms cgroup,
  mount, and all 46 loop cleanups passed.
- Filtered logcat contains permissive AVCs attributed to `ksu` for actions
  logged as `system_server`, while the worker reads the process leader as
  `ssal_p0001_system_server` (`logcat-filtered.txt:187-188`,
  `worker.log:341`). Whether this reflects a per-thread SID difference is not
  established; the next sample will read thread contexts and `oom_score_adj`.

ATTEMPT109's isolated userdata clone and evidence are preserved. ATTEMPT110 has
not started.

## Phase 7B breakthrough — attempts111–112 (2026-11-17)

**Attempt112 reaches real Framework code.** Guest SystemServer PID28920 logs
`Entered the Android system server!` at raw Guest timestamp
`11-16 17:18:15.367` (2026-11-17 02:18:15 KST), then starts its init thread pool
and reads system configuration. This is an entry milestone, not a full boot:
it subsequently dies because Guest `/dev/ashmem` is absent.

Evidence root: `out/guest-first-boot-20261116/`.

### What the previous evidence concealed

- Attempt111 combines an isolated tracefs `signal_generate` instance (SIGKILL
  only) with external ptrace register/FP/stack snapshots of all nine Guest
  SystemServer threads. No debuggerd, SID/cgroup/memory re-investigation, timeout
  extension, Host process signals, or Host permissive change was used.
- `attempt111/signals.txt:24` records sender TID26304 (`system_server`) killing
  PID26304 at kernel time105386.284049. Line25 records Zygote TID26216 killing
  itself at105386.321499, 37.450ms later. Line26 is the supervisor's later
  teardown kill, with result2 (already pending). The initial kill is therefore
  self-directed, not a supervisor timeout. Zygote exits after64,989ms
  (`attempt111/device-stage/attempt111/worker/phase7b/metadata.jsonl:2`).
- `attempt111/snapshot-1.txt` and the copied GSI libraries show main-thread
  libc `syscall`+0x9c4dc, ART `ConditionVariable::TimedWait`+0x24f628 and
  `Monitor::Wait`+0x456474. The other threads include the signal catcher,
  perfetto pipe reader, stats writer, JIT pool and normal ART daemons. This is
  managed timed waiting, not a procattr syscall or inherited pthread mutex lock.
- The launcher populated only `ro.product.cpu.abilist64`. It did not populate
  `ro.product.cpu.abilist`; the loaded GSI build.prop supplies partition-scoped
  `ro.system.product.cpu.*` values. AOSP `ZygoteInit.hasSecondZygote` compares the
  total ABI property with the actual Zygote ABI list. Their mismatch makes the
  child wait for the absent `zygote_secondary`. `ZygoteProcess` retries every50ms
  for60,000ms. Sources:
  [ZygoteInit](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/main/core/java/com/android/internal/os/ZygoteInit.java),
  [ZygoteProcess](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/main/core/java/android/os/ZygoteProcess.java).
- The apparent freeze at procattr write was also a logging blind spot:
  SystemServer's startup/final domains lacked permission to use/write the
  launcher's KSU-owned stderr pipe. The existing Zygote-only grant stopped
  applying immediately after specialization. Attempt112 restores both
  `SSAL_PROCATTR_WRITE_RETURN` markers (stderr lines438,449) without changing
  the transition implementation.

### Fix and device result

- The private Guest property service now publishes total/64-bit ABI lists as
  `arm64-v8a`, an empty32-bit list, and `ro.zygote=zygote64`, matching the one
  Zygote actually launched. Its existing live property check verifies the lists
  agree. No Host property is changed.
- Policy version27 adds exactly four statements: `fd use` and `fifo_file write`
  from each of `ssal_p0001_system_server_startup` and
  `ssal_p0001_system_server` to KSU-owned stdio. Applied-ledger comparison records
  four additions and zero removals (`attempt112/policy-rule-diff.json`). No
  permissive rule or Host-source rule is added. Kernel rule readback remains
  unverified; the ledger diff describes the submitted/applied statements.
- `attempt112/worker.log:203` verifies the ABI configuration; lines342–344
  verify the final SystemServer domain, Guest root/network namespace and
  `framework_entry=true`. `attempt112/stderr.log:457–459` records Framework entry,
  creation of the eight-thread init pool and configuration loading. The old
  60-second wait disappears; Zygote's whole lifetime is5,298ms.
- The next failure is explicit: `ApplicationSharedMemory.nativeCreate` throws
  `Failed to create ashmem: No such file or directory` from
  `SystemServer.run` (stderr lines670–680). `RuntimeInit$KillApplicationHandler`
  then sends SIGKILL (lines704–710). This proves attempt112's post-entry kill
  path; attempt111's exact Java exception was hidden and is not directly proven.
- Five-second residence and the complete phase readiness verdict still fail.
  No attempt113 was run with unchanged conditions. Full boot, UI, Samsung device
  behavior and hard-reboot recovery remain unverified.

Validation:14 focused Rust tests pass (launcher13, Guest stdio-policy1), Android
release build passes, the ARM64 ptrace helper builds with warnings as errors,
and the build shell syntax check passes. Selected changed Rust files pass
rustfmt; repository-wide formatting still reports a pre-existing difference in
`guest_mounts.rs:845`, which was left alone.

Both attempts preserve Host Enforcing, boot ID
`187ab5ca-c953-4032-b5fb-38875175d198`, Host SystemServer PID2280, Host mountinfo,
Host cgroup configuration, original userdata metadata, system image and
production binary hashes. Runtime teardown releases all46 loop allocations and
reports no residual mounts/cgroups. Attempt112's active-policy hash changes as
expected for its four additive Guest grants. Disposable userdata artifact
deletion is handled separately by Luna; evidence directories are retained.

Luna cleanup completed:17 inactive trial images (attempts96–112) deleted after
mount/loop reference checks; no `.userdata-*.img*` remains in the y702 profile.
The disabled attempt111 trace instance and accidental local payload duplicate
were removed. Original userdata size/mtime/inode and all evidence are preserved.
Record: `out/guest-first-boot-20261116/cleanup-phase7b-111.txt`.

## Ashmem fix — attempt113 (2026-11-17)

The missing boot-ID ashmem device is fixed with a private Guest node using the
existing mapped SELinux type. A no-boot diagnostic first confirmed ENOENT,
memfd/sealing support and missing ashmem-on-memfd ioctl compatibility; the same
diagnostic then passed create, mmap, fork sharing and protection checks.
Attempt113 passes Framework entry, SystemServer/Zygote five-second residence,
service readiness and teardown, with Host state and active policy hash unchanged.
Full boot remains unverified. See
[the ashmem investigation report](guest-ashmem-compatibility-20261117.md) for
source conditions, evidence, changes and remaining limits.

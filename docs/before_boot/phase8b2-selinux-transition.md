# Phase 8B-2 — Guest system_server SELinux 전환 분석

## 판정

정적 전환 경로와 Guest 전용 정책 초안을 작성했다. 실제 Guest `system_server` fork는 실행하지 않았다. stock GSI는 Guest 내부에서 시작한 서버도 최종 `u:r:system_server:s0`로 바꾸므로, 현재 구성으로 실행을 허용할 수 없다.

## 고정한 대상

| 항목 | 확인값 |
|---|---|
| GSI | `out/LineageOS-23.2-20260524-VANILLA-EXT4-GSI.img` |
| GSI SHA-256 | `7b9ba62e8b48b6e40432be949ae0858a8971175c79502550e74691222d3889ff` |
| Build / SDK | `BP4A.251205.006` / 36 (Android 16) |
| 추출 정책 | `out/selinux-check/2026-10-30T21-06-36-556Z-feba58ef/guest/system/etc/selinux/` |
| `plat_seapp_contexts` SHA-256 | `7a4d14a898fb234d87cd49ae106e245324ad365d9029230d2a6306e6d4aa7a7a` |
| `plat_sepolicy.cil` SHA-256 | `be4eb2bcc7c1fe5bec30ec686b8ac1df28eec0eefcc48b9f541fd2f8cfffa167` |
| GSI `libandroid_runtime.so` SHA-256 | `d35220026ef94be6992d8b9b31cd446f937b8e782833813b2ac68140f41fc035` |
| GSI `libselinux.so` SHA-256 | `9801ecf09ba52fcdd937b8195119996450628cf66e40b5896c1c5475411d3818` |
| GSI `framework.jar` SHA-256 | `cc72f9cd2d55bf8b1f0afa50cb3c8a06baadac0bade9b7995cf41aa9dfb95590` |
| GSI ART `libart.so` SHA-256 | `bdbb62005b32fd575e92d58afac9ac85e8551ff26e643474bcae02bd9061a465` |

The image hash matches the Phase 8B-1 baseline. The extracted binary hashes identify the artifacts examined; they do not establish a matching LineageOS source revision.

## Stock transition and Guest boundary

1. GSI `framework.jar` disassembly shows `ZygoteInit.forkSystemServer()` requests UID/GID 1000, the supplementary groups and capabilities listed below, then forks the child. The request is not proof of the resulting child credentials.
2. Android 16's native zygote specialization calls `selinux_android_setcontext()` with the system-server flag. `libselinux` resolves `isSystemServer=true` using the Guest-visible seapp contexts and validates the resulting context before changing it. The extracted GSI `plat_seapp_contexts` selects `system_server_startup`.
3. The extracted CIL permits `system_server_startup` to set its own current context (line 68829), transition to `system_server` (line 68834), and permits `zygote` to transition to `system_server_startup` (line 78546). The running SSAL Guest zygote is `u:r:ssal_guest_probe:s0`, not the Host `zygote` domain, so the candidate transition source is the Guest domain.
4. ART's `nativePostForkSystemServer` hook performs runtime post-fork work; it does not select the final SELinux SID.
5. Android 16's native zygote code then calls `selinux_android_setcon("u:r:system_server:s0")`. The GSI `libandroid_runtime.so` contains that exact label and the SELinux setter symbols. Therefore changing only Guest `plat_seapp_contexts` changes the startup SID but leaves the final SID shared with Host `system_server`.

The stock sequence is consistent with AOSP Android 16's [`seapp_contexts`](https://android.googlesource.com/platform/system/sepolicy/+/android16-release/private/seapp_contexts), [`system_server_startup.te`](https://android.googlesource.com/platform/system/sepolicy/+/android16-release/private/system_server_startup.te), [`zygote.te`](https://android.googlesource.com/platform/system/sepolicy/+/android16-release/private/zygote.te), and [`libselinux` Android context handling](https://android.googlesource.com/platform/external/selinux/+/refs/heads/master/libselinux/src/android/android_device.c). AOSP's startup domain explicitly transitions to `system_server`; zygote's `neverallow` also limits its transition targets. The GSI binaries and extracted policy are the authority for this particular image.

The Guest source patch at [phase8b2-guest-gsi.patch](../scripts/guest-domain-poc/phase8b2-guest-gsi.patch) makes the two required Guest-specific selections: `isSystemServer=true` resolves to `ssal_guest_system_server_startup`, and native specialization's final `setcon()` targets `u:r:ssal_guest_system_server:s0`. It also extends the seapp `neverallow` assertions to both Guest types. This is a review candidate only; no GSI was rebuilt or modified.

## Candidate policy

[phase8b2-domain-transition.rule](../scripts/guest-domain-poc/phase8b2-domain-transition.rule) declares only Guest startup/final types, their transition edges, and child-exit notification back to `ssal_guest_probe`. Only those two new Guest target domains are temporarily permissive for a controlled AVC collection run. The candidate adds no permissive statement for `ssal_guest_probe`; its current live permissive state was not established. Host `zygote` and `system_server` receive no new rules. The permissive statements must be removed before enforcing acceptance or production use.

This is a transition seam, not a complete production `system_server` policy. Runtime AVCs must be attributed to the Guest-specific type and reviewed before adding narrowly scoped rules. No live policy was loaded, and no AVC collection was attempted. Host remains globally enforcing; the current connected device reported `getenforce=Enforcing` and `/sys/fs/selinux/enforce=1`.

## Credential and capability contract

The actual GSI DEX requests UID/GID 1000 and supplementary groups:

`1001,1002,1003,1004,1005,1006,1007,1008,1009,1010,1018,1021,1023,1024,1032,1065,3001,3002,3003,3005,3006,3007,3009,3010,3011,3012`.

Its requested capability names are `CAP_IPC_LOCK`, `CAP_KILL`, `CAP_NET_ADMIN`, `CAP_NET_BIND_SERVICE`, `CAP_NET_BROADCAST`, `CAP_NET_RAW`, `CAP_SYS_NICE`, `CAP_SYS_PTRACE`, `CAP_SYS_TIME`, `CAP_SYS_TTY_CONFIG`, `CAP_WAKE_ALARM`, and `CAP_BLOCK_SUSPEND`. The GSI intersects this request with the parent's current effective set. Do not infer child `CapEff`, `CapPrm`, `CapBnd`, ambient capabilities, seccomp, or `no_new_privs` from the request. None has been observed for a Guest system-server child.

Before any future fork, capture the Guest zygote's effective/bounding capability sets and exact fork request; after a permitted test child exists, record `/proc/<pid>/status`, UID/GID/groups, SELinux context, seccomp, and `no_new_privs`. Reject any child capability outside the observed parent-effective/request intersection. Specifically investigate `CAP_KILL`, `CAP_SYS_PTRACE`, network administration/raw, and time-setting capabilities for Host boundary impact. A privilege reduction or proof of non-reachability is required before acceptance.

## Execution guard

The GSI's own `init.zygote64.rc` starts app_process with `--start-system-server` and defines restart actions. SSAL does not execute that Guest init rc: it launches its zygote directly, reports `start_system_server=false` in [guest_launcher.rs](../src/guest_launcher.rs#L1197), and the service profile remains `launch_enabled=false`. Do not invoke the GSI init rc or pass `--start-system-server` during this phase. `SystemServer.main()` / `SystemServer.run()` were not called.

## Source references

- AOSP Android 16: [`ZygoteInit.java`](https://android.googlesource.com/platform/frameworks/base/+/android16-release/core/java/com/android/internal/os/ZygoteInit.java), [`com_android_internal_os_Zygote.cpp`](https://android.googlesource.com/platform/frameworks/base/+/android16-release/core/jni/com_android_internal_os_Zygote.cpp), [`dalvik_system_ZygoteHooks.cc`](https://android.googlesource.com/platform/art/+/android16-release/runtime/native/dalvik_system_ZygoteHooks.cc).
- This device/GSI baseline and the explicit no-fork gate: [Phase 8B-1 results](phase8b1-preflight-results.md).

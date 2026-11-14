# Y702 active SELinux policy export recovery — 2026-11-14

## Result

On Lenovo TB320FC, an existing SSAL allow rule was reapplied through KernelSU.
This restored the complete `/sys/fs/selinux/policy` export without rebooting or
changing Enforcing. The installed module binaries and Host policy source were
not replaced. No Guest framework services were launched.

Before recovery, `open()` itself returned EINVAL for O_RDONLY, O_NONBLOCK and
O_RDWR. A new selinuxfs mount in a private mount namespace behaved identically.
The reference ODM precompiled policy could be opened and read normally.
The selinuxfs node reported 1,265,336 bytes before recovery, exactly the size of
the ODM precompiled policy; after recovery it reported 1,767,563 bytes.

KernelSU: ksud 3.3.1, UAPI 5. Kernel:
`5.10.233-android12-9-g122af8c9f8ab-ab113`.
Root context: `u:r:ksu:s0`. `selinux_hide` was disabled.

## Reproduced workaround

Run in a root shell. This exact rule already exists in the installed SSAL
module's `sepolicy.rule`; reapplying it requests no additional permission.
Do not substitute a wildcard allow or reload a precompiled policy.

```sh
umask 077
printf '%s\n' 'allow ksu ssal_image_file file read' > /data/local/tmp/ssal-policy-noop.rule
/data/adb/ksu/bin/ksud sepolicy apply /data/local/tmp/ssal-policy-noop.rule
rm /data/local/tmp/ssal-policy-noop.rule
dd if=/sys/fs/selinux/policy of=/dev/null bs=65536
getenforce
```

The first post-recovery test read 4,096 bytes; two subsequent complete reads
both read 1,767,563 bytes successfully. Captured policy SHA-256:
`959a2366d71c6a911137d56630d8220877d431d79b67001a7a39a911ca0cacbf`.
Boot ID remained `8981ba94-feff-471e-8908-98bb535ce749`.
Temporary helpers and policy dump on the device were removed after testing.

## Interpretation and limits

The symptoms and successful reapplication are consistent with stale serialized
policy length metadata after dynamic policy changes. KernelSU's upstream
`ksu_dup_sepolicy()` serializes into a larger buffer and records the resulting
length in the copied policy. This is an explanation supported by the upstream
code and observed behavior, not a trace of the installed kernel's internals:
https://github.com/tiann/KernelSU/blob/main/kernel/selinux/sepolicy.c

The read-only `/sys/fs/selinux/context` path also worked: 242 of 262 shared GSI
type references were valid and 20 returned EINVAL. A positive control (`init`,
`ksu`, `ssal_image_file`) and negative control (a nonexistent type) were correct.
This path does not establish attribute absence, so SSAL's full-policy symbol
collision check was not replaced or bypassed.

## Next prepare result

One installed-version `ssal prepare y702` retry passed the policy-read stage,
then stopped at `KernelSU check failed (51 rules)`: the text parser rejected
named anon_inode transitions with `[userfaultfd]` (also the category addressed by
the existing Native injector work). No Guest policy commands were applied:
`applied.json` recorded `pending=false`, zero symbols, and zero statements.
The worker reported both loop allocations released; Enforcing remained enabled.

The installed CLI lacks `--native`, and its cached plan is version 2. The next
step is a matched current build of the daemon/CLI/helpers and regeneration of
the plan before the explicit Native backend can be tested. This was not done
as part of recovering policy export. Reboot recurrence was not tested and no
automatic recovery hook was installed.

Evidence and the standalone C diagnostic source are in
`out/y702-policy-read/` (local, untracked build artifacts).

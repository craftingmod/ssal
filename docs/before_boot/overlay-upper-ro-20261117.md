# OverlayFS upper metadata and Guest system RO views

2026-11-17 KST. Two independent changes: `59074c2` initializes new upper
roots; the following commit seals prepared Guest system mount views.

## New upper roots

`src/guest/selinux/runtime.rs::isolate_tree` reads lower root metadata and
maps only the type component of its SELinux context, preserving the other
context components. It creates a fresh upper with initial mode 0700,
applies lower UID/GID with fchown, then all lower permission/special bits
with fchmod, then the mapped security.selinux label and label readback.
Errors identify the upper path and failed operation and abort preparation.
The root is initialized before OverlayFS is mounted, so merged root metadata
comes from the intended Guest system type rather than userdata inheritance.

Existing scratch/upper reuse remains unsupported: creation fails instead of
resetting existing metadata. There is no migration or recursive chmod/chown.
The same isolate_tree implementation serves system partitions and APEX.

## RO views

`src/guest/mount/readonly.rs` selects mounts under system, product, system_ext,
vendor, odm, vendor_dlkm, system_dlkm and apex, including nested mounts and
versioned APEX paths. It also selects aliases elsewhere within the Guest root
that reference these OverlayFS devices. An alias outside the Guest root is
rejected before remounting. Mountinfo path escapes are decoded.

After common preparation, writable selected mounts receive
MS_BIND|MS_REMOUNT|MS_RDONLY|MS_NOSUID|MS_NODEV, preserving noexec and atime
flags. Mountinfo is read again: selected mounts must all be RO and original
mount IDs must still exist at the same paths. Any failure aborts launch.
This includes hidden stacked mounts in the check, so an unaddressable RW
stack is rejected rather than silently accepted.

Shell and Android launcher repeat sealing immediately before publishing
their attachable environment, covering additional mounts installed during
their final preparation. Shell attach reuses that prepared namespace.
This protects mount views; it does not remount an OverlayFS superblock or
userdata ext4 RO. Private upper/work storage remains RW outside the Guest
root, hidden from Guest /data by the existing mask mount.

## Validation and limits

All builds/tests ran outside the sandbox through WSL. No device binaries
were installed, no active Guest namespace was changed, and original GSI,
Host data and existing Guest userdata were not used for write tests.

- SELinux runtime tests: 11 passed, including new upper ownership/mode,
  existing-upper rejection and contextual setxattr-failure checks.
- Root-run library tests: 52 passed, 2 fixture-dependent tests ignored.
- CLI unit tests: 6 passed; CLI integration tests: 3 passed.
- Root-run ssald tests excluding the two failures below: 63 passed,
  5 privileged tests ignored. This includes Android launcher, environment
  lease, preparation, mount selection and alias parsing regressions.
- New privileged RO test passed separately in a disposable WSL mount
  namespace. Real OverlayFS, nested tmpfs, a /run alias and both APEX names
  become RO; attempted writes return EROFS, /data remains writable, lower
  contents are unchanged, and sealing twice succeeds.
- Host PTY regression passed: argv, stdout/stderr, exit status, streaming
  input, PTY, resize, Ctrl-C and terminal restoration.
- Android arm64 release builds for ssal and ssald passed with NDK r30.
- Clippy passed with the pre-existing double_ended_iterator_last warning
  explicitly excluded. git diff --check passed.

The unrestricted suite was not fully green: unchanged
`diagnostics::zygote::tests::pipes_are_bounded_reaped_and_record_signal_without_controller`
recorded 786432 instead of 1048576 stdout bytes, and unchanged
`guest::userdata::tests::formats_checks_and_locks_without_overwriting`
failed its allocated-block-count assertion in this WSL environment.
Running root-required tests as a normal user also causes ownership checks
to fail; the reported passing counts above use root where required.

Real-device SELinux relabel acceptance, Guest Shell startup and Android
boot with the new binary remain untested. WSL mount success does not certify
the Lenovo or Samsung kernel. An already-running old Guest is not migrated.
build.prop permissions and security.sehash handling are unchanged.

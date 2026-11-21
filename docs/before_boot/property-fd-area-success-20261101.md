# FD 격리와 Property Area Live 성공 — 2026-11-01

이 문서는 이전 Property Area Live 문서의 미완료 상태와 바이너리 hash를 대체하는 최신 결과다. 기존 성공한 Guest 전환, self SID, Enforcing 조회, private mount namespace, tmpfs 및 전용 타입 transition은 재구현하지 않았다. `vendor/`는 읽지 않았다.

## 최종 실기기 결과

사용자가 각각 승인한 Live 두 번 중 첫 번째는 Parent의 공유 mount 오탐으로 Guest main 전에 중단했다. 수정·회귀 시험·재빌드·preflight 뒤 별도 승인된 두 번째 실행에서 Property Area 전체 경로가 성공했다. 두 번 모두 새 정책은 적용하지 않았다.

```text
guest_transition = PASS
guest_enforcing = PASS
mount_isolation = PASS
property_root_label = PASS
inherited_fd_isolation = PASS
area_creation = PASS
area_label = PASS
fsetxattr = PASS
writer_mmap = PASS
property_add = PASS
reader_mmap = PASS
property_find = PASS
host_integrity = PARTIAL
namespace_cleanup = UNVERIFIED
```

위 PASS는 두 번째 실행 PID 7187의 관찰이다. Guest SID는 `u:r:ssal_guest_probe:s0`, 전역 Enforcing 및 Guest permissive flag 0을 Parent와 기존 Guest 경로에서 확인했다. Host mount namespace는 `mnt:[4026532950]`, Guest는 `mnt:[4026536413]`이었다. Guest tmpfs 확인과 root label `u:object_r:ssal_guest_property_dir:s0` 검사는 성공 반환까지 반드시 거치는 코드 gate다.

새 area inode의 최초 `fgetxattr` 결과는 `u:object_r:ssal_guest_property_area:s0`였다. 즉 `fsetxattr` 전부터 기대한 생성 타입이 관찰됐다. 같은 context로 `fsetxattr`가 성공하고 재조회도 일치했다. `ftruncate(131072)`, shared RW mmap, `add("ssal.guest.poc", "guest-area-ok")`, 별도 shared RO mmap, `find` 및 값 대조가 모두 성공했다. Area device는 3145748, inode 2, mount ID 40037이며 Guest property root와 같고 Host mount ID 42와 다르다. Writer와 reader 주소도 서로 달랐다.

Parent는 exec-stop과 exit-stop 모두에서 FD 0, 1, 2, 10만 관찰했다. FD 0은 `/dev/null`의 read-only FD, 나머지는 승인된 stdout/stderr/trace pipe의 write endpoint다. 각 FD의 inode, device, type/mode, rdev, mount ID와 status flags가 Parent의 사전 whitelist와 일치했다. Pipe, helper 및 proc 검사에 필요한 다른 FD는 Guest에 상속되지 않았다. Child는 timeout 없이 exit 0으로 회수됐고 사후 `/proc/7187`이 없었다.

주요 Host 프로세스의 PID/starttime/context/exe와 Property 디렉터리·mount identity 및 646개 항목 metadata/context inventory는 전후 동일했다. **Host Property 파일 내용은 비교하지 않았으므로 전체 무결성은 PARTIAL이다.** Child 회수와 mapping FD close는 확인했으나 namespace의 모든 외부 참조가 사라졌는지는 조사하지 않아 cleanup은 UNVERIFIED다. 런처의 기존 `namespace_teardown_after_child_exit` 문자열은 이 검증을 대신하지 않는다.

원본 증거:

- [성공 Live 및 단계별 stderr](../out/property-fd-live-v2-20261101.txt)
- [최종 read-only preflight](../out/property-fd-preflight-v2-20261101.txt)
- [기기 SHA-256·실행 라벨·이전 child 회수](../out/property-fd-staging-v2-20261101.txt)
- [성공 후 child 부재·Enforcing·정책 hash·boot ID](../out/property-fd-postflight-20261101.txt)
- [첫 실행: 공유 mount 오탐과 Host 사후 검사](../out/property-fd-live-20261101.txt)

## fdopendir 원인과 대체 경로

기존 실제 정적 링크 ELF를 `llvm-objdump`로 조사했다. `fdopendir`는 `fstat64`를 호출하고 이 함수의 AArch64 stub은 x8=80, `svc #0`으로 `fstat` syscall을 실행한다. 이후 ENOTDIR, allocation 또는 fdsan 초기화 경로와 달리 기존 `fdopendir errno=13`은 이 내부 `fstat` 실패 경로와 연결된다. 기존 self dir:getattr 거부가 SELinux 원인과 일치하지만 정확한 Samsung LSM 반환 훅을 syscall tracing/AVC로 직접 관찰하지는 않았다. [링크된 코드 disassembly](../out/fd-bionic-disassembly-before-20261101.txt).

같은 ELF의 `opendir`는 `O_DIRECTORY` open 뒤 DIR 객체를 만들며 이 `fstat`를 실행하지 않는다. 따라서 직접 대체 후보였다. 그러나 `readdir`는 `__getdents64`를 실행해 디렉터리 read를 요구하고, 이전 검사의 각 FD `fstat`는 대상 inode의 getattr, `readlink`는 proc link read, fdinfo 읽기는 self file open/read에 의존한다. `opendir`만 바꾸어도 이 후속 권한 의존은 남는다. AOSP의 [dirent 구현](https://android.googlesource.com/platform/bionic/+/master/libc/bionic/dirent.cpp)과도 교차 확인했으며, 실제 링크 여부의 근거는 위 ELF다.

이번에는 Guest의 전체 `/proc/self/fd` 열거를 Parent로 옮겼다. Guest의 기존 mount ID 확인용 fdinfo 읽기, self SID 및 namespace 링크 확인은 유지한다. 따라서 self dir:search, file:open/read, lnk_file:read를 계속 필수 gate로 둔다. 전체 FD 열거만을 위한 self dir:open/read는 참고 조회로 낮췄다. self dir:getattr을 새로 허용하지 않았다.

## Parent 검사와 보장 범위

1. KSU Child가 stdio를 연결한 뒤 `close_range(3, UINT_MAX, CLOSE_RANGE_CLOEXEC)`로 FD table 전체를 CLOEXEC 처리한다. Trace write FD 하나만 CLOEXEC를 해제한다. 실패는 exec 이전에 중단하며, snapshot 기반 누락 허용 또는 ENOSYS fallback은 없다. 현재 Samsung 6.6 커널에서 실제 성공했다.
2. Parent는 자신의 `/dev/null` FD와 세 pipe write endpoint로 기대 identity를 만든다. 승인된 helper hash와 ELF/실행 라벨을 preflight에서 검사한다.
3. `PTRACE_EVENT_EXEC`에서 기존 SID/starttime/executable dev·inode/namespace/Enforcing gate와 실제 실행 파일 라벨을 확인한 후 Child FD 목록을 읽는다. 디렉터리 열거 FD는 Parent 소유이므로 Child 목록에서 별도 제외할 FD가 없다.
4. 모든 entry, stat, fdinfo, readlink와 숫자 필드 parse를 검사한다. 누락·중복·형식 오류, 알 수 없는 FD, 빠진 FD 또는 identity/flags 불일치는 fail-closed로 Child를 종료·회수한다. FD whitelist 검증을 생략하지 않는다.
5. Host Property root 및 inventory의 `(dev, inode)` 일치나 Property 경로가 발견되면 차단한다. 허용 목록과 다르면 경로를 바꾸거나 삭제한 FD도 차단한다.
6. `PTRACE_EVENT_EXIT`에서도 파일 테이블이 닫히기 전에 동일 검사를 수행한다. 이는 Guest 자체 signal permission을 추가하지 않고, Area FD가 모두 닫혔는지도 확인한다. `host_fd_separated`와 `host_fd_scope=exec_and_exit_stop`는 Guest JSON을 신뢰하는 대신 Parent가 결과에 넣는다.

실기기에서는 Host `/dev/__properties__`가 `/dev`와 device 18, mount ID 42를 공유했다. 첫 구현의 `st_dev == Host` 또는 `mnt_id == Host` 차단은 정상 `/dev/null`도 거부했다. 두 값은 각각 filesystem 및 mount identity이며 디렉터리 하위 여부를 나타내지 않는다. 수정 후 mount ID는 각 승인 FD identity 비교 및 진단에 사용하고, 같은 mount라는 이유만으로 거부하지 않는다. Host inode inventory는 다른 bind mount ID에서도 같은 inode를 잡는다. Inventory 밖 객체도 정확한 whitelist를 통과할 수 없다. 공유 mount 정상 FD와 Host inode alias 회귀 시험을 추가했다.

이 검사는 승인된 단일 helper의 **exec 및 exit 두 정지 시점**의 FD 상태를 보장한다. 실행 도중 열었다가 닫힌 FD의 전수 추적, 향후 Host Property open 차단, 다른 프로세스를 통한 FD 전달 차단 또는 Property socket 차단을 증명하지 않는다. `PTRACE_O_TRACEEXIT`는 해당 Property Live 경로에서만 추가했다. Proc-Only의 정책 및 실행 경로는 보존했다.

## Property 단계 권한과 결과

현재 boot 정책에 대한 preflight에서 아래 AV와 생성 context가 모두 허용/일치했고 실제 syscall 경로도 성공했다. 신규 allow 요청 또는 적용은 없다.

| Source | Target | Class | Permission / 확인 경로 |
| --- | --- | --- | --- |
| `ssal_guest_probe` | `ssal_guest_property_dir` | `dir` | search, write, add_name, getattr; 생성 경로 탐색 및 root label |
| `ssal_guest_probe` | `ssal_guest_property_area` | `file` | create, open, read, write, getattr; 생성·xattr 조회·truncate·RO fstat |
| `ssal_guest_probe` | `ssal_guest_property_area` | `file` | relabelfrom, relabelto; 동일 타입 fsetxattr |
| `ssal_guest_probe` | `ssal_guest_property_area` | `file` | map 및 read/write; shared RW·RO mmap |
| `ssal_guest_property_dir`, `ssal_guest_property_area` | `tmpfs` | `filesystem` | associate |

Source의 전체 context는 `u:r:ssal_guest_probe:s0`, object context는 각각 `u:object_r:<type>:s0`다. `type_transition ssal_guest_probe ssal_guest_property_dir:file ssal_guest_property_area`의 생성 context 질의와 실제 최초 라벨이 일치했다. 같은 라벨 `fsetxattr` 성공은 다른 타입으로의 relabel 권한을 의미하지 않는다. `ftruncate`는 기존 O_RDWR FD와 file:write를 사용하며 일반 setattr 권한이 추가로 필요하다고 가정하지 않았다. 실제 0444 생성 inode를 그 열린 RW FD로 확장하고 매핑했다.

고정 Android 16 r2 `prop_area`의 O_EXCL 생성, fsetxattr, ftruncate, MAP_SHARED writer, add와 별도 RO map/find 순서는 유지했다. Wrapper는 생성 직후 및 fsetxattr 직후 label이 모두 맞아야 truncate를 허용한다. RO 경로의 fstat 오류도 이제 syscall/errno로 보존한다. 기존 Bionic 초기화의 `properties_serial` ENOENT와 `sched_getscheduler` EACCES stderr는 여전히 관찰되지만 이번 성공 경로를 막지 않았다. 전체 Android 서비스 동작에 미칠 영향은 검증하지 않았다.

## 변경 파일과 검증

- `src/bin/ssal-guest-domain-poc.rs`: FD 정리, Parent exec/exit-stop 검사·결과 귀속, 오류 시 Host 사후 관찰, AV gate 및 Unix 회귀 시험 3개.
- `native/property-area-live-poc/main.cpp`: Guest의 전체 FD 열거 두 곳 제거; Parent 검사로 대체, Area close 유지.
- `native/property-area-live-poc/bionic_area.cpp`: 단계별 성공 증거, relabel 후 label 재확인, Bionic RO fstat 실패 기록.
- 이 보고서와 `guest-property-area-live-poc.md`, `proc-access-continuation-20261101.md`: 최신 결과 연결. 이전 사용자 변경은 유지했다.

`cargo fmt --all -- --check` 통과. 최종 Linux `cargo test --locked`는 **63 passed, 3 ignored**이며 런처 24개(새 Unix 시험 3개 포함)가 통과했다. 새 시험은 fdinfo parse 오류, 실제 stopped Child의 extra/missing FD·status flag mismatch·Host inode alias·공유 mount 정상 FD·죽은 Child 열거 실패, 실제 ptrace exit-stop의 FD table 가용성을 확인한다. [전체 결과](../out/property-fd-tests-20261101.txt).

Native FD/procfs 및 property label assert 시험을 `g++ -std=c++17 -Wall -Wextra -Werror`로 빌드·실행했다. Android AArch64 Rust release와 NDK static helper 빌드가 통과했고 helper에 PT_INTERP/NEEDED가 없다. [ELF 검사](../out/property-fd-elf-20261101.txt).

추가 `clippy -D warnings`는 기존 코드의 too_many_arguments 2곳, unnecessary_map_or 및 manual_is_multiple_of로 실패했다. 이 세 종류를 CLI에서만 제외한 런처 clippy는 통과했다. lint 설정과 관련 없는 기존 코드는 바꾸지 않았다. 이번 Windows cargo test는 로컬 registry cache 쓰기 권한으로 실행되지 않았으며 변경의 Unix 경로는 Linux에서 검증했다. ignored 3개는 Linux root/capability 전용 기존 시험이며 실행하지 않았다.

## 최신 바이너리와 정책

| Artifact | SHA-256 |
| --- | --- |
| Launcher | `2c7a35e632aad741b5ecc2397cb189b178c736ba64044bf7db26df8c27458dc1` |
| Helper | `bdab7c5f05f160c98041a092777632e354d70e184bb6c29a62dd27c9bf8a2415` |
| 실행 전후 live policy | `0a18e0177467b3d802ed985c5b25c755876263467120a0f4dfd27102985b6310` |

로컬 `out/bin`과 기기 `/data/local/tmp/ssal-proc-preflight-20261101` 값이 일치한다. 두 파일은 0755, staging 디렉터리는 0711, helper label은 `u:object_r:ssal_guest_probe_exec:s0`다. adb push가 mode/context를 기본값으로 바꾸어 기존 승인된 0755와 전용 helper 실행 label을 복구했다. 이는 정책 확장이 아니다. 기존 정책 규칙·permissive 상태와 boot ID `bd037ba2-9b84-438e-ae43-5717af227c53`는 유지됐다. KSU permissive flag는 1이므로 KSU 동작 성공을 KSU Enforcing 검증으로 해석하지 않는다.

재부팅, 새 정책 적용, Guest Property Service/전체 LineageOS 부팅과 One UI 복귀는 이번에 실행하지 않았다. 새 Live 실행은 이번 두 번의 개별 1회 승인에 포함되지 않는다.

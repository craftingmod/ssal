# Guest Property Area Android live PoC

최신 결과: [FD 격리와 Property Area Live 성공 — 2026-11-01](property-fd-area-success-20261101.md). Parent FD 검사와 Guest area 생성·fsetxattr·RW/RO mmap·add/find가 실기기에서 통과했다. 최신 hash·테스트·보장 범위는 이 후속 문서를 따른다. 아래는 이전 단계의 기록이다.

## selinuxfs 권한 적용 후 재시험

사용자 승인으로 현재 실행 정책에 `allow ssal_guest_probe selinuxfs file { open read }` 한 규칙을 적용했다. 적용 명령은 exit 0이고, 이후 읽기 전용 preflight에서 두 권한이 ALLOWED이며 전체 필수 검사가 통과했다. 이 권한은 `enforce` 파일 하나로 제한되지 않는다. [적용 기록](../out/property-selinuxfs-patch-20261101.txt), [preflight](../out/property-selinuxfs-post-preflight-20261101.txt).

승인된 Live를 한 번 재시험했다. Guest Enforcing과 별도 mount namespace 및 tmpfs property mount를 확인했고, 코드 진행상 전용 root 라벨 검사도 통과했다. 이전 `enforce` 접근 실패는 지나갔으나, area 생성 전 상속 FD 검사에서 `/proc/self/fd`를 열고 procfs를 확인한 뒤 `fdopendir`가 EACCES로 실패했다. 이 결과만으로 정확한 거부 원인은 확정할 수 없다. area 생성, fsetxattr, mmap, 값 읽기와 전체 FD 격리는 검증되지 않았다. [실행 기록](../out/property-selinuxfs-live-retry-20261101.txt).

Child PID 4953은 종료 코드 1로 회수됐고 사후 `/proc/4953`은 없었다. 실행 전후 주요 Host process identity, property mount identity 및 646개 파일 metadata는 일치했다. Property 파일 내용은 비교하지 않았다. 사후 전역 SELinux는 Enforcing이고 정책 SHA-256은 `0a18e0177467b3d802ed985c5b25c755876263467120a0f4dfd27102985b6310`이었다. 적용 전 정책 hash는 `22ebed301ddda5337c6b9cf1286bd4110ba35712e03f35e0f8a7485aca6b1b4e`다. 승인된 규칙은 현재 boot에 남아 있으며 child 종료만으로 namespace에 대한 모든 독립 참조가 없어졌다고 증명하지 않는다.

## 전용 Property Live 1회 실행 결과

사용자 승인 후 기기에서 한 번 실행했다. Child PID 4549는 mount namespace unshare, private propagation, tmpfs mount와 Guest exec에서 모두 errno 0을 기록했다. Parent exec-stop에서 Guest SID와 executable identity, Guest enforcing과 별도 mount namespace를 확인했고, Guest 자체 SID 조회도 성공했다. 그러나 Guest의 `/sys/fs/selinux/enforce` `openat`이 EACCES여서 Guest 자신의 전역 Enforcing 검사에서 종료했다. 따라서 root 라벨 검증, FD 검사, area 생성·fsetxattr·mmap·값 읽기에는 도달하지 않았다. Bionic 초기화의 `properties_serial` ENOENT도 관찰했지만 이 결과만으로 오류인지 판정하지 않는다. [실행 기록](../out/property-dedicated-live-20261101.txt).

Child 종료 코드는 1이고 wait에서 회수됐으며 이후 `/proc/4549`가 없었다. 실행 전후 주요 Host process identity, property mount identity 및 646개 파일 metadata는 같고 전역 Enforcing과 정책 hash가 유지됐다. Property 파일 내용은 확인하지 않았다. 당시 helper의 `cleanup=not_needed`는 mount 이후 main에서 실패해 실제 namespace 정리 상태를 반영하지 못하는 보고 오류였다. 수정 후 승인된 실행에서 namespace 검증 전 실패는 `namespace_teardown_unverified`를 보고한다. Child 종료와 회수만으로 독립적인 namespace 참조 전체의 부재를 확인했다고 주장하지 않는다.

실제 경로 라벨은 `/sys`, `/sys/fs`가 `sysfs`, `/sys/fs/selinux`와 `enforce`가 `selinuxfs`였다. Guest의 `sysfs dir:search`와 `selinuxfs dir:search`는 허용, `selinuxfs file:open/read`는 둘 다 거부였다. 런처의 preflight에 이 실제 라벨 검사와 네 AV를 추가해, [최신 기기 preflight](../out/property-live-fix-preflight-20261101.txt)가 두 file 권한 거부 시 child 생성 전에 중단하는 것을 확인했다. Windows/Linux 런처 단위 시험 각 21개, native 시험과 Android 재빌드가 통과했다. 최신 launcher SHA-256은 `189d0931dbc5d67643f0dcd30b3721ad347b9bfa94b3e34c5fe278ec948cd753`, helper는 `179b0df4b225b51d5a3416eb3c6c6338cdb5f0c2c57bb7dfa7c0ee220d630d87`이며 기기 값과 일치하고 helper 실행 라벨은 유지됐다. Guest enforcing 자체 확인이나 Guest SID 검사를 우회하지 않았다.

후속 정책 후보는 `allow ssal_guest_probe selinuxfs file { open read }`다. source는 `u:r:ssal_guest_probe:s0`, target은 `u:object_r:selinuxfs:s0`이며 `enforce` 한 파일에만 국한되지 않는다. 같은 SELinux 타입을 가진 다른 파일의 open/read도 DAC 및 별도 SELinux 검사에 따라 가능해질 수 있다. 후보는 아직 적용하지 않았으며 Property Area Live 추가 실행도 별도 승인 전에는 하지 않는다.

## 승인된 정책 적용 및 Live 직전 상태

사용자 승인으로 전용 디렉터리·area type과 `file_type` attribute, file type transition, Guest의 전용 dir/file allow 및 self dir open/read·self lnk_file read·helper file getattr을 현재 live 정책에 적용했다. 두 context와 생성 context가 유효하며 필수 AV가 모두 허용됨을 [기기 preflight](../out/property-policy-ready-preflight-20261101.txt)에서 확인했다. `dir:getattr` on Guest self는 추가하지 않았다. 기기 정책 SHA-256은 적용 전 `591b6588474b2a36e03d66179a5ce0cbd2ee902c0104f5478b159d7d9dc788bb`, 적용 후 `22ebed301ddda5337c6b9cf1286bd4110ba35712e03f35e0f8a7485aca6b1b4e`다. 전역과 Guest는 Enforcing이고 KSU는 permissive다. 전용 타입 적용 전후 주요 Host process identity와 property metadata inventory는 일치했다. Property 내용은 확인하지 않았다. 실효 정책 allow는 현재 boot에 남아 있다.

FD 검사의 proc 디렉터리 FD 자체를 fstat할 때 Guest self `dir:getattr` 거부가 차단 원인 후보임을 발견했다. 이 FD는 검사기가 직접 연 것이므로 `fstatfs`로 procfs임을 확인한 다음 그 FD만 제외하고 다른 모든 FD는 기존처럼 검사하도록 수정했다. procfs 확인 실패는 차단하며 필요한 `proc filesystem:getattr`은 preflight 필수 항목이다. `/dev/null` 실제 label과 Guest의 null chr_file:getattr, KSU pipe fifo_file:getattr 및 fd:use도 preflight에서 확인한다. 이것이 다른 Guest FD 전체의 성공이나 접근 격리를 증명하지는 않는다.

Windows/Linux 런처 시험 각 21개, procfs·FD 및 label native 시험, Rust 형식 검사, Android 런처와 helper 빌드가 통과했다. 기기에 staging된 런처 SHA-256은 `7fbabce8e9ac8bfe31c0c0f1436ae42ba39bbce78bee7d110a7dc2c37664336e`, helper는 `61ecc22ec8e2a84c71341d069880714840b5fc209cb0c76395949c1f1380522b`이며 로컬과 일치한다. helper에는 `u:object_r:ssal_guest_probe_exec:s0` 라벨이 있다. Property Area Live 및 mount/unshare는 아직 실행하지 않았고 별도 승인이 필요하다.

## 전용 Property 타입 코드 연결

런처는 tmpfs superblock을 기존 `u:object_r:tmpfs:s0`로 유지하면서 mount root에 `rootcontext=u:object_r:ssal_guest_property_dir:s0`를 요청한다. helper는 root의 실제 라벨이 전용 디렉터리 타입인지 확인한다. area 생성 전에는 selinuxfs의 읽기 전용 생성 context 조회 결과가 `u:object_r:ssal_guest_property_area:s0`인지 확인하고, Guest dir/file 권한과 두 전용 타입의 tmpfs `filesystem:associate`를 필수 조회한다. 범용 tmpfs dir 쓰기와 기존 Host property 타입 file 쓰기를 필수 권한으로 요구하지 않는다.

Bionic area 생성 wrapper는 새 파일의 초기 SELinux 라벨을 `fgetxattr`로 확인한다. 라벨이 다르거나 조회 및 후속 `fsetxattr`가 실패하면 `ftruncate`와 mmap을 진행하지 않는다. 성공 후에는 최종 area 라벨을 다시 확인한다. 이는 실제 type transition과 mount root 라벨을 대체하지 않는 실행 시 fail-closed 검사다. selinuxfs 생성 context 조회의 형식은 현재 기기에서 KSU/tmpfs 파일 생성 context를 읽어 Android libsepol의 오프라인 계산과 교차검증했다.

Windows와 Linux 런처 테스트 각 21개, 전용 라벨 및 FD 검사 native 시험, Rust 형식 검사, Android AArch64 런처 및 static helper 빌드가 통과했다. 새 런처 SHA-256은 `f907cae37e6eda4844f9d41502671b3c40a752c1cabef7e523c4d7d43a342a01`, helper는 `b7b91872b5fba712c1a71c3320c35a859eaaffbdd72a4bf4780528517e736854`이며 기기 값과 일치하고 helper 전용 실행 라벨을 복원했다.

[실기기 Property preflight](../out/property-dedicated-preflight-20261101.txt)는 현재 정책에 없는 `u:object_r:ssal_guest_property_dir:s0`에서 EINVAL로 중단됐다. Child 생성 및 mount는 실행되지 않았다. 이후 [Proc-Only preflight](../out/proc-dedicated-post-preflight-20261101.txt)에서 Host process identity와 property metadata의 전후 비교가 통과했고 전역 Enforcing과 이전 정책 SHA-256이 유지됐다. Property 파일 내용은 검사하지 않았다. 전용 타입 후보는 오프라인 복사본에서만 검증됐고 실제 rootcontext mount, Guest writer·FD 검사 및 정책 적용은 아직 별도 승인과 검증이 필요하다.

## 2026-11-01 전용 타입 오프라인 검토

실효 정책을 읽기 전용으로 저장했고 기기와 로컬 SHA-256이 `591b6588474b2a36e03d66179a5ce0cbd2ee902c0104f5478b159d7d9dc788bb`로 일치했다. 저장본에는 `ssal_guest_probe`와 기존 `ssal_guest_probe_exec`가 있고, 제안된 `ssal_guest_property_dir`, `ssal_guest_property_area`는 없다. `seinfo`는 저장본의 타입과 통계를 읽었으나 `sesearch`는 `Unknown extended permission: 3`으로 실패했고 `checkpolicy` CIL 변환은 `Unknown policy capability id: 9`에서 실패했다. 부분 출력은 분석 결과로 사용하지 않는다.

기존에 빌드한 Android 호환 libsepol을 이용하는 [읽기 전용 attribute 열거기](../native/selinux-offline-query/attribute_rules.c)로 이 제한을 일부 우회했다. `file_type`을 source 또는 target으로 직접 참조하는 저장 정책의 raw 규칙은 132개다: 일반 allow 118개, auditdeny 2개, 확장 권한 12개. [전체 결과](../out/property-file-type-rules-20261101.tsv). 예를 들어 `file_type → tmpfs filesystem:associate`와 `ksu → file_type file/dir`의 광범위한 allow, `domain → file_type`의 file/dir/lnk_file 확장 권한이 존재한다. `file_type`이 source인 규칙은 객체 타입을 process 도메인으로 쓰는 권한이라는 뜻이 아니다. auditdeny 마스크는 allow가 아니다. 확장 권한은 일반 ioctl 등 기본 권한이 있어야 효력이 있으며, 이 표는 raw 규칙이므로 각 도메인의 최종 허용 AV나 안전성을 뜻하지 않는다.

저장 정책의 기존 `ssal_guest_probe_exec → tmpfs filesystem:associate`를 Android libsepol AV 계산으로 조회해 허용을 확인했고 열거기 결과와 교차검증했다. 기존 타입이므로 새 타입의 실제 권한 증명은 아니다. 열거기 회귀 검사는 이 규칙과 KSU 규칙을 확인하고 존재하지 않거나 attribute가 아닌 이름을 거부했다. attribute 상속·constraint·role/MLS·실제 타입 추가 전후의 완전한 AV 차이 및 확장 권한의 실제 효과는 남았다. 저장본에는 neverallow 규칙이 없으므로 소스 정책의 neverallow 적합성도 증명하지 못한다. 분석 전후 기기 정책 hash는 같고 Enforcing이었다.

설치된 `ksud sepolicy check`는 아래 기존 후보의 두 type 선언, type_transition과 두 allow 문장을 각각 exit 0으로 파싱했다. 이는 구문 검사이며 타입 추가, AV 허용, rule 적용, constraint 통과 또는 mount 동작을 확인하지 않는다. `rootcontext=`와 fscontext의 실제 동작, KSU의 mount/relabel 권한, 전용 타입과 tmpfs filesystem의 실기기 `associate`, 새 inode의 최초 label, `fsetxattr`과 DAC는 미확인이다. 이후 전용 경로의 코드는 이 문서 첫 부분처럼 연결했지만 정책 적용과 실제 mount는 수행하지 않았다.

별도로 [오프라인 프로토타입](guest-property-area-prototype.md)은 AOSP serializer에서 반환된 exact/prefix context를 두 개의 독립 `prop_area`에 연결하고, 쓰기·재매핑·읽기·교차 부재 및 미등록 context 거부를 합성 fixture에서 확인했다. 고정된 시험용 매핑이며 Android Property Service나 기기 격리 검증은 아니다.

### Android 도구를 이용한 정책 복사본 시험

Android 호환 libsepol의 [변환기](../native/selinux-offline-query/policy_to_cil.c)와 CIL 지원 컴파일러를 작업 디렉터리에서 빌드해 저장 정책 전체를 CIL로 변환하고 재컴파일했다. 빌드에만 사용한 Debian bookworm flex 2.6.4-8.2는 [공식 패키지 SHA-256](https://packages.debian.org/en/bookworm/amd64/flex/download)을 확인한 뒤 로컬 디렉터리에 추출했다. 전역 설치는 하지 않았다. 원본은 type/attribute 5,510개·규칙 196,796개였고 왕복본은 5,470개·191,958개다. 세 Guest/파일시스템 AV 및 init·system_server·zygote의 대표 Host AV 여섯 개는 원본과 왕복본, 후보에서 일치했지만 이 표본은 전체 동등성을 증명하지 않는다.

[전용 타입 후보 CIL](../scripts/guest-domain-poc/property-area-candidate.cil)을 왕복 전 CIL에 추가해 **오프라인에서만** 컴파일했다. [회귀 검사](../scripts/guest-domain-poc/test-property-policy.sh)는 후보의 네 dir AV와 여덟 file AV, 두 타입의 tmpfs associate, Guest의 파일 생성 context가 `u:object_r:ssal_guest_property_area:s0`인 점, `untrusted_app:s0`의 대상 dir search 및 file read 거부를 확인했다. 타입별 role/MLS 또는 다른 도메인과 모든 범주의 전체 차분, neverallow 및 실기기 정책 로더의 적용 결과는 이 검사 범위 밖이다. 원본·왕복본·후보 바이너리 SHA-256은 각각 `591b6588474b2a36e03d66179a5ce0cbd2ee902c0104f5478b159d7d9dc788bb`, `c821f2b1b0df3784159d0ae5fbff442e288efbb4a0f4ab951a41e9d4d3194392`, `eab0c3ad1673954c779bc43b6e803f5f4b438c2b831f130706f7c7fabf8f4516`이다. 이 바이너리를 기기에 로드하면 안 된다.

## 2026-11-01 후속 안전 검사

기존 Proc-Only 실기기 시험에서 Guest self context 조회가 성공했다. 근거와 현재 boot에 적용된 정책은 [후속 기록](proc-access-continuation-20261101.md)을 따른다. 아래의 과거 `/proc` 원인 미확정 서술은 당시 기록이다.

Property helper의 실제 호출을 기준으로 preflight에 Guest self `dir:open/read`, `lnk_file:read`, Guest → helper 실행 파일 `file:getattr`을 필수 조회로 추가했다. 각각 `/proc/self/fd` 열거, proc 링크 조회 및 실행 파일 `fstat`에 필요한 후보이다. 런처는 이 가운데 하나라도 거부되거나 질의가 실패하면 기존과 같이 child 생성 전에 중단한다. 실제 각 proc inode의 라벨은 향후 별도 확인해야 하며 AV 조회만으로 모든 syscall 성공을 보장하지 않는다.

Android AArch64 런처를 다시 빌드하고 로컬·기기 SHA-256 `be00f435f7f1c1cfa8f93da08233255ea535af2fec60070b632983e7023be967`을 확인했다. Linux 및 Windows 런처 단위 테스트 각 20개와 Rust 형식 검사를 통과했다. [기기 Property preflight](../out/property-new-helper-preflight-20261101.txt)에서는 새 네 AV 모두 DENIED였으며, 기존 tmpfs/property 타입의 필수 거부와 함께 child 생성 전 차단됐다. Property 내용은 비교하지 않았다.

기존 `has_host_property_fd`는 경로 문자열이 `/dev/__properties__`로 시작하는 FD만 mount ID를 검사해 별칭을 놓칠 수 있었다. 이제 열거한 모든 FD를 `fstat`하고 Host property 디렉터리와 같은 `st_dev`이면 경로와 무관하게 차단한다. 조회 실패도 차단한다. 같은 파일시스템의 무관한 FD도 거부할 수 있는 보수적 검사이며, 다른 device에 노출된 복제나 다른 접근 경로 전체의 격리까지 입증하지 않는다. Linux 회귀 시험에서 원본·dup FD, 다른 device 값과 유효하지 않은 FD를 확인했다. 이 검사 자체의 Guest 실기기 실행 및 임의 FD의 `fstat`에 필요한 추가 AV는 아직 미검증이다. 전체 Host FD/socket 격리로 간주하지 않는다.

새 helper SHA-256 `9f2fd003b757c3f838b093a096a432054dcba4f1bdfacb36611da8af55cf4e3e`을 기기와 대조하고 전용 실행 라벨을 복원했다. [Proc-Only 실행](../out/proc-new-helper-device-20261101.txt)에서 새 executable dev/inode와 Guest SID를 Parent가 확인했고, Guest가 세 self context 경로를 모두 읽었다. Child가 회수되고 실행 전후 Host process와 property metadata, 전역 Enforcing이 유지됐다. Proc-Only는 FD 분리 검사나 Property Live를 실행하지 않는다.

**Property Area Live 검증은 미완료다.** 이 문서는 단일 Android 16 Bionic Property Area의 생성·라벨링·매핑·분리만 다룬다. 아래 과거 기록의 정책·실행 상태는 해당 시점 기준이다.

## 2026-11-01 진단 및 사전 검사 수정

### `/proc/thread-self/attr/current` 실패

기존 실기기 로그의 실패는 helper `current_identity()`가 실행한 첫 `openat`이다. 정확한 인자는 `pathname=/proc/thread-self/attr/current`, `dirfd=AT_FDCWD (-100)`, `flags=O_RDONLY|O_CLOEXEC (0x80000)`이며 결과는 `EACCES (13)`이다. `read()`에는 도달하지 않아 helper JSON의 `context`가 비어 있고 Guest SID는 확인되지 않았다.

기존 로그보다 앞선 `openat errno=2`는 pathname과 호출 위치가 없어 정상 fallback인지 판별할 수 없다. 수정된 helper와 Bionic wrapper는 자체 `openat` 실패에 stage, PID/TID, pathname, dirfd, flags, errno, SELinux context(확인된 경우)를 함께 기록한다. 처음 identity 조회가 실패하면 `/proc/thread-self`의 `readlink`와 `/proc` 경로 구성요소의 읽기 전용 `stat`도 남기며, 진단 중 errno가 바뀌어 최초 `openat` 결과를 덮지 않는다. 이전 ENOENT는 소급해서 확정할 수 없고, main 진입 전 런타임 syscall은 이 계측 범위 밖이다.

`/proc/thread-self`는 현재 thread를 가리키는 경로 별칭이며 `/proc/self/task/<tid>`로도 지정할 수 있다. `/proc/<pid>/attr/current`는 process leader, `/proc/<pid>/task/<tid>/attr/current`는 지정한 thread를 조회한다. 기존 KSU 자기 경로의 context/file label 결과를 Guest child에 일반화하지 않는다. 수정된 런처는 `PTRACE_EVENT_EXEC` stop에서 parent가 child의 PID/TID, starttime, 두 attr 경로의 내용과 file context, 실제 executable, mount namespace를 읽기 전용으로 기록한다. 조회 실패는 syscall·pathname·errno로 표시한다. 이 parent 관측은 helper 내부 SID 확인을 대신하지 않는다.

실패 syscall은 `openat()`이므로 `read()`까지 도달하지 않았다. Android common SELinux proc attr getter는 file read 시 실행되고, caller와 target이 같은 task면 `process:getattr` 검사를 건너뛴다([kernel source](https://android.googlesource.com/kernel/common/+/f0de70f8bb56952f6e016a65a8a8d006918f5bf6/security/selinux/hooks.c)). 따라서 기존 `Guest → Guest process:getattr` 거부는 자기 `openat()`의 직접 원인으로 볼 수 없다. parent가 child attr을 읽을 때는 caller가 다른 task이므로 `KSU → Guest process:getattr`이 참고 조회에 추가됐다. 실제 Guest `openat EACCES`는 경로상 `dir:search`, 파일 `open` 또는 DAC/커널 변형 중 무엇이 막혔는지 AVC와 syscall 세부 정보가 있어야 확정할 수 있다. 현재 기록에는 연결된 AVC가 없어 원인은 미확정이다.

기존 실기기 사전 조회에서 `u:r:ssal_guest_probe:s0 → u:r:ssal_guest_probe:s0 process:getattr`는 거부였다. 하지만 해당 거부와 실패한 `openat`을 연결하는 AVC는 수집되지 않았다. 이를 EACCES 원인으로 단정하지 않는다. 새 사전 조회는 `/proc`의 `dir:search`, `lnk_file:read`, target context의 디렉터리 탐색 및 `file:open/read/getattr`를 분리해 출력하며, `lnk_file:read`, `file:getattr`, target `process:getattr`는 참고 항목으로 취급해 미사용 권한을 차단 조건으로 삼지 않는다.

### Fail-Closed 사전 검사

AV 출력은 `ALLOWED`, `DENIED`, `QUERY_ERROR`와 `requirement=required|reference`를 구분한다. `/sys/fs/selinux/access`의 selinuxfs transaction은 `source_context target_context class_index` 세 필드를 받으며, permission mask는 입력하지 않고 class permission bit와 반환된 allowed mask를 비교한다. 이 형식은 [Linux selinuxfs 구현](https://github.com/torvalds/linux/blob/master/security/selinux/selinuxfs.c#L3430-L3504)에 맞춘 것이다. 기존 런처는 네 번째 permission mask도 썼으나 커널 구현의 입력 형식과 일치하지 않아 수정했다. 과거 shell 조회의 `EINVAL`은 실패 원문과 대상 커널 구현이 남아 있지 않아 이 불일치만으로 원인을 확정하지 않는다.

Guest가 Property Area를 직접 생성·라벨·매핑하는 필수 AV가 `DENIED` 또는 `QUERY_ERROR`면 전체 항목을 출력한 뒤 `fork` 전에 종료한다. 조회 실패는 정책 거부로 바꾸지 않고 허용으로 처리하지 않는다. 참고 항목의 거부나 조회 실패는 차단 조건이 아니지만, Guest Enforcing 상태를 확인하는 조회 자체가 실패하면 그 상태를 검증할 수 없어 종료한다. `process:getattr` 결과는 Guest 상태 확인 또는 parent-side 관측의 참고값일 뿐 Guest 자기 `openat()`의 원인 판정에 쓰지 않는다.

기존 로그에서 Guest Property 경로의 필수 거부는 다음과 같다.

- `tmpfs:dir`의 `write`, `add_name`
- `tmpfs:file`의 `create`, `open`, `read`, `write`, `relabelfrom`
- `vendor_ctl_port-bridge_prop:file`의 `relabelto`, `open`, `read`, `write`, `map`, `getattr`

`tmpfs:file getattr`도 거부로 조회됐지만 현재 Bionic 생성 경로에서 relabel 전 별도 getattr 호출이 없어 참고 항목으로 분류한다. `vendor_ctl_port-bridge_prop:filesystem associate → tmpfs`는 허용으로 조회됐다. 이 AV 질의는 실효 정책을 읽을 뿐 정책을 변경하지 않는다. KSU 쪽 성공했던 namespace/mount 작업은 재구현하지 않았으며 KSU 결과는 `ksu_permissive=1`인 상태에서의 참고 결과로만 취급한다. 이전 런처가 이 거부를 기록하고도 child를 실행한 동작은 수정했다.

### Guest Property 객체 경계 및 후속 규칙 후보

Android 16 r2 `prop_area::map_prop_area_rw()`는 `O_RDWR|O_CREAT|O_NOFOLLOW|O_CLOEXEC|O_EXCL`로 파일을 직접 생성한 뒤 `fsetxattr`, `ftruncate`, writer `mmap`을 수행한다. 따라서 KSU가 시험 파일을 미리 만들면 현재 Bionic 경로는 `EEXIST`로 끝난다. Guest의 쓰기·읽기 매핑과 `add/find`를 검증하려면 사전 파일 생성 방식은 같은 시험을 만족하지 않는다. 디렉터리만 사전 생성해도 Guest의 파일 생성 권한은 여전히 필요하다. KSU가 파일을 준비하고 Guest가 read-only `map_prop_area()`만 호출하는 별도 시험은 가능하지만, Guest writer 시험과는 다르다.

현재 방식의 범위를 줄일 후보는 Guest 전용 tmpfs 디렉터리/파일 타입이다. tmpfs는 `security.*` extended attribute를 지원하고, 인용한 AOSP 정책은 `file_type` 속성이 있는 타입에 `tmpfs:filesystem associate`를 이미 허용한다. 그러므로 전용 타입에 `file_type`을 붙일 경우 후보 규칙에 타입별 중복 `associate` allow를 추가하지 않는다. SM-S937N의 현재 정책과 mount의 `rootcontext=` 지원은 확인되지 않았고, 새 타입을 실제로 라벨하거나 `fsetxattr`하지 않았다. 실제 적용 전 타입별 실효 AV와 mount 라벨링 방식을 읽기 전용으로 확인해야 한다. [Linux tmpfs 문서](https://www.kernel.org/doc/html/latest/filesystems/tmpfs.html)와 [AOSP의 tmpfs associate 규칙](https://android.googlesource.com/platform/system/sepolicy/%2B/069435505e292bb6d96a7f37b1c6d68c0a754033/public/file.te)를 근거로 한 설계 후보이지, 이 장치에서 검증된 동작은 아니다.

후속 승인 시 검토할 최소 규칙 형태는 아래와 같다. mount root에는 전용 디렉터리 context를 주고 새 파일에는 `type_transition`으로 전용 area type을 부여하며, helper의 `kPropertyContext`도 전용 area type으로 바꿔야 범용 tmpfs 파일 라벨에 접근하지 않는다.

```te
type ssal_guest_property_dir, file_type;
type ssal_guest_property_area, file_type;
type_transition ssal_guest_probe ssal_guest_property_dir:file ssal_guest_property_area;

allow ssal_guest_probe ssal_guest_property_dir:dir { getattr search write add_name };
allow ssal_guest_probe ssal_guest_property_area:file { create getattr open read write map relabelfrom relabelto };
```

`/proc` 관련 후속 후보는 다음과 같이 거부가 실효 AV에서 확인된 권한만 검토한다. `lnk_file:read`는 현재 참고 항목이다.

```te
allow ssal_guest_probe proc:dir search;
allow ssal_guest_probe ssal_guest_probe:dir search;
allow ssal_guest_probe ssal_guest_probe:file { open read };
# lnk_file:read는 실제 거부/경로 요구가 확인될 때만 추가 검토
```

위 규칙은 적용하지 않는다. AVC가 없는 현재 기록으로 `process:getattr` allow는 후보에 넣지 않는다. 영향 범위는 Guest probe 도메인과 전용 private tmpfs root/file 두 타입으로 한정하며 `allow ssal_guest_probe tmpfs dir write;` 같은 범용 권한은 후보에서 제외한다.

실기기에서 수정된 selinuxfs AV transaction과 parent-side proc 관측은 아직 실행하지 않았다. 새 mount, tmpfs, Guest helper 실행, 정책 변경, 재부팅도 수행하지 않았다. 다음 읽기 전용 preflight에서 각 proc 경로별 AV 결과와 `QUERY_ERROR` errno를 받아야 한다.

Linux LSM UAPI에는 [`lsm_get_self_attr(LSM_ATTR_CURRENT, ...)`와 `struct lsm_ctx`](https://github.com/torvalds/linux/blob/master/include/uapi/linux/lsm.h#L398-L527)가 있고 upstream generic syscall table은 syscall 번호 [459](https://github.com/torvalds/linux/blob/master/tools/include/uapi/asm-generic/unistd.h#L3487-L3489)를 할당한다. 하지만 Android NDK/Bionic wrapper와 이 장치 커널의 syscall 지원은 확인되지 않았고, syscall ABI를 직호출하는 대체 경로는 구현하지 않았다. 검증된 Android 헤더/ABI와 대상 기기의 read-only 지원 확인이 먼저 필요하다.

## 이전 도메인 전환 결과

기존 SIGSEGV 차단 판정은 오래된 기록이다. 이후 실기기에서는 ssal_guest_probe Enforcing 전환, PTRACE_EVENT_EXEC, Child의 실제 SID u:r:ssal_guest_probe:s0, Bare ELF 종료 코드 42가 확인됐다. 당시 실행 파일 file:map/read/execute/entrypoint 등 필요한 전환 AV도 허용됐고 전역 SELinux Enforcing이 유지됐다.

이번 실행은 이 성공 실험을 별도 Bare ELF로 반복하지 않는다. 실행 직전에 런처가 현재 부팅의 전환 AV, Guest permissive 상태, policy sequence 및 전역 Enforcing을 읽기 전용으로 다시 확인한다. 정책은 재적용하거나 수정하지 않는다.

## 실행 흐름

### KSU 제어 영역

런처는 u:r:ksu:s0에서 다음을 수행한다.

1. /dev/__properties__ 디렉터리의 device/inode/mount ID와 Host mount namespace를 기록한다. init, Zygote, system_server, surfaceflinger, servicemanager의 PID·starttime·SELinux context·exe도 실행 전후 비교한다.
2. selinuxfs/context에서 시험 파일 context와 tmpfs context를 검증하고, 실행 파일·mount namespace·mount·Guest 파일 작업에 필요한 정확한 AV를 조회한다.
3. 전용 child에서 unshare(CLONE_NEWNS) 후 /의 propagation을 recursive private으로 바꾸고, 해당 namespace에서만 /dev/__properties__에 tmpfs를 마운트한다.
4. 기존의 검증된 execveat() 경로로 Guest Enforcing SID에 진입한다. Namespace 준비 syscall의 실패는 trace에 syscall 이름과 errno를 남긴다.

KSU child는 원본 Host 경로 identity를 환경값으로 넘긴다. 기존 Host Property 경로를 열어 쓰거나 파일·라벨을 만들지 않는다.

### Guest Enforcing 영역

Guest helper는 실제 SID와 전역 Enforcing을 확인한 다음:

- Host namespace와 다른 mount namespace, tmpfs filesystem, u:object_r:tmpfs:s0 root label 및 Host와 다른 mount ID를 확인한다.
- 새 tmpfs에서 ssal_guest_probe.area가 아직 없는지 확인하고 Android 16 r2 Bionic prop_area의 map_prop_area_rw, fsetxattr, writer mmap, add, 별도 read-only map_prop_area 및 find를 실행한다.
- ssal.guest.poc=guest-area-ok, 128 KiB 크기, 시험 라벨 u:object_r:vendor_ctl_port-bridge_prop:s0, 파일 inode/device/mount ID를 기록한다.
- Guest에 상속된 Host Property FD가 없는지 확인한다. execveat는 이전 주소 공간을 교체하며 launcher는 표준 출력·오류와 trace 외 FD를 close-on-exec 처리한다.

child가 종료되면 그 child만 소유한 mount namespace와 tmpfs가 함께 해제된다. 런처는 종료 뒤 Host 디렉터리 identity/mount ID와 주요 Host PID가 그대로인지 확인한다.

Host Property Area 내용의 read-only 교차검사는 다음 단계에서 추가한다. 먼저 기존 디렉터리 안의 실제 area 파일 하나와, 실행 중 바뀌지 않는 `ro.*` 대표 속성의 연결을 읽기 전용으로 확인한 뒤 file device/inode/size/mount ID/SELinux label과 속성 이름·값을 실행 전후 비교한다. area 전체 바이트 해시는 값 갱신으로 달라질 수 있으므로 참고 정보로만 출력하고 단독 실패 조건으로 쓰지 않는다. digest가 달라지면 같은 identity에서 대표 속성을 다시 읽어 일시 변동과 경계 변경을 나눈다. 실제 파일 선택과 안정적인 대표 속성은 아직 기기에서 검증하지 않았고, 이 검사는 구현·실행되지 않았다.

## SELinux 확인 범위

| 주체 | 사전 조회 | 구분 |
|---|---|---|
| KSU 제어 영역 | capability:sys_admin, root 및 /dev 탐색, root·property mountpoint dir:mounton, tmpfs filesystem:mount/relabelfrom/relabelto | 참고; 기존 성공 경로를 재검사하며 KSU permissive 상태를 함께 기록 |
| Guest Property 작업 | 경로 탐색, tmpfs 디렉터리 생성, 파일 생성/열기/읽기/쓰기/relabel, property 파일 open/read/write/map/getattr, filesystem:associate | 필수; 하나라도 거부되면 child 생성 전 중단 |
| Guest `/proc` context 확인 | proc 디렉터리 및 self 경로 search, self 파일 open/read, `lnk_file:read`와 getattr 후보 | Guest self 경로의 search/open/read는 필수; symlink read/getattr와 parent의 `KSU → Guest process:getattr`은 참고 |
| Guest 실행 상태 조회 | `Guest → Guest process:getattr` 응답의 permissive flag | 참고; upstream proc attr getter는 self read에서 `process:getattr`을 검사하지 않음. 실제 openat 실패 원인으로 간주하지 않음 |
| Guest 실행 | process:setexec/transition, helper file:open/read/getattr/execute/map/entrypoint | 필수; 모두 읽기 전용 AV 조회 |

Guest AV 목록에는 capability:sys_admin 또는 filesystem:mount를 요청하지 않는다. 정책에 allow를 추가하지 않는다. ksu_permissive 상태도 실행 기록에 남긴다. KSU가 permissive라면 KSU의 syscall 성공은 KSU 도메인에서 정책이 enforcing 됐다는 증거가 아니다. Guest 도메인은 permissive면 런처가 거부한다.

AV 조회 결과와 syscall 실패 시 최초 syscall/errno를 보고한다. 이전 실기기 실행은 거부된 AV를 출력한 후 child를 실행했지만, 현재 코드는 필수 거부 전체를 모아 child 생성 전에 중단한다. 정책 변경, fallback filesystem, 라벨 변경 또는 permissive 전환은 수행하지 않는다. fsetxattr 실패도 그대로 기록한다.

시험 라벨은 기존에 검증한 SELinux 타입을 재사용하는 PoC 전용 라벨이며 SSAL 정식 Property Context 선언이 아니다. Property Service는 실행하지 않는다.

## 빌드와 오프라인 검증

아래는 Proc-Only 분리 전 빌드 기록이다. 최신 테스트 수, 바이너리 hash와 staging 절차는 [후속 빌드 기록](#2026-11-01-proc-only-후속-빌드)을 따른다.

- `cargo fmt --all -- --check`: 통과.
- `cargo test --locked`: 51개 통과, Linux capability/root가 필요한 테스트 3개는 ignored.
- `cargo check --locked --target aarch64-linux-android`: 통과.
- `bun run build:windows`: 성공. Android AArch64 Rust release와 `out/ssal-module.zip`을 생성했다.
- `scripts/build-rust/build-property-area-live-poc.sh`: 빌드 컨테이너의 Android NDK로 성공. Android API 29, 고정된 Android 16 r2 Bionic 소스를 사용했다. ELF는 AArch64 static executable이며 `PT_INTERP`와 동적 `NEEDED` 항목이 없다.
- 새 Native Helper SHA-256: `0cc7954ee328fa35ecc8527ece611b2153d34c241da61146228bf158072cdd85`.
- 이번 `--dry-run`은 Linux host target에서 실행했고 `exec=not_run`, `policy=unchanged`를 출력했다. 기기에는 새 바이너리를 올리지 않아 기기 dry-run은 실행하지 않았다.
- 읽기 전용 SM-S937N 확인: SELinux `Enforcing`, kernel `6.6.127-android15-8-p87b1ce1-abogkiS937NKSSBDZJ2-4k`; adb shell의 현재 context는 `u:r:ksu:s0`이고 `/proc/thread-self/attr/current` 및 `/proc/thread-self` 조회가 성공했다. 이는 KSU self 경로만 확인하며 Guest 권한이나 Guest EACCES 원인을 증명하지 않는다. `/data/local/tmp`에는 새 런처/헬퍼가 없었다.
- 이전 승인 Helper hash `9a7f81d1f28f77985f026cac2acdb2bb790df48196d6fc3a16b3857c62628f5a`는 과거 실행 기록에만 해당한다. 현재 바이너리는 위의 새 hash이며 이전 승인 hash를 재사용하지 않는다.
- 오프라인 Bionic/AOSP prototype의 serializer exact/prefix 조회와 prop_area add/find/remap 검증은 기존 기록이다.

Host Property 파일과 안정적인 `ro.*` 속성의 read-only 대조는 설계만 기록했다. 대표 파일 선택 및 digest 기반 검사는 구현하거나 실기기에서 실행하지 않았다.

## 실기기 재시험 승인 준비

이전 빌드의 런처/헬퍼 hash와 `--property-area-preflight` staging 절차는 폐기했다. 최신 바이너리 hash 및 현재 staging, Proc-Only preflight, 별도 child 실행 안내는 아래 [Proc-Only 후속 빌드](#2026-11-01-proc-only-후속-빌드)를 따른다. Property Area Live는 여전히 별도 승인 단계이며, 이 문서의 과거 live 실행 기록은 당시 결과로 유지한다.

### 2026-11-01 실기기 실행 결과

SM-S937N에서 승인된 helper의 SHA-256과 전용 실행 라벨을 확인하고 런처를 한 차례 실행했다. Guest 전환 AV는 허용, Guest permissive flag는 0이었지만 `Host process snapshot missing zygote`로 사전 검사에서 종료 코드 1을 반환했다. 따라서 child 생성, tmpfs mount, Guest 전환 및 Property Area 작업은 실행되지 않았다. 출력은 [실행 기록](../out/property-area-live-device-20261101.txt)에 남겼다.

기기의 PID 1765는 `/proc/1765/comm`이 `main`이고 cmdline이 `zygote64`였다. 당시 검사는 `main`의 cmdline에 `--zygote`가 있어야 하므로 이 프로세스를 인식하지 못했다. 검사를 우회하거나 정책을 변경하지 않았다. 전용 임시 파일은 제거했고, 이후 전역 Enforcing과 부팅 ID `bd037ba2-9b84-438e-ae43-5717af227c53`를 확인했다. init, servicemanager, zygote64, surfaceflinger, system_server는 종료 후 관찰됐다. 실행 전후 자동 비교는 완료되지 않았다.

### 2026-11-01 Zygote 탐지 수정 후 재실행

`comm=main`, NUL로 끝나는 `argv[0]=zygote64`, `/system/bin/app_process64` 조합을 탐지하도록 고쳤고, Host 비교에 PID·starttime·SELinux context·exe를 포함했다. 회귀 테스트 9개, Android AArch64 check와 전체 release build, Rust 형식 검사를 통과했다. 런처 SHA-256은 `0c9a6ceeb81175d0d8180b25daa4b52488f09d6efcb085124c997c3e7e0ac221`, helper는 기존 승인 해시와 일치했다. 변경 없는 dry-run과 읽기 전용 Host 스냅샷이 성공했으며 Zygote는 PID 1765, starttime 627, `u:r:zygote:s0`, `/system/bin/app_process64`였다.

한 차례 실행 결과 child PID 15448의 `unshare`, private propagation 설정과 tmpfs mount는 errno 0, `execveat` 후 helper main 진입을 기록했다. 그러나 helper의 `/proc/thread-self/attr/current` 읽기 `openat`이 errno 13 (`EACCES`)으로 실패하여 Guest SID와 Guest mount namespace를 검증하지 못했다. stderr에는 이보다 앞서 경로가 기록되지 않은 `openat` errno 2도 출력됐다. 이 기록만으로 errno 2의 경로와 원인은 확정할 수 없다. Guest SID가 보고되기 전에 종료됐으므로 `fsetxattr`, writer/read-only `mmap`, add/find, Guest 측 Host FD 분리 검사는 실행되지 않았다.

사전 AV 조회에서 Guest `tmpfs dir:write`가 최초 거부였고 `dir:add_name`, 파일 생성·접근·relabel 및 property 타입 파일 접근도 거부였다. Guest `process:getattr`도 거부였지만, 수집한 로그에 이 `openat`과 연결된 AVC는 없어 실패의 정확한 SELinux 원인은 확정하지 않는다. KSU는 permissive flag 1, Guest는 0이었으며 전역 Enforcing이 유지됐다. 정책은 변경하지 않았다. 전체 출력은 [재실행 기록](../out/property-area-live-device-retry-20261101.txt)에 있다.

Host mount namespace `mnt:[4026532950]`, property 디렉터리 device 18·inode 118·mount ID 42와 다섯 Host 프로세스 identity는 실행 전후 동일했다. child는 회수됐고 전용 임시 파일을 제거했다. child만 소유한 namespace는 종료 시 해제되는 구조이나 별도 namespace 목록으로 해제를 확인하지는 못했다. 재부팅은 하지 않았다. Property Area 검증은 미완료다.

### 2026-11-01 Proc-Only 후속 빌드

아래 내용이 이 문서 앞부분의 오래된 런처/헬퍼 해시와 `--property-area-preflight` 실행 안내를 대체한다. 이전 기기 실행 기록은 과거 결과로 유지한다.

Proc-Only 경로는 Property Area Live와 독립적이다.

- `--proc-only-preflight <helper> --sha256 <hash>`는 KSU 영역에서 전역 Enforcing, Guest permissive flag, 필요한 transition AV, helper 해시·ELF·실행 권한·SELinux label을 읽고 Host snapshot을 비교한다. child를 만들거나 mount를 시도하지 않는다. Property Area 권한은 참고 출력일 뿐 gate가 아니다.
- `--proc-only-after-approval <helper> --sha256 <hash>`는 별도 승인 뒤에만 Guest child를 실행한다. child에는 mount/unshare와 Property Area 작업 경로가 없다. parent는 `PTRACE_EVENT_EXEC` 정지 상태에서 PID/starttime, Guest SID, 실행 파일 identity·label, namespace 및 Enforcing 상태를 검증하고, 검증 실패 시 child를 계속 실행하지 않는다.
- Helper는 `/proc/thread-self/attr/current`, `/proc/self/attr/current`, `/proc/self/task/<tid>/attr/current`를 독립적으로 열어 결과와 errno를 보존한다. `/proc` 경로 구성요소 stat/readlink는 읽기 전용이다. parent는 가능할 때 `/dev/kmsg`를 read-only/nonblocking으로 열고 새 기록에서 child PID·Guest SID·관련 proc AVC만 상관 분석한다. 이 reader의 cursor만 이동하며 global ring을 지우지 않는다 ([Linux `/dev/kmsg` ABI](https://github.com/torvalds/linux/blob/master/Documentation/ABI/testing/dev-kmsg)). AVC가 없거나 읽을 수 없다는 사실은 SELinux 원인을 배제하지 않으며, 경로 실패 증거가 없으면 결과는 `UNDETERMINED`다.
- Host snapshot은 Property 디렉터리 identity와 파일별 metadata/context inventory, 주요 Android 프로세스 identity를 실행 전후 비교한다. Property 파일 내용은 읽지 않으며 내용 무결성은 확인하지 않는다.

오프라인 검증 결과:

- `cargo fmt --all -- --check`: 통과.
- `cargo test --locked`: 24개 통과 (lib 4, 런처 20).
- `bun run build:windows`: Android AArch64 release와 모듈 패키징 성공.
- `scripts/build-rust/build-property-area-live-poc.sh`: AArch64 static helper 성공. `PT_INTERP`와 동적 `NEEDED` 항목이 없는지 빌드 스크립트가 확인했다.
- 로컬 `cargo run --locked --bin ssal-guest-domain-poc -- --dry-run`: `exec=not_run`, `policy=unchanged`.
- 현재 런처 SHA-256: `52f971a73919a0a4895e0b9a8b53d759e49c4abe22f4381d2c7c9a05f857602a`.
- 현재 Helper SHA-256: `f19b8b416c30060f0f058418503365a1ac09fe7befeefe0167ef9b642d97ff08`.

SM-S937N 기기 `R5CY52JC03H`에 대한 staging과 read-only Proc-Only preflight를 승인받아 실행했다. 다음 staging 명령은 성공했고 두 기기 hash가 빌드 결과와 일치했다. helper label은 변경하지 않았다.

~~~sh
adb.exe -s R5CY52JC03H shell mkdir -p /data/local/tmp/ssal-proc-preflight-20261101
adb.exe -s R5CY52JC03H push out/bin/ssal-guest-domain-poc /data/local/tmp/ssal-proc-preflight-20261101/ssal-guest-domain-poc
adb.exe -s R5CY52JC03H push out/bin/ssal-property-area-live-poc /data/local/tmp/ssal-proc-preflight-20261101/ssal-property-area-live-poc
adb.exe -s R5CY52JC03H shell chmod 0755 /data/local/tmp/ssal-proc-preflight-20261101/ssal-guest-domain-poc /data/local/tmp/ssal-proc-preflight-20261101/ssal-property-area-live-poc
adb.exe -s R5CY52JC03H shell toybox sha256sum /data/local/tmp/ssal-proc-preflight-20261101/ssal-guest-domain-poc
adb.exe -s R5CY52JC03H shell toybox sha256sum /data/local/tmp/ssal-proc-preflight-20261101/ssal-property-area-live-poc
~~~

읽기 전용 preflight는 아래처럼 remote shell에서 인자를 명시적으로 전달해야 한다. `adb shell <launcher> --proc-only-preflight ...` 직접 형식은 `usage`를 반환했다.

~~~sh
adb.exe -s R5CY52JC03H shell 'set -- --proc-only-preflight /data/local/tmp/ssal-proc-preflight-20261101/ssal-property-area-live-poc --sha256 f19b8b416c30060f0f058418503365a1ac09fe7befeefe0167ef9b642d97ff08; exec /data/local/tmp/ssal-proc-preflight-20261101/ssal-guest-domain-poc "$@"'
~~~

기기 해시 확인 결과는 launcher `52f971a73919a0a4895e0b9a8b53d759e49c4abe22f4381d2c7c9a05f857602a`, helper `f19b8b416c30060f0f058418503365a1ac09fe7befeefe0167ef9b642d97ff08`였다. Preflight는 global Enforcing, KSU caller, 두 ELF의 AArch64 형식·0755 mode와 hash를 통과한 뒤 종료 코드 1로 중단됐다. 두 파일의 기기 label은 `u:object_r:shell_data_file:s0`였지만 helper에는 `u:object_r:ssal_guest_probe_exec:s0`가 필요하다. 따라서 AV 검사와 Host snapshot까지 도달하지 않았고 child나 mount도 만들지 않았다. label·policy를 바꾸지 않았다.

helper가 이미 요구된 label을 받는 경로에서 staging되어 preflight를 통과한 뒤에도 **별도 Guest child 실행 승인**이 필요하다. 현재 label 상태에서는 아래 명령을 실행하지 않는다.

~~~sh
adb.exe -s R5CY52JC03H shell 'set -- --proc-only-after-approval /data/local/tmp/ssal-proc-preflight-20261101/ssal-property-area-live-poc --sha256 f19b8b416c30060f0f058418503365a1ac09fe7befeefe0167ef9b642d97ff08; exec /data/local/tmp/ssal-proc-preflight-20261101/ssal-guest-domain-poc "$@"'
~~~

`--property-area-live-after-approval`는 이 Proc-Only 승인에 포함되지 않으며, Property Area Live는 별도 명시 승인이 필요하다. staging/preflight 동안 policy, allow rule, permissive 상태, file context를 수정하지 않고 reboot도 하지 않았다.

# Guest ashmem / memfd 조사 및 수정 — 2026-11-17

Guest 전용 `/dev`에서 boot ID가 붙은 ashmem 장치를 누락한 것이
attempt112의 `ApplicationSharedMemory.nativeCreate()` 실패 원인이다.
Guest 전용 장치 inode를 추가한 뒤 메모리 생성·매핑·프로세스 간 공유·보호
검사가 통과했고, attempt113에서 기존 SystemServer Framework 진입 및
5초 생존 검증도 통과했다. Host property, 장치 노드, SELinux 정책과
Enforcing 상태는 변경하지 않았다.

실기기는 **Lenovo TB320FC / HA1WAQ7P**이다. 목표인 잠긴 삼성 순정 커널의
검증 결과로 확대 해석하지 않는다. 증거 루트는
`out/guest-ashmem-20261117/`이다.

## 선택 조건과 호출 경로

확인한 호출 경로:

1. `SystemServer.run()` → `ApplicationSharedMemory.create()` →
   JNI `nativeCreate()` → `ashmem_create_region()`.
   Lineage 소스의 `SystemServer.java:1024`,
   `ApplicationSharedMemory.cpp:164-170`에 해당한다.
2. JNI `nativeMap()`은 `MAP_SHARED`로 매핑하고,
   읽기 전용 FD 생성 경로는 `ashmem_set_prot_region(PROT_READ)`을 사용한다.
3. `android.os.SharedMemory` JNI의 생성/보호도 같은 libcutils API를 사용한다.
   Binder `MemoryHeapBase` 역시 `ashmem_create_region()`을 사용한다.
   `MemoryFile`의 pin/get-size는 libcutils의 pin/size API를 사용한다.

관련 일차 소스:
[ApplicationSharedMemory JNI](https://github.com/LineageOS/android_frameworks_base/blob/lineage-23.2/core/jni/com_android_internal_os_ApplicationSharedMemory.cpp),
[SharedMemory JNI](https://github.com/LineageOS/android_frameworks_base/blob/lineage-23.2/core/jni/android_os_SharedMemory.cpp),
[MemoryHeapBase](https://github.com/LineageOS/android_frameworks_native/blob/lineage-23.2/libs/binder/MemoryHeapBase.cpp).
조사 시점의 소스 사본을 증거 루트에 보관했다.

**AOSP Android 16과 실제 GSI 구현을 구분해야 한다.**

- [AOSP android16-release](https://android.googlesource.com/platform/system/core/+/android16-release/libcutils/ashmem-dev.cpp)는
  `ro.treble.enabled=true`와 `sys.use_memfd=true`를 요구한다.
  둘 다 기본값은 false다. 이후 `memfd_create(MFD_CLOEXEC | MFD_ALLOW_SEALING)`,
  `F_ADD_SEALS(F_SEAL_FUTURE_WRITE)`, 페이지 크기 `ftruncate`,
  `ioctl(ASHMEM_GET_SIZE)`의 크기 일치를 검사한다. 하나라도 실패하면 ashmem을
  선택한다. 지원 판정은 프로세스별 static 값으로 캐시된다.
- [Lineage 23.2](https://github.com/LineageOS/android_system_core/blob/lineage-23.2/libcutils/ashmem-dev.cpp)의
  해당 구현은 Treble property gate를 제거했고, 나머지 조건을 검사한다.
  로컬 GSI에서 추출한 실제 ELF도 `sys.use_memfd`만 참조한다.
  `libcutils-disassembly.txt:5935`의 `has_memfd_support()`에서 property 판정,
  syscall 279, seal 0x10, truncate, ioctl 0x7704 순서를 확인했다.
  `ashmem_create_region`은 주소 0x124cc에 있다.
- 추출 ELF: SHA256
  `57dbcfe913e23525ee221e2337a3405b36773b3a0800853b8b91181d3cfe2dbb`,
  Build ID `3c5853e8f013efff6bcc23a06eadf57d`.
  입력은 `out/LineageOS-23.2-20260524-VANILLA-EXT4-GSI.img`이며 vendor는 읽지 않았다.
- ashmem 경로는 `/dev/ashmem`에 `/proc/sys/kernel/random/boot_id`를 trim한 값을
  **구분자 없이** 붙인 경로다. 일반 `/dev/ashmem`으로 재시도하지 않는다.
  실제 GSI는 이 경로를 먼저 `stat()`한 다음 `open(O_RDWR | O_CLOEXEC)`한다.
  따라서 attempt112의 `Unable to stat ashmem device`와 일치한다.

## 수정 전 실측과 원인 분류

추가 부팅 전에 `SSAL_ASHMEM_PROBE=1`과 `--guest-service-worker`로
private property service 및 메모리 진단만 실행했다. 이 경로는
Zygote/SystemServer를 시작하기 전에 반환한다.

| 항목 | Host | 수정 전 Guest |
| --- | --- | --- |
| `ro.treble.enabled` | `true` | `true` |
| `sys.use_memfd` | `false` | 빈값, bool 기본 false |
| `memfd_create` | 성공 | 성공 |
| `F_SEAL_FUTURE_WRITE` | 성공, seal=16 | 성공, seal=16 |
| 페이지 크기 truncate | 성공 | 성공 |
| memfd `ASHMEM_GET_SIZE` | `-1 / ENOTTY(25)` | `-1 / ENOTTY(25)` |
| `/dev/ashmem` stat/open | 성공 | `ENOENT(2)` |
| `/dev/ashmem<boot_id>` stat/open | 성공 | `ENOENT(2)` |
| Guest libcutils 지원 판정 | 해당 없음 | `has_memfd_support=0` |
| libcutils 메모리 생성 | 해당 없음 | `-1 / ENOENT(2)` |

증거: `host-kernel-probe.txt`, `baseline/worker.log:212-228`.
Guest 진단은 uid=1000, `u:r:ssal_p0001_shell:s0`에서 실행했다.
Guest build.prop에는 `ro.treble.enabled=true`가 있으며,
실제 launcher의 private property 입력은 `/system/build.prop`과 Guest override다.
`sys.use_memfd`를 Host에서 가져오거나 임의로 true로 설정하지 않았다.

분류 결과:

- **Property 판정:** 빈 Guest `sys.use_memfd`는 false로 해석된다. Host의 명시적
  false와 표현은 다르지만 둘 다 ashmem 선택이다. 수정 대상이 아니다.
- **memfd 호환성:** memfd/sealing 지원만으로 Android libcutils의 조건을
  충족하지 못한다. 이 커널의 ashmem-on-memfd ioctl은 ENOTTY다.
  property를 true로 강제해도 정상 검사에서는 ashmem으로 돌아간다.
- **장치 경로:** 기존 private `/dev`는 null/zero/random/urandom만 구성했다.
  필요한 boot ID 장치가 없는 것이 직접 원인이다.
- **SELinux:** 기존 실패는 EACCES가 아니라 ENOENT다. 수정 후 기존 mapped
  `ashmem_libcutils_device` 타입만으로 접근에 성공했다. 추가 정책은 필요 없었다.

기존 실패 증거: `out/guest-first-boot-20261116/attempt112/stderr.log:670-696`,
Guest 로그 시각 `11-16 17:18:15.615`.
동 로그 `:166`의 ART `memfd.cc` 메시지는 libcutils의 지원 판정 성공을 의미하지 않는다.

## 수정 파일과 범위

- `src/guest_mounts.rs`: mapped Guest worker에만 boot ID ashmem **전용 inode**를
  만든다. kernel boot ID 형식을 검사하고 Host 일반/boot ID 노드가 동일한
  character device인지 및 root:root 0666인지 확인한다. major/minor는 Host에서
  확인한 값을 사용한다. Guest 노드에 기존 mapped
  `u:object_r:ssal_p0001_ashmem_libcutils_device:s0`를 적용한다.
  Host inode를 bind/relabel하지 않는다. boot ID 경로 검사 단위 테스트를 추가했다.
- `src/guest_launcher.rs`: 부팅 없이 진단할 수 있는 `SSAL_ASHMEM_PROBE` 경로.
  private property service 이후 helper를 실행하고 서비스 본 실행 전에 반환한다.
- `native/binder-probe/ashmem-probe.c`: 실제 Guest libcutils를 dlopen하고 property,
  경로별 stat/open errno, memfd/sealing/ioctl을 기록한다. assert로 메모리 크기,
  mmap, fork 후 FD 재매핑과 양방향 데이터 가시성, 보호 변경을 검증한다.
  `--kernel-only`는 Host property나 정책 변경 없이 커널/장치만 검사한다.
- `scripts/build-guest-launcher.sh`: 진단 helper 빌드 추가.

일반 Guest `/dev/ashmem` alias는 추가하지 않았다. 이번에 확인된 libcutils가
사용하는 boot ID 경로만 복구했다. property override 및 SELinux 정책 변경은 없다.

## 수정 후 검증

1. 부팅 없는 동일 Guest 진단: boot ID 장치 `open()` 성공.
   `ashmem_create_region`, 크기 조회, RW `mmap`, fork 후 재매핑/공유,
   `PROT_READ` 전환, 새 RW 매핑 거부 및 RO 매핑 성공을 확인했다.
   `fixed/worker.log:214-231`의 `SSAL_ASHMEM_MEMORY=PASS`.
   `sys.use_memfd`와 `has_memfd_support=0`은 그대로다.
2. 원인과 메모리 동작 확인 후 **한 번만** 추가 부팅했다: attempt113.
   `attempt113/worker.log:344`에서 Guest SystemServer PID9443의 uid1000,
   Guest root/netns, `ssal_p0001_system_server`와 Framework entry를 확인했다.
   `:353-360`에서 Zygote 및 SystemServer의 5초 생존과
   `PHASE7A_SYSTEM_SERVER=PASS`, `PHASE7A_ZYGOTE=PASS`를 확인했다.
   `attempt113/console.txt`의 worker exit=0, 서비스 readiness/PHASE5B도 PASS다.
   `attempt113/stderr.log:506-507`에서 이전 실패 지점을 지나
   `InitBeforeStartServices` 완료와 `StartServices` 진입을 확인했다.
   ashmem 생성 예외 및 관련 AVC는 발견되지 않았다. Framework 진입 로그의
   raw Guest 시각 `11-16 17:49:58.854`는 2026-11-17 02:49:58.854 KST에 해당한다.
3. 경계 검사 2개와 기존 launcher 13개, 합계 Rust 테스트 **15개 통과**.
   Android release 빌드, C `-Wall -Wextra -Werror` 빌드,
   `bash -n scripts/build-guest-launcher.sh`, `git diff --check` 통과.
   기존 무관한 rustfmt 차이는 보존했다.
4. Host 전후 snapshot 일치: `host-before.txt`, `host-after.txt`.
   property 두 값, 장치 inode 920/921, major:minor 10:127,
   root:root 0666 및 두 SELinux label이 모두 동일하다.
   Enforcing, boot ID `187ab5ca-c953-4032-b5fb-38875175d198`,
   Host SystemServer PID2280도 유지됐다.
5. `attempt113/console.txt`의 Host mount/cgroup 상태, 원본 userdata 메타데이터,
   system image 메타데이터, production binary hash 및 Guest policy ledger는 불변이다.
   active policy SHA256도 전후 동일:
   `f701a6483d4feef686aa87658ddfd65cea61977c9ad46eaa4695b3d234b67587`.
   매 실행의 mount/cgroup 정리 및 46개 loop 해제가 통과했다.

baseline/fixed용 wrapper는 기존 부팅용 wrapper를 재사용했기 때문에,
진단 worker exit=0이어도 실행하지 않은 부팅 readiness를 MISSING으로 표시하고
wrapper exit=1을 반환한다. 이는 예상된 결과다. 실제 부팅 검증인 attempt113의
wrapper와 worker는 모두 exit=0이다.

## 미해결 및 검증 한계

- 현재 검증은 기존 launcher의 Framework 진입 및 5초 생존 단계까지다.
  전체 Framework 서비스 준비, UI 및 Guest `sys.boot_completed`는 검증하지 않았다.
- 후속 로그에는 `aidl/apexservice`의 `ctl.interface_start` 실패
  (`attempt113/worker.log:370-375`)가 반복된다. process 전환 중의 기존
  `dyntransition`/`setcurrent` AVC도 남아 있다
  (`attempt113/stderr.log:431-443`, raw Guest 17:49:58.772-794).
  ashmem과 무관한 이 문제들은 이번 패치에서 수정하지 않았다.
  cgroup ENOENT(`:404`), memevents BPF(`:486`), aconfig(`:517-574`) 등의
  환경 경고도 남지만 이번 5초 검증에서는 fatal exception/crash가 발견되지 않았다.
- 공유 검사는 동일 Guest domain의 fork/FD 상속·재매핑이다.
  서로 다른 Guest domain 간 Binder FD 전달과 실제 앱 사용은 별도 검증 대상이다.
- 삼성 대상 장치 및 하드 재부팅 후 One UI 복구는 이번 Lenovo 실험으로 검증할 수 없다.
- 이번 패치는 Host ashmem driver와 boot ID 장치가 존재하는 환경을 사용한다.
  ashmem driver가 없는 커널에 대한 대체 backend는 구현하지 않았다.
- 최신 branch 소스는 추적 보조 자료다. GSI ELF 및 실측 결과를 판정 근거로 사용했다.
  runtime policy rule readback 자체는 별도 수행하지 않았으며 접근 성공과
  active policy hash 불변을 확인했다.

Luna가 process FD/mount/loop 참조가 없음을 확인한 뒤 이번에 만든 임시 userdata
한 개만 삭제했다. 원본 userdata 메타데이터는 보존됐고, profile과 로컬 workspace에
`.userdata-*.img*`가 남지 않았다. payload 및 로그는 보존했다.
완료 증거: `out/guest-ashmem-20261117/cleanup.txt`.

# Private Binder와 SELinux Enforcing — 우회 경로 조사

조사일: 2026-10-31. 첨부된 선행 조사, 현재 SSAL 소스와 저장소의 SM-S937N 시험 기록을 원문 소스와 대조했다. 이번 작업은 문헌·코드 조사다. 새 기기 시험, 정책 패치, 서비스 실행은 수행하지 않았다.

## 결론

**가장 먼저 시험할 방법은 새 private binderfs가 원래 생성한 `binder` 노드를 그대로 사용하는 것이다.** 현재 `ssal-probe`를 `/dev/binderfs/binder` 위에 bind하는 구현 때문에, 기존 결과는 원래 `binder` 노드의 genfs 라벨을 검증하지 못했다. 정책 변경 없는 해결 가능성이 아직 남아 있다.

이 방법이 실패하면 `context=` 실패의 `filesystem:associate` 검사를 분리한다. `fscontext=`를 함께 지정하는 무정책 변경 후보와, 필요한 association만 추가하는 정책 후보가 있다. 최단 정책 실험은 기존 `binderfs` 노드에 대한 servicemanager 접근 허용이지만, 적용 범위가 Host에도 미친다.

`neverallow`는 런타임 정책 패치 자체를 막는 커널의 별도 거부 규칙이 아니다. 또한 확인한 KernelSU 삼성 포크는 `genfscon` 구문을 파싱하지만 실제 변경 함수가 미구현이다. 이 두 점은 선행 조사의 판단을 보정해야 한다.

## 1. 현재 증거가 말하는 범위

근거는 [Binder 시험](binder-probe.md), [실행 환경 검사](servicemanager-execution-environment.md), [원시 결과](servicemanager-execution-environment-device-20261031.json)다.

| 확인된 사실 | 해석 |
|---|---|
| Host 507:1, private 507:8, private IPC 성공 | 독립 Binder context 생성은 이미 가능하다. 번호는 해당 세션의 관측값이다. |
| IPC 시험 주체 `u:r:ksu:s0` | enforcing servicemanager에서의 IPC 성공이 아니다. |
| `servicemanager → binderfs:chr_file` 접근 AV 거부 | 현재 선택한 노드의 라벨이 실제 차단 요인이다. |
| `servicemanager → binder_device:chr_file` 조사 권한 및 `self:binder set_context_mgr` AV 허용 | 새 context-manager 권한을 추가하기 전에 기존 도메인·타입 재사용을 검증할 근거가 있다. |
| private FD 라벨 변경 EOPNOTSUPP(95) | 단순한 allow 추가로 chcon이 가능해진다고 볼 수 없다. |
| 단일 `context=binder_device` 마운트 EACCES(13) | `context=` 자체가 지원되지 않는다고 확정할 수 없다. |
| linkerconfig 라벨 변경 성공 | linkerconfig 차단은 별도로 해결됐지만 Binder 라벨 문제는 남아 있다. |

전역 Enforcing과 target servicemanager enforcing은 확인됐지만, source `ksu`는 permissive다. 이후의 성공 기준도 전역 상태와 실제 시험 도메인의 permissive 플래그를 따로 기록해야 한다. 현재 실효 정책은 KernelSU가 적용된 정책이며, 변경 전 삼성 순정 정책과 동일하다고 간주하지 않는다.

## 2. 우선순위 1 — 원본 `binder` 노드 사용

### 기존 결과에 숨어 있는 bind mount

현재 [`Session::provision_with_context`](../src/binder_probe.rs)는 다음 순서로 동작한다.

1. 새 binderfs를 마운트한다.
2. `BINDER_CTL_ADD`로 **`ssal-probe`**를 생성한다.
3. Guest `/dev/binder`를 [`guest_path`](../src/guest_mounts.rs)로 해석한다.
4. 해석한 목적지 위에 `ssal-probe`를 bind한다.

기기의 `/dev/binder`는 `/dev/binderfs/binder`를 가리킨다. 따라서 원래 `binder`가 존재해도 4단계에서 가려진다. 원시 결과의 Guest `/dev/binderfs/binder`와 `/dev/binderfs/ssal-probe`는 모두 **dev=2097207, ino=11, rdev=129800**이다. `binder` 경로에서 관측된 `binderfs` 라벨은 덮어씌운 `ssal-probe`의 라벨이다.

**그러므로 “`binder`라는 이름으로 생성해도 이 기기에서는 `binderfs`가 된다”는 결론은 현재 증거로 성립하지 않는다.**

AOSP Android 16은 다음 genfs 규칙을 제공한다. 이 경로는 binderfs 내부 경로다. 외부 마운트 위치를 `/data/...`로 바꿔도 규칙의 기준이 그 위치로 바뀌지 않는다. [AOSP genfs_contexts](https://android.googlesource.com/platform/system/sepolicy/+/android-16.0.0_r2/private/genfs_contexts#312)

```text
genfscon binder /binder    u:object_r:binder_device:s0
genfscon binder /hwbinder  u:object_r:hwbinder_device:s0
genfscon binder /vndbinder u:object_r:vndbinder_device:s0
genfscon binder /          u:object_r:binderfs:s0
```

### 구체적인 다음 시험

새 mount namespace에서 mount propagation을 private으로 만든 뒤, **새 binderfs를 마운트하고 어떠한 alias bind도 하기 전에** 원본 `/binder`의 FD·라벨·장치 정체성을 기록한다.

- 커널이 `binder`를 미리 만들었다면 그 장치를 검사한다. Linux v6.6도 설정된 기본 장치 이름들을 mount 시 생성하는 코드가 있다. [binderfs_fill_super](https://github.com/torvalds/linux/blob/v6.6/drivers/android/binderfs.c#L715)
- 없다면 해당 **새 인스턴스의** binder-control에 `BINDER_CTL_ADD(name="binder")`를 호출한다.
- EEXIST만 보고 기존 장치를 신뢰하지 않는다. 해당 세션이 만든 새 mount에 속하는지, character device인지, Host Binder와 rdev가 다른지 확인한다. ioctl로 생성했다면 반환 major/minor도 대조한다.
- `created_by=kernel_mount_default`와 `created_by=BINDER_CTL_ADD`를 구분한다. 현재 시험의 “항상 ioctl로 생성한 객체” 가정을 그대로 유지하면 기본 장치를 쓸 수 없다.
- 실제 라벨이 `binder_device`이고 target AV가 허용되면 그 FD를 기준으로 Guest의 최소 `/dev/binder`를 연결한다. 기존 `ssal-probe` bind 단계는 이 경로에서 실행하지 않는다.
- 원래 `binder`도 `binderfs`라면 그때 삼성 정책/커널 차이 또는 실제 라벨 초기화 경로를 조사한다.

Host 원래 노드는 `binder_device`로 관측됐지만, 이것만으로 새 노드의 동일 라벨을 보장하지는 않는다. Host 부팅 중 init의 별도 처리와 새 mount의 처리가 같다는 증거가 없기 때문이다. 최우선 **미검증 가설**로 분류한다.

## 3. `chcon`과 `context=`의 실패는 다르다

Android common `android15-6.6`의 SELinux 코드는 binder를 genfs 경로 라벨링 대상으로 처리하지만, genfs의 in-core relabel 허용 목록에는 binder가 없다. `SBLABEL_MNT`가 없으면 SELinux xattr 변경 경로에서 EOPNOTSUPP를 반환한다. 현재 errno와 일치하는 설명이며, 해당 삼성 빌드의 정확한 코드 대응까지 확인한 것은 아니다. [SELinux hooks.c](https://android.googlesource.com/kernel/common/+/refs/heads/android15-6.6/security/selinux/hooks.c)

`context=`는 다른 경로다. 단일 옵션은 파일 라벨뿐 아니라 superblock SID도 그 context로 설정하며, 기본 rootcontext에 대해 `filesystem:associate`를 검사한다. 따라서 `context=binder_device`만 지정하면 다음 질의가 중요해진다.

```text
binder_device → binder_device : filesystem associate
```

이 검사의 source는 마운트를 요청한 `ksu`가 아니라 **파일 라벨인 `binder_device`**다. `ksu`의 wildcard allow나 permissive만으로 이 검사가 통과하는 것은 아니다. 단, 기존 시험에는 이 질의 결과와 해당 시점 AVC가 없으므로 EACCES의 확정 원인으로 단정하지 않는다.

추가로 같은 커널 계열은 initial user namespace 밖에서 binderfs에 SELinux context 옵션을 지정하면 EACCES를 반환하는 경로가 있다. **mount namespace와 user namespace는 별개**이므로 실제 user namespace도 확인해야 한다. AVC가 없다고 자동으로 권한 문제가 아니라고 판정해서도 안 된다.

### 우선순위 2 — 파일과 superblock context 분리

AOSP의 `binder_device`는 `dev_type`이며, `dev_type → tmpfs:filesystem associate`를 허용한다. 그러므로 다음 조합은 단일 `context=` 시도와 다른, **정책 변경 없는 후보**다. [device.te](https://android.googlesource.com/platform/system/sepolicy/+/android-16.0.0_r2/public/device.te#6), [private/file.te](https://android.googlesource.com/platform/system/sepolicy/+/android-16.0.0_r2/private/file.te#202)

```text
context=u:object_r:binder_device:s0,
fscontext=u:object_r:tmpfs:s0
```

위 두 줄은 하나의 mount option 문자열로 전달하는 설계 예시다. 기존 Host mount의 remount 명령이 아니다. **새 private superblock에만 적용**한다.

실제 파일시스템은 계속 binderfs이며, `fscontext=tmpfs`는 SELinux가 검사할 superblock SID만 바꾼다. 마운트 주체의 filesystem relabelfrom/relabelto, mount 권한 등은 별도로 필요하다. 기존 정책의 타입 의미를 빌리는 방법이므로 기본 `binder` 경로가 성공하면 이 방법까지 사용할 이유는 없다.

다음 AV를 실제 기기에서 먼저 조회하고, 파일 라벨·mountinfo·FD identity로 결과를 확인한다.

| 후보 조합 | 필요한 association |
|---|---|
| `context=binder_device` | `binder_device → binder_device` |
| `context=binder_device,fscontext=tmpfs` | `binder_device → tmpfs` |
| `context=binder_device,fscontext=binderfs,rootcontext=binderfs` | `binder_device → binderfs`, `binderfs → binderfs` |

`context=`는 인스턴스 안의 장치들을 같은 라벨로 만들기 때문에 framework/hw/vnd를 한 mount에 넣고 각각의 타입이 보존된다고 가정하면 안 된다. 이 후보 시험은 framework Binder만 Guest에 제공하고 binder-control·나머지 노드·원래 mount 경로는 서비스 뷰에서 숨긴다. hw/vnd까지 확장하려면 기본 genfs 경로를 사용하거나 인스턴스/라벨 구성을 따로 설계한다.

## 4. 정책 확장이 필요한 경우

### 후보 A — association 하나를 추가하고 기존 타입 사용

실효 AV와 감사 로그가 `binder_device → binderfs:filesystem associate` 부족을 확인한다면 다음 **추가 정책 후보**를 검토할 수 있다. KernelSU 문법이며 자동 적용하지 않는다.

```text
allow binder_device binderfs filesystem associate
```

이후 새 private binderfs에 다음 option 조합을 사용한다.

```text
context=u:object_r:binder_device:s0,
fscontext=u:object_r:binderfs:s0,
rootcontext=u:object_r:binderfs:s0
```

이 구성은 superblock/root를 기존 binderfs 타입으로 두고 장치만 mountpoint context로 `binder_device`에 연결하는 후보다. 기존 Binder 파일 접근·ioctl 정책을 재사용할 수 있지만, 마운트 주체 권한과 삼성 커널 동작까지 이 한 줄로 보장하지 않는다. 정책은 전역이며 해당 세션에만 한정된 allow가 아니다.

### 후보 B — 현재 `binderfs` 노드에 접근 허용

라벨링을 바꾸지 않고 현재 관측한 접근 거부를 해소하는 가장 직접적인 후보는 다음과 같다.

```text
allow servicemanager binderfs chr_file { open read write getattr ioctl map }
```

이것은 **관측된 거부를 대상으로 한 실험용 출발점**이다. 완성된 최소 정책이나 Android 전체 기동 정책이 아니다. 현재 target의 `self:binder set_context_mgr`는 이미 AV 허용이므로 새로 추가할 이유가 관측되지 않았다.

- Host servicemanager도 같은 도메인이므로 이 허용을 얻는다. binder-control을 비롯해 같은 타입의 다른 character node에 대한 접근도 넓어질 수 있다.
- Guest system_server/앱 등 다른 주체의 device 접근과 Binder IPC 권한은 따로 필요하다.
- 일반 `ioctl` AV 허용이 ioctl 확장 권한 검증을 대신하지 않는다. 실제 쓰는 command의 xperm을 확인하고 부족한 것만 추가한다.
- 별도 `set_context_mgr` 권한은 `chr_file`이 아니라 **`binder` 클래스의 프로세스 간 권한**이다. device 라벨에 그 권한을 부여하는 규칙은 잘못된 방향이다.

AOSP는 `binder_device`에 일반 Binder ioctl allowlist를 제공한다. 다른 타입인 `binderfs`에 같은 allowlist가 자동 적용되지는 않는다. 시험에서 VERSION만 성공한 것을 WRITE_READ나 SET_CONTEXT_MGR_EXT 성공으로 바꾸어 기록하면 안 된다. [domain.te](https://android.googlesource.com/platform/system/sepolicy/+/android-16.0.0_r2/private/domain.te#83), [ioctl_macros](https://android.googlesource.com/platform/system/sepolicy/+/android-16.0.0_r2/public/ioctl_macros#71)

### 후보 C — Guest 전용 도메인·타입

장기적으로 Host와 Guest를 MAC으로 구분하려면 전용 실행 도메인과 자원 타입이 필요하다. xattr가 안 된다는 이유로 전용 타입 자체가 불가능한 것은 아니다. 작동이 검증된 `context=` mount나 실제로 구현된 genfs 정책 변경으로 타입을 적용할 수 있다.

도메인 생성 외에도 exec/entrypoint/transition, device 접근, self context-manager, Binder call/transfer, 서비스 이름별 add/find, loader·property·logging 정책이 필요하다. 새 타입을 `dev_type`과 `fs_type` 양쪽에 무작정 넣어 association을 통과시키는 방식은 타입 의미를 훼손하므로 피한다.

## 5. 선행 조사에서 보정할 사항

### neverallow는 런타임의 별도 deny 목록이 아니다

AOSP의 context-manager neverallow는 정책 빌드 시 검증되는 assertion이다. 확인한 KernelSU는 실행 중 정책의 AV 테이블을 변경하고 AVC를 reset하는 경로를 사용한다. 따라서 “AOSP neverallow가 있으므로 KernelSU allow 추가도 원리적으로 불가능하다”는 해석은 맞지 않는다. 실제 포크의 정책 변경 기능·제약·기기 결과는 별도로 확인해야 한다. [AOSP assertion 설명](https://android.googlesource.com/platform/system/sepolicy/+/1f5939a97647bb71414588be8f26114773edceaf/assert.te), [KernelSU 삼성 포크 rules.c](https://github.com/diabl0w/KernelSU/blob/b38f4096f33632ad5871dc3fff0ec426e23c9358/kernel/selinux/rules.c)

표준 Android 정책 빌드/호환성 검사에서는 해당 assertion이 여전히 중요하다. 전역 Enforcing을 유지한 런타임 정책 확장과 순정 정책 무변경은 서로 다른 조건이다.

### KernelSU의 genfscon은 parser 지원만 확인하면 안 된다

저장소 FreeSam 문서가 가리키는 삼성 포크 `diabl0w/KernelSU`, 태그 `samsung-v2.2`의 commit **b38f4096f33632ad5871dc3fff0ec426e23c9358**을 확인했다. `add_genfscon()`은 `return false`뿐이다. 확인한 upstream main **51c217863c5e1fb639501e92ef17ac6d0cf90c92**도 동일하다. [삼성 포크 sepolicy.c](https://github.com/diabl0w/KernelSU/blob/b38f4096f33632ad5871dc3fff0ec426e23c9358/kernel/selinux/sepolicy.c#L629), [upstream sepolicy.c](https://github.com/tiann/KernelSU/blob/51c217863c5e1fb639501e92ef17ac6d0cf90c92/kernel/selinux/sepolicy.c#L629)

따라서 이 구현에서 `genfscon binder /ssal-probe ...` 한 줄을 sepolicy.rule에 넣는 것만으로 해결되지 않는다. 삼성 포크의 `sepolicy check`는 파싱 검사이며, `live_patch`는 일부 적용 실패를 warning으로 처리할 수 있다. 구문 검사나 CLI 종료 코드만으로 성공 판정하지 말고 실제 label/AV와 커널 적용 결과를 확인해야 한다. [삼성 포크 sepolicy.rs](https://github.com/diabl0w/KernelSU/blob/b38f4096f33632ad5871dc3fff0ec426e23c9358/userspace/ksud/src/sepolicy.rs#L727)

이 소스가 현재 연결 기기에 로드된 바이너리와 정확히 일치하는지는 이번 조사에서 검증하지 않았다. 다른 포크의 genfscon 지원 여부까지 일반화하지 않는다.

## 6. 효과가 없거나 검증을 왜곡하는 접근

| 접근 | 이유 |
|---|---|
| `chmod 666` 또는 UID만 변경 | DAC와 SELinux 접근은 별개다. 기존 UID 1000/ksu 성공도 target enforcing 성공이 아니다. |
| bind 목적지의 라벨을 `chcon`으로 변경 | bind는 원래 inode를 가리킨다. mount 경로별 독립 라벨이 되지 않는다. |
| genfs 파일을 Guest 이미지에서 편집 | Guest 텍스트 파일 수정만으로 현재 커널 전역 정책이 바뀌지 않는다. |
| 같은 major/minor로 tmpfs에 `mknod` | binderfs는 inode의 private 데이터와 전용 file_operations로 context에 연결한다. rdev 복사로 private Binder 객체가 복제되지 않는다. [binderfs.c](https://github.com/torvalds/linux/blob/v6.6/drivers/android/binderfs.c#L150) |
| `ssal-probe`를 나중에 `binder`로 rename | 이미 초기화된 inode SID가 새 경로에 맞춰 자동 재라벨된다고 보장할 수 없다. 처음부터 올바른 이름으로 생성·관측하는 편이 명확하다. |
| ksu에서 Binder FD를 열어 넘기기 | Binder는 open 시 credentials를 보존한다. enforcing 프로세스의 새 open 검증을 대신할 수 없고 이후 impersonate/FD-use 문제도 생길 수 있다. [binder_open](https://github.com/torvalds/linux/blob/v6.6/drivers/android/binder.c#L5620) |
| Guest servicemanager의 SELinux 검사를 끄기 | userspace 서비스 add/find 검사만 바뀐다. 커널의 device/context-manager/IPC 검사는 남는다. |

Waydroid 사례는 다른 배포판 정책에서 context mount가 유효했던 증거다. 삼성에서 동일 옵션이 성공한다거나 Android 서비스 권한까지 충족한다는 증거는 아니다. [Waydroid 개발자 이슈 #208](https://github.com/waydroid/waydroid/issues/208)

## 7. 다음 실험의 순서와 판정

1. **정책 무변경 원본 노드 검사:** 새 binderfs의 alias 전 `binder`/`ssal-probe`/binder-control 라벨, FD mount ID, dev/inode/rdev, mountinfo를 비교한다. 원본 `binder`가 `binder_device`이면 우선 사용한다.
2. **대상 도메인의 실제 접근:** target entrypoint가 가능한 전용 시험 helper를 Guest 소유 파일시스템에 준비하고 명시적 exec 전환을 검증한다. exec 후 `u:r:servicemanager:s0`와 해당 도메인의 enforcing을 확인한 뒤 **그 프로세스에서 새로** open, mmap, VERSION을 시험한다. 기존 shell_data_file helper의 entrypoint 실패와 구분한다. 실제 servicemanager는 이 단계에 필요하지 않다.
3. **라벨 실패 분석:** 위 association AV 세 조합, 마운트 주체의 filesystem 권한, user namespace와 제한된 시간 구간의 AVC를 수집한다. 근거에 따라 fscontext 분리 또는 최소 정책 후보 하나만 시험한다. errno와 AVC 양쪽을 남긴다.
4. **context manager 검증:** 2단계가 통과한 별도 helper로 private context에만 EXT/legacy ioctl과 최소 IPC를 시험한다. 각 ioctl 결과를 따로 기록한다. Host Binder에는 context-manager ioctl이나 시험 transaction을 보내지 않는다.
5. **정식 servicemanager Test B:** 그 뒤에만 정확한 Guest 바이너리·service_contexts와 서비스 add/find, Guest 시험 서비스의 Host 비노출·Host 고유 서비스의 Guest 비노출을 검증한다. Host 조회가 필요하면 기존 계획의 읽기 전용 관찰 범위로 제한한다.
6. **자원/Host 상태 비교:** 새 FD와 시험 프로세스 회수, alias와 binderfs의 정상 unmount, rootfs/loop 정리, Host 프로세스 및 Binder identity·라벨·소유권·전역 Enforcing을 전후 비교한다.

AOSP libbinder는 지정 장치의 access 실패 시 `/dev/binder`로 fallback한다. 따라서 Guest 기본 경로 자체를 private으로 유지하고 상속 Host Binder FD를 제거해야 한다. 또한 EXT 실패 후 legacy context-manager ioctl로 fallback하므로 최종 bool만 보면 첫 실패 원인을 잃는다. [ProcessState.cpp](https://android.googlesource.com/platform/frameworks/native/+/android-16.0.0_r2/libs/binder/ProcessState.cpp#133)

서비스 add/find는 Guest service_contexts가 지정한 타입과 현재 커널 정책을 다시 검사한다. Guest에만 있는 타입이 Host 커널 정책에 없으면 기존 device 허용만으로 해결되지 않는다. [Access.cpp](https://android.googlesource.com/platform/frameworks/native/+/android-16.0.0_r2/cmds/servicemanager/Access.cpp#149)

현재 남은 PID/IPC namespace, 기능하는 proc, Guest property 초기화, logging, task profile 조건은 이 조사로 해결되지 않았다. **Private Binder 접근이 통과해도 전체 LineageOS 기동 성공이나 `launch_enabled` 해제 조건으로 바꾸지 않는다.**

정책 변경을 시험한다면 live 변경도 커널 전역에 적용되고 프로세스 종료만으로 원복되지 않는다는 점을 복구 절차에 반영해야 한다. 모듈 sepolicy.rule에 영구 추가하면 재부팅 시 다시 적용될 수 있으므로, “하드 재부팅으로 One UI 복구” 목표의 첫 시험은 자동 재적용 없는 일회성 구성으로 구분한다. [KernelSU 모듈 가이드](https://kernelsu.org/guide/module.html)

## 8. 권장 선택

**원본 `binder` + 기존 servicemanager 도메인 → fscontext 분리 → 근거가 확인된 association 최소 확장 → binderfs 장치 접근 확장** 순서가 현재 증거에 맞다. Guest 전용 도메인·타입은 별도 MAC 경계가 필요한 운영 설계로 병행 검토한다.

이번에 추가로 확인한 핵심은 새로운 취약점이 아니라, 기존 시험에서 가려진 원본 노드와 SELinux의 서로 다른 라벨링·association 경로다. 첫 번째 경로의 실제 기기 결과를 얻기 전에는 정책 확장이 반드시 필요하다고 확정하지 않는다.

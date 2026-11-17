# Phase 7C Guest lazy AIDL apexd 사전 검증 — BLOCKED

2026-11-17 KST. ATTEMPT115 다음 부팅은 실행하지 않았다. 실제 이미지와 현재
SSAL의 APEX 준비 방식이 apexd의 활성 패키지 복원 방식과 맞지 않아, 요청의
사전 검증 중단 조건을 적용했다. dispatcher, launcher, 정책 및 기기 설정은
수정하지 않았다. 아래의 BLOCKED는 현재 이미지/마운트 조합에 대한 판정이며,
Guest apexd 구현 자체가 불가능하다는 뜻은 아니다.

## 실제 이미지와 실행 의존성

- 등록 이미지: `/data/local/ssal/images/1794661103681-12276/system.img`.
  로컬 `out/LineageOS-23.2-20260524-VANILLA-EXT4-GSI.img`와 기기 파일의 SHA256이
  모두 `7b9ba62e8b48b6e40432be949ae0858a8971175c79502550e74691222d3889ff`다.
- 이미지에서 `/system/bin/apexd`와 `/system/etc/init/apexd.rc`를 직접 추출했다.
  apexd는 981304-byte AArch64 ELF, SHA256은
  `6a24a0f45453bb24e261738e37a98932fb5f309de40ed6f2ff10864b2571da8d`다.
  PT_INTERP는 `/system/bin/bootstrap/linker64`다.
- DT_NEEDED 17개가 모두 같은 이미지의 `/system/lib64`에 있다:
  `apex_aidl_interface-cpp.so`, `libbase.so`, `libbinder.so`, `libc++.so`,
  `libc.so`, `libcrypto.so`, `libcutils.so`, `libdl.so`, `libfs_mgr.so`,
  `liblog.so`, `liblogwrap.so`, `libm.so`, `libprotobuf-cpp-full.so`,
  `libselinux.so`, `libutils.so`, `libvintf.so`, `libziparchive.so`.
  이는 직접 의존 파일의 존재 확인이다. 전이 의존성 전체와 실제 Guest linker
  namespace에서의 로딩 성공은 검증하지 않았다.
- 실제 RC 1–12행은 lazy `interface aidl apexservice`, root/system,
  `oneshot`, `disabled`, `reboot_on_failure reboot,apexd-failed`,
  `CHOWN DAC_OVERRIDE DAC_READ_SEARCH FOWNER SYS_ADMIN`을 선언한다.
  bootstrap 서비스 14–21행에는 `reboot,bootloader,bootstrap-apexd-failed`도 있다.
  이 RC의 action이나 reboot 처리를 실행하지 않았다.

추출 및 ELF 자료는 `out/guest-apexd-preflight-20261117/`에 보존했다.
7-Zip은 ext4 끝의 추가 데이터에 대한 경고를 냈으며, 지정한 파일 추출은 성공했다.

## 차단 원인 1: 활성 패키지 데이터베이스를 복원할 수 없는 backing file

현재 `src/guest/mount/apex.rs:174–221`의 실제 경로는 다음과 같다.

1. APEX ZIP에서 `apex_payload.img`를 cache의 `<index>.img`로 추출한다.
2. 이 **raw ext4 파일**을 loop backing으로 사용해 `/apex/<name>@<version>`에
   RO mount하고, `/apex/<name>`에 RO bind한다.
3. 원래 APEX ZIP은 별도로 `/apex/.packages/<index>.apex`에 RO bind한다.
4. raw payload 파일을 unlink한다. loop FD/mount가 payload 수명을 유지한다.
5. 자체 XML을 쓰고 `/apex` 부모 tmpfs까지 RO로 remount한다 (`:217–241`).

apexd의 lazy 재시작 초기화는 이 XML을 활성 패키지 DB로 읽지 않는다.
`/proc/mounts`에서 versioned mount를 열거하고
`/sys/block/loopN/loop/backing_file`에서 APEX 파일 경로를 복원한다.
`GetActivePackages()`는 복원된 `data.full_path`를 **APEX ZIP**으로 다시 연다.
현재 backing은 Guest에서 접근할 원래 APEX ZIP 경로가 아니라, 이미 unlink된
raw ext4 cache 경로다. XML의 `.packages` 경로가 이를 대체하지 않는다.
따라서 현재 상태를 그대로 유지한 채 service 등록만 성공시켜도, 요구한 실제
활성 패키지 목록과 Guest 마운트 상태의 일치를 입증할 수 없다.

실제 ELF에서도 해당 경로를 확인했다. ELF entry의 main 포인터는 `0x32958`이고,
main의 `0x32d90`은 초기화 함수 `0x6c1a4`를 호출한다. 이 함수의 `0x6c264`는
mount DB 복원 함수 `0x83018`로 분기한다. 그 함수에는 다음 참조가 있다.

- `0x8310c–0x83110`: `/proc/mounts` (`0x19da4`).
- `0x83ce8–0x83cec`: `loop/backing_file` (`0x17c22`).
- `0x85b8c–0x85b90`: `Populating APEX database from mounts...` (`0x19d7c`).

원본 disassembly, main/initialize 발췌와 ELF headers를 증거 디렉터리에 보존했다.
복원 경로의 의미와 ZIP reopen 동작은 아래 소스와 대조했다. GSI의 정확한 빌드
커밋을 입증한 것은 아니므로, 소스 대조와 ELF에서 직접 확인한 사실을 구별한다.

## 차단 원인 2: 정상 초기화는 조회 전용 실행이 아니다

실제 ELF의 `0x94bc0` 함수는 Guest `apexd.status`를 읽어 `ready`/`activated`와
비교한다. main은 결과를 `w23`에 보관하고, `0x32dec`에서 분기한다.
booting이면 `0x32df0`에서 OnStart 경로를 실행한 뒤, `0x32df4`에서 Binder 등록
경로로 들어간다. non-booting 분기는 `0x32e6c`에서 같은 Binder 등록 경로로 간다.

대조 소스의 OnStart는 staged session 처리, 압축 APEX 처리, activation 및
실패 시 revert/reboot 경로를 포함한다. 단순히 일반 apexd를 lazy 시작하는 것은
요청한 설치·활성화·재마운트 금지를 만족하는 실행 방법이 아니다.
Guest status를 `ready` 또는 `activated`로 미리 설정해 OnStart를 건너뛰는
방법도 차단 원인 1을 해결하지 않는다. 실제 APEX 상태 복원 검증 없이 이 값을
선언하거나, 빈 활성 목록을 성공으로 판정하지 않았다.

현재 mount profile의 `/metadata`는 빈 RO tmpfs이고
`module/profiles/mounts/initial.json:runtime_tmpfs`에서 Host metadata와 분리된다.
`/data`는 Guest userdata다. apexd가 사용하는 `/data/apex/active`,
`/data/apex/decompressed`, `/data/apex/sessions`, `/data/apex/images`,
`/metadata/apex/images`, `/metadata/apex/sessions` 등의 상태 경로는 별도 검증이
필요하다. 현재 최소 `/dev`는 Host loop-control/device-mapper를 제공하지 않는다.
이를 열어 activation을 성공시키는 우회는 수행하지 않았다.

## 정책·launcher·property service 조사

기기의 기존 `applied.json` ledger에는 `ssal_p0001_apexd`,
`ssal_p0001_apexd_exec`, `ssal_p0001_apex_service`와 다음 규칙이 이미 있다.

- Guest apexd → Guest apex_service: `service_manager { add find }`.
- Guest apexd → Guest servicemanager: `binder { call transfer }`.
- Guest system_server → Guest apex_service: `service_manager { find }`.
- Guest apexd capability에는 `sys_admin` 등이 포함된다.

ledger는 `rule_readback_verified=false`라고 명시한다. 도메인 존재 기록을 실제
apexd exec 전이·Binder 등록 성공으로 간주하지 않았다. 기존 Guest 타입을 재사용할
수 있으며 삭제·재생성할 이유가 없다. 새 정책을 적용하거나 Host 정책을 변경하지 않았다.

후속 구현이 가능해지면 변경이 닿아야 할 기존 경로는 다음과 같다.

- `src/guest/properties/policy.rs:75`: 현재 모든 `ctl.*`을 거부한다.
- `src/guest/properties/server.rs:30,231`: SO_PEERCRED/SO_PEERSEC 수집과 요청 처리.
  정확한 Guest servicemanager SID로 요청을 검증할 위치다.
- `src/guest/launcher/mod.rs:30,67`: 현재 apexd 매핑이 없으므로 기본 shell
  도메인으로 떨어진다. `apexd` 매핑이 필요하다.
- `src/guest/process/command.rs:38`, `src/guest/init/service.rs`:
  기존 root/namespace/FD 정리와 supervised child 수명을 재사용할 경로다.
- APEX mount/state 준비, 해당 회귀 테스트, 단독 실행 및 실제 AIDL 검사도 함께
  필요하다. dispatcher만 열면 현재 차단된 초기화가 실행되므로 부분 구현하지 않았다.

## 실측 범위와 다음 단계

Luna가 ATTEMPT115 로그를 필터링해 재확인했다.
`device-stage/attempt115/worker.log:372–402`는 interface-start 거부,
`worker/phase7b/stderr.log:692–740`은 raw Guest 시각
`11-17 12:09:47.049–12:10:16.086`의 apexservice 대기,
`apexservice-state.txt:5,8,11,14`는 서비스 부재를 기록한다.
기존 결과이며 이번에 부팅한 로그가 아니다.

이번 작업은 로컬 추출·정적 분석 및 기기 read-only 조회만 수행했다.
Host Enforcing, boot ID, PID 1 mountinfo hash, active policy hash, Host APEX XML
hash, Host apexd 상태, 원본 userdata/system 메타데이터를 보고서 작성 전후 비교했다.
snapshot 파일은 `host-before-report.txt`와 `host-after-report.txt`다.
이 비교는 snapshot 사이의 범위이며 전체 Host init/APEX 상태의 완전한 증명은 아니다.

우선 필요한 작업은 Guest 전용 APEX backing/mount 배치를 실제 apexd가 복원 가능한
형태로 맞추고, 조회용 재시작 초기화에서 그 목록을 읽을 수 있는지 입증하는 것이다.
그때도 Host loop/device-mapper 노드 접근을 추가하지 않고 Guest metadata/data만
사용해야 한다. 그 증명이 된 뒤에 SID 제한 dispatcher와 전용 도메인 실행을 연결하고,
요청한 단위 테스트 → shell/servicemanager → 단독 apexd → 등록 → 실제 AIDL 순서를
따른다. 현재는 단독 apexd도 실행하지 않았고 SystemServer 실험은 0회다.

Luna가 로컬 및 기기 y702 profile의 `.userdata-*.img*` 부재를 확인했다.
이번에 임시 userdata, mount, loop 또는 기기 helper를 만들지 않아 삭제 작업은 없었다.

## 대조 소스

- [AOSP android-16.0.0_r2 apexd_main.cpp](https://android.googlesource.com/platform/system/apex/+/android-16.0.0_r2/apexd/apexd_main.cpp),
  170–220행: 초기화와 서비스 등록 순서.
- [동일 태그 apex_database.cpp](https://android.googlesource.com/platform/system/apex/+/android-16.0.0_r2/apexd/apex_database.cpp),
  179–270행: mount/loop에서 backing APEX 경로 복원.
- [동일 태그 apexd.cpp](https://android.googlesource.com/platform/system/apex/+/android-16.0.0_r2/apexd/apexd.cpp),
  1309–1324행: 활성 패키지 ZIP reopen, 2636행 이후: OnStart.
- Lineage `lineage-23.2` 대조 커밋은
  `97548ed51112062a4d1762a7dffa0cadcc09bda9`:
  [main](https://github.com/LineageOS/android_system_apex/blob/97548ed51112062a4d1762a7dffa0cadcc09bda9/apexd/apexd_main.cpp#L159),
  [mount DB](https://github.com/LineageOS/android_system_apex/blob/97548ed51112062a4d1762a7dffa0cadcc09bda9/apexd/apex_database.cpp#L266),
  [GetActivePackages](https://github.com/LineageOS/android_system_apex/blob/97548ed51112062a4d1762a7dffa0cadcc09bda9/apexd/apexd.cpp#L1265),
  [ZIP open](https://github.com/LineageOS/android_system_apex/blob/97548ed51112062a4d1762a7dffa0cadcc09bda9/apexd/apex_file.cpp#L80).
  GSI ELF와 완전히 일치하는 빌드 커밋이라는 주장은 아니다.

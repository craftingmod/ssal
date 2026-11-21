# Guest Rust apexservice — 구현됨, 첫 등록 검증 BLOCKED

2026-11-17 KST. 완료 조건은 **미달성**이다. 등록 검증을 한 번 실행했고,
새 서버가 Guest 도메인으로 exec된 직후 SIGSEGV로 종료했다. 재시도와
PackageManager/SystemServer 단계는 실행하지 않았다.

## 구현 범위

- `experiments/binder-service`: 재사용 가능한 Guest Binder 초기화·등록 계층.
  launcher가 전달한 private device rdev와 실제 FD, 현재 Guest SID를 검증한다.
  다른 Binder 장치 alias와 기존 서비스 덮어쓰기를 거부한다.
- `src/guest/init/binder_service.rs`: 서비스 이름, 실행 경로, Guest domain 및
  exec type을 선언하고 private helper 복사·라벨링, 등록 대기, 조회 검사와
  기존 `Service`의 프로세스 그룹 감독·종료를 재사용한다.
- `experiments/apexservice`: `rsbinder 0.12.0` 및 같은 버전 AIDL 생성기 사용.
  기존 phase3에서 검증한 Android 16 Binder 라이브러리를 재사용하며 raw
  Binder driver/Parcel 구현을 추가하지 않았다.
- `src/guest/mount/apex.rs`: 기존 RO mount 성공 뒤 manifest 이름·버전·선택적
  versionName, 원본 Guest 경로, backing ZIP 경로, versioned mount 경로,
  검색한 partition 및 활성 상태를 `/apex/ssal-registry.json`에 기록한다.
  외부/payload manifest를 비교하고 이름·버전이 없으면 실패한다. capex 원본
  경로와 추출하여 bind한 ZIP 경로는 구별한다. Registry는 APEX 부모와 함께 RO다.
- `getActivePackages`, `getAllPackages`, SSAL이 관리하는 빈 staged session
  목록과 unknown session 조회를 구현했다. 설치·업데이트·rollback·snapshot
  및 그 밖의 미지원 요청은 `EX_UNSUPPORTED_OPERATION`을 반환한다.
  `markBootCompleted`도 현재 미지원이다. 성공한 업데이트로 위장하지 않는다.
- mapped SystemServer worker는 Zygote 전에 등록·조회 검사를 요구한다.
  `SSAL_GUEST_APEX_CHECK_ONLY=1`과 service worker로 Zygote 없이 검사할 수 있다.
  SystemServer 관찰 중 서버의 종료도 검사한다.

등록용 프로세스는 기존 `ssal_p0001_apexd` / `apexd_exec` / `apex_service`
매핑을 재사용한다. Host Binder는 기존 private Binder mount·root 전환·FD
정리와 Guest SELinux 경계로 분리하며, 공통 라이브러리가 장치와 SID를 재확인한다.
새 정책은 적용하지 않았다. Host apexd, Host `/data/apex`, Host init 및
device-mapper를 변경하는 코드가 없다. 기존 Guest APEX loop/mount 과정은 유지한다.

Registry의 선택적 versionName 부재는 null로 보존하고 AIDL 변환 시 protobuf의
빈 문자열 기본값을 사용한다. `hasClassPathJars`는 staged 전용이라 활성 목록에서
기본값이다. 이전 Guest 부팅과의 변경 이력은 구현하지 않아 `activeApexChanged`는
AIDL 기본값이며 이전 부팅과 비교한 관측값이 아니다.

## 실제 GSI AIDL 및 Framework 대조

대조 소스는 Lineage `android_system_apex` 커밋
`97548ed51112062a4d1762a7dffa0cadcc09bda9`의
[IApexService](https://github.com/LineageOS/android_system_apex/blob/97548ed51112062a4d1762a7dffa0cadcc09bda9/apexd/aidl/android/apex/IApexService.aidl),
[ApexInfo](https://github.com/LineageOS/android_system_apex/blob/97548ed51112062a4d1762a7dffa0cadcc09bda9/apexd/aidl/android/apex/ApexInfo.aidl),
[ApexSessionInfo](https://github.com/LineageOS/android_system_apex/blob/97548ed51112062a4d1762a7dffa0cadcc09bda9/apexd/aidl/android/apex/ApexSessionInfo.aidl)다.
원본 라이선스를 유지한 AIDL을 crate에 포함했다. ApexInfo에 추가한
`@RustDerive(Clone=true, PartialEq=true)`는 Rust 코드 생성용이며 wire를 바꾸지 않는다.
GSI 전체 빌드 커밋이 이 소스와 동일하다는 주장은 아니다.

실제 GSI에서 추출했던 아래 jar를 JADX 1.5.3으로 대조했다.

| 파일 | SHA256 |
| --- | --- |
| `out/guest-lock-compat/evidence/framework.jar` | `cc72f9cd2d55bf8b1f0afa50cb3c8a06baadac0bade9b7995cf41aa9dfb95590` |
| `out/guest-lock-compat/evidence/image-services.jar` | `81a66ff7d7e6a736332e34d602ab3c4e7e5adc06aec858b2fc19b220d7395b9d` |

`out/apexservice-IApexService.java:167–189`의 23개 transaction은 AIDL 선언 순서
1–23과 일치한다. 활성/전체 목록은 7/8, 설치는 23이다.
`out/apexservice-ApexInfo.java:44–60`은 size-prefixed parcelable, 문자열 3개,
long versionCode, versionName, boolean 4개, byte partition의 순서다.
`out/apexservice-ApexSessionInfo.java:38–55`는 size, sessionId, boolean 9개,
문자열 2개다. Android Parcel의 boolean/byte slot은 32비트로 검증한다.

`out/apexservice-ApexManager.java:160–167`은 실제
`ServiceManager.waitForService("apexservice")` → `IApexService.Stub.asInterface`
→ `getAllPackages()` 호출이다. 같은 파일 230행은 활성 목록,
287행은 session 목록 호출이다. 이 경로의 **정적 대조**를 실제 호출 성공으로
간주하지 않았다.

## 검증 결과와 최초 차단점

- WSL root, NDK r30으로 Android aarch64 release 빌드 성공.
- AIDL crate 단위 테스트 5개 통과: 모든 transaction 번호, ApexInfo/SessionInfo
  Parcel 필드·크기, Registry 유효성, 모든 미지원 요청의 명시적 오류.
- 기존 manifest parser 및 Guest 실행 도메인 매핑 회귀 테스트 통과.
  `cargo check --locked --bin ssald`와 shell 구문 검사 통과.
- 전체 `ssald` 테스트: 63 통과, 2 실패, 5 제외. 수정하지 않은
  `diagnostics::zygote::tests::pipes_are_bounded_reaped_and_record_signal_without_controller`
  (786432 vs 1048576) 및
  `guest::userdata::tests::formats_checks_and_locks_without_overwriting`
  (WSL filesystem allocated blocks 검사)가 실패했다. 전체 green은 아니다.

기기 증거는 `out/guest-apexservice-20261117/`에 보존했다.
`check.log:229–232`는 Guest servicemanager·기존 private AIDL IPC 통과 뒤
새 apexservice PID 6381이 `u:r:ssal_p0001_apexd:s0`로 exec되고 SIGSEGV로
종료했음을 보여준다. `check.log:3083`에서 worker는 최초 오류를 반환했다.
등록 완료 이벤트와 조회 성공 이벤트는 없다. 실제 충돌 시각·PC·backtrace는
확보되지 않았다. 필터링한 logcat/dmesg에도 이 프로세스의 crash record가 없었다.
따라서 SELinux 거부나 특정 Rust/Binder 함수가 원인이라고 단정할 수 없다.

실험 바이너리 SHA256:

- apexservice: `56bbf62d5902e2d3f4b82c7b87f24b393a59fa7513e3bd807b6e77ea534e4a24`
- ssald: `f2249401e947becdfa63a002636575505c910e7efb0aee59a4169701a4554a1f`

실험 후 소스에는 추가 호환성 테스트, 형식 정리 및 SystemServer 관찰 중의
서버 생존 검사가 추가되었다. 최종 소스는 로컬 검사했으며 기기 재실행은 하지 않았다.

## Host 보존 및 정리

`host-before.txt`와 `host-after-check.txt`는 byte 단위로 동일하다. 비교 항목은
Enforcing, boot ID, Host system_server/apexd PID, PID 1 mountinfo hash,
Host APEX XML hash, active policy hash, Host apexd init 상태, 원본 userdata와
system image의 size/mtime/inode다. 이는 측정한 항목의 보존 증거이며 모든
Host init 상태나 `/data/apex` 전체 내용의 완전한 snapshot은 아니다.

Luna가 증거를 보존하고 실험 process/mount/loop/cgroup 잔여 부재를 확인했다.
임시 `.userdata-apexservice.img`, 실험 전용 bindir와 stage는 삭제했다.
생산 바이너리와 원본 userdata는 보존했다. 정리 증거는 같은 디렉터리의
`cleanup-proof.txt`다. 다음 단계는 재부팅/재시도 없이 확보 가능한 startup
crash 원인을 조사하는 것이다. 실제 PackageManager 호출과
`waitForApexService()` 통과, SystemServer 후속 부팅은 아직 미검증이다.

# SSAL SELinux & Auth HAL Boundary Audit — 2026-10-31

## 판정

**Guest 최초 부팅과 Host 인증 격리는 blocked다.** 기존 37개 invalid context 중 실제 부팅 필수 또는 불필요하다고 확정할 수 있는 것은 없다. [분류표](selinux-auth-boundary-classification-20261031.md)에 37개 전부와 기존 권한 및 후보를 기록했다. 서비스 매핑, 정책 선언과 이미지의 파일 존재는 실행·접근 증거가 아니다. 이 감사는 저장된 산출물과 커널 소스의 정적 검토이며 새 기기 접근, 인증 HAL 호출, 인증 데이터 접근, Guest Framework 실행, 정책 적용 및 원본 GSI 변경을 하지 않았다.

기준 이미지 SHA-256 `7b9ba62e8b48b6e40432be949ae0858a8971175c79502550e74691222d3889ff`; patch-plan SHA-256 `843d97ae962b88a67a09da3e8e08d176bbb66ecc8eb0d68402f5de8e9f57ec01`. 해시는 선행 기록을 인용하며 이번에 원본을 재해시하지 않았다. 정책 소스와 이미지의 정확한 빌드 일치는 미확인이다. [정적 분석](../out/selinux-check/2026-10-31-offline-guest/analysis-report.md), [patch-plan](../out/selinux-check/2026-10-30T21-06-36-556Z-feba58ef/patch-plan.json), [Enforcing Binder](enforcing-binder-device-20261031.md), [Lock v5](../out/guest-lock-compat-v5/report.md)를 재사용한다.

## 기존 정책과 정책 후보

실효 정책에서 새 private binder의 `binder_device` 및 실제 enforcing `servicemanager`와 `shell` 간 transaction, Guest libbinder 객체 왕복이 성공했다. 이는 특정 시험 자격·최소 뷰에 한정된다. Host Binder alias와 상속 FD 비노출도 해당 시험 범위만 통과했고 실제 Host/Guest 레지스트리 양방향 검증, 정식 servicemanager 및 HAL은 not_run이다. 519개 고유 service context 중 9개가 EINVAL이었으나, 이것은 등록 시도나 각 서비스의 필수성을 입증하지 않는다. 나머지 유효 context도 모든 add/find 권한의 증거가 아니다.

Lock v5의 사전 라벨링 ext4는 기존 `ssal_image_file`과 kernel read 허용을 전제로 XML을 `system_file`로 노출했고, system_server의 해당 dir/file AV 조회는 허용됐다. 실제 읽기는 ksu에서만 했고 Guest system_server의 읽기 및 feature 제거는 not_run이다. 기존 정책은 KernelSU가 이미 반영된 실효 정책이며 잠긴 부트로더의 완전 순정 정책과 동일하다고 볼 수 없다. sysconfig context tmpfs의 `system_file → system_file:filesystem associate`는 거부됐으며 추가 후보지만 v5 ext4에는 필요하지 않다. 정책은 전역이므로 후보를 적용하거나 최소 안전 규칙으로 확정하지 않는다.

37개는 모두 필요성 unknown이다. 특히 9개 서비스 context의 실제 등록 조건과 주체별 add/find, attribute에 의해 상속되는 권한을 먼저 확인해야 한다. 별도 Guest 도메인과 전용 객체 타입은 경계 설계 후보이나 전이·의존성·Host 영향은 미검증이다. 서비스 이름을 기존 타입에 매핑하거나 일괄 선언·allow를 부여할 근거는 없다. 재구성 정책은 실효 정책의 완전한 내보내기가 아니며 기존 baseline의 extended permission 오류와 live policy export EINVAL 때문에 전체 권한 차분은 blocked다.

## Host 인증 경로: 정적 매핑과 미확인

저장된 Host [platform service contexts](../out/selinux-check/2026-10-30T21-06-36-556Z-feba58ef/host/system/etc/selinux/plat_service_contexts)에는 AIDL Gatekeeper, Weaver, KeyMint/default, AuthSecret, RebootEscrow와 keystore2가 있고, [vendor service contexts](../out/selinux-check/2026-10-30T21-06-36-556Z-feba58ef/host/vendor/etc/selinux/vendor_service_contexts)에는 KeyMint/strongbox, 삼성 KeyMint extension/factory, Gatekeeper/mdfpp 및 SharedSecret 등이 있다. 이들은 Binder service-manager 이름→타입 매핑이며 인스턴스의 실제 존재·실행·등록·호출 허용을 뜻하지 않는다. StrongBox와 default는 같은 `hal_keymint_service` 타입으로 매핑되어 이름 차단만으로 SELinux 타입 경계를 만들 수 없다.

[platform hwservice contexts](../out/selinux-check/2026-10-30T21-06-36-556Z-feba58ef/host/system/etc/selinux/plat_hwservice_contexts)에는 HIDL Gatekeeper, Weaver, Keymaster, AuthSecret이 있고, [vendor hwservice contexts](../out/selinux-check/2026-10-30T21-06-36-556Z-feba58ef/host/vendor/etc/selinux/vendor_hwservice_contexts)에는 삼성 SKeymaster와 CryptfsHw 매핑이 있다. HIDL 실제 사용과 AIDL/HIDL 간 fallback은 unknown이다. VndBinder의 인증 서비스 등록·접근 경로는 unknown이다. private framework Binder 하나만으로 Host hw/vnd Binder 및 이미 열린 Binder 핸들 차단이 증명되지는 않는다.

[Host vendor file contexts](../out/selinux-check/2026-10-30T21-06-36-556Z-feba58ef/host/vendor/etc/selinux/vendor_file_contexts)에는 `/dev/qseecom`, `/dev/smcinvoke`, QSEE DMA heap, SPU 관련 노드와 `/efs/gatekeeper`, `/data/vendor/gatekeeper`, `/data/vendor/tee`, `/data/misc/qsee`, `/mnt/vendor/spunvm` 등의 라벨 규칙이 있다. 규칙은 실제 장치·파일 존재나 특정 HAL의 사용을 뜻하지 않는다. Host 인증 저장소와 secure world 접근의 잠재 경계로 취급하고 Guest에 노출하지 않는 설계가 필요하다. 실제 socket 이름·리스너·DAC·SELinux connect 경로, 각 서비스의 실제 device open/ioctl 및 FD 전달은 unknown이다. pathname을 가려도 상속 또는 SCM_RIGHTS/Binder로 전달된 열린 FD와 Binder handle은 별도 경로다. 모든 Guest 자격에서 FD allowlist, `/proc` 재진입, root/mount namespace, socket/장치 alias와 전달 경로를 검증해야 한다. 선행 시험의 상속 FD 부재는 해당 helper에만 해당한다.

## 공유 system_server 도메인의 위험

Host와 Guest가 동일 `u:r:system_server:s0`이면 SELinux의 같은 source SID에 같은 대상 타입·클래스에 대한 권한이 적용된다. 프로세스가 별도 mount/Binder namespace에 있다는 사실은 정책이 두 system_server를 구별한다는 뜻이 아니다. Host 자원 경로나 연결, 전달된 FD/handle이 보이면 기존 권한으로 접근할 가능성이 있다. 반대로 동일 SID만으로 DAC, 서비스 인가, 연결 가능성까지 증명되지는 않는다. 동일 타입 재사용 또는 전역 allow 추가는 Host에도 영향을 미칠 수 있다. 독립 도메인과 접근 가능한 모든 IPC/FD 경로의 제한, Host 보호 객체의 분리 및 전후 실효 정책 분석이 필요하지만 현재 설계·검증은 blocked다.

## Guest 인증 의존성과 Host 보호

Lock v5는 무잠금 신규 사용자에 대해 secure-lock 기능 제거와 Weaver 사용 축소를 목표로 한다. 실제 feature 제거·RRO 활성화는 not_run/blocked이며 기존 protector의 이전이나 모든 인증 호출의 부재를 증명하지 않는다. Gatekeeper/Weaver는 잠금 자격·synthetic password와 관련되며 조건부 경로가 남을 수 있다. AuthSecret과 RebootEscrow는 별도 수명주기 경로이므로 무잠금 설정으로 자동 차단된다고 가정하지 않는다.

Guest keystore2는 키 서비스와 KeyMint 보안 수준·인증 토큰에 의존할 수 있고, vold/FBE의 장치 암호화·사용자 DE/CE 키와 키 보호는 빌드 및 설정에 따라 KeyMint/keystore와 연관된다. 무잠금이 암호화 또는 KeyMint 의존성 제거를 뜻하지 않는다. 실제 GSI의 최초 생성·재시작·사용자 잠금 해제 경로, software 대안과 보안 성질, 데이터 영속성은 unknown이다. Host HAL을 직접 공유하면 키 네임스페이스, UID/SID·인증 토큰, Weaver 슬롯, rollback/삭제, secure storage 및 하드웨어 상태의 충돌 가능성을 배제할 수 없다. 독립 userdata만으로 TEE 내부 상태 격리는 보장되지 않는다. Host 인증 HAL을 노출하지 않는 상태에서 독립적이고 호환되는 Guest 백엔드와 FBE 키 수명주기를 설계·검증하기 전에는 부팅을 진행할 수 없다. 강제 소프트웨어 대체나 암호화 해제는 이 감사의 결론이 아니다.

## 후속 읽기 전용 증거

1. 이미지의 init/APEX/서비스 선언과 조건, 사용자·도메인·라벨을 연결해 실제 최초 부팅 필요성을 따로 입증한다. 파일 부재만으로 unused를 확정하지 않는다.
2. 저장된 Host VINTF/init/정책과 정확히 일치하는 실행 빌드의 메타데이터가 확보되면 서비스 인스턴스, 도메인, Binder 종류, socket·device·FD 경로 및 DAC/SELinux를 경로별로 대조한다. 등록 매핑만으로 활성 여부를 추론하지 않는다.
3. Guest 전용 도메인과 자원별 차단 모델에 대해 기존 정책의 실효 AV 및 attribute 확장, 추가 후보의 Host 영향과 기존 권한을 비교한다. 동일 SID의 Host 보호 보장은 별도 증거가 필요하다.
4. keystore2/vold/FBE, Gatekeeper/Weaver 및 AuthSecret/RebootEscrow의 조건부 의존성과 독립 백엔드의 저장·재시작·오류 동작을 오프라인에서 분석한다. 실기기 검증과 정책 변경은 별도 범위다.

## 삼성 제공 커널 소스의 경계 근거

요청에 따라 Luna MAX 서브에이전트가 삼성 제공 `S937NKSU2BYI3` 소스의 관련 커널 코드만 읽었다. [Binder Kconfig](../vendor/S937NKSU2BYI3/kernel_platform/msm-kernel/drivers/android/Kconfig:28)의 기본 이름은 binder,hwbinder,vndbinder이며 [binder_internal.h](../vendor/S937NKSU2BYI3/kernel_platform/msm-kernel/drivers/android/binder_internal.h:20)는 장치별 context manager를 나타낸다. [binder.c](../vendor/S937NKSU2BYI3/kernel_platform/msm-kernel/drivers/android/binder.c:3361)는 transaction 보안 hook을, [FD 전달 경로](../vendor/S937NKSU2BYI3/kernel_platform/msm-kernel/drivers/android/binder.c:2557)는 전달 파일의 보안 검사를 포함한다. 이는 해당 코드의 구조이지 실제 Guest의 접근 거부를 입증하지 않는다. `gki_defconfig`의 Binder/binderfs 설정은 기기 최종 config를 보장하지 않는다. 제공 소스 6.6.77과 선행 실험 기기의 실행 커널 6.6.127은 빌드가 다르다. 인증 서비스별 실제 driver·socket·FD 경로는 미확인이다.

같은 소스에서 Unix stream 연결은 [af_unix.c](../vendor/S937NKSU2BYI3/kernel_platform/msm-kernel/net/unix/af_unix.c:1572)의 hook과 [SELinux connectto 검사](../vendor/S937NKSU2BYI3/kernel_platform/msm-kernel/security/selinux/hooks.c:4987)를 거친다. SCM_RIGHTS 수신은 [scm.c](../vendor/S937NKSU2BYI3/kernel_platform/msm-kernel/net/core/scm.c:309), [file.c](../vendor/S937NKSU2BYI3/kernel_platform/msm-kernel/fs/file.c:1156)의 file-receive 검사 후 FD 설치 경로다. fork/exec FD 상속에서 close-on-exec로 표시되지 않은 FD는 유지될 수 있다 ([file.c](../vendor/S937NKSU2BYI3/kernel_platform/msm-kernel/fs/file.c:789)). 장치 경로 open은 [namei.c](../vendor/S937NKSU2BYI3/kernel_platform/msm-kernel/fs/namei.c:504)의 권한 검사와 [char_dev.c](../vendor/S937NKSU2BYI3/kernel_platform/msm-kernel/fs/char_dev.c:373)의 장치 open 경로를 포함한다. 이런 일반적 검사 지점은 특정 인증 HAL이 해당 경로를 이용한다거나 Guest 접근이 차단됐다는 증거가 아니다.

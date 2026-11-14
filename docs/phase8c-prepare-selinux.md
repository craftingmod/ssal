# Phase 8C — 프로파일별 자동 SELinux 구성

최신 실기기 결과는 [Y702 적용 결과](y702-native-placeholder-live-20261115.md)를 참조한다. Native 정책·placeholder·APEX overlay 적용은 통과했고, 전체 prepare/첫 부팅은 아직 완료되지 않았다. Overlay upper는 tmpfs 대신 Guest ext4 userdata 안의 세션 전용 디렉터리를 사용한다. Guest `/data` 뷰에서는 이를 가리고, 모든 세션 마운트 해제 후 삭제한다.

Native KernelSU 백엔드와 오프라인 검증 결과는 [phase8c-native-injector.md](phase8c-native-injector.md)를 참조한다. 기본 적용 경로는 ksud이며, `[userfaultfd]`, `[io_uring]`, `[aaa]`처럼 특수 이름의 전환 규칙이 있으면 전체 적용을 Native로 자동 선택한다. `--native`로도 선택할 수 있으며 Native 실패 시 ksud로 재시도하지 않는다.

`ssal prepare --regen PROFILE_NAME`은 입력 해시가 같아도 마운트한 GSI에서 계획을 다시 생성합니다. 프로파일 ID와 버전별 계획 이력은 유지합니다.

`ssal prepare <profile>`는 마운트된 등록 GSI의 system/system_ext/product 정책과 contexts를 읽는다. 파일 경로와 내용의 SHA-256을 비교해 변경된 경우에만 CIL을 다시 변환한다. 생성기 버전도 캐시 키의 일부다. 변경되지 않은 입력은 `selinux/plan.json`을 재사용한다. vendor 소스나 Host vendor 정책을 탐색하지 않는다. 버전별 mapping/compat CIL은 활성 파티션 정책과 중복되므로 입력에서 제외한다.

프로파일 생성 시 `profile.json.selinux_id`에 `p0001` 형식의 ID를 저장한다. 기존 프로파일은 첫 prepare에서 할당한다. `state/selinux-ids/`의 예약 파일은 프로파일 삭제·생성 실패 시에도 남으므로 ID가 재사용되지 않는다. 복제된 프로파일의 ID 충돌은 거부한다.

`selinux/plan.json`에는 입력 해시, 원본 타입/attribute 매핑, 생성할 KernelSU 선언과 규칙, 변환된 contexts, 미지원 구문의 파일·행 번호를 저장한다. 타입은 `ssal_<ID>_<original_type>`이다. 타입 alias는 실제 타입의 매핑을 공유한다. allow/auditallow/dontaudit, ioctl 확장 허용, named transition, typechange/member, attribute 집합 연산을 변환한다. 실행 규칙에서 쓰이지 않는 컴파일용 attribute는 매핑만 보존한다.

`selinux/plans/v<생성기 버전>-<입력 해시>.json`에도 생성 결과를 남겨 GSI가 바뀐 뒤에도 이전 타입 매핑을 확인할 수 있다.

Guest attribute에는 Guest 타입만 넣는다. Host 공유 레이블이 필요한 target에는 별도의 Guest 소유 target attribute를 사용한다. 기존 Host attribute에 Guest 타입을 넣지 않는다. `/vendor`, `/odm`, 공유 `/dev`, `/proc`, `/sys` 레이블은 유지한다. Private Binder·property socket/area는 Guest 타입을 사용한다. Host MLS 제약과 fsuse/genfscon은 그대로 사용하고 GSI 전역 선언으로 교체하지 않는다. GSI의 permissive 선언은 설치하지 않는다.

KernelSU 적용은 `/data/adb/ksu/bin/ksud`의 check/apply를 사용한다. `selinux/applied.json`에 boot ID, 등록 심볼, 적용한 문장, 진행/실패 상태를 기록한다. 같은 부팅에서는 차이만 적용하며, 재부팅 후에는 기존 생성 결과를 다시 적용한다. 선언 → attribute membership → 접근/transition 순서를 보장한다. 프로파일 잠금과 커널 심볼 충돌 검사도 수행한다. check는 인자 크기를 제한해 나누고, 실제 apply는 하나의 파일로 실행한다. 출력은 `apply-stdout.txt`, `apply-stderr.txt`에 남긴다.

적용 전 활성 커널의 class/permission과 공유 심볼을 비교한다. 타입 존재는 바이너리 정책의 실제 type/attribute 테이블을 읽어 판별한다. 파일시스템 이름 등 다른 문자열을 타입으로 세지 않으며 현재 판독 범위는 policy v24–v33이다. Host에 없는 class/permission은 `compatibility.json`에 기록하고 생략한다. 하나의 allow에 지원/미지원 permission이 함께 있으면 지원되는 permission은 유지한다.

`iso9660`처럼 GSI에서 공유 대상으로 참조하지만 Host에 없는 타입은 원래 이름으로 placeholder 선언만 추가한다. 권한 없는 `ssal_<ID>_placeholders` attribute만 사용하고, 그 타입을 참조하는 allow·xperm·Guest target attribute membership은 제외한다. 별도의 `ssal_<ID>_iso9660` Guest 타입과 Guest 전용 규칙은 유지한다. 기존 Host 타입·attribute·fsuse/genfscon 및 파일 레이블은 변경하지 않는다. `compatibility.json`에 placeholder 목록과 실제 선택 백엔드를 기록하며, `applied.json`에 생성한 placeholder를 기록해 같은 프로파일의 재실행에서도 권한 없는 상태를 유지한다. 이 동작은 적용 시 계산하므로 기존 생성 캐시도 재사용할 수 있다.

규칙 제거·교체가 필요한 입력 변경이나 apply 중단으로 결과가 불확실한 경우에는 재부팅 후 재실행해야 한다. 기존 Guest 정책을 삭제하거나 ID를 바꿔 우회하지 않는다. 프로파일을 삭제해도 현재 부팅에 추가한 정책은 남는다. Host가 Enforcing이 아니면 오류를 반환하며 전역 모드를 바꾸지 않는다. 적용 후에는 필수 프로세스 context의 유효성을 확인한다. 모든 AV 규칙을 커널에서 역조회했다는 의미는 아니다.

Guest 시스템·APEX는 세션 전용 overlay의 레이블을 변경한다. 등록 GSI와 Host bind 원본은 변경하지 않는다. 커널의 overlayfs `metacopy=on` 지원이 필요하다. 패치와 런타임 helper는 Guest 전용 복사본을 레이블링한다. 변환한 file/seapp/property/service/hwservice 등 contexts를 Guest 경로에 bind하고, userdata는 Guest restorecon으로 레이블링한다. 기존 compiled file_contexts는 overlay에서 숨겨 원본 binary context 캐시를 사용하지 않게 한다.

Guest Zygote·servicemanager exec SID와 Property Service의 프로세스/area/socket/default property context는 프로파일 매핑을 사용한다. Property Service는 GSI property_contexts와 실제 SELinux AV 결정을 사용한다. Guest 전용 preload는 system_server 등의 하드코딩된 setcon/setexeccon/setfscreatecon 타입을 변환하며 role·MCS는 보존한다. 원본/이미 변환된 타입만 허용하고 알 수 없는 타입으로의 setter는 실패한다. 기존 고정 SID·SELinux 우회 실험 옵션과는 함께 실행하지 않는다. 기존 8B-5 실행 차단을 해제하지 않는다.

기존 SELinux/Binder PoC 명령은 종전 진단 경로를 유지한다. 자동 매핑은 prepare와 준비된 프로파일의 Guest launcher 경로에 연결한다. 전용 파일 패치는 지원하지만 디렉터리 전체를 bind하는 패치는 자동 레이블 경로에서 오류를 반환한다.

검증: Rust 단위/회귀 테스트, 저장된 GSI export 변환, 네이티브 setter 매핑 self-check, Android AArch64 빌드. 저장 GSI에서는 26개 입력, 타입/alias 2,040개, 약 4.6만 규칙을 처리했다. KernelSU의 ioctl 변환으로 표현할 수 없는 `nlmsg` 확장 허용 23건은 진단에 남기고 생략한다(권한 추가 없음). 그 밖의 미지원 구문은 적용을 차단한다. 새 GSI도 prepare 시 동일하게 검사한다.

기기 live apply, overlay/restorecon 동작, 실제 setter interposition 및 Enforcing 첫 부팅은 아직 검증하지 않았다. 기존 FIVE 패닉 실험과 별도로 실기기 검증이 필요하다.

2026-11-14 placeholder 변경 검증: 관련 단위 테스트 18개, 저장 GSI 전체 인코딩 회귀, Y702 active/precompiled 정책의 심볼 판독, clippy 및 Android AArch64 CLI·데몬·정책 도구 빌드 통과. GSI 특수 이름 전환 51개를 보존했으며, 두 Y702 정책 모두 `iso9660` 타입 부재를 확인했다. 새 정책의 실기기 적용과 첫 부팅은 실행하지 않았다.

### 활성 정책 읽기의 EINVAL 복구

`prepare`와 `ssal-sepolicy apply`는 활성 `/sys/fs/selinux/policy` 읽기가
`EINVAL`로 실패한 경우에만 export 복구를 한 번 시도한다. 먼저 활성 커널의
`access` 인터페이스에서 `ksu → ssal_image_file:file read`의 명시적 허용을
확인하고, 이미 허용된 동일 규칙을 `ksud sepolicy patch`로 재적용한 뒤 정책을
처음부터 다시 읽는다. 이 복구 단계는 Native 백엔드를 선택해도 ksud를 사용한다.
기존 권한 확인·ksud 실행·재읽기가 실패하면 중단하며 반복 복구하지 않는다.
권한 거부 등 다른 errno에는 복구하지 않는다. Host Enforcing과 기존 정책을
유지하며, 읽기 전용 진단 명령의 정책 해시 조회는 정책 재적용을 하지 않는다.

[Y702에서 검증한 복구 결과와 한계](y702-policy-export-recovery-20261114.md)를 참조한다.

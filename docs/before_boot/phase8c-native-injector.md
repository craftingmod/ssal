# Phase 8C Native KernelSU injector — 2026-11-07

초기 구현 이후의 실제 적용 결과: [Y702 Native / placeholder 실기기 검증](y702-native-placeholder-live-20261115.md). 16 KiB 배치로 정책 적용 전체가 통과했다. 아래 초기 구현 기록과 구분한다.

구현 완료. 실제 `SET_SEPOLICY`는 실행하지 않았다. 설치된 SSAL 데몬/런타임도 교체하지 않았다.

## 구현

- CIL 생성기와 기존 텍스트 규칙 및 `delta()`를 유지한다. 생성기 v3는 의미 분석 시 구조화된 `native_rules`를 함께 기록한다. Native는 KernelSU 텍스트 파서를 사용하지 않는다. v2 캐시는 Native 적용 전에 재생성이 필요하다.
- `native.rs`는 KernelSU `uapi/supercall.h`, `uapi/selinux.h`, `ksucalls.rs`, `sepolicy.rs`, `kernel/selinux/rules.c`를 참조한다. 명령 헤더와 `[u32 length][bytes][NUL]` 인자를 AArch64 little-endian으로 인코딩한다. 선택적 transition 객체의 NULL도 인코딩한다.
- allow/auditallow/dontaudit, ioctl xperm 세 종류, type/attribute/typeattribute, type_transition/type_change/type_member를 지원한다. 이름과 ioctl 범위를 변경하지 않는다.
- 전체 계획을 먼저 인코딩·검증하고, 이후 기존 Host 호환성 필터와 delta를 적용한다. 선언 → 타입 → membership → 의존 규칙 순서를 검사한다. 누락된 구조화 데이터, 원문 불일치, NUL, 잘못된 인자/범위, 미지원 명령은 원문과 사유를 포함해 실패한다.
- 기존 Host SELinux 정책과 Enforcing을 유지한다. Guest 소유 명령만 허용하며 deny/permissive/Host attribute 변경 명령은 제공하지 않는다. 기존 `nlmsg` 미지원 23건은 사유와 CIL 원문을 `unsupported`/`unsupported_source`에 기록한다.
- Native는 상속된 `[ksu_driver_su]`/`[ksu_driver]` FD를 복제하거나 KernelSU reboot magic hook으로 FD를 획득한다. GET_INFO로 UAPI 5 일치를 확인한 다음 `KSU_IOCTL_SET_SEPOLICY=0xc0004b04`를 호출한다. 배치는 16 KiB 이하이다. Y702에서 256 KiB 첫 배치 후 export/다음 ioctl이 EINVAL로 막힌 관측에 따라, 정책 복제 사이의 심볼 증가량을 줄였다. 축소 배치의 실기기 효과는 재부팅 후 검증해야 한다.
- `applied.json.native_batches`에 배치별 expected/succeeded/error/partial_or_uncertain을 기록한다. 호출 전 pending 기록을 저장한다. 부분 성공/오류에서는 중단하고 pending을 유지하며 자동 fallback/재시도/rollback을 하지 않는다. 성공 건수만으로 실패한 개별 명령을 알 수 없다. 이전 배치의 추가 정책은 남을 수 있으므로 재부팅이 필요하다.
- 기본 백엔드는 ksud이며 `--native`로 Native를 선택할 수 있다. 현재는 `[aaa]`처럼 특수 이름의 전환 규칙이 있으면 ksud 요청에도 Native를 자동 선택한다. 실제 선택은 `compatibility.json.backend`에 기록한다.

## 명령

```sh
# 읽기 전용: 실제 설치 커널의 UAPI 확인
ssal-sepolicy info

# 오프라인: 구조화 계획 인코딩
ssal-sepolicy encode PLAN_JSON OUTPUT_DIR

# 저장된 GSI export로 p0001 검증 계획 생성 및 인코딩
ssal-sepolicy generate-encode GSI_EXPORT OUTPUT_DIR

# 실제 정책을 바꾸는 별도 명령 — 이번 단계에서는 실행하지 않음
ssal-sepolicy apply --native PROFILE_DIR
ssal-sepolicy apply --ksud PROFILE_DIR
```

`generate-encode`는 오프라인 fixture용 p0001 계획을 만든다. 다른 프로파일에는 해당 프로파일 ID로 생성된 계획을 사용해야 한다. helper는 Android 빌드 및 모듈 패키징 목록에 포함했다. 신규 런타임 의존성은 추가하지 않았다.

## 검증 결과

- 저장 GSI: 입력 26개, 타입/alias 2,040개, 규칙 47,335개. 33배치, atomic 명령 104,139개, 8,497,863바이트 인코딩 성공.
- type_transition 총 346개 중 기존 텍스트 파서가 거부한 `[userfaultfd]`/`[io_uring]` 51개도 인코딩 성공. allowxperm ioctl atomic 범위 1,296개 보존.
- `scripts/compare-native-sepolicy.py`로 원본 `sepolicy.rs`의 직렬화 함수를 직접 포함한 비교 harness를 실행했다. 모든 배치 바이트가 일치했다. 원본 파서가 처리하는 규칙은 파싱/atomic 확장 결과까지 일치했다. 원본 파서는 특수 transition 51개를 거부하므로 이 51개는 구조화 인자를 원본 serializer에 직접 전달해 비교했다.
- 정책 단위 테스트 및 고정 GSI fixture 회귀 테스트 통과. 누락/변조/Host 명령/순서 오류, 부분 성공/errno 기록, Host permission 축소 후 Native 인코딩을 검사한다. `cargo clippy --locked --lib --bin ssal-sepolicy -- -D warnings` 통과.
- Android AArch64 릴리스 빌드 완료. 전체 테스트도 실행했으나 변경 범위 밖의 기존 pipe 진단 및 환경 의존 테스트 실패로 전체 suite는 green이 아니다. root 실행의 pipe 테스트는 786,432/1,048,576바이트 차이로 실패했고, 축소 PATH에서는 mke2fs를 찾지 못했다. 일반 사용자 재검증에서도 환경/권한 의존 실패가 남았다. 관련 코드는 수정하지 않았다.
- 기기 `ksud samsung-v2.2 (uapi: 5)`. 새 helper의 읽기 전용 GET_INFO 결과: version 32687, flags 5, features 5, uapi_version 5. staging helper는 확인 후 삭제했다.
- 기기 확인 전후 SELinux 정책 SHA-256 동일: `77c6de80769f2a365d1e707cb933d4e6c4ba6778fb4f7704dbc0738de6ec9f7a`. Enforcing=1, boot ID 동일.

산출물은 `out/phase8c-native/`: `encoding/encoding.json`, `encoding/upstream-comparison.json`, 바이너리 배치, `fixture-test.log`, `clippy.log`, `android-build.log`, 전체 테스트 로그, `device-info.json`, `device-before.txt`, `device-after.txt`, 원본 파일 SHA-256 목록에 보관했다. 실행 바이너리는 `out/bin/ssal-sepolicy`이다.

실제 주입 및 Enforcing 첫 부팅은 검증하지 않았다. 바이너리 동일성은 해당 커널에서 모든 규칙이 의미적으로 성공한다는 보장은 아니다.
`ssal prepare [--regen] --native PROFILE_NAME`에서도 Native를 명시적으로 선택할 수 있다. CLI 요청의 선택값을 데몬이 prepare worker 전용 환경으로 전달한다. 옵션 생략·기존 버전 요청은 ksud를 요청하며 특수 이름 전환이 있으면 적용 단계에서 Native를 자동 선택한다. 실제 prepare/주입은 실행하지 않았다.
`ssal-sepolicy check PLAN_JSON`는 전체 계획을 Native 인코더로 검증하고 커널 FD/ioctl에 접근하지 않는다. `ssal prepare`도 백엔드 선택과 관계없이 같은 검사를 먼저 수행하며, 기존 `ksud sepolicy check` subprocess는 제거했다. ksud apply fallback은 유지한다. check는 커널의 의미적 적용 성공을 보장하지 않는다.
생성기 v4: 90자 permission 분할/제한을 생성기와 delta에서 제거했다. 전체 permission 집합을 유지하고 Native 인코더가 atomic 명령으로 변환한다. 기존 캐시는 버전 변경으로 재생성된다. 고정 GSI 결과는 규칙 46,300개, atomic 명령 104,140개, 8,497,958바이트이며 원본 serializer와 전체 바이트가 일치했다. 텍스트 파서 제한이 있으므로 긴 규칙은 명시적 Native 백엔드를 사용해야 한다. 기존 부팅에 이전 형태 규칙이 적용돼 있다면 delta의 제거/변경 감지가 재부팅을 요구할 수 있다.

생성기 v5: Native UAPI는 `self`를 타입 이름으로 조회하므로 allow/auditallow/dontaudit 및 ioctl xperm의 `self`를 명시적 타입으로 변환한다. source가 attribute이면 멤버별 `(type, type)` 쌍으로만 펼쳐 멤버 간 교차 권한을 만들지 않는다. 기존 캐시는 재생성하며 v5 이전 계획의 Native 적용은 거부한다. 고정 GSI는 규칙 49,802개, atomic 명령 133,794개, 11,258,910바이트, 16 KiB 배치 702개다. 특수 이름 전환 51개는 유지된다. 관련 단위 테스트 19개와 전체 GSI 인코딩 회귀·clippy·Android 빌드를 통과했다.

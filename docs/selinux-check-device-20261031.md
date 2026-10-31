# SELinux 진단 — 2026-10-31

**판정: blocked.** 정책은 적용하지 않았다. `bun run selinux:check`를 추가하고 연결된 SM-S937N의 정책 파일과 등록된 GSI를 검사했다. 기기 검사는 한국 시간 2026-10-31 06:07에 완료됐으며, 한도 중단 후 재개 시 기기가 연결되지 않아 저장된 결과를 검토했다.

## 결과

| 항목 | 결과 |
|---|---|
| 현재 커널 context 조회 | 2,686개 중 2,649개 유효, 37개 EINVAL(22) |
| Framework 서비스 context | 기존 누락 타입 9개가 여전히 유효하지 않음 |
| AV 조회 | 2,615회: 허용 1,162, 거부 1,408, 오류 45 |
| 전역 Enforcing | 조회 전후 1 유지 |
| 관측한 AV sequence | 1 유지 |
| Host 관측 | 주요 프로세스 PID·이름·도메인, init mountinfo 및 모듈 정책 파일 해시가 전후 일치 |
| 임시 기기 파일 | 제거 확인 |
| 정책 로드·라벨 변경·서비스 기동·마운트 | 수행하지 않음 |

AV 거부 1,408건은 지정한 주체별 진단 결과다. servicemanager가 다른 서비스의 등록 권한을 갖지 않는 경우처럼 의도된 거부도 포함하므로, 모두 추가할 allow 규칙으로 해석하면 안 된다. 오류 45건은 유효하지 않은 서비스 context 9개에 대한 5개씩의 조회다. 실제 등록·실행·Binder transaction 시험은 이번 검사에 포함하지 않았다.

37개는 **서비스 9, 파일 라벨 12, property 라벨 12, seapp 도메인 3, SSAL 계약 도메인 1**이다. 선언된 context의 커널 유효성 검사이며 해당 파일이나 서비스가 실제 사용된다는 증거는 아니다. 전체 목록과 출처는 [요약 JSON](selinux-check-device-20261031.json)에 있다.

서비스 타입 9개는 `adbroot_service`, `fingerprint_hidl_service`, `lineage_globalactions_service`, `lineage_hardware_service`, `lineage_health_interface_service`, `lineage_livedisplay_service`, `lineage_profile_service`, `lineage_trust_service`, `qcrilam_service`다. `ssal_property` 도메인도 유효하지 않다.

## 삼성 vendor/odm과 정책 조합

삼성 정책은 기기에서 직접 읽었다. 사용자가 별도 소스를 제공할 필요는 없었다. vendor 정책 API는 `202404`다. GSI 이미지의 등록 SHA-256을 검증했고 실제 이미지의 Android 버전은 16, SDK는 36이다.

Debian `secilc` 3.4는 실제 Android CIL의 `nlmsg` permissionx 구문을 처리하지 못했다. 이는 설치 누락과 다른 컴파일러 호환성 문제다. 따라서 기기의 `/system/bin/secilc`로 **추출한 복사본만 임시 컴파일**했다. 생성된 정책은 로드하지 않았다.

- **Host CIL 조합:** neverallow 검사를 포함하면 실패했다. Android init 방식의 `-N`을 사용한 별도 컴파일은 성공했고, SETools가 버전 33·타입 4,983개·permissive 도메인 0개로 읽었다. `-N` 성공을 neverallow 검사 통과로 해석하지 않는다.
- **Guest system/system_ext/product + 삼성 vendor/odm:** 일반 모드와 `-N` 모드 모두 genfscon 처리 중 실패했다. 같은 파일시스템·경로의 서로 다른 선언도 아래와 같이 확인했다. 충돌을 제거한 재컴파일은 하지 않았으므로 다른 오류까지 모두 배제한 결과는 아니다.

| 파일시스템·경로 | GSI system_ext 라벨 | 삼성 vendor 라벨 |
|---|---|---|
| `iso9660 /` | `iso9660` | `vfat` |
| `udf /` | `udf` | `vfat` |

따라서 GSI 전체 정책을 그대로 조합하는 방식은 현재 통과하지 않는다. SSAL 목표에 맞춰 기존 삼성 실효 정책에 필요한 타입·attribute·권한을 최소 확장하는 설계와 별도 검증이 필요하다.

odm의 사전 컴파일 정책은 버전 30이며 현재 system/system_ext/product의 정책 해시와 모두 불일치했다. 이 파일을 현재 커널 정책으로 간주하지 않았다. `/sys/fs/selinux/policy` 읽기는 EINVAL로 실패해 현재 실효 정책 전체의 해시를 확보하지 못했다. `/sys/fs/selinux/policyvers`의 33은 커널의 지원 상한이며, 로드된 정책의 버전을 직접 읽은 값이 아니다.

## 재실행

```powershell
bun run selinux:check
bun run selinux:check --profile profile1 --serial ADB_SERIAL
```

adb의 su 접근과 실행 중인 `ssal-dev`가 필요하다. 원본 이미지는 읽기만 하고, 해시가 일치하는 복사본을 `.cache/selinux-images/`에 보관한다. 정책 디렉터리는 debugfs로 추출하므로 이미지 마운트가 필요 없다. 기기 컴파일러 확인과 selinuxfs 조회를 위해 고유한 임시 디렉터리를 만들고 종료 시 제거한다. vendor 소스 저장소를 빌드하지 않는다.

결과는 `out/selinux-check/<run>/report.json`, 최신 결과 위치는 `out/selinux-check/latest.json`에 남긴다. 종료 코드 0은 진단 완료를 의미하며, 호환 판정은 `overall`과 세부 결과를 확인한다. `contexts_valid_only`도 Android 부팅이나 서비스 실행 성공을 보장하지 않는다.

이번 원시 결과는 `out/selinux-check/2026-10-30T21-06-36-556Z-feba58ef/report.json`이다. 각 입력 파일·도구·헬퍼의 해시, 컴파일 로그, 조회 결정과 정리 결과를 기록했다. TypeScript 검사, Python 구문 검사, 생성 셸의 shellcheck와 C 헬퍼의 `-Wall -Wextra -Werror` 빌드가 통과했다. 잘못된 프로필 이름을 수집 시작 전에 거부하는 것도 확인했다.

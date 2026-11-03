# Phase 2: directory-backed userdata — 2026-11-03

SM-S937N의 순정 삼성 커널에서 새 프로필 userdata 디렉터리를 Guest `/data`에 bind한 채 실제 Guest `installd`와 `artd`를 실행했다. Permissive 기준 데이터 격리 시험의 다섯 게이트가 통과했다. 새 파일시스템이나 userdata loop ext4는 추가하지 않았다. `switch` 및 운영 계약의 `launch_enabled=false`는 유지한다.

[최종 실기기 보고서](phase2-data-isolation-device-20261103.json)는 각 게이트, PID/starttime, 도메인·자격·실행 파일·FD, bind inode/mountinfo, private Binder, 클래스패스와 컴파일 산출물, Host 비교 및 정리 증거를 포함한다. 초기 실패도 같은 정리 경로를 거쳤다.

## 실행

```sh
ssal create lineage NEW_PROFILE
# 시험 관리자가 원래 SELinux 모드를 기록하고 Permissive로 설정한다.
ssal probe-guest-data NEW_PROFILE
# 성공·실패와 관계없이 원래 SELinux 모드로 복원한다.
```

프로브는 스스로 `setenforce`하거나 정책을 로드하지 않는다. 실제 시험에서는 EXIT trap으로 Enforcing 복원을 수행했다. 사용한 프로필은 데이터와 소유권이 변경되므로 재시험은 다른 새 프로필로 실행한다. 기존 Host 데이터 복사·migration은 지원하지 않는다.

`scripts/build-binder-probe.sh GUEST_LIB_DIR`가 IPC helper, 재현 가능한 작은 DEX APK, 컴파일 namespace 보조기 및 stderr 로거를 함께 빌드한다. 패키징은 바이너리·소스·fixture 해시를 검사한다. 이 시험의 ART AIDL은 Android 16 QPR2 [고정 소스](https://android.googlesource.com/platform/art/+/1690c6912a7972c9e62c39b48c706de9b8b18b4a/artd/binder/com/android/server/art/IArtd.aidl)를 따른다. 다른 Guest ABI는 다시 확인해야 한다.

## 통과 조건

| 게이트 | 확인한 작업 |
| --- | --- |
| `guest_data_isolation` | 빈 root-owned userdata, 경로 구성요소 symlink 거부, Host와 다른 mount namespace, private 전파, bind source dev/inode, `rw,nosuid,nodev`, profile 경유 쓰기 왕복 |
| `installd` | 실제 `u:r:installd:s0`, root 및 제한 capability, Guest root/executable/private Binder FD 검사 후 `createAppData`와 `destroyAppData`; CE/DE 출력 소유권·inode 및 삭제 확인 |
| `artd` | 실제 `u:r:artd:s0`, UID/GID 1082, Guest root/executable/private Binder FD; private Binder `dexopt(verify)`의 비취소 성공·반환 크기와 userdata의 OAT/VDEX 파일 검사 |
| `host_unchanged` | Host mountinfo·Framework/installd/artd 신원, 전체 service registry 해시, 전체 property 값 해시, 대응 Host 앱·프로필·dalvik-cache 시험 경로의 부재가 전후 일치 |
| `cleanup` | 요청자→artd→installd→시험 서버→manager 역순 TERM/유한 대기/KILL, 프로세스 그룹 생존 검사와 회수, private Binder·임시 bind 해제 |

내부 `daemon_probe_passed`만으로 완료하지 않는다. 바깥 worker가 rootfs와 system/userdata mount, 세션 loop backing까지 해제한 뒤 `Phase 2 worker gate: {"phase2_complete":true,...}`를 출력해야 한다. 정리 실패는 같은 boot의 새 시험을 막는 recovery marker와 자원 보존 경로로 간다.

## 삼성 커널에 맞춘 시험 환경

- 이 커널은 PID namespace 생성을 `EINVAL`로 거부한다. 데몬에는 자기 PID의 proc 디렉터리만 보이고 Host PID 트리는 보이지 않는다. 컴파일 자식에는 별도 mount namespace에서 그 자식의 proc 디렉터리만 bind한다.
- 사용자가 명시적으로 승인한 **시험 전용** 예외로 artd에 `CAP_SYS_ADMIN`을 추가한다. 보조기는 session socketpair로 감독자에게 요청한다. 감독자는 PID/starttime·프로세스 그룹·Guest root·보조기 executable·artd 도메인과 분리된 namespace를 검사한다. proc 연결 후 SYS_ADMIN이 effective/permitted/inheritable/ambient에서 제거되고 NNP가 유지된 실제 status를 확인해야 순정 `art_exec`를 진행한다. 컴파일러의 bounding set에는 해당 비트가 남지만 NNP 및 제거된 permitted/inheritable/ambient 때문에 exec로 복구할 수 없다. 운영 서비스에 이 예외를 적용하지 않았다.
- 세션 프로세스 그룹 이탈을 seccomp로 차단한다. 감독자는 leader를 `WNOWAIT`로 관찰해 PID 소유권을 유지한 채 자식 그룹 전체를 종료하고, live task가 사라진 뒤 leader를 회수한다.
- property는 Host 영역 대신 독립 Bionic pre-split RO area다. Guest SDK 36을 확인하고 manager-ready, SDK/codename, ARM64 ABI 및 64-bit dex2oat 선택 값만 준비한다. Guest property service는 없고 모든 `connect`는 EPERM이다. Host property 원문은 보고서에 넣지 않는다.
- `derive_classpath`는 Guest classpath protobuf만 읽어 BOOTCLASSPATH/DEX2OATBOOTCLASSPATH를 만든다. Guest ART/system/statsd/i18n 라이브러리 검색 경로와 session stderr 로거를 명시한다. Host cgroup/task profile 및 logd/tombstoned는 연결하지 않는다.
- 준비한 `/data` 하위 경로의 UID/GID·mode·라벨 적용 결과를 기록한다. Permissive에서는 일부 Guest 라벨이 Host 정책에 없어 relabel 오류가 남을 수 있다. 그 오류를 Enforcing 허용 증거로 취급하지 않는다.

## 검증 범위

실제 데몬 RPC와 작은 생성 DEX의 `verify` 컴파일이 통과했다. 컴파일러는 Guest boot image의 read-barrier 불일치를 보고한 뒤 imageless 모드로 정상 완료했다. 이는 앱 설치·실행, 속도 최적화, boot-image 호환성이나 Guest FBE/CE 키 수명주기 검증이 아니다. Package Manager 전체 경로는 Guest `system_server` 부팅 단계에서 별도로 검증한다.

새 SELinux 규칙, Host Framework 중지, 재부팅, 운영 서비스 활성화는 수행하지 않았다. `vendor/` 코드는 읽지 않았다. 실제 unkillable task와 mount/loop 해제 실패 주입은 미실시다.

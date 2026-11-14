# Y702 Native SELinux / placeholder 실기기 적용

2026-11-14 23:29부터 2026-11-15 00:04 KST까지 Lenovo TB320FC, ADB `HA1WAQ7P`, 프로파일 `y702`에서 실행했다. 사용자 승인에 따라 재부팅 두 번을 포함했다. 최종 boot ID는 `c6de69a6-5ab5-4ed0-9c14-cd1eab6fea35`이다.

## 확인된 결과

- Native UAPI 5로 **700개 배치 / 133,304개 명령** 전부 성공. `pending=false`, 등록 심볼 2,741개, 적용 문장 56,089개다.
- `iso9660`, `udf` 등을 포함한 누락 공유 타입 20개를 placeholder로 생성했다. 모두 `ssal_p0001_placeholders` attribute만 가지며, Guest allow/allowxperm의 직접·attribute 확장 대상에 포함되지 않는다.
- `[userfaultfd]` / `[io_uring]` named transition 51개를 실제 정책에서 확인했다. Guest init/zygote/system_server context 질의도 성공했다.
- 기존 Host attribute membership과 permissive 상태는 동일하다. 기존 Host source 규칙 추가·삭제는 0개이며 기존 SELinux constraint도 동일하다. 새 `ssal_p0001_*` 타입에 permissive는 없다.
- 시스템 metadata overlay와 Guest APEX 44개 구성까지 성공했다. Guest userdata의 세션 전용 디렉터리를 ext4 upper로 사용하고, Guest `/data` 뷰에서는 숨긴다. 세션 종료 시 upper 디렉터리·마운트·46개 loop allocation을 정리했다.
- 최종 Host는 Enforcing, `sys.boot_completed=1`, system_server PID 2247 유지. `/data/local/ssal/mnt`는 비었다.
- 최종 정책 SHA-256: `f2ae794aa9d57c8639f206b1950534e6379a808caa2e3b8b420d6b099d0d8f1e`. 같은 부팅의 재실행에서도 동일했다.

## 실기기에서 수정한 원인

1. 256 KiB 첫 배치 후 다음 ioctl과 policy export가 EINVAL이 됐다. 16 KiB로 줄인 뒤 다음 배치 및 export가 진행됐다. clone buffer의 정책 증가 여유와 일치하는 관측이며, 설치된 커널 내부를 trace한 결과는 아니다.
2. 작은 배치의 154번에서 거부된 22개 명령은 모두 `self` 대상이었다. 실제 AV 질의에서도 그 22개만 거부됐다. Native API는 `self`를 타입으로 조회하므로 생성기 v5에서 concrete `(type, type)` 쌍으로 변환했다. Attribute source는 멤버별 자기 대상만 생성한다.
3. Y702의 `CONFIG_TMPFS_XATTR`가 꺼져 있다. 별도 ext4 이미지에서 metacopy overlay와 라벨 복사는 성공했고 lower 라벨은 유지됐다. 이를 기존 Guest userdata의 ext4 upper로 연결했다.
4. 별도 probe에서 `close_range(3, UINT_MAX, CLOSE_RANGE_CLOEXEC)`가 EINVAL이었다. 지원하지 않는 커널에서만 단일 스레드 pre-exec 자식의 현재 `/proc/self/fd` 전체를 순회하여 CLOEXEC를 설정한다. stdio는 유지하고 실패 시 exec를 중단한다.

## 남은 실행 차단

후속 수정으로 아래 linkerconfig gate와 restorecon 탐지 문제는 실기기에서 해소했다. 현재 중단점은 동적 shell probe의 별도 gate다. [수정 및 재실행 결과](guest-prepare-linkerconfig-restorecon-20261115.md)를 참조한다. 아래는 최초 적용 당시의 관측이다.

전체 `prepare`와 Guest 첫 부팅은 성공하지 않았다. 최신 실행은 linkerconfig 준비에서 기존 `Automatic Guest launch is disabled; use the explicit disposable --guest-service-worker launcher` gate에 도달했다. 이를 해제하지 않았다.

또한 Guest restorecon은 `SELinux is disabled, skipping restorecon`을 출력했다. Host Enforcing은 계속 1이므로 이를 Host SELinux 비활성화로 해석하지 않는다. Guest 측 SELinux 탐지/selinuxfs 뷰를 조사해야 하며, userdata relabel 성공으로 세지 않는다. 시스템 overlay 라벨 보존 검사와 scratch 정리는 통과했다.

증거: `out/y702-placeholder-live-20261114/`의 `applied-final.json`, `policy-verification.json`, `query-final.jsonl`, `prepare-fd.log`, `host-final.txt`. 초기 설치 바이너리와 계획 백업은 같은 디렉터리의 `backup.tar`에 있다. 최신 CLI/데몬/정책 도구를 모듈에 설치했고 `out/bin`에도 반영했다.

검증: 정책 테스트 19개, FD 테스트 2개, mount 관련 테스트 12개, 저장 GSI 인코딩 회귀, 정책 도구/라이브러리 clippy, Android AArch64 빌드 통과. 전체 ssald clippy는 기존 too_many_arguments와 double_ended_iterator_last 경고 때문에 `-D warnings`에서 실패했다. 이번 변경과 무관한 경고는 수정하지 않았다.

# Guest bringup 실행 결과 — 2026-11-04

## 결과

Phase 5A는 **PARTIAL**로 확정한다. 과거 NO-GO 및 정책 원복 요구는 이 작업의 진행 조건이 아니다. Guest 전용 domain과 AVC 대응은 후속 부채다. 이번 실행은 첫 부팅이 아니며, 실제 Guest child와 private Binder IPC까지 확인했다.

| 단계 | 이번 실기기 결과 |
|---|---|
| mount namespace / 독립 `/data` | PASS: Host `mnt:[4026532950]`, worker `mnt:[4026535837]`. profile `phase5a-bringup-20261104`의 userdata bind에 write/read 성공, `rw,nosuid,nodev`. 별도 filesystem은 아니다. |
| Guest child | PASS (제한된 probe): `ssal prepare`에서 Android 16 Guest `/system/bin/sh`가 chroot와 pivot_root 양쪽에서 실행되어 root identity 및 profile userdata write/read 확인. 두 child의 context는 `u:r:ksu:s0`; Guest 전용 domain 검증이 아니다. 상속 FD 정리는 해당 경로의 코드에 있으나 이번 결과에서 child FD 목록을 실측하지 않았다. |
| private Binder | PASS (제한된 probe): `ssal probe-binder`에서 Guest `507:5`, Host `507:1`, protocol 8; context manager와 helper 간 실제 IPC 성공, cleanup 성공. Guest helper는 `ksu`이며 Android servicemanager나 Host registry 격리 검사는 이번 명령에서 실행하지 않았다. |
| property 경계 | 미완료: 기본 profile은 Host property area를 공유한다. 소켓 경로는 가려지지만 Guest property service는 없다. 이전 별도 시험의 차단 결과를 이번 검증으로 간주하지 않는다. |
| installd / artd | 이번 실행 안 함. 2026-11-03 별도 Permissive 시험 성공은 [Phase 2](phase2-data-isolation.md)에 있다. |
| Zygote / system_server | 실행 안 함. 첫 부팅 미달성. |

기기 SM-S937N, boot ID `f7900911-c061-4570-8f65-900571a55c11`. 실행 후 Host SELinux는 Enforcing이고 init PID 1, zygote64 27927, system_server 28271, netd 27933, adbd 23785가 실행 전 표본과 같았다. 두 worker 모두 rootfs 잔여 mount 부재와 55개 loop backing 해제를 보고했다. 하드 리부팅은 하지 않았다. 전체 Host 데이터 불변성은 측정하지 않았다.

## 남은 문제와 다음 실행

현재 기본 실행 경로는 Host `/dev`의 Binder와 property area 및 cgroup/BPF를 공유하고, PID namespace가 없다. 제한된 고정 shell만 실행한 결과를 임의 Guest 서비스 실행의 안전성으로 확대할 수 없다. 다음 구현은 기존 시험 세션의 private Binder, 빈/private property 경로, FD 정리 및 Host PID 접근/신호 차단을 서비스 런처에 연결하고 Guest 전용 domain을 permissive로 만들어 실제 서비스에서 AVC를 수집하는 것이다. Host 기존 domain의 권한이나 enforcing 상태는 변경하지 않는다. 이후 installd/artd, Zygote, system_server 순으로 실행한다.

기존 정책에서 `ssal_guest_probe` type이 없다는 5A 진단은 참고 자료다. 이번 child 실행에서 SELinux 전환 실패 syscall이나 AVC는 관측하지 않았다. Guest domain 전환을 시도하지 않았으므로 errno와 AVC는 **미측정**이며 0으로 간주하지 않는다. 정책 원복 불가 또는 해시 변경 자체는 중단 사유가 아니다. 기존 Host 제어 장치로 접근 가능한 일반 서비스 실행 경로는 격리될 때까지 사용하지 않는다.

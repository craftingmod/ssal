# SSAL Phase 7C — Guest Memory Isolation

2026-11-05 KST, Samsung SM-S937N 순정 Host. **완료 기준 PASS: root 직속 Guest 전용 cgroup의 memory.high/max 설정·readback, 작은 테스트 프로세스의 memcg OOM, Host 핵심 상태 유지 및 설정 복원을 실기기에서 확인했다.** Guest Zygote·system_server는 실행하지 않았다. 기존 서비스 launcher에 메모리 보호를 적용했다는 판정은 아니다.

## 조사와 변경 범위

읽기 전용 [계층 조사](../out/phase7c/inventory-analysis.md)와 [원본 inventory](../out/phase7c/inventory.txt)를 보존했다. 대량 cgroup dump와 logcat/dmesg 분석은 Luna가 로컬에서 필터링했다. [실행 분석](../out/phase7c/runtime-analysis.md)에 시간·원본 경로·행 번호를 기록했다.

| 항목 | 관측·선택 |
|---|---|
| v2 mount | `/sys/fs/cgroup`, `memory_recursiveprot`; root available controller는 `memory` |
| 최초 delegation | root 포함 전체 subtree_control 재귀 조사에서 모두 비어 있음 |
| Host apps/system | domain, direct process 0; UID/PID 하위 계층에 Host process 배치. root에도 다수 Host process 존재 |
| 기존 Guest 경로 | `/sys/fs/cgroup/apps/ssal_guest`; memory 사용에는 root와 apps 양쪽의 `+memory` 필요 |
| 이번 전용 경로 | `/sys/fs/cgroup/ssal_memory_7c_<probe PID>`; 필요한 공통 ancestor 변경은 **root subtree_control의 `+memory` 한 곳** |
| 변경하지 않은 대상 | Host apps/system의 subtree_control, membership, 기존 task profile, v1 cpuctl/cpuset/blkio, SELinux 정책 및 핵심 서비스 설정 |

root controller를 켜면 apps/system 등 기존 root 자식에도 memory 인터페이스와 회계가 노출된다. 따라서 Host 영향이 전혀 없는 변경이라고 부르지 않는다. 모든 root 자식의 `memory.high/max=max`, `memory.min/low=0`, memory 하위 전달 부재를 검사했다. Host 기존 노드에 제한을 쓰거나 process를 이동하지 않았다. root의 특례와 controller 전달, high/max 동작 및 공유 메모리 회계는 [Linux cgroup v2 공식 문서](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html)를 참조했다.

실제 제한 전에 `+memory → sibling 기본값 확인 → -memory → 빈 root subtree_control readback`을 먼저 통과했다. 마지막 실행에서 이 복구 시험은 00:19:49.355–.369 KST였다. 이어 root를 다시 활성화하고 전용 leaf만 생성했다. 최종 root 복원은 .481 KST에 끝났다. 실기기에서 복구 불가능한 변경은 발견하지 않았다.

## 구현

- [ssal-memory-probe.rs](../src/bin/ssal-memory-probe.rs): 고정 cgroup2 mount·Enforcing·available controller·최초 빈 root delegation·512 MiB 이상 MemAvailable 확인. 기존 디렉터리를 재사용하지 않고 PID별 leaf를 배타 생성한다. 새로 spawn한 allocator만 exec 전에 `cgroup.procs=0`으로 가입한다.
- allocator가 SIGSTOP한 동안 leaf membership이 소유 PID 하나뿐인지, `/proc/<pid>/cgroup`의 v2 경로가 일치하는지 확인한 뒤 재개한다. 부모·ADB·Host 핵심 PID는 leaf에 넣지 않는다. 제한 설정·검증 이전에는 allocator를 시작하지 않는다.
- Guest leaf에 `memory.high=25165824`(24 MiB), `memory.max=33554432`(32 MiB), `memory.swap.max=0`을 쓰고 각각 정확한 readback을 검사한다. allocator는 최대 64 MiB의 private anonymous 페이지를 실제로 touch한다.
- high 이벤트를 먼저 확인한 후 high만 32 MiB로 올려 readback하고, 같은 32 MiB max에서 OOM을 검증한다. **high=24 MiB를 끝까지 유지한 채 OOM까지 확인한 시험은 아니다.** 마지막 바이너리의 실행 상한은 5초이며, timeout에는 소유 child만 kill/reap하고 마지막 진단을 남긴다.
- Phase 7B [Diagnostics](../src/zygote_diagnostics.rs)를 그대로 재사용해 stdout/stderr, launch/exit metadata, membership, memory.current/peak/high/max/events/stat/pressure, Host PSI/meminfo, process maps를 보존한다. 빠른 시험에서는 시작·종료 표본 중심이며, 250 ms 미만 구간의 모든 변동을 포착하지는 못한다. metadata의 native_capture 설명은 기존 진단 기능 설명이며 이 allocator에는 abort interposer를 preload하지 않았다.
- [run-memory-probe.sh](../scripts/run-memory-probe.sh): 전후 Enforcing·boot ID·핵심 PID/starttime/context/cgroup·service property, root/apps/system controller 및 PSI/meminfo 기록·비교. 기존 `run-guest-launcher.sh`를 호출하지 않는다.

코드 변경 범위는 새 probe 바이너리, 전용 실행 스크립트, 이 문서다. 기존 launcher·진단 모듈·task profile·vendor 소스를 수정하지 않았다. 추가 dependency나 module 설치 경로도 만들지 않았다. Cargo가 새 bin을 자동 인식하며 별도 production export/fixture 변경은 필요 없다.

## 실기기 결과

| 실행 | 결과 |
|---|---|
| 최초 wrapper | root에는 cgroup.type이 없어 snapshot 단계 종료. probe 미실행·cgroup 쓰기 없음. snapshot의 unavailable 처리 보완 |
| 첫 allocator, 00:14:24–44 | high throttling으로 약 26.1 MiB에서 정체, 20초 timeout. max/oom/oom_kill 모두 0. child kill/reap, leaf 제거와 root 복원 PASS |
| 재배포 wrapper | adb push 후 executable mode 소실로 exit 126. probe 미실행·cgroup 쓰기 없음. chmod 700 후 진행 |
| 순차 high/max 검증, 00:17:30 | PASS. PID 21171, high 35/max 38/oom 1/oom_kill 1, SIGKILL, peak 32 MiB, reap 뒤 current 0. 전체 child 수명 95 ms |
| 최종 빌드 확인, 00:19:49 | **PASS.** PID 23068만 `/ssal_memory_7c_23067`에 가입. high **19**, max **35**, oom **1**, oom_kill **1**; SIGKILL 후 leaf empty·rmdir·root 복원 PASS. root controller 변경부터 최종 복원까지 126 ms |

최종 증거는 [device-run4.txt](../out/phase7c/device-run4.txt), [probe.log](../out/phase7c/run-1793805588-22970/probe.log), [memory.jsonl](../out/phase7c/run-1793805588-22970/phase7b/memory.jsonl), [exit metadata](../out/phase7c/run-1793805588-22970/phase7b/metadata.jsonl), [allocator membership](../out/phase7c/run-1793805588-22970/phase7b/stdout.log)에 있다. 최종 코드 검토에서 raw waitpid 대신 `Child::try_wait`로 reap 소유권을 통일해 조기 종료 후 PID 재사용 시 잘못된 kill 가능성을 제거했고, 그래서 최종 빌드를 한 번 더 실기기 검증했다.

Host 핵심 비교는 init, zygote64, zygote_next, system_server, servicemanager, surfaceflinger, netd, lmkd, installd, tombstoned를 포함한다. 성공 실행의 [core-before](../out/phase7c/run-1793805588-22970/core-before.txt)와 [core-after](../out/phase7c/run-1793805588-22970/core-after.txt)가 일치했다. Enforcing·boot ID·핵심 PID/starttime/context/cgroup·관측 service property가 유지됐다. 실행 전후 모든 앱 membership의 동일성을 주장하지는 않는다. Host 앱 생성·종료는 계속되며 root direct task 수도 조사 중 변했다.

첫 20초 시험에서는 Host PSI avg10 some/full이 **0/0 → 31.21/13.98**로 상승했다. MemAvailable은 6,509,000→6,503,196 kB였고, 새 LMK kill·AVC·핵심 서비스 재시작은 관측되지 않았다. 이 PSI 상승을 숨기거나 무영향 PASS로 분류하지 않는다. cgroup high reclaim/throttling의 stall도 전역 PSI에 기여할 수 있어 이 값만으로 Host 특정 서비스의 stall 원인을 확정할 수 없다.

00:17:30의 짧은 성공 시험에서는 avg10 some/full **0/0 → 0.18/0.18**, PSI total 증가는 각각 약 30 ms, MemAvailable은 6,497,308→6,503,668 kB였다. kernel OOM 기록은 해당 Guest leaf와 allocator PID만 명시했다. 최종 빌드의 전후 수치와 epoch로 필터링한 LMK/AVC/kernel 결과도 [runtime-analysis.md](../out/phase7c/runtime-analysis.md)에 따로 보존한다. 이전 log buffer의 LMK 기록을 이번 시험의 결과로 계산하지 않았다. 제한 적용이 전역 PSI를 0으로 유지한다는 보장은 없다.

최종 빌드 실행에서는 PSI avg10 some/full이 **2.51/2.05 → 2.23/1.86**, total 증가는 약 **28.8/27.9 ms**였으며, 이미 실행 전에 압력이 있었다. MemAvailable은 **5,936,792→5,927,936 kB**였다. memory.peak는 정확히 **33,554,432 bytes**, reap 후 current는 **0**이다. 커널 OOM은 Guest PID 23068만 지목했다.

그러나 같은 구간의 [필터링한 logcat](../out/phase7c/run4-logcat-epoch-filtered.txt) 3–11행에 lmkd의 `memory pressure events were skipped after a kill` 메시지와, 이미 crashed 상태였던 세 앱 서비스의 mem-pressure-event 재시작 지연이 있다(00:19:49.541 KST). 수집 구간 내 새 Host kill/crash/ANR/AVC 또는 핵심 프로세스 교체는 발견되지 않았지만, 이 압력 반응과 시험의 인과관계를 확정하거나 배제할 수 없다. **메모리 한도·복원·핵심 상태 검증은 PASS이며, Host PSI/LMK에 대한 무영향 격리는 미입증이다.** Guest memcg OOM이 Host 전체 압력 관측과 LMK 반응까지 차단한다는 보장은 없다. 이 관측 이후 추가 실행 없이 종료했다.

## 복원과 중단 동작

정상 종료·반환 가능한 오류·timeout은 소유 child kill/reap → 비어 있는 leaf rmdir → root `-memory` → 빈 subtree_control readback 순서다. SIGINT/TERM/HUP는 중단 플래그를 통해 cleanup으로 진행한다. child에는 parent-death SIGKILL을 설정했다. 신호·timeout의 모든 fault 경로를 실기기에서 주입 시험한 것은 아니다.

복원 직전 root 자식의 subtree delegation 및 기본 high/max/min/low를 재확인한다. 다른 관리자가 memory delegation/정책을 새로 사용하거나 root controller 구성이 바뀌면 이를 강제로 제거하지 않고 오류와 경로를 남긴다. 비어 있지 않은 cgroup도 강제로 지우지 않는다. 이번에는 그런 충돌이 없었다.

parent SIGKILL·ADB/기기 비정상 종료처럼 cleanup이 실행되지 않는 경우의 수동 복구는 journal의 **이번 leaf**를 먼저 확인하고, 그 membership이 비어 있으면 rmdir한 뒤 root 자식에 memory delegation·새 정책이 없을 때만 root `-memory`를 수행한다. Host PID를 이동하거나 기존 apps/system cgroup을 삭제하지 않는다. cgroup 데이터 파일을 일반 파일처럼 삭제하는 방식은 사용하지 않는다. hierarchy 설정 복원은 PSI/event 누계나 page-cache charge 이력을 과거 값으로 되돌리는 것을 뜻하지 않는다.

[최종 확인](../out/phase7c/final-check.txt)과 [부재 확인 stderr](../out/phase7c/final-check.stderr)에 Enforcing, 빈 root/apps/system subtree_control 및 `ssal_memory_7c_*` 부재를 기록했다. 증거는 로컬로 pull했으며 `/data/local/tmp/ssal-phase7c`의 root mode-0700 실행 산출물은 검토용으로 남겨 뒀다. 활성 cgroup·메모리 한도는 남기지 않았다.

## 적용 범위와 회계 한계

이번 PASS는 **명시적으로 가입한 테스트 PID와 그 cgroup의 memory controller**에 한정한다. 일반적으로 후손은 membership을 상속하지만, 후손 생성·Guest의 task profile 이동·전체 Android 서비스 집합은 이번에 시험하지 않았다. 실제 Guest는 Host cgroup 변경 권한과 ancestor 경로에 접근할 수 없도록 기존 mount/권한 경계도 유지해야 한다.

기존 launcher는 여전히 `apps/ssal_guest`를 사용한다. 새 root 직속 경로를 production launcher에 연결하거나 실제 Android Guest 예산을 결정한 것은 아니다. 이번 24/32 MiB는 allocator 검증값이며 Zygote나 Android 서비스의 실행 예산이 아니다. Guest 서비스 재실행 전에 이 분리 경로를 launcher lifecycle에 연결하고 실제 서비스 membership·budget·OOM 정책을 별도로 검증해야 한다.

APEX 준비·loop/mount·linkerconfig 준비를 수행하는 worker는 이 leaf에 가입하지 않았다. 기존 APEX·ART·dex/JAR shared file cache는 최초 charge 소유권에 따라 Host/기존 cgroup에 남을 수 있으며, process를 나중에 이동해도 이미 charge된 페이지 전체가 따라오는 것은 아니다. 이 제한으로 APEX 준비·Host daemon·공유 cache 전체 비용 또는 Guest의 총 물리 메모리를 포괄한다고 주장하지 않는다. memory.max는 이 memcg에 charge되는 메모리의 상한이며, 어떤 작업이 만들어낸 모든 시스템 비용을 회수하는 경계는 아니다.

## 오프라인 검증과 재현

WSLc는 AGENTS.md 지침에 따라 sandbox 밖 기존 `ssal-dev`에서 실행했다.

| 검사 | 결과 |
|---|---|
| `cargo test --locked --bin ssal-memory-probe` | [3 passed, 0 failed](../out/phase7c/probe-tests.txt): controller/event 파싱 및 재사용 Phase 7B pipe 검사 |
| `cargo test --locked --lib` | [15 passed](../out/phase7c/lib-tests.txt) |
| `cargo test --locked --bin ssald` | [40 passed, 3 기존 ignored](../out/phase7c/ssald-tests.txt) |
| Android release build | [PASS](../out/phase7c/android-build.txt) |
| rustfmt·`sh -n scripts/run-memory-probe.sh` | PASS |

빌드: `wslc exec --workdir /src ssal-dev cargo build --locked --release --target aarch64-linux-android --bin ssal-memory-probe`. 이 환경의 산출물은 `/build/target/aarch64-linux-android/release/ssal-memory-probe`이며 `out/bin/ssal-memory-probe`로 복사해 사용했다. 기기에는 전용 mode-0700 stage에 바이너리·스크립트만 push하고 **push 후 바이너리 chmod 700**을 적용한 뒤 `su -c 'sh /data/local/tmp/ssal-phase7c/run-memory-probe.sh'`로 실행한다. 현재와 같은 초기 빈 root delegation일 때만 지원하며 다른 초기 상태를 자동 변환하지 않는다.

최종 실행 바이너리 SHA-256: `fd953eebed09544fe8c7ce5e9ecef4a342f3f4bcadc7bb91c575696d20101e94`.

Zygote 실행·SIGABRT 원인 수정·system_server 기동·artd dexopt backlog·실제 서비스 launcher 연결 및 예산 검증은 후속 Phase로 유지한다. 장시간 Host 안정성이나 모든 장애 주입 경로는 이번 PASS 범위에 포함하지 않는다.

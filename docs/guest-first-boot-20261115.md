# Y702 첫 부팅 검증 시도

2026-11-15 00:59–01:00 KST, Lenovo TB320FC (`HA1WAQ7P`), 프로필 `y702`.

판정: **첫 부팅 미도달**. 기존 mapped Guest launcher를 실행했으나 cgroup 준비에서 exit 1로 중단됐다. Android 서비스나 Zygote는 시작하지 못했다. 앞서 통과한 전체 prepare는 유지되지만 부팅 성공을 뜻하지 않는다.

## 실행과 실제 차단 원인

설치된 `ssald --guest-zygote-7a-worker`에 등록 system 이미지와 `y702/userdata.img`를 전달했다. `SSAL_PHASE7I_PROPERTIES=1`, `SSAL_PHASE7FB_FORK=1`, `SSAL_MEMORY_HIGH=1073741824`, `SSAL_MEMORY_MAX=1610612736`으로 기존 private property/fork 경로와 유한 메모리 제한을 선택했다. 고정 SID, SELinux bypass, 이전 8B-5 runtime hook은 선택하지 않았다. 바이너리나 정책은 이번 시도에서 변경하지 않았다.

근거: `out/guest-first-boot-20261115/attempt1.log`.

- 14행: 기존 `p0001` SELinux 계획을 재사용했다.
- 15–19행: private Guest `/dev` 준비와 Host endpoint 부재 검사를 통과했다.
- 20–22행: cgroup 정리, rootfs 잔여 mount 부재, loop 2개 해제를 확인했다.
- 23행: `No such file or directory (os error 2)`로 중단됐다.

읽기 전용 후속 조회 `preflight.txt`에서 `/sys/fs/cgroup/apps` 부재를 확인했다(10–11행). 당시 테스트 바이너리의 `GuestMemory::prepare`는 해당 v2 경로를 canonicalize하므로 여기서 ENOENT가 발생했다(`src/memory_cgroup.rs:357`). 이 제한은 아래의 후속 cgroup v1 변경 및 실제 단말 검증으로 갱신됐다.

디렉터리 생성만으로는 당시 실패를 해결할 수 없었다. 실제 메모리 컨트롤러는 `/dev/memcg`의 cgroup v1에 연결돼 있고(`preflight.txt:7`), cgroup v2의 `cgroup.controllers`와 `cgroup.subtree_control`은 비어 있었다(8–9행). 당시 바이너리는 v2 memory controller를 필수로 검사했다(`src/memory_cgroup.rs:368`). 후속 구현은 Guest 전용 v1 memory subtree의 제한·membership·계측·정리와 Guest cgroup 경로 투영을 추가했다. Host 메모리 컨트롤러를 이동하거나 제한 검사를 우회하지 않았다.

## Host 및 정리 확인

`before.txt`와 `after1.txt`의 시각을 제외한 항목이 모두 동일했다: Enforcing, boot ID `c6de69a6-5ab5-4ed0-9c14-cd1eab6fea35`, Host `sys.boot_completed=1`, system_server PID 2247, 활성 정책 SHA-256 `f2ae794aa9d57c8639f206b1950534e6379a808caa2e3b8b420d6b099d0d8f1e`, PID 1 mountinfo SHA-256 `f1b637790e24c55d934e64efce665a37478f7c26f4c7726eaf278745670a7333`.

`preflight.txt:14` 이후에서 Host 세션 mount, Guest cgroup, 세션 및 userdata loop backing 부재를 별도로 확인했다. Host의 `sys.boot_completed`는 Guest 부팅 근거로 사용하지 않는다. userdata를 삭제하거나 초기화하지 않았다.

## 남은 범위

00:59 첫 실행을 차단한 원인은 Y702의 cgroup v1 구성과 그 시점 런처의 v2 전용 검사 불일치였다. cgroup v1 경로는 아래에서 검증했지만, 현재 7A 런처는 `start_system_server=false`이며 Zygote 진단 완료 후 종료한다(`src/guest_launcher.rs:1356`, `:1565`). 전체 부팅에는 이 진단을 넘어 mapped system_server 및 필요한 Guest 서비스의 기동·종료 경로와 Guest 전용 부팅 완료 증거가 필요하다. 기존 삼성 패닉 이력의 8B-5 경로를 다시 열지 않았다.

부팅 화면, Guest `sys.boot_completed`, Guest FBE/HAL, 하드 재부팅 후 복구는 이번 실행에서 검증하지 못했다. 새 코드 변경이 없어 빌드/단위 테스트는 재실행하지 않았다. logcat/dmesg 분석은 서비스 실행 이전에 중단돼 수행하지 않았다.

## cgroup v1 실제 단말 검증

2026-11-15 02:19–02:22 KST에 `wslc.exe`의 `ssal-builder:dev` 컨테이너에서 `scripts/build-android.sh`를 실행했다. 릴리스 `ssald` SHA-256은 `bcf74deee9444b53ac4f576f2c104493ddd8b598bf7731e195ef4497d4ec19b0`이다.

`attempt5`의 `--guest-memory-worker`는 **PASS**했다. Y702에서 cgroup v1 backend를 선택하고 `/dev/memcg/ssal_guest/memory.use_hierarchy=1`, soft limit 1 GiB, hard limit 1.5 GiB를 설정했다. Guest memory probe PID 5761은 `/ssal_guest`에 속했고 `memory_usage=2740224`를 보고했다. Guest cgroup 정리, 46개 loop 할당 해제, mount cleanup이 통과했다.

`attempt6`의 `--guest-zygote-7a-worker`는 Guest cgroup 준비와 network namespace 격리까지 통과했지만, Zygote 시작 전 private binderfs mount에서 `EPERM`으로 중단됐다. 필터링한 logcat은 02:21:55.734 KST에 Enforcing 정책이 `ssal_p0001_binder_device:filesystem associate`를 거부했음을 기록한다(`attempt6/binderfs-avc.txt`). `attempt4`에서 선택한 optional Guest property-service 경로도 property service SIGSEGV 뒤 중단됐다.

모든 시도에서 Host 정책 파일 hash, PID 1 mountinfo, Host cgroup 상태, 원본 userdata가 전후 동일했다. 임시 userdata 사본, 테스트용 daemon 복사본, cgroup, mount, loop는 정리됐다. 따라서 cgroup v1 메모리 경로와 장기 프로세스 membership은 실제 단말에서 검증됐지만 Guest Zygote readiness는 아직 검증되지 않았다. system_server, 필수 Guest 서비스, Guest `sys.boot_completed`, 하드 재부팅 복구도 미검증이다.

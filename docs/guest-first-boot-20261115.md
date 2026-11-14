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

읽기 전용 후속 조회 `preflight.txt`에서 `/sys/fs/cgroup/apps` 부재를 확인했다(10–11행). `GuestMemory::prepare`는 해당 경로를 canonicalize하므로 여기서 ENOENT가 발생한다(`src/memory_cgroup.rs:357`).

디렉터리 생성만으로 해결되지 않는다. 실제 메모리 컨트롤러는 `/dev/memcg`의 cgroup v1에 연결돼 있고(`preflight.txt:7`), cgroup v2의 `cgroup.controllers`와 `cgroup.subtree_control`은 비어 있다(8–9행). 현재 코드는 v2 memory controller를 필수로 검사한다(`src/memory_cgroup.rs:368`). 이 기기에서 실행하려면 Guest 전용 v1 memory subtree의 제한·membership·계측·정리와 Guest cgroup 경로 투영을 함께 지원해야 한다. Host 메모리 컨트롤러를 이동하거나 제한 검사를 우회하지 않았다.

## Host 및 정리 확인

`before.txt`와 `after1.txt`의 시각을 제외한 항목이 모두 동일했다: Enforcing, boot ID `c6de69a6-5ab5-4ed0-9c14-cd1eab6fea35`, Host `sys.boot_completed=1`, system_server PID 2247, 활성 정책 SHA-256 `f2ae794aa9d57c8639f206b1950534e6379a808caa2e3b8b420d6b099d0d8f1e`, PID 1 mountinfo SHA-256 `f1b637790e24c55d934e64efce665a37478f7c26f4c7726eaf278745670a7333`.

`preflight.txt:14` 이후에서 Host 세션 mount, Guest cgroup, 세션 및 userdata loop backing 부재를 별도로 확인했다. Host의 `sys.boot_completed`는 Guest 부팅 근거로 사용하지 않는다. userdata를 삭제하거나 초기화하지 않았다.

## 남은 범위

첫 실행 차단은 Y702 cgroup 구성과 런처의 불일치다. 이를 해결해도 현재 7A 런처는 `start_system_server=false`이며 Zygote 진단 완료 후 종료한다(`src/guest_launcher.rs:1356`, `:1565`). 전체 부팅에는 이 진단을 넘어 mapped system_server 및 필요한 Guest 서비스의 기동·종료 경로와 Guest 전용 부팅 완료 증거가 필요하다. 기존 삼성 패닉 이력의 8B-5 경로를 다시 열지 않았다.

부팅 화면, Guest `sys.boot_completed`, Guest FBE/HAL, 하드 재부팅 후 복구는 이번 실행에서 검증하지 못했다. 새 코드 변경이 없어 빌드/단위 테스트는 재실행하지 않았다. logcat/dmesg 분석은 서비스 실행 이전에 중단돼 수행하지 않았다.

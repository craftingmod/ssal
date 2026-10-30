# SELinux 전환 사전 검사

`ssal probe-selinux-transition PROFILE_NAME`은 prepare의 임시 Guest rootfs에서 실제 servicemanager 파일 라벨을 읽고, 현재 호스트 커널 정책에 권한을 질의한다. 새 명령에는 빌드된 클라이언트와 데몬이 필요하다. 설치 데몬 교체 없이 별도 워커로도 실행할 수 있다.

```sh
ssald --selinux-probe-worker SYSTEM_IMG USERDATA SESSION_DIR
```

`SESSION_DIR`은 새 전용 디렉터리이며 빈 `system`, `data` 하위 디렉터리를 준비한다. 직접 실행한 워커는 mount와 loop를 정리하지만 scratch 디렉터리는 호출자가 mount 부재를 확인한 후 제거한다. 일반 CLI에서는 기존 prepare 감독 경로가 처리한다.

검사는 `ksu`와 전역 Enforcing을 요구한다. `class/*/index`, `class/*/perms/*`로 현재 커널의 클래스와 권한 번호를 해석한다. `/sys/fs/selinux/access`에 대한 쓰기는 권한 질의 요청이며 정책 로드나 allow 추가가 아니다. 형식은 [공식 libselinux 구현](https://github.com/SELinuxProject/selinux/blob/main/libselinux/src/compute_av.c)을 따른다.

- source → source `process:setexec`
- source → servicemanager `process:transition`
- servicemanager → 실제 Guest 파일 라벨 `file:entrypoint`
- source → 실제 Guest 파일 라벨 `file:{ execute open read getattr map }`

일회용 자식이 `/proc/thread-self/attr/exec`에 대상 컨텍스트를 기록한다. 이는 setexeccon과 같은 커널 인터페이스의 지정 수락 여부만 검사한다. 자식은 exec 없이 종료하고 부모가 회수한다. 부모 컨텍스트, 전역 Enforcing, AV 정책 시퀀스를 전후 확인한다. 정책 원본 읽기가 가능하면 SHA-256도 비교하고, 불가능하면 오류와 null을 기록한다. 해시 미확인을 정책 원본 동일성 증명으로 취급하지 않는다.

`prerequisites=passed`는 조회한 권한 허용, permissive 도메인 부재, 지정 성공, 전후 일관성을 모두 요구한다. 실패하더라도 rootfs 및 loop 정리 경로를 실행한다. 실제 exec의 모든 검사, UID/GID 전환, linker 접근, nosuid 전환, Binder 접근, property 격리까지 검증하는 명령은 아니다. `actual_exec_transition`, `servicemanager`는 항상 `not_run`이며 운영 서비스 기동 조건을 해제하지 않는다.

## 2026-10-31 SM-S937N 결과

Android 16 Guest `profile1`에서 [원시 검사 결과](selinux-transition-device-20261031.json)를 기록했다.

- 실제 Guest 파일 라벨: `u:object_r:servicemanager_exec:s0`.
- 조회한 8개 권한 모두 `allowed=true`. `ksu → servicemanager` transition이 없을 것이라는 예상은 이 기기의 현재 실효 정책에는 맞지 않았다.
- 자식 실행 컨텍스트 지정: errno 0, 자식 종료·회수 확인. 실제 도메인 전환 exec는 실행하지 않았다.
- 전역 Enforcing이지만 `ksu` 출발 도메인의 AV 응답은 `permissive_domain=true`. 대상 servicemanager의 entrypoint 응답은 false였다. 엄격한 Enforcing 검증 요건 때문에 전체 사전 검사는 실패로 처리했다. 권한 deny가 관측됐다는 뜻은 아니다.
- 정책 AV 시퀀스 1 유지, 부모 도메인 유지. 정책 원본 읽기는 EINVAL로 해시 미확인.
- rootfs 잔여 mount 없음, 세션 loop backing 55개 해제. Host Zygote/SurfaceFlinger PID 각각 1784/2023 유지, 전역 Enforcing 유지.
- 설치된 `sepolicy.rule` SHA-256 전후 동일: `0f6b0e1c3e4217f685826d6a46ff7150667aa0a5be612c554964bfe3e5b3d39b`. 정책 변경·permissive 설정 변경·설치 데몬 교체는 수행하지 않았다.

현재 관측만으로 추가 allow 규칙이 필요하다는 근거는 없다. 다음 실제 서비스 시험은 기존 Test B 계획의 property 전달 차단과 프로세스 감독을 먼저 갖춘 뒤, exec 후 추적 PID의 실제 컨텍스트를 확인해야 한다. Host와 동일한 servicemanager 도메인은 Guest 전용 보안 경계의 증명이 아니다.

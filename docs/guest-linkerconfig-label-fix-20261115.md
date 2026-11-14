# Guest linkerconfig tmpfs 라벨 수정

`/linkerconfig`는 Host bind가 아닌 Guest 전용 tmpfs였지만, 생성 직후 라벨이 `u:object_r:tmpfs:s0`으로 남았다. mapped Guest `linkerconfig` 실행에 맞는 파일 타입을 지정하지 않아 `ld.config.txt` 생성 단계에서 Permission denied / SIGABRT가 발생했다.

`guest_policy::runtime::install`에서 Guest 전용 디렉터리에 `plan.context("linkerconfig_file", false)`를 지정한다. 새 파일은 이 타입을 상속한다. 기존 set_label 오류 처리를 사용하며 실패하면 준비를 중단한다. Host 파일이나 SELinux 정책, Enforcing 상태는 변경하지 않는다. 정책 생성 내용은 같으므로 캐시 버전 변경은 필요 없다.

## 검증

- Guest 정책 검사 20개, mount 검사 12개 통과. 외부 fixture/특권 mount가 필요한 기존 검사 3개는 ignored.
- Android AArch64 release ssald 빌드, Rust 2021 rustfmt check, 수정 파일 diff whitespace check 통과.
- Lenovo TB320FC (`HA1WAQ7P`), 기존 `.userdata-first-boot-test.img` 사본과 별도 시험 바이너리로 실행. 운영 바이너리 교체 및 재부팅 없음.
- 수정 전 `out/linkerconfig-stack-20261115/worker4.log:258–266`: 디렉터리 root:root 0755, `u:object_r:tmpfs:s0`, 별도 RW tmpfs. 대상 파일은 ENOENT. `:284`에서 Permission denied fatal.
- 수정 후 `label-fix-live.txt`에서 `u:object_r:ssal_p0001_linkerconfig_file:s0` 확인. `worker-label-fix.log:196`에서 linkerconfig exit 0, `:208–209`에서 잔여 rootfs mount 없음 및 loop 46개 해제 확인.
- `before-label-fix.txt` / `after-label-fix.txt` 일치: Host Enforcing, boot ID, boot_completed, system_server PID, PID 1 mountinfo hash, Host linkerconfig 디렉터리 라벨과 ld.config.txt hash, 운영 userdata 크기/mtime/inode. `policy-before-label-fix.txt` / `policy-after-label-fix.txt`도 일치.
- 재실행 `worker-label-verify.log:196`에서도 linkerconfig exit 0. `:207–209`에서 cgroup 정리, rootfs mount 부재, loop 46개 해제 확인. 이 실행의 Host snapshot과 정책 hash도 전후 일치했다. 정상 종료 시 진단 라이브러리의 destructor 출력은 없어 생성 파일 자체의 라벨 readback은 확보하지 못했다.

증거 파일은 모두 `out/linkerconfig-stack-20261115/`에 보존한다. 전체 worker는 후속 shell probe의 기존 context 기대값 검사에서 exit 1로 종료했다. linkerconfig 수정 범위에서 해당 shell 검사는 변경하지 않았다. Guest 첫 부팅 성공과 삼성 기기 검증은 주장하지 않는다.

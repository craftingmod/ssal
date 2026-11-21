# Y702 동적 shell probe 및 전체 prepare 검증

2026-11-15 00:55:54–00:56:09 KST, Lenovo TB320FC (`HA1WAQ7P`), `y702`에서 재부팅 없이 `ssal prepare y702`가 종료 코드 0으로 완료됐다.

## 변경 범위

`src/guest_probe.rs`의 고정 chroot/pivot shell, VINTF inventory/checker만 기존 `root_command`를 사용한다. 고정 스크립트, 20초 timeout, process group 종료, inherited FD 닫기, root identity 검사는 유지한다. 일반 `command`와 자동 서비스 admission gate는 계속 거부한다. 정책 변경은 없다.

Gate 유지 회귀를 추가했고, 기존 privileged pivot fixture도 실제 진단과 같은 root command 경로를 사용하도록 수정했다. 기기 데몬은 `/data/local/tmp/ssal-shell-probe-20261115/backup/ssald`에 백업 후 설치했고, 로컬 `out/bin/ssald`에도 반영했다.

## 실기기 결과

근거는 `out/guest-shell-probe-20261115/prepare.log`와 같은 디렉터리의 `prepare.rc`, `before.txt`, `after.txt`다.

- 174행: restorecon 시험 파일이 매핑된 `ssal_p0001_system_data_file`로 변경됐다.
- 199–217행: chroot 동적 shell, root identity, profile userdata 쓰기/읽기를 통과했다.
- 218–236행: pivot_root 동적 shell과 같은 검사를 통과했다. 스크립트는 `/.ssal-old-root` 부재도 확인한다.
- 216·235행: 두 shell 모두 `u:r:ksu:s0`에서 실행됐다. Guest 서비스 도메인 실행 증거는 아니다.
- 261행: `checkvintf`가 이미지에 없어 VINTF는 `unavailable`이다.
- 266행: Android 서비스 admission은 계속 blocked다.
- 530–533행: rootfs 잔여 mount 없음, loop 46개 해제, 전체 prepare 완료를 확인했다.

전후 Host Enforcing, boot ID `c6de69a6-5ab5-4ed0-9c14-cd1eab6fea35`, `sys.boot_completed=1`, system_server PID 2247이 동일했다. 활성 정책 SHA-256은 `f2ae794aa9d57c8639f206b1950534e6379a808caa2e3b8b420d6b099d0d8f1e`, PID 1 mountinfo SHA-256은 `f1b637790e24c55d934e64efce665a37478f7c26f4c7726eaf278745670a7333`로 전후 동일했다.

## 검증과 한계

Guest probe 회귀 7개, mount 회귀 12개, privileged chroot FD 회귀 1개를 통과했고 Android AArch64 release 데몬 빌드도 통과했다. 컨테이너의 privileged mount/pivot 테스트는 실행하지 않았으며 실제 pivot은 위 기기 prepare에서 검증했다. 수정 파일 rustfmt 및 diff whitespace 검사는 통과했다. 전체 `cargo fmt --check`는 기존 `src/guest_mounts.rs`의 포맷 차이로 실패했으며 해당 기존 코드는 변경하지 않았다.

첫 부팅, Guest 서비스 SELinux 도메인, FBE/CE·DE 및 VINTF/HAL 호환성은 미검증이다. 삼성 순정 커널에서 같은 결과가 나온다는 의미도 아니다. 이전 overlay hash-cache xattr 경고 경로는 수정하지 않았다. 성공 시 데몬은 worker stderr를 응답에 포함하지 않으므로 이번 성공 로그에서 경고가 보이지 않는 것을 해결 근거로 삼지 않는다.

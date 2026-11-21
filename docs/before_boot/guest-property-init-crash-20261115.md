# Guest private property 초기화 SIGSEGV 원인

2026-11-15 KST, Lenovo TB320FC (`HA1WAQ7P`), Host kernel `5.10.233-android12-9-g122af8c9f8ab-ab113`.

**원인: `ksu`에서 연 실행 파일의 FD를 Guest shell 문맥에서 사용하지 못해, exec의 ELF 매핑이 SELinux `fd:use` 검사에서 실패한다.** property 초기화 함수에 진입하기 전 발생한다. 재현과 커널 실패 지점 확인은 완료했으며, 런처나 정책 수정은 하지 않았다.

## 증거

- 기존 `attempt7/worker.log:175`는 `/system/bin/bootstrap/linker64 /run/ssal/guest_probe --initialize-private-properties /dev/guest-properties`의 SIGSEGV와 빈 출력을 기록한다. 초기화 함수의 첫 stderr 표식도 없다.
- 같은 이미지의 bootstrap linker, libc, libdl과 같은 probe를 별도 최소 chroot에서 실행하면 초기화 함수에 진입한다. 이후 라벨 설정 단계에서 정상적인 오류 반환으로 종료한다. 근거: `out/property-init-crash-20261115/trace-bootstrap-empty-area.txt:26–29`. 이 대조군은 원래 Guest 보안 환경 전체를 재현한 것은 아니다.
- 실제 worker의 자식 PID 14820을 ptrace로 관측했다. `trace-context.txt:641–656`에 `x0=0xfffffffffffffff3` (`-13`, EACCES), 실제 문맥 `u:r:ssal_p0001_shell:s0`, `si_code=128` (SI_KERNEL), `si_addr=0`이 기록됐다. 해당 자식의 성공 `PTRACE_EVENT_EXEC`는 없고, 새 linker 매핑도 없다. 따라서 stop PC는 property 코드의 fault 명령어로 심볼화할 대상이 아니다.
- **ptrace 없는 실행에서도 재현했다.** `kernel-trace-fd.txt:44779–44783`, PID 14352, monotonic `11989.364393–11989.369791`:

  ```text
  begin_new_exec()                                      = 0
  avc_has_perm(ssid=2508, tsid=2155, class=9, requested=1)
  file_has_perm()       [caller: file_map_prot_check]    = -13
  selinux_mmap_file()                                   = -13
  elf_map()            [caller: load_elf_binary]         = -13
  ```

  이 검사는 커널 내부 `fd:use`다. `kernel-focus.txt`에는 해당 PID의 11개 이벤트만 원본 행 번호와 함께 추렸다. 기존 로그에 AVC가 없다는 사실로 SELinux 거부를 배제할 수 없다.
- 읽기 전용 live AV 조회 `av-extra.jsonl:2`는 `ssal_p0001_shell -> ksu:fd use`가 `allowed=false`, `flags=0`임을 확인한다. `:5`의 `ssal_p0001_init -> ksu:fd use`도 거부된다. 반면 `av.jsonl:20–25`의 Guest shell -> mapped bootstrap linker `file` 권한은 entrypoint/execute/open/read/map/execute_no_trans 모두 허용된다. `file:map` 추가만으로 해결되는 경우가 아니다.

일반 Linux 5.10의 [`file_has_perm()`](https://github.com/torvalds/linux/blob/v5.10/security/selinux/hooks.c#L1698)은 현재 SID와 파일을 연 문맥의 SID가 다르면 inode 권한 검사보다 먼저 `FD__USE`를 검사한다. `file_map_prot_check()`도 이 함수를 호출한다. 이는 위 실기기 반환값 및 FD 접근 검사와 일치한다. Lenovo downstream 소스 전체와의 대조는 하지 않았다.

## 호출 경로와 해석

`src/guest_launcher.rs`의 `run()`은 `command()`를 사용한다. mapped policy가 있으면 일반 helper는 `shell`로, property service는 `init`으로 선택한다. `command()`의 pre-exec 처리는 `/proc/thread-self/attr/exec`에 대상 문맥을 설정하지만, 이 시점 실행 주체는 여전히 `ksu`다.

커널이 실행 파일을 열고 새 Guest 자격 증명을 적용한 뒤 ELF를 매핑할 때, 파일을 연 SID와 현재 SID가 달라진다. 해당 `fd:use`가 거부되어 `elf_map()`이 EACCES를 반환한다. 이미 `begin_new_exec()`를 통과해 이전 주소 공간을 버렸으므로 exec 호출자에게 정상적인 오류 반환을 할 수 없고 fatal SIGSEGV로 끝난다. 실제 관측은 사용자 코드 NULL 접근과 구별되는 SI_KERNEL 및 새 실행 매핑 부재를 보여준다.

별도로, `begin_new_exec()` 안의 `match_file()`에서도 같은 FD 사용 검사가 세 번 거부됐다(`kernel-focus.txt:1–6`). 표준 FD 처리에서도 같은 문맥 경계를 고려해야 한다. 이는 property 초기화 함수 첫 로그 부재를 함수 내부 버그의 증거로 해석하면 안 되는 이유다.

`attempt4`의 optional property service도 같은 실행 구조와 `init -> ksu:fd use` 거부 조건을 갖지만, **그 프로세스 자체의 커널 trace는 수집하지 않았다.** 동일 원인 가능성이 높으며 별도 확정으로 취급하지 않는다.

## 수정 범위와 남은 검증

수정 대상은 property trie나 rsproperties가 아니라 Guest exec/FD 문맥 경계다. 실행 파일뿐 아니라 전달되는 표준 FD도 함께 다뤄야 한다. Guest 문맥에서 필요한 파일을 여는 단계 또는 최소한의 FD 전달 정책을 검토해야 한다. `allow Guest ksu fd use`는 객체 파일 종류에 한정되지 않으므로 Host FD 격리 영향 확인 없이 일괄 추가하지 않았다.

SIGSEGV 해결 후에는 property 라벨 매핑과 실제 생성/readback까지 다시 검증해야 한다. 이번 최소 chroot 대조군의 라벨 오류는 전체 Guest 환경의 다음 실패를 확정한 결과가 아니다.

## 정리 및 Host 상태

worker는 Guest cgroup 정리, rootfs 잔여 mount 부재, 실행당 loop 46개 해제를 보고했다(`trace-context.txt:672–674`). 읽기 전용 검사와 진단용 tracefs instance/kprobe만 사용했고, 진단 instance와 probe는 제거했다. 기존 tracing_on=0도 유지됐다. 원본 userdata 대신 기존 임시 userdata 사본을 사용했다. 증거 회수 후 진단용 단말 디렉터리와 이번에 보충한 임시 bin 디렉터리의 context-map 사본도 제거했다. 기존 임시 userdata 사본과 기존 bin 파일들은 유지했다.

`before.txt`와 `final-host.txt`가 동일하다: Enforcing, boot ID, Host system_server PID 2247, active policy SHA-256, PID 1 mountinfo SHA-256, 원본 userdata 크기/mtime/inode. 원본 userdata 전체 hash를 계산한 검증은 아니다. 재부팅은 하지 않았다.

모든 증거 및 일회성 진단 소스는 `out/property-init-crash-20261115/`에 있다. 제품 코드 수정, 정책 추가, Guest 부팅 성공 및 하드 재부팅 복구 검증은 이번 조사 범위에 포함하지 않았다.

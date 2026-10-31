# Guest SELinux Enforcing 재시도 결과

**결과: 전환 전 실패.** 승인된 네 정책 문장을 적용한 후 전용 process/file context가 유효했고, `ksu → ssal_guest_probe process:transition`과 `ssal_guest_probe → ssal_guest_probe_exec file:entrypoint`는 허용이었다. 전역 Enforcing이 유지됐다. 승인된 identity 파일만 전용 타입으로 라벨링했고 SHA-256이 승인된 값과 일치했다.

런처는 실행 전 검사에서 `Invalid argument (os error 22)`로 종료했으며 AV 결과 행을 출력하지 않았다. Guest 프로세스 생성·전환 및 identity 정상 실행은 확인되지 않았다. 실행 전후 커널 로그 비교에서 `ssal_guest_probe` 관련 새로운 AVC 거부는 발견되지 않았으나, 로그 부재만으로 모든 거부가 없었다는 뜻은 아니다. 실제 오류 syscall이나 정확한 원인은 추적하지 못했다. [런처 결과](../out/guest-domain-retry/run.json) 및 실행 전후 dmesg를 `out/guest-domain-retry/`에 보관했다.

오프라인 검토에서 기존 런처는 selinuxfs/access 요청을 `write!`로 작성했다. 로컬 계측에서 동일한 형식의 요청이 일곱 번의 개별 write로 나뉘는 것을 재현했다. selinuxfs/access는 하나의 완전한 요청을 한 트랜잭션으로 전달해야 하므로 이는 `EINVAL`의 유력한 원인이다. 실제 기기에서 syscall trace를 얻지 못했으므로 확정 원인은 아니다. 런처를 완전한 요청 한 번의 write로 수정하고 짧은 write는 실패로 처리하도록 했다. 관련 단위 테스트 3개와 Android 타깃 check는 통과했다. **수정된 바이너리는 기기에서 실행하지 않았다.**

전용 임시 파일과 디렉터리를 제거하고 `adb reboot`을 요청했다. 사용자의 지시에 따라 재부팅 후 원상복구 확인은 수행하지 않았다. 따라서 재부팅 완료, 정책 원복, Host 및 One UI 정상 여부는 unknown이다. 추가 allow나 permissive 설정은 하지 않았다.

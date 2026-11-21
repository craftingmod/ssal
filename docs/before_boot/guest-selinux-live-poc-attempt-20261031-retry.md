# Guest SELinux Enforcing Live PoC — 재시도 결과

**결과: 전환 전 중단.** 2026-10-31 `R5CY52JC03H`에서 재전송한 세 파일의 기기 SHA-256이 로컬 원본과 일치했다. 네 정책 문장을 순서대로 적용했고 전용 process/file context는 유효해졌으며 `ssal_guest_probe → ssal_guest_probe_exec file:entrypoint` AV는 `0x04000000` 허용이었다. 전역 Enforcing과 Guest 대상 permissive flag 0을 확인했다.

실행 사전 검사에서 `ssal_guest_probe → ssal_guest_probe dir:search`의 requested mask `0x10000000`, allowed mask `0`, flags `0`, sequence `1`을 관측해 중단했다. 이것은 같은 도메인 SID를 가진 디렉터리에 대한 커널 AV 질의이며 실제 실행된 프로세스의 `/proc/self` 디렉터리 라벨과 접근 실패를 증명하지 않는다. 해당 라벨은 실제 Guest 프로세스를 실행하지 않아 미확인이다. 추가 allow, permissive 또는 재시도는 수행하지 않았다. 전용 identity 파일에 SELinux 라벨을 적용하지 않았고, Guest 프로세스도 실행하지 않았다.

적용 단계에서 `ksu → ssal_guest_probe process:transition`은 새 allow 적용 전에도 `0xffffffff`, source permissive flag 1이었다. 적용 후 전용 entrypoint 외에 `ssal_guest_probe → system_linker_exec file:execute`, `system_lib_file file:open`, `proc dir:search`, `ksu → ssal_guest_probe process2:nosuid_transition`, `ssal_guest_probe → ksu fd:use`/`fifo_file:write`, `ksu`의 해당 relabel AV는 조회된 범위에서 allowed였다. `ssal_guest_probe_exec → labeledfs filesystem:associate`도 allowed였으나 `labeledfs`는 저장된 f2fs CIL의 filesystem SID 후보이며 실제 superblock SID의 독립 증명은 아니다. `ssal_guest_probe → ssal_guest_probe process:getattr`의 allowed mask는 0이었으며 이 질의는 대상 flag 확인용이었다.

정책 적용 후 `/sys/fs/selinux/policy`의 SHA-256은 `860432bbfd7d7ab7b2627bac58b41d498eac8c41a7e9b4953a27dbe516e82500`이었다. 적용 전에는 policy read가 EINVAL이어서 전체 전후 차분은 불가능하다. 정책 적용 전후 관찰한 세 Host AV는 일치했고 기존 두 모듈 정책 파일 해시도 일치했다. AV sequence가 1로 유지된 것만으로 정책이 변경되지 않았다는 뜻은 아니다. [적용 후 수집 원본](../out/guest-domain-live/post-policy.json)을 보존했다.

전용 임시 파일과 디렉터리를 삭제한 후 승인된 `adb reboot`으로 전체 기기 재부팅을 수행했다. 이는 하드웨어 전원 차단 시험은 아니다. boot ID는 `c0f129b3-1ba5-4b78-8246-58dae210994e`에서 `3f01fc00-ada4-44bd-969f-c67988799f20`으로 바뀌었다. 재부팅 후 `getenforce` Enforcing, `sys.boot_completed=1`, boot animation stopped, init/servicemanager/zygote64/system_server/surfaceflinger 및 SystemUI 프로세스, 삼성 Launcher의 화면 포커스를 확인했다. 일반 shell의 selinuxfs context 조회에서 정상 대조군 `u:r:init:s0`는 유효했고 두 전용 context는 각각 EINVAL이었다. 전용 임시 경로도 없었다. 이 범위에서는 해당 context가 재적용되지 않았다.

재부팅 후 ADB shell에서 `su`는 찾을 수 없어 root 전용 모듈 정책 해시와 전체 실효 정책의 재확인은 불가능했다. 재부팅 전에는 `su`가 사용 가능했다. 원인과 root 기능 복구 여부는 미확인이다. Launcher 포커스와 프로세스 생존은 One UI의 완전한 정상 동작을 입증하지 않으므로 사용자 기기 확인이 필요하다. 하드웨어 전원 차단 후 복구, 전체 Host 정책 원복 및 전체 기능 정상 여부는 unknown이다.

## su 복구 후 읽기 전용 재확인

사용자가 `su`를 복구한 뒤 2026-10-31 21:50 KST에 재조회했다. `su`는 `uid=0`, `u:r:ksu:s0`로 동작하고 boot ID는 재부팅 직후와 동일하다. 전역 Enforcing, 두 전용 context의 EINVAL, 임시 디렉터리 부재, 기기 부팅 완료와 주요 Host 프로세스 생존이 확인됐다. 두 기존 모듈의 `sepolicy.rule` 해시와 선택된 세 Host AV 응답은 실험 전과 일치했다. 전체 실효 정책 읽기는 다시 EINVAL로 실패해 전체 정책 해시·완전한 원복은 여전히 unknown이다. [복구 후 원본](../out/guest-domain-live/root-restored.json)을 기록했다. 정책·라벨 변경과 Guest 실행은 이 재확인에서 수행하지 않았다.

# Guest SELinux Enforcing 재시도 준비 — 2026-10-31

**실행 승인 대기.** 기존 네 정책 문장은 변경하지 않았다. 이번 준비에서는 정책 적용·라벨 변경·Guest 전환·재부팅을 하지 않았다.

이전 `ssal_guest_probe → ssal_guest_probe dir:search` 거부는 실제 AVC가 아니라 새 SID 두 개로 한 사전 AV 조회였다. 재부팅 후 읽기 전용으로 기존 `ksu` 및 Enforcing `servicemanager`를 확인하니 각각 `/proc/<pid>`, `attr`, `attr/current`, `ns`, `status`가 해당 프로세스 도메인과 같은 라벨이었다. 이는 Guest에서도 이전 조회가 관련될 가능성을 뒷받침하지만 Guest 프로세스의 실제 inode 라벨이나 접근 실패를 증명하지는 않는다. Android 공통 커널의 [proc 속성 접근](https://android.googlesource.com/kernel/common/+/a8200613c8c9f/security/selinux/hooks.c)도 참고하되 삼성 실행 커널과 동일하다고 단정하지 않는다.

수정한 런처는 실제로 확인하지 않은 Guest proc 라벨을 추정해 사전 통과·실패로 결정하지 않고 `unknown_before_exec`로 보고한다. Identity Reporter는 실패한 `/proc` 경로를 오류에 포함하고 런처는 child stderr를 수집한다. 실패 시 실행 직전후 커널 audit/dmesg를 읽어 실제 AVC의 시간·PID·source/target SID·class·permission을 기록한다. 로그가 없거나 접근하지 못하면 실제 거부 원인은 unknown으로 기록하며 추정 AV를 실제 AVC로 취급하지 않는다. AVC 거부가 확인되면 즉시 중단하고 추가 정책은 적용하지 않는다.

## 승인 대상

대상 SM-S937N `R5CY52JC03H`, boot ID `3f01fc00-ada4-44bd-969f-c67988799f20`. 21:54 KST 읽기 전용 기준: 전역 Enforcing, root `u:r:ksu:s0`, 두 Guest context EINVAL, 기존 두 모듈 정책 해시 및 선택된 Host AV는 이전과 일치. `/data`는 f2fs `seclabel,nosuid`; 실효 정책 전체 export는 EINVAL이다. [기준 수집](../out/guest-domain-retry/baseline.json).

| 항목 | SHA-256 |
|---|---|
| AArch64 launcher | `67be7ec75afac3d02b5add6fd4988835f272e97a57eecf15c857f06b99102786` |
| AArch64 identity | `14a4fb68c00faa76f768f7e59b28b019b06c41845d7511aef9b6ed3b9264bf7f` |
| [네 문장 후보](../scripts/guest-domain-poc/policy-candidate.txt) | `22da591be41b4ee26ed7c500af1fbedbc0fb5932448da045bca7735c4a117214` |

두 ELF는 `/system/bin/linker64`, `libc.so`, `libdl.so`에 의존한다. 기존 WSL Android NDK에서 release 빌드했으며 launcher 테스트 2개, 후보·관측 비교 테스트 3개 및 Android 타깃 check가 통과했다.

승인 후 이전에 검증한 `adb push`로 전용 임시 디렉터리에 파일을 전송하고 root 소유로 고정해 해시를 대조한다. 네 문장만 일회성 적용하고 각 context·AV와 대상 enforcing flag를 확인한다. 전용 identity 파일에만 라벨을 부여한 뒤 런처로 1회 실행한다. 예상과 다른 정책 반영, 실제 AVC 거부, 파일 해시 불일치 또는 global/target enforcing 불일치는 즉시 중단한다. 정책·모듈 자동 재적용은 만들지 않는다. 전용 임시 파일을 삭제하고 전체 기기 재부팅 후 부팅 ID·전용 context·전역 Enforcing·Host 및 One UI 상태를 확인한다.

정책은 커널 전역이며 부분 적용 가능성이 있다. 이전 재부팅 후 `su`가 일시적으로 사라져 사용자가 복구한 이력이 있다. 재부팅은 진행 중인 기기 작업을 중단하며, 완전한 정책 차분·One UI 전체 기능·하드웨어 전원 차단 복구는 별도 확인 없이는 unknown이다. 실행 및 재부팅은 별도 명시적 승인 후에만 한다.

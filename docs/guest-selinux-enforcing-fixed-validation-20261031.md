# 수정된 런처 실기기 간단 검증 — 2026-10-31

**결과: 실패.** 단일 write로 수정한 Android 런처와 identity를 빌드·전송하고 각각 SHA-256 `ea15f0bed95fd7cd337765cd187cd8a33ac8d2d23da47d28d6d784f089e8167a`, `14a4fb68c00faa76f768f7e59b28b019b06c41845d7511aef9b6ed3b9264bf7f`가 일치함을 확인했다. 대상은 SM-S937N `R5CY52JC03H`, 실험 전 boot ID `118a77f7-ec04-40dc-9d48-762d67cdb3af`다.

기존 네 문장 적용 후 두 context 유효성, `ksu → ssal_guest_probe process:transition`, `ssal_guest_probe → ssal_guest_probe_exec file:entrypoint`를 확인했다. 전역 Enforcing, 대상 permissive flag 0이었다. 전용 identity 파일을 `u:object_r:ssal_guest_probe_exec:s0`로 라벨링하고 해시를 재검증했다.

수정된 런처는 이전의 `EINVAL`을 넘어서 자신이 요구하는 source 및 entrypoint AV가 allowed, 대상 permissive flag가 0임을 보고했다. 이어서 child가 `SIGSEGV`로 종료했고 stderr는 비어 있었다. identity의 실제 SID나 정상 종료는 확인되지 않았으며, child가 exec 이전에 죽었는지 exec 후 죽었는지도 확정되지 않았다. 런처 로그는 [run.json](../out/guest-domain-fixed/run.json)에 있다.

실행 전후 dmesg 비교와 관련 logcat 검색에서 새로운 Guest 관련 AVC 거부는 찾지 못했다. 로그 부재로 AVC 발생 가능성을 완전히 배제하거나 SIGSEGV 원인을 결정할 수 없다. 별도 allow·permissive를 추가하지 않고 중단했다. 원인 규명에는 해당 child의 실행 단계와 signal 발생 위치를 확인할 수 있는 증거가 필요하다.

전용 임시 파일과 디렉터리를 제거했고 전역 Enforcing을 확인한 뒤, 기존 승인 범위에 따라 `adb reboot`을 요청했다. 사용자가 이전에 요청한 대로 재부팅 후 원상복구 확인은 생략했으므로 정책 원복과 One UI 상태는 unknown이다.

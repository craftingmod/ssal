# Guest `apexservice` SIGSEGV 조사 — 2026-11-18

## 결론

정확한 fault PC와 backtrace를 얻지 못해 **근본 원인과 코드 수정은 아직 확정하지 못했다.** Lenovo TB320FC(Android 15/ZUI)에서 유효하게 실행된 다섯 번의 시도 모두 private Binder 단계는 통과한 뒤, Guest `apexd` SID로 실행된 PID가 곧바로 SIGSEGV로 끝났다. 최신 시도는 PID `27978`, 15:57:35 KST다. [최신 체크 로그 230–232행](../out/guest-real-boot-20261118/preinit-check.log#L230) [실행 결과](../out/guest-real-boot-20261118/preinit-result.txt)

현재 가장 강한 위치 판단은 **Rust `main()`보다 앞선 ELF 로딩 또는 초기화 구간**이다. 이를 원인 확정으로 볼 수는 없다. 기기에 올린 진단 ELF에는 `DT_PREINIT_ARRAY`와 relocation이 있고, 그 첫 함수는 `APEX_DIAG preinit_array entered`를 stderr에 쓰도록 되어 있다. 하지만 실제 로그에는 이 마커도, 이전 `.init_array`/Rust `main`/preload 생성자 마커도 없었다. Android Bionic은 필요한 라이브러리 연결 뒤 실행 파일의 preinit 함수를 일반 생성자보다 먼저 호출한다([Bionic linker_main.cpp](https://android.googlesource.com/platform/bionic/%2B/refs/heads/main/linker/linker_main.cpp), [Bionic linker_soinfo.cpp](https://android.googlesource.com/platform/bionic/%2B/59bebc7eb9ad9183c3342f543f7bdc2af3a8d263/linker/linker_soinfo.cpp)). 따라서 동적 링커의 의존성/relocation 처리 또는 preinit 진입 직전이 우선 조사 대상이다. 첫 마커를 쓰는 동작 자체에서 fault가 났을 가능성은 남는다.

## 관찰 근거

- `PHASE5B=PASS`와 private Binder `234:5`가 확인된 뒤 `apexservice` PID가 Guest SID `u:r:ssal_p0001_apexd:s0`로 실행되고 SIGSEGV를 받았다. [로그 230–232행](../out/guest-real-boot-20261118/preinit-check.log#L230) [종료 기록 3086행](../out/guest-real-boot-20261118/preinit-check.log#L3086)
- Rust 진입부는 인자 확인 → APEX registry `load()` → Binder 초기화 → 서비스 등록 순서다. 이 단계의 로그가 없어 registry 파싱, `ProcessState::init`, rsbinder 등록 문제로 단정할 증거가 없다. [apexservice main.rs](../experiments/apexservice/src/main.rs#L132) [Binder 초기화](../experiments/binder-service/src/lib.rs#L26)
- phase3와 같은 `LD_LIBRARY_PATH=/system/lib64/bootstrap:/system/lib64`로 맞춘 진단 실행도 동일하게 종료했다. 현재 launcher 기본값 `/run/ssal`만의 문제라는 가설은 약해졌다. [launcher 환경](../src/guest/launcher/mod.rs#L87)
- Guest 정책이 활성화되면 launcher는 모든 서비스의 `LD_PRELOAD` 앞에 `/run/ssal/ssal-context-map.so`를 넣는다. 해당 라이브러리의 진단 생성자도 실행 로그에 나타나지 않았다. 이것은 preload 자체를 무혐의로 만들지 않는다. 링커가 생성자 전 단계에서 실패했을 수 있으므로, 이 preload는 여전히 가장 작은 A/B 대상이다. [공통 preload 주입](../src/guest/init/service.rs#L148)
- logcat/dmesg에는 해당 PID의 crash trace나 새 tombstone이 없었다. 기록된 AVC는 exec 직전 KSU SID의 `permissive=1` 이벤트뿐이며, exec 후 enforcing Guest 도메인의 차단은 찾지 못했다. 따라서 SELinux 허용 규칙 추가나 Host 정책 변경은 현재 증거로 뒷받침되지 않는다. [AVC와 로그 필터](../out/guest-real-boot-20261118/init-diagnostic-sixth-filtered.txt#L19) [crash buffer/dmesg 필터](../out/guest-real-boot-20261118/init-diagnostic-sixth-filtered.txt#L22)
- 이번 실행의 Host 전후 스냅샷은 동일했고, Luna가 임시 userdata와 staging 경로를 제거했다. Guest 프로세스, mount, loop, cgroup 잔여도 없고 원본 userdata/system/profile 메타데이터는 유지됐다. [Host 전후 비교](../out/guest-real-boot-20261118/preinit-host-before.txt) [정리 증거](../out/guest-real-boot-20261118/init-diagnostic-cleanup6.txt)

## 가장 작은 해결 검증 순서

1. 같은 Guest 정책·SID·인자·라이브러리 경로에서 **`apexd`에만 `ssal-context-map.so` 주입을 끈 A/B 실행**을 한다. phase2 로그 preload와 SELinux 전환은 유지한다. 이때 preinit/main 마커가 나타나면 APEX 서비스에서 불필요한 preload를 제외하는 것이 수정 후보가 된다. 등록 및 AIDL 조회까지 다시 통과하기 전에는 해결로 판정하지 않는다.
2. A/B 결과가 같으면 launcher 부모가 exec 직후 자식의 SIGSEGV를 ptrace로 포착하도록 진단해 레지스터와 `/proc/<pid>/maps`를 보존하고, PC를 정확한 linker/ELF build에 symbolicate한다. 지금은 PC가 없어 특정 라이브러리나 명령으로 좁힐 수 없다.
3. AVC의 `{ noatsecure }`는 `permissive=1`로 기록됐다. 이 로그만 보고 `noatsecure` 허용이나 다른 SELinux 규칙을 추가하지 않는다. 원인 분리 결과가 나온 뒤 Guest 전용 최소 변경만 검토한다.

이번 조사는 Lenovo 기기에서 check-only로 수행했다. Samsung/One UI와 Guest SystemServer 부팅은 검증하지 않았다. worker 사망 후 stale 상태 및 세션 teardown에 의존하는 자식 정리 위험은 별도 이슈로 남는다.

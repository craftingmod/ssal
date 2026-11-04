## GOAL

잠긴 부트로더의 순정 삼성 커널에서, 재부팅 없이 독립된 userdata를 사용하는 LineageOS로 전환하고, 하드 재부팅만으로 One UI가 정상 복구되도록 한다.

## WARNING

vendor has huge codebase so don't read unless explicit request.

## Rule

- Run WSL and WSLc commands outside the sandbox.
- Prioritize incremental runtime validation and first boot over exhaustive preemptive hardening. Avoid blocking all progress on unverified risks.

### SELinux Experimental Policy

- Missing Guest-only SELinux types, attributes, or permissions are implementation tasks, not automatic NO-GO conditions. Prepare the minimal policy delta and continue validation when Host isolation boundaries remain intact.
- Prefer controlled runtime experiments with Guest-specific permissive domains for AVC collection. Keep Host enforcing and do not grant new broad permissions to existing Host domains.
- Stop only for demonstrated Host safety violations, unresolved policy conflicts, or changes that cannot be safely contained under the approved experimental boundaries. Report static warnings separately from runtime failures.


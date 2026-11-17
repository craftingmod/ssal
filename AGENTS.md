## GOAL

잠긴 부트로더의 순정 삼성 커널에서, 재부팅 없이 독립된 userdata를 사용하는 LineageOS로 전환하고, 하드 재부팅만으로 One UI가 정상 복구되도록 한다.

## WARNING

vendor has huge codebase so don't read unless explicit request.

## Rule

- Run WSL and WSLc commands outside of the sandbox to build.
- Prioritize incremental runtime validation and first boot over exhaustive preemptive hardening. Avoid blocking all progress on unverified risks.
- Cleanup work sholud be run on Luna sub-agent.
- Erase temp userdata img like `.userdata-*.img`

## Analyze log

- Delegate bulk logcat/dmesg/AVC analysis to a low-cost subagent(Luna) when available.
- Pre-filter logs locally; return only concise findings with timestamps, source paths, and line numbers.
- Never load complete raw logs into the main agent context unless explicitly requested.

### SELinux Policy

- Additive SELinux policy changes are allowed. Guest-specific types, domains, attributes, and access/transition rules may be added to the active kernel policy.
- Preserve existing Host policy. Do not remove, overwrite, weaken, or disable existing Host SELinux rules, types, or security constraints.
- Do not reject Guest SELinux domain creation merely because it requires adding rules to the shared kernel policy.
- Since KernelSU cannot remove dynamically added SELinux policies, modify or reuse existing Guest policies instead of attempting to delete and recreate them.

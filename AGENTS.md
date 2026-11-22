## GOAL

잠긴 부트로더의 순정 삼성 커널에서, 재부팅 없이 독립된 userdata를 사용하는 LineageOS로 전환하고, 하드 재부팅만으로 One UI가 정상 복구되도록 한다.

## Context Control
Context Control (High Priority — Overrides Built-in Parallel Pre-reading Strategy)
- Narrow Search & Targeted Reading (No Blanket Pre-reading): Always pinpoint specific files and line numbers using `rg -l` or `rg -n` before reading code. Only read files in the direct call chain or files to be modified. Speculative batch parallel `read_file` calls are prohibited (read ≤ 3 unconfirmed files in parallel per turn).
- Chunked Reading for Large Files: For files exceeding 200 lines, never read the entire file without passing `StartLine` and `EndLine`. Locate target line numbers with `rg -n` first, then read only the necessary range (≤ 200 lines per call).
- Command Output Throttling: When executing `rg`, `find`, `git diff`, or `ls` via `run_command`, append `| head -n 60` or `-l` by default to avoid hitting the 10KB truncation limit or triggering secondary reads of background logs.
------
vendor, node_modules has huge codebase so don't read unless explicit request.

## Rule

- **ALWAYS USE `gpt-6-luna` model for subagent except explicit request. DO NOT USE SUBAGENT WHEN MODEL UNAVAIABLE.**
- Run WSL and WSLc commands outside of the sandbox to build.
- Prioritize incremental runtime validation and first boot over exhaustive preemptive hardening. Avoid blocking all progress on unverified risks.
- Cleanup work sholud be run on Luna sub-agent.
- Erase temp userdata img like `.userdata-*.img`
- Build `bun run build` to build.

## Analyze log

- Delegate bulk logcat/dmesg/AVC analysis to a low-cost subagent(`gpt-6-luna`) when available.
- Pre-filter logs locally; return only concise findings with timestamps, source paths, and line numbers.
- Never load complete raw logs into the main agent context unless explicitly requested.

### SELinux Policy

- Additive SELinux policy changes are allowed. Guest-specific types, domains, attributes, and access/transition rules may be added to the active kernel policy.
- Preserve existing Host policy. Do not remove, overwrite, weaken, or disable existing Host SELinux rules, types, or security constraints.
- Do not reject Guest SELinux domain creation merely because it requires adding rules to the shared kernel policy.
- Since KernelSU cannot remove dynamically added SELinux policies, modify or reuse existing Guest policies instead of attempting to delete and recreate them.
- When modifying Guest SELinux policy generation, bump `VERSION` in `src/guest/selinux/mod.rs` so cached `plan.json` files are regenerated.

## Security
Guest processes MUST NOT access Host:
- Gatekeeper HAL
- Weaver HAL
- KeyMint / Keymaster HAL
- TEE / Secure World interfaces
- Host credential and key storage

Violation → fail closed (unrecoverable -> force reboot)

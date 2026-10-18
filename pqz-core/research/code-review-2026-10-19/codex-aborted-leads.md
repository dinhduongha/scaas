# Codex whole-code review 2026-10-19: aborted after ~3 min (workspace out of credits); unverified leads

- D (LaZer fork): z2 rejection test receives z1's variance; tbox beta4 sampler reads bit 8 on every fourth attempt (forces a positive sign). Prover side.
- B (PQZH STARK backup): decoder accepts overlong length varints (proof re-encodable / malleable); both hiding paths seed masks from rnd32 without the spec's witness/statement hedge.
- A (PQZH Ligero): sparse FFT path in the prover branches on raw witness bit rows (zero entries leak via trace/timing). Prover side, not verifier acceptance.
- C (PQZL C): SV challenge-domain schedule reuses a domain (C and Rust alike) — was checking whether equations can cancel; also decryption signed representatives and proof-encoding canonicality.
Logs: ~/.claude/plugins/data/codex-openai-codex/state/scaas-4d9f7fc7dc3d9c11/jobs/task-mvebn*.log

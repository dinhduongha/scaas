# leaky-LWE-Estimator 0a9caf8 (DDGR20), vendored

- Source: <https://github.com/lducas/leaky-LWE-Estimator>, commit `0a9caf8bf0f80097724e0c6147194c52c6b90f86`
  (2022-11-14); the hint estimates (DDGR20) of the PQZ parameter sizing (P6-ANON S1,
  `docs/contracts/pq-zero-knowledge.md`).
- License: no license file at this commit; it is used for research runs only and, git-ignored, never redistributed from
  here.
- Fetched (TODO 8b-9 (4b), [ARCH-POS-24](../docs/decisions.md#ARCH-POS-24); group `research`): `scripts/vendor.sh
  install research` runs `git fetch --depth 1` of that commit id alone (git checks every object against it) and checks
  it out in a fresh temporary directory, then moves it to `vendor/leaky-LWE-Estimator-0a9caf8/`; the one-commit `.git`
  stays, so `git -C <dir> rev-parse HEAD` and a local `git clone` of the directory work. Nothing is edited.
- Pins (in `scripts/vendor.sh`; `install` and `check` require all three): the commit; sha256
  `200aa5fd0f441e120cf31cd6926789b2ac4b9ff03136709048259f8512fafcf0` over `sha256sum` of every file but `.git`, sorted
  by path; git tree id `ff8f143c948362d60c6c49f8b3be7bc9dfb62bee` (`git write-tree` over the same files).
- The tree id equals the commit's own tree (no submodule) and the clone the parameter-set runs used (`PQZ_TOOLS/lk`).
- Use: `pqz-core/pqzl/params` (`anon/run_hints.sh`, `aprime/run.sh`, `n-study/run_sage.sh`, `p16k/run_hints16k.sh`) and
  `params/sets/make.sh` (`e_s1`), all run in a pinned Sage container on the owner's machine; never by CI or the gate.
- Status: **UNAUDITED** (third-party; no SCaaS audit round covers it).

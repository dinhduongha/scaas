# SCaaS testnet reset 3: state (done)

Branch ua-mtx-merge at d709d672 (short final gate green at 7c85c2a3). Owner 2026-11-10 "tự động làm, không cần hỏi nữa".

- Prep: the previous chain's books (deployments/scaas-testnet*.json, onchain-scaas-testnet-*), broadcast/*/7622 and the
  vcheck block-scan cache moved to `pre-reset3-20261112/` folders (git-ignored), not deleted.
- Step 1 reset: done 20:48:55Z-20:49:13Z; check ok (probe + MLDSA87 439 ok / 0 FAIL); Blockscout up on a fresh DB.
- Step 2 deploy: first try in a 2 GiB scope outside capped OOM-killed before any send (deploy-2gib-oom.log); rerun under
  scripts/capped as reset 2: 113 tx all status 1, 20:54:06Z-21:13:34Z. check3.py ok.
- Step 3 verify (verify.sh, VERIFY_REVS=HEAD, snapshot 55ebc179dc49): rc 0, 91 verified, 3 linked clones (appended data),
  3 create3 proxies, 1 data, 1 genesis (CREATE2 deployer), 1 no code (the admin EOA), 0 unverified at head 303
  (verify-scaas-testnet-after-deploy.txt).
- Step 5 e2e (e2e3.sh): try 1 FAIL, e2e.py's own gas (estimate x 1.15 + 50 k) left the ML-DSA-signed mtxShield(alice, 7)
  out of gas (448,624 asked); try 2 through e2e3.py (pq.py's gas: estimate x 1.5 + 300 k) FAIL in section 6c,
  AuditorRequired() on pqUSD (auditor FULL; e2e.py's rotation sends the leg off, pq.py patches it on); try 3 with that
  patch: rc 0 (e2e3.log, e2e-pqz-scaas-testnet.txt): 571 ok lines, 178 tx ok, 9 negatives refused, 0 FAIL, 1834 s.
  Harness only, no contract change.
- matrix.sh: the scaas-testnet base book now reads this deploy's dry-run plan when it exists (the Step 5 note was stale).
- Machine shutdown 2026-11-11 ~23:11Z stopped the first matrix try in group tokens (matrix-scaas-testnet.log,
  tokens-scaas-testnet.log, coverage.json in this dir: that try's partial output, superseded). Step 4 rerun: matrix.sh
  scaas-testnet, MATRIX_OUT=matrix/ (this dir), RPC named, remote broadcast (compile under capped, sends in a 1G scope).
- Step 4 matrix (matrix/): group tokens ok, 504 tx / 504 status 1, negatives 5 / 5 refused (records-scaas-testnet-tokens.jsonl,
  5062 s). Matrix cut after group tokens (controller decision 2026-11-12: full matrix at reset 4); its post-group
  Blockscout verify skipped at 35/162 (35 ok) (owner 2026-11-12: "bỏ bước verify này: dừng ngay, chạy smoke 2 rồi commit";
  reset 4 resets Blockscout; the deploy's own verify was complete: 91 verified, 0 unverified). The summary row
  `groups | fail` is that stop (TERM), not a red. Groups gov, dex, liquidity, misc, zether, pq, pqoff, verifiers, views:
  not run.
- Step 6 smoke (smoke3.sh): try 1 FAIL, harness: forge build of Smoke.s.sol compiled 40 files under capped, forge script
  then recompiled 172 inside the 1G scope and was killed (smoke-try1.log); fixed: the capped step is forge script without
  --broadcast. Try 2 rc 0: smoke 1 relayed mtxTransfer status 1 (gasUsed 182,231 of 387,240), smoke 2
  RelayFeeRouter.relay status 1 (gasUsed 244,085 of 518,680, forge's estimate x 2.00), blocks 3059, 3061.
- Nothing left running; nothing to resume.

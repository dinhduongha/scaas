# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# Fable fix round 2, part node: one mutant per new guard (N-1..N-4); each must fail its test. Each file is restored after.
import subprocess, sys, shutil, os
os.chdir(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))  # scaas-node
M = [
 ("N1 no FeatureDisabled branch", "src/dex/venue.rs",
  "    } else if topic0 == crate::abi::IGovernance::FeatureDisabled::SIGNATURE_HASH {\n        // the DEX's only",
  "    } else if false {\n        // the DEX's only", "feature_disabled_29_opens"),
 ("N2a no regulated load on reopen", "src/dex/venue.rs",
  "        self.load_regulated(fresh).await.context(\"regulated legs\")?;\n        let load",
  "        let _: Vec<Address> = fresh;\n        let load", "feature_disabled_29_opens"),
 ("N2b no pending on reopen", "src/dex/venue.rs",
  "        self.load_pending(&mut opened).await.context(\"pending fills\")?;\n        Ok(Some(opened))",
  "        Ok(Some(opened))", "feature_disabled_29_opens"),
 ("N2c no rows on reopen", "src/dex/venue.rs",
  "Book::load(out.into_iter().map(|(m, _)| m).collect(), &load.rows)?",
  "Book::load(out.into_iter().map(|(m, _)| m).collect(), &load.rows[..0])?", "feature_disabled_29_opens"),
 ("N3 start drops an unread market", "src/dex/venue.rs",
  "                    unread.push(m);\n", "                    let _ = m;\n", "a_market_unread_at_start"),
 ("N3b no retry each round", "src/dex/venue.rs",
  "        if !seen && unread.is_empty() {", "        if !seen {", "a_market_unread_at_start"),
 ("N4 no refusal on non-EVM", "src/adapter.rs",
  "    if let Err(e) = crate::submit::refuse_payee_fee_fields(&job) {", "    if let Err(e) = Err::<(), _>(()).or(Ok::<(), String>(())).and(Err::<(), String>(String::new())).or_else(|_| Ok::<(), String>(())) {", "payee_fee_fields_are_refused"),
 ("N4b no PAYEE code", "src/submit.rs", "anyhow::bail!(\"PAYEE_FEE_REFUSED:", "anyhow::bail!(\"PAYEE_FEE:", "payee_fee_fields_are_refused"),
]
for name, f, a, b, test in M:
    src = open(f).read(); assert src.count(a) == 1, name
    shutil.copy(f, f + '.bak')
    try:
        open(f, 'w').write(src.replace(a, b))
        r = subprocess.run(['../scripts/capped', 'cargo', 'test', '--lib', '--', test], capture_output=True, text=True)
        out = r.stdout + r.stderr
        killed = 'FAILED' in out or 'panicked' in out
        comp = 'error[' in out
        line = next((l for l in out.splitlines() if 'panicked' in l or 'assertion' in l), '')
        nxt = [l for l in out.splitlines() if l.startswith('assertion') or 'left:' in l][:1]
        print(f"{name}: {'KILLED' if killed and not comp else ('COMPILE-ERR' if comp else 'SURVIVED')} {nxt}", flush=True)
    finally:
        shutil.move(f + '.bak', f)

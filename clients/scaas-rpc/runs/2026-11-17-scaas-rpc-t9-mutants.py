# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-rpc plan T9 mutants: python3 clients/scaas-rpc/runs/2026-11-17-scaas-rpc-t9-mutants.py check | run"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

L = "scaas-pqz-verifier/src/lib.rs"
CH = "scaas-pqz-verifier/src/chain.rs"
T = "cd scaas-pqz-verifier && ../scripts/capped cargo test --locked --offline -j2 --test service "
PROOF_THEN_KEYS = '''        if self.proof(at, stmt::input(plan.op(), st, &req.proof)).await? != VALID {
            return Err(refuse("VERDICT_ZERO", "pqz-ffi does not accept the proof"));
        }
        for (ua, version, off) in self.named_keys(at, plan, st, &t, scope).await? {
            self.check_key(at, ua, scope, version, &st[off..off + PK]).await?;
        }
'''
KEYS_THEN_PROOF = '''        for (ua, version, off) in self.named_keys(at, plan, st, &t, scope).await? {
            self.check_key(at, ua, scope, version, &st[off..off + PK]).await?;
        }
        if self.proof(at, stmt::input(plan.op(), st, &req.proof)).await? != VALID {
            return Err(refuse("VERDICT_ZERO", "pqz-ffi does not accept the proof"));
        }
'''
OLD_CLASSIFY = '''    match scaas_rpc::evm::classify(&e) {
        scaas_rpc::evm::SimError::Revert(_) => ChainError::Revert(scaas_rpc::evm::revert_data(&e).unwrap_or_default()),
        scaas_rpc::evm::SimError::Transport(_) => ChainError::Rpc(e.to_string()),
    }'''
OLD_BODY = '''    match e.as_error_resp() {
        Some(p) => match p.as_revert_data() {
            Some(d) => ChainError::Revert(d),
            None if p.message.starts_with("execution reverted") => ChainError::Revert(Bytes::new()),
            None => ChainError::Rpc(e.to_string()),
        },
        None => ChainError::Rpc(e.to_string()),
    }'''
MUTANTS = [
    ("agree replaced by failover under strict_majority", [(L, "            Some(pool) => self.agreed(pool, req).await,", "            Some(_) => self.on_nodes(|at| self.request_at(at, req)).await,")],
     T + "strict_majority_signs_the_honest_answer"),
    ("probe on failover under strict_majority", [(L, "        self.request(&Req::Probe(req.token, req.proposal)).await",
                                                  "        let r = Req::Probe(req.token, req.proposal);\n        self.on_nodes(|at| self.request_at(at, &r)).await")],
     T + "probe_runs_under_agree_too"),
    ("Reads compared without the key records", [(L, "        self.registry == o.registry && self.reads == o.reads",
                                                  "        self.registry == o.registry && self.reads.iter().filter(|r| r.to != self.registry).eq(o.reads.iter().filter(|r| r.to != o.registry))")],
     T + "two_lying_nodes_refuse_rpc_no_majority_and_sign_nothing"),
    ("a key read moved after the proof under strict_majority", [(L, "        if at.reads_only {\n            return Ok(VALID);\n        }",
                                                                  "        if at.reads_only {\n            return Ok(INVALID);\n        }")],
     T + "strict_majority_signs_the_honest_answer"),
    ("check in another order", [(L, PROOF_THEN_KEYS, KEYS_THEN_PROOF)], T + "the_refusal_is_the_same_under_both_policies"),
    ("the old classifier", [(CH, OLD_CLASSIFY, OLD_BODY)], T + "the_classifier_is_the_crates"),
]

if __name__ == "__main__":
    main("t9", MUTANTS)

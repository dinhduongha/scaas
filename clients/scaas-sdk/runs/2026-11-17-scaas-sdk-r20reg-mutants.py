# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Registry writes quoted from the gas table (controller call, owner auto-run 2026-11-19) and a registration carrying its PQZ
key's proof in one transaction or two (owner 2026-11-20): the step's caps (the regular gas to the per-transaction cap, the
whole to half the block), the step's figure (the table's regular, the larger whole), the quote's, the plan, the shapes of the
writes (KEM and PQZ additions, an `msig`'s count and slots), the sum of the rows and the generator's fresh-only groups:
python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-r20reg-mutants.py check | run"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

R = "clients/scaas-sdk/src/account/register.rs"
MS = "clients/scaas-sdk/src/account/msig.rs"
G = "clients/scaas-sdk/src/op/gas.rs"
GEN = "clients/scaas-sdk/gas/generate.py"
F = "vault,account,wallet,zether,pqz,pqz-set-n2304-kmax4096,dex,admin,classical-roots"
T = f"cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --features {F} --lib "
RT = T + "account::register::tests::"
PY = "cd clients/scaas-sdk/gas && python3 -I test_generate.py"
MUTANTS = [
    (
        "a step's regular gas not held to the cap",
        [(R, "if s.regular_gas.zip(self.tx).is_some_and(|(r, c)| r > c) {", "if false {")],
        RT + "pq_registration_step_that_does_not_fit_refused",
    ),
    (
        "a step's whole not held to half the block",
        [(R, "if s.gas.is_some_and(|g| g > self.half) {", "if false {")],
        RT + "pq_registration_two_steps_above_half_the_block",
    ),
    (
        "the whole block, not half",
        [(R, "half: block.limit / 2,", "half: block.limit,")],
        RT + "pq_registration_two_steps_above_half_the_block",
    ),
    (
        "a step's regular bound the estimate, not the table's",
        [(R, "regular_gas: table.map(|t| t.regular).or(est),", "regular_gas: est.or(table.map(|t| t.regular)),")],
        RT + "pq_registration_one_transaction_above_2_24",
    ),
    (
        "a step's gas the table's alone",
        [(R, "gas: est.max(table.as_ref().map(|t| t.gas)),", "gas: table.as_ref().map(|t| t.gas).or(est),")],
        RT + "pq_registration_one_transaction_above_2_24",
    ),
    (
        "the quote's gas limit the table's alone",
        [(R, "gas: t.gas.max(est),", "gas: t.gas,")],
        RT + "pq_registration_one_transaction_above_2_24",
    ),
    (
        "the quote's regular bound the whole",
        [(R, "regular: t.regular,", "regular: t.gas.max(est),")],
        RT + "pq_registration_one_transaction_above_2_24",
    ),
    (
        "a registration step not held to half the block at its quote",
        [(R, "if write.registration.is_some() {", "if false {")],
        RT + "pq_registration_two_steps_above_half_the_block",
    ),
    (
        "the resumed second step not held",
        [(R, "Caps::of(sdk, chain, &pool).await?.refusal(&s2)", "None::<SdkError>")],
        RT + "pq_registration_resumes_the_second_step",
    ),
    (
        "the plan's total the first step's",
        [(R, "total_gas: s1.gas.zip(s2.gas).map(|(a, b)| a.saturating_add(b)),", "total_gas: s1.gas,")],
        RT + "pq_registration_two_steps_above_half_the_block",
    ),
    (
        "a KEM key's addition not counted",
        [(R, 'if kem || set(a.get("kemPkHash")) {', "if false {")],
        RT + "registry_write_shapes",
    ),
    (
        "the PQZ additions swapped",
        [
            (
                R,
                'let kind = if pop { "pqz-pop" } else { "pqz-key" };',
                'let kind = if pop { "pqz-key" } else { "pqz-pop" };',
            )
        ],
        RT + "registry_write_shapes",
    ),
    (
        "a missing row quoted from the others",
        [
            (
                G,
                "        let Some((x, y, from)) = base_gas(chain, opt_in, tables, entry, kind, members)? else {\n"
                "            return Ok(None);\n",
                "        let Some((x, y, from)) = base_gas(chain, opt_in, tables, entry, kind, members)? else {\n"
                "            continue;\n",
            )
        ],
        RT + "reference_rows_cover_every_registry_write",
    ),
    (
        "a slot's verify row not added",
        [(G, "(g, r) = (g.saturating_add(v), r.saturating_add(v));", "(g, r) = (g.saturating_add(0 * v), r);")],
        RT + "reference_rows_cover_every_registry_write",
    ),
    (
        "an acceptance's slot kind not read",
        [(MS, ".map_or(u16::MAX, |m| slot_signer(m.kind))", ".map_or(u16::MAX, |_| u16::MAX)")],
        T + "account::msig::tests::msig_writes_landed_by_record",
    ),
    (
        "an update not counted by its members",
        [(MS, "members: u.structure.members.len() as u64,", "members: 0,")],
        T + "account::msig::tests::update_msig_current",
    ),
    (
        "generator: a fresh-only group asks for the used lane",
        [(GEN, 'for fresh in (True,) if group.get("fresh_only") else (True, False):', "for fresh in (True, False):")],
        PY,
    ),
]

if __name__ == "__main__":
    main("r20reg", MUTANTS)

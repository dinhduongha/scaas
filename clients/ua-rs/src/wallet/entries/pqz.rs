// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! T8c: the rows on the `pqz` kind alone: the rollover and the prepare (each naming the key version), the six debits (their
//! `pqzAuth` and, last, the `PqzSignedVerdict`: the empty one of a `PRECOMPILE` token; the node takes the verifier's part by
//! name, `args.pqz_verdict`), the holder's signed rollover. `PqzAuth` has no entry (the facade attaches it). A copy of
//! `scaas-node/src/typed.rs` `TYPED`, held equal by `tests/entries.rs`.
use super::Def;

const P: &[&str] = &["pqz"];
const PQZ_PLAN: &str = "E args proof pqzAuth:UASig accHint @ verdict";
const PQZ_BURN_PLAN: &str = "E args (amount,recipient) proof pqzAuth:UASig accHint @ verdict";
const PQZ_UNWRAP_PLAN: &str = "E args unwrap proof pqzAuth:UASig accHint @ verdict";

pub(super) const ROWS: &[Def] = &[
    ("UAPqzRollOver", "mtxRollOver", P, "bytes32 from,bytes32 ua,uint64 keyVersion,uint256 n,E", ""),
    ("UAPrepareAcc", "mtxPrepareAcc", P, "bytes32 from,bytes32 ua,uint64 keyVersion,uint256 half,E", ""),
    ("UAPqzTransferSingle", "mtxConfidentialTransferSingle", P, "bytes32 from,PqzTransferArgs args,bytes proof,bytes accHint,E", PQZ_PLAN),
    ("UAPqzTransferSingleCompact", "mtxConfidentialTransferSingleCompact", P, "bytes32 from,PqzTransferArgs args,bytes proof,bytes accHint,E", PQZ_PLAN),
    ("UAPqzTransfer", "mtxConfidentialTransfer", P, "bytes32 from,PqzMultiArgs args,bytes proof,bytes accHint,E", PQZ_PLAN),
    ("UAPqzTransferCompact", "mtxConfidentialTransferCompact", P, "bytes32 from,PqzMultiArgs args,bytes proof,bytes accHint,E", PQZ_PLAN),
    ("UAPqzUnshield", "mtxUnshield", P, "bytes32 from,PqzBurnArgs args,uint256 amount,bytes32 recipient,bytes proof,bytes accHint,E", PQZ_BURN_PLAN),
    ("UAPqzUnshieldUnwrap", "mtxUnshieldUnwrap", P, "bytes32 from,PqzBurnArgs args,Unwrap unwrap,bytes proof,bytes accHint,E", PQZ_UNWRAP_PLAN),
    ("PqzRollOver", "mtxRollOverSigned", P, "bytes32 ua,uint64 keyVersion,uint64 rollSeq,uint64 rolled,uint64 n,uint64[] skip,bytes32 entriesHash,uint64 validUntilBlock,bytes32 chainUid", "ua keyVersion n skip validUntilBlock @ua"),
    ("PqzAuth", "", P, "uint8 op,bytes32 opTag,bytes32 psid,uint256 chainId,address token,address registry,bytes32 from,bytes32 to,bytes32 beneficiary,uint256 fee,uint256 amount,bytes32 recipient,uint64 sendCounter,uint64 p,uint256 validUntilBlock,bool auditorOn,uint256 shieldIn,bytes32 chainUid,bytes32 binding,uint128 salt,bytes32 memoHash,bytes32 bodyHash", ""),
];

// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;
import {PqzSet} from "./PqzSet.sol";
import {IFactoryToken} from "../factory/IFactoryToken.sol";

import {ERC20MetaTx} from "../metatx/ERC20MetaTx.sol";
import {MetaTokenBase} from "../metatx/MetaTokenBase.sol";
import {MetaTxLib} from "../common/MetaTxLib.sol";
import {ZetherTypes} from "../zether/ZetherTypes.sol";
import {IPqzToken} from "./IPqzToken.sol";
import {IConfidentialToken} from "../confidential/IConfidentialToken.sol";
import {PqzCore} from "./PqzCore.sol";
import {PqzBurnLib} from "./PqzBurnLib.sol";
import {PqzStateLib} from "./PqzStateLib.sol";
import {PqzTransferLib} from "./PqzTransferLib.sol";
import {PqzViewLib} from "./PqzViewLib.sol";
import {ENV_PQZ_VERIFIER} from "../factory/IFactoryToken.sol";
import {ChainEnvCode} from "../factory/ChainEnvCode.sol";
import {SSTORE2} from "../common/SSTORE2.sol";
import {SigCheck} from "../common/SigCheck.sol";
import {UAKinds} from "../ua/UAKinds.sol";
import {IUARegistry} from "../ua/IUARegistry.sol";
import {GovernanceUse} from "../governance/GovernanceBase.sol";
import {GovernanceBits} from "../governance/GovernanceBits.sol";

/// @dev The token's `disclosureStatement` entry, for the self-call of `PqzLayer` (T66b: the entry is the face's).
interface IPqzDisclosureStatement {
    function disclosureStatement(bytes32 entryRef, uint256 leg, uint256 amount, uint8 kind, uint64 keyVersion)
        external view returns (bytes memory);
}

/// @title The PQZ layer of the kinds `NORMAL_PQZ` and `WRAPPED_PQZ` (CTR-PQZ-15, CTR-PQZ-22; P6g plan D1): the entry
///        points and views of pq-zero-knowledge.md §9.4; the state and the logic are the four libraries (`scaas.pqz`; D14).
/// @notice **UNAUDITED.** Any chain whose `PQZ` precompile passes the self-test (`PqzSafety`); never on Hedera.
///         A layer over the
///         public ERC-20 balance: `mtxShield` moves public units to `SHIELD_POOL` into a TRIVIAL pending entry (no
///         proof, any holder, free; plan 5h D18, D19), every debit may top up `shieldIn` from the signer's public
///         balance in the same call, `mtxUnshield` moves units out of the pool (to an address or a signing UA); fees
///         (txFee to the beneficiary, op 7's `decoyFee` to every leg) go from the pool to public UA-ledger balances. Nothing is minted or burnt by the
///         layer: `balanceOf(SHIELD_POOL) == totalShielded · shieldScale`. Ciphertexts, `acc` and the queue
///         live in state (plan 5h D1–D9): debits take an optional `accHint`, rollovers are `(ua, n)` by anyone. The verifier (precompile and proof system) is an
///         implementation immutable (CTR-ZTH-20 / CTR-PQZ-10), so the proof system is an attribute of the release; the
///         auditor UA and the two modes are fixed at creation. Every entry point is `nonReentrant`; the shared entry
///         points are `IConfidentialToken`'s (plan 5h D20), allowlisted on both relaying paths (fee class `ABSOLUTE`)
///         and never batched (CTR-PQZ-21); the rollover and `mtxPrepareAcc` are allowlisted too, never batched (Task R,
///         owner 2026-10-20). A holder is a signing UA: `pqzAuth` is that UA's own signature over the typed `PqzAuth` of the
///         statement (TS-D19), and its PQZ key is a record attribute (UA-6 U7); a UA without the key is refused as sender, leg,
///         beneficiary, shield target and auditor. The direct ops take explicit parameters (`IPqzToken`, TS-D17); each has a
///         signed overload (`UAEnvelope` first, `UASig` last; ua-mtx-merge R36) for native and derived ids, which runs it
///         through the ticket self-call, so the op's body and the statement's binding are the generic path's.
abstract contract PqzLayer is MetaTokenBase {
    /// @notice The PQZ parameter set this code was built at: its self-test hash (`PqzSet.SELFTEST`, rewritten by `at-set.sh`).
    ///         Every body module of a PQZ kind answers it, and the implementation's constructor compares it (T66b, Fable P2-A).
    function pqzSet() public pure returns (bytes32) {
        return PqzSet.SELFTEST;
    }

    // The address signed forms (`Envelope` + `bytes sig`) and their typehashes are in legacy/ua-mtx-merge/ (R36): the
    // `UA*` structs are the one signed form, native ids zero-padded.
    bytes32 private constant UA_ROLL_OVER_TYPEHASH = keccak256(
        "UARollOver(bytes32 from,bytes32 ua,uint64 keyVersion,uint256 n,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"
    );
    bytes32 private constant UA_PREPARE_ACC_TYPEHASH = keccak256(
        "UAPrepareAcc(bytes32 from,bytes32 ua,uint64 keyVersion,uint256 half,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"
    );
    bytes32 private constant UA_TRANSFER_SINGLE_TYPEHASH = keccak256(
        "UAPqzTransferSingle(bytes32 from,PqzTransferArgs args,bytes proof,bytes accHint,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)PqzTransferArgs(uint64 p,uint256 validUntilBlock,uint256 shieldIn,bytes32 fromUA,uint64 keyVersion,bytes32 toUA,bytes32 beneficiaryUA,bytes16 salt,bytes32 ownTag,bytes u,bytes vTo,bytes vFrom,bytes vAuditor,bytes sealedMemo)"
    );
    bytes32 private constant UA_TRANSFER_SINGLE_COMPACT_TYPEHASH = keccak256(
        "UAPqzTransferSingleCompact(bytes32 from,PqzTransferArgs args,bytes proof,bytes accHint,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)PqzTransferArgs(uint64 p,uint256 validUntilBlock,uint256 shieldIn,bytes32 fromUA,uint64 keyVersion,bytes32 toUA,bytes32 beneficiaryUA,bytes16 salt,bytes32 ownTag,bytes u,bytes vTo,bytes vFrom,bytes vAuditor,bytes sealedMemo)"
    );
    bytes32 private constant UA_TRANSFER_TYPEHASH = keccak256(
        "UAPqzTransfer(bytes32 from,PqzMultiArgs args,bytes proof,bytes accHint,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)PqzLeg(bytes32 ua,bytes v,bytes vAuditor)PqzMultiArgs(uint64 p,uint256 validUntilBlock,uint256 shieldIn,bytes32 fromUA,uint64 keyVersion,bytes32 beneficiaryUA,uint256 decoyFee,bytes16 salt,bytes32 ownTag,bytes[] u,PqzLeg[] legs,bytes vFrom,bytes sealedMemo)"
    );
    bytes32 private constant UA_TRANSFER_COMPACT_TYPEHASH = keccak256(
        "UAPqzTransferCompact(bytes32 from,PqzMultiArgs args,bytes proof,bytes accHint,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)PqzLeg(bytes32 ua,bytes v,bytes vAuditor)PqzMultiArgs(uint64 p,uint256 validUntilBlock,uint256 shieldIn,bytes32 fromUA,uint64 keyVersion,bytes32 beneficiaryUA,uint256 decoyFee,bytes16 salt,bytes32 ownTag,bytes[] u,PqzLeg[] legs,bytes vFrom,bytes sealedMemo)"
    );
    bytes32 private constant UA_UNSHIELD_TYPEHASH = keccak256(
        "UAPqzUnshield(bytes32 from,PqzBurnArgs args,uint256 amount,bytes32 recipient,bytes proof,bytes accHint,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)PqzBurnArgs(uint64 p,uint256 validUntilBlock,uint256 shieldIn,bytes32 fromUA,uint64 keyVersion,bytes32 beneficiaryUA,bytes32 ownTag,bytes u,bytes vFrom)"
    );

    /// @dev The `UAPqzVerifier` of this release and chain: the env's `deps[ENV_PQZ_VERIFIER]`, from the clone's code
    ///      (chain-neutral spec §2.2); `init` takes the precompile and the proof system from it.
    function _pqzVerifier() internal view returns (address) {
        return ChainEnvCode.dep(ENV_PQZ_VERIFIER);
    }

    /// @dev `env.deps = [UAPqzVerifier]`, never on Hedera, a registry: `PqzStateLib.validateEnv`.
    function _validateEnv(IFactoryToken.ChainEnv calldata env) internal view virtual override {
        PqzStateLib.validateEnv(env.deps, env.hedera, env.registry);
    }

    /// @notice CTR-PQZ-15: the token signs under `"SCaaS PqzToken"`.
    function _domainName() internal pure virtual override returns (string memory) {
        return "SCaaS PqzToken";
    }

    // ------------------------------------------------------------------ views

    function _verifierBody() internal view returns (address) { return _pqzVerifier(); }
    function _precompileBody() internal view returns (address) { return PqzCore.$().pqz; }
    function _proofSystemIdBody() internal view returns (bytes32) { return PqzCore.$().psid; }
    function _shieldScaleBody() internal view returns (uint256) { return PqzCore.$().shieldScale; }
    function _maxShieldedBody() internal view returns (uint256) { return PqzCore.$().maxShielded; }
    function _confidentialFeeBody() internal view returns (uint256) { return PqzCore.$().confidentialFee; }
    function _minDecoyFeeBody() internal view returns (uint256) { return PqzCore.$().minDecoyFee; }
    function _auditorUABody() internal view returns (bytes32) { return PqzCore.$().auditorUA; }
    function _auditorModeBody() internal view returns (ZetherTypes.AuditorMode) { return PqzCore.$().auditorMode; }
    function _disclosureModeBody() internal view returns (ZetherTypes.DisclosureMode) { return PqzCore.$().disclosureMode; }
    function _totalShieldedBody() internal view returns (uint256) { return PqzCore.$().totalShielded; }
    function _proofStoreBody() internal view returns (uint8) { return PqzCore.$().proofStore; }

    /// @notice The account of `(ua, keyVersion)` (D13; group 3g KV-6): counters, the `acc` reference, `accUnits`, flags, the
    ///         UA's `sendCounter` (one for every version), `accHash`, `lastDebit` (group 3h PP-2).
    function _pqzAccountBody(bytes32 ua, uint64 keyVersion) internal view returns (IPqzToken.AccountState memory) {
        PqzCore.PqzStorage storage s = PqzCore.$();
        PqzCore.Account storage a = s.acct[ua][keyVersion];
        return IPqzToken.AccountState(a.pendingCount, a.rolled, a.floor, a.cleared, a.accBlob, a.accUnits, a.flags,
            s.sendCounter[ua], a.accHash, a.lastDebit);
    }

    /// @notice Group 3h (PP-2): the record of `ua`'s debit `counter` (`PqzViewLib.debitRecord`; spec §8 lever 1).
    function _pqzDebitRecordBody(bytes32 ua, uint64 counter) internal view returns (IPqzToken.DebitRecordView memory) {
        return PqzViewLib.debitRecord(ua, counter);
    }

    /// @notice Pending slot `i` of `(ua, keyVersion)` (plan 5h D2): `blob(160) ‖ uOff(16) ‖ vOff(16) ‖ block(64)`, `vOff =
    ///         0` a TRIVIAL entry with its amount in the low 64 bits of the blob field; every `i < pendingCount` (group 3h
    ///         PP-1: kept for good), 0 for an unwritten index.
    function _pqzPendingBody(bytes32 ua, uint64 keyVersion, uint64 i) internal view returns (uint256) {
        return PqzCore.$().acct[ua][keyVersion].pending[i];
    }

    /// @notice The `acc` ciphertext of `(ua, keyVersion)` from state (restore from state, D13, §3.5).
    function _pqzAccBody(bytes32 ua, uint64 keyVersion) internal view returns (bytes memory) {
        return PqzStateLib.accOf(ua, keyVersion);
    }

    /// @notice Entry `i` of `(ua, keyVersion)` as a ciphertext from state (a TRIVIAL entry: `Trivial(digits(amount))`).
    function _pqzPendingCtBody(bytes32 ua, uint64 keyVersion, uint64 i) internal view returns (bytes memory) {
        return PqzStateLib.pendingCt(ua, keyVersion, i);
    }

    /// @notice The op blob of a transfer as stored, `R ‖ v_f` packed at `PACK_BITS` (P46; `v_f` the trailing
    ///         `PqzCt.VP` bytes; D1, D13; both storage modes), empty if unknown.
    function _pqzEntryBlobBody(bytes32 entryRef) internal view returns (bytes memory) {
        address p = PqzCore.$().entryPtr[entryRef];
        return p == address(0) ? bytes("") : SSTORE2.read(p);
    }

    /// @notice `keccak256(R)` of the entry over the stored (packed, P46) `R`, read from its op blob (0 = unknown).
    function _transferCiphertextHashBody(bytes32 entryRef) internal view returns (bytes32) {
        return PqzCore.ciphertextHash(entryRef);
    }

    /// @notice The raw entry: `R` (BUNDLE), `keccak256(R) ‖ memo` (commit-reveal), empty (unknown).
    function _transferEntryBody(bytes32 entryRef) internal view returns (bytes memory) {
        PqzCore.PqzStorage storage s = PqzCore.$();
        address p = s.entryPtr[entryRef];
        if (p == address(0)) return "";
        bytes memory r = PqzCore.rOf(p);
        bytes memory m = s.memos[entryRef];
        return m.length == 0 ? r : abi.encodePacked(keccak256(r), m);
    }

    /// @notice The op 7 statement the token builds for `t`, after every cheap check; a `sealedMemo` reads as commit-reveal.
    ///         `binding` 0 = a direct call, else the relayed call's envelope binding; the statement's word is either folded
    ///         with the mode (W-A, D15).
    function _transferStatementBody(IPqzToken.PqzMultiArgs calldata t, bytes32 binding) internal view returns (bytes memory) {
        return PqzViewLib.multiStatement(_envOf(binding), t);
    }

    /// @notice The op 1 statement of `t` (`mtxConfidentialTransferSingle*`; `binding` as above).
    function _transferSingleStatementBody(IPqzToken.PqzTransferArgs calldata t, bytes32 binding) internal view returns (bytes memory) {
        return PqzViewLib.singleStatement(_envOf(binding), t);
    }

    /// @notice The burn (`amount > 0`) or refresh (`amount = 0`, `recipient = 0`) statement.
    function _burnStatementBody(IPqzToken.PqzBurnArgs calldata b, uint256 amount, bytes32 recipient, bytes32 binding) internal view returns (bytes memory)
    {
        PqzCore.Env memory e = _envOf(binding);
        (e.amount, e.recipient) = (amount, recipient);
        return PqzViewLib.burnStatement(e, b);
    }

    /// @notice The disclosure statement (§7.9) of leg `leg` of `entryRef` for `kind` (0 `SENDER_S`, 1 `RECEIVER_X`,
    ///         2 `AUDITOR`); a single-recipient entry is leg 0. `R` is read from the entry's op blob (D11). Group 3g (KV-11):
    ///         `keyVersion` selects the registered key the opening is checked against (the leg owner's, the auditor's for
    ///         `AUDITOR`); a version not stored: `KeyVersionUnknown`. It does not attest which version the leg was for.
    function _disclosureStatementBody(bytes32 entryRef, uint256 leg, uint256 amount, uint8 kind, uint64 keyVersion) internal view returns (bytes memory)
    {
        return PqzViewLib.disclosureStatementOf(entryRef, leg, amount, kind, keyVersion, _envOf(0));
    }

    /// @notice CTR-PQZ-14 / -26: the precompile's verdict on `proof` for `amount` in leg `leg` of `entryRef` (`R` from
    ///         the op blob, D11). A view; no attestation. An empty proof, an unknown entry, no leg `leg`, `kind > 2`
    ///         and `amount ≥ 2^64` are false; a precompile call that fails (out of gas) reverts (C2-6).
    function _verifyTransferAmountBody(bytes32 entryRef, uint256 leg, uint256 amount, uint8 kind, uint64 keyVersion,
        bytes calldata proof) internal view returns (bool)
    {
        // group 3f (spec §5.4): an `OFFCHAIN` token cannot verify without a verdict; `false` would read "the wrong amount"
        if (PqzCore.$().pqzVerifyMode != PqzCore.PRECOMPILE) revert IPqzToken.PqzVerdictRequired();
        return _verifyAmount(entryRef, leg, amount, kind, keyVersion, proof);
    }

    /// @notice Group 3f (spec §5.4): the disclosure with the verifier's verdict. `PRECOMPILE`: the verdict ignored, the
    ///         precompile's answer as above. `OFFCHAIN`: true iff the verdict passes spec §5.3 against `disclosureStatement`
    ///         and `proof`; false on a mismatch, a refused signature, a revoked or changed verifier, and on the statement's
    ///         shape errors as above; a starved signature check reverts `UAVerifyGas`. A view: nothing recorded
    ///         (CTR-PQZ-14). The stronger check runs off chain: `pqz-ffi`'s verifier on `disclosureStatement` and `proof`.
    function _verifyTransferAmountBody(bytes32 entryRef, uint256 leg, uint256 amount, uint8 kind, uint64 keyVersion,
        bytes calldata proof, IPqzToken.PqzSignedVerdict calldata pqzVerdict) internal view returns (bool)
    {
        if (PqzCore.$().pqzVerifyMode == PqzCore.PRECOMPILE) return _verifyAmount(entryRef, leg, amount, kind, keyVersion, proof);
        bytes memory st = proof.length == 0 ? bytes("") : _discStatement(entryRef, leg, amount, kind, keyVersion);
        if (st.length == 0) return false;
        return PqzViewLib.verdictOk(keccak256(st), keccak256(proof), pqzVerdict, _envOf(0));
    }

    /// @dev The precompile's answer (C2-6: only the statement's shape errors read false).
    function _verifyAmount(bytes32 entryRef, uint256 leg, uint256 amount, uint8 kind, uint64 keyVersion,
        bytes calldata proof) private view returns (bool)
    {
        // C2-6: only the statement's shape errors (custom errors) read false; an empty revert (out of gas in the
        // sub-call) is propagated, and a failed precompile call reverts in `verdict`. KV-11: an unknown version reverts.
        if (proof.length == 0 || _discStatement(entryRef, leg, amount, kind, keyVersion).length == 0) return false;
        return PqzViewLib.verifyAmountOf(entryRef, leg, amount, kind, keyVersion, proof, _envOf(0));
    }

    /// @dev `disclosureStatement`, empty on its shape errors (custom errors); an empty revert and `KeyVersionUnknown`
    ///      propagate, as the precompile form's.
    function _discStatement(bytes32 entryRef, uint256 leg, uint256 amount, uint8 kind, uint64 keyVersion)
        private view returns (bytes memory st)
    {
        try IPqzDisclosureStatement(address(this)).disclosureStatement(entryRef, leg, amount, kind, keyVersion) returns (bytes memory r) { st = r; }
        catch (bytes memory err) {
            if (err.length == 0 || bytes4(err) == IPqzToken.KeyVersionUnknown.selector) assembly ("memory-safe") {
                revert(add(err, 32), mload(err))
            }
        }
    }

    // ------------------------------------------------------------------ the verifier UA (group 3f, spec §4.2-§4.4)

    /// @notice The owner's transfer of a transferable `OFFCHAIN` verifier (`PqzStateLib.setVerifier`): propose, then
    ///         confirm after the notice period; through the router as `mtxPqzSetVerifier`.
    function _pqzSetVerifierBody(bytes32 next) internal {
        PqzStateLib.setVerifier(next, _govSubject(), _registry());
    }

    /// @notice The owner deletes a live pending transfer.
    function _pqzCancelVerifierBody() internal {
        PqzStateLib.cancelVerifier(_govSubject());
    }

    /// @notice The owner's immediate revocation of a transferable verifier (freeze only, spec §4.3).
    function _pqzRevokeVerifierBody() internal {
        PqzStateLib.revokeVerifier(_govSubject());
    }

    /// @notice Group 3h (spec §5): bit 24 `PQZ_PROOF`'s power, `use(24)` (no scalar; disabling the bit freezes the value:
    ///         `FeatureNotSet`), then `PqzStateLib.setProofStore`; through the router as `mtxSetProofStore`.
    function _setProofStoreBody(uint8 next) internal {
        GovernanceUse.use(GovernanceBits.PQZ_PROOF, _govSubject(), 0);
        PqzStateLib.setProofStore(next);
    }

    /// @notice Spec §4.4: mode, verifier, fixed, epoch, a live pending and its `eta`, the notice period.
    function _pqzVerifyConfigBody() internal view returns (IPqzToken.PqzVerifyConfig memory) {
        return PqzStateLib.verifyConfig();
    }

    /// @notice CTR-PQZ-21, R36: the binding of every relayed proof on the merged entries and `mtxExecute`, tag
    ///         `SCAAS-PQZ-UA-ENVELOPE-V1`, `from` as `bytes32` (native ids zero-padded); every envelope field except `data`,
    ///         plus `chainUid`. `executeMetaTransaction` keeps the address binding (`SCAAS-PQZ-ENVELOPE-V1` over its
    ///         `MetaTransaction`), which clients compute; its view is in legacy/ua-mtx-merge/.
    function _envelopeBindingBody(MetaTxLib.UAMetaTransaction calldata m) internal view returns (bytes32) {
        return _uaEnvelopeBinding(m);
    }

    // ------------------------------------------------------------------ shield (§7.3, P6g plan D1)

    /// @notice Moves `amount · shieldScale` public units of the signer to `SHIELD_POOL` (D19) into a TRIVIAL entry of
    ///         `toUA` (plan 5h D18); free, into any holder (owner 2026-10-20).
    function _mtxShieldBody(bytes32 toUA, uint256 amount) internal {
        _regPayer();
        PqzStateLib.shield(toUA, amount, _msgSender(), _registry());
        _toPool(amount);
    }

    /// @notice The signed `mtxShield` (TS-D14, TS-D16) over `UAShield`, an explicit `UASig` (R47).
    function _mtxShieldBody(MetaTxLib.UAEnvelope calldata e, bytes32 toUA, uint256 amount, IUARegistry.UASig calldata auth) internal returns (bytes memory)
    {
        return _namedUA(MetaTxLib.UA_SHIELD_TYPEHASH, IConfidentialToken.mtxShield.selector, e, abi.encode(toUA, amount), auth);
    }

    // ------------------------------------------------------------------ transfer (§7.4, CTR-PQZ-23, CTR-PQZ-25)

    /// @notice The multi-recipient transfer, op 7 `R_TXM` (`M` legs, decoys included; CTR-PQZ-26), in the token's
    ///         default form: the bundle stored (BUNDLE token) or commit-reveal (COMPACT token). `accHint`: optional,
    ///         the materialised `acc` packed at `PACK_BITS` (P46: `PqzCt.CTP` bytes, `pack(pqzAcc(ua))`; `pqzAcc`
    ///         returns 64-bit lanes), used only when it hashes to `accHash`, else ignored (plan 5h D5).
    function _mtxConfidentialTransferBody(IPqzToken.PqzMultiArgs calldata t, bytes calldata proof, IUARegistry.UASig calldata pqzAuth,
        bytes calldata accHint, IPqzToken.PqzSignedVerdict calldata pqzVerdict) internal returns (bytes32)
    {
        return _multi(_envTransfer(_defaultMode()), t, proof, pqzAuth, accHint, pqzVerdict);
    }

    function _mtxConfidentialTransferCompactBody(IPqzToken.PqzMultiArgs calldata t, bytes calldata proof, IUARegistry.UASig calldata pqzAuth,
        bytes calldata accHint, IPqzToken.PqzSignedVerdict calldata pqzVerdict) internal returns (bytes32)
    {
        return _multi(_envTransfer(ZetherTypes.TransferMode.HASH), t, proof, pqzAuth, accHint, pqzVerdict);
    }

    /// @notice The single-recipient transfer, op 1 `R_TX` / `R_TX0` (§7.4), in the token's default form.
    function _mtxConfidentialTransferSingleBody(IPqzToken.PqzTransferArgs calldata t, bytes calldata proof, IUARegistry.UASig calldata pqzAuth,
        bytes calldata accHint, IPqzToken.PqzSignedVerdict calldata pqzVerdict) internal returns (bytes32)
    {
        return _single(_envTransfer(_defaultMode()), t, proof, pqzAuth, accHint, pqzVerdict);
    }

    function _mtxConfidentialTransferSingleCompactBody(IPqzToken.PqzTransferArgs calldata t, bytes calldata proof,
        IUARegistry.UASig calldata pqzAuth, bytes calldata accHint, IPqzToken.PqzSignedVerdict calldata pqzVerdict) internal returns (bytes32)
    {
        return _single(_envTransfer(ZetherTypes.TransferMode.HASH), t, proof, pqzAuth, accHint, pqzVerdict);
    }

    /// @notice The signed forms (TS-D14, TS-D16) over the `UA*` structs (R36: native and derived ids): `args`, `proof` and
    ///         `accHint` by hash, as a wallet shows them; `pqzAuth` and `auth` are signatures, never in a signed struct
    ///         (Appendix X.1). Group 3f (spec §5.3, R2): `pqzVerdict` last, outside the struct (no
    ///         typehash moves), handed to the self-call: an unbound field like `relayer`, a relayer may swap it for another
    ///         valid one over the same hashes.
    function _mtxConfidentialTransferBody(MetaTxLib.UAEnvelope calldata e, IPqzToken.PqzMultiArgs calldata t, bytes calldata proof,
        IUARegistry.UASig calldata pqzAuth, bytes calldata accHint, IUARegistry.UASig calldata auth,
        IPqzToken.PqzSignedVerdict calldata pqzVerdict) internal returns (bytes32)
    {
        bytes memory words = _multiWords(t, proof, accHint);
        bytes memory data = _multiData(IPqzToken.mtxConfidentialTransfer.selector, t, proof, pqzAuth, accHint, pqzVerdict);
        bytes memory ret = _namedCallUA(UA_TRANSFER_TYPEHASH, e, words, data, auth);
        return _ref(ret);
    }

    function _mtxConfidentialTransferCompactBody(MetaTxLib.UAEnvelope calldata e, IPqzToken.PqzMultiArgs calldata t, bytes calldata proof,
        IUARegistry.UASig calldata pqzAuth, bytes calldata accHint, IUARegistry.UASig calldata auth,
        IPqzToken.PqzSignedVerdict calldata pqzVerdict) internal returns (bytes32)
    {
        bytes memory words = _multiWords(t, proof, accHint);
        bytes memory data = _multiData(IPqzToken.mtxConfidentialTransferCompact.selector, t, proof, pqzAuth, accHint, pqzVerdict);
        bytes memory ret = _namedCallUA(UA_TRANSFER_COMPACT_TYPEHASH, e, words, data, auth);
        return _ref(ret);
    }

    function _mtxConfidentialTransferSingleBody(MetaTxLib.UAEnvelope calldata e, IPqzToken.PqzTransferArgs calldata t, bytes calldata proof,
        IUARegistry.UASig calldata pqzAuth, bytes calldata accHint, IUARegistry.UASig calldata auth,
        IPqzToken.PqzSignedVerdict calldata pqzVerdict) internal returns (bytes32)
    {
        bytes memory words = _singleWords(t, proof, accHint);
        bytes memory data = _singleData(IPqzToken.mtxConfidentialTransferSingle.selector, t, proof, pqzAuth, accHint, pqzVerdict);
        bytes memory ret = _namedCallUA(UA_TRANSFER_SINGLE_TYPEHASH, e, words, data, auth);
        return _ref(ret);
    }

    function _mtxConfidentialTransferSingleCompactBody(MetaTxLib.UAEnvelope calldata e, IPqzToken.PqzTransferArgs calldata t, bytes calldata proof,
        IUARegistry.UASig calldata pqzAuth, bytes calldata accHint, IUARegistry.UASig calldata auth,
        IPqzToken.PqzSignedVerdict calldata pqzVerdict) internal returns (bytes32)
    {
        bytes memory words = _singleWords(t, proof, accHint);
        bytes memory data = _singleData(IPqzToken.mtxConfidentialTransferSingleCompact.selector, t, proof, pqzAuth, accHint, pqzVerdict);
        bytes memory ret = _namedCallUA(UA_TRANSFER_SINGLE_COMPACT_TYPEHASH, e, words, data, auth);
        return _ref(ret);
    }

    /// @dev Op 1 in the form of `e.mode`; the token pays what the library moved.
    function _single(PqzCore.Env memory e, IPqzToken.PqzTransferArgs calldata t, bytes calldata proof, IUARegistry.UASig calldata pqzAuth,
        bytes calldata accHint, IPqzToken.PqzSignedVerdict calldata pqzVerdict) private returns (bytes32 r)
    {
        _regSender(t.fromUA);
        if (t.shieldIn != 0) _regPayer();
        _regName(t.beneficiaryUA);
        _pullShieldIn(t.shieldIn);
        PqzCore.Paid memory f;
        (r, f) = PqzTransferLib.transfer(e, t, accHint, proof, pqzAuth, pqzVerdict);
        _fromPool(f.ben, f.fee);
    }

    /// @dev Op 7 in the form of `e.mode`: txFee to the beneficiary, then `decoyFee` to EVERY leg (the real recipient too;
    ///      owner 2026-10-20).
    function _multi(PqzCore.Env memory e, IPqzToken.PqzMultiArgs calldata t, bytes calldata proof, IUARegistry.UASig calldata pqzAuth,
        bytes calldata accHint, IPqzToken.PqzSignedVerdict calldata pqzVerdict) private returns (bytes32 r)
    {
        _regSender(t.fromUA);
        if (t.shieldIn != 0) _regPayer();
        _regName(t.beneficiaryUA);
        _pullShieldIn(t.shieldIn);
        PqzCore.Paid memory f;
        (r, f) = PqzTransferLib.transferMulti(e, t, accHint, proof, pqzAuth, pqzVerdict);
        _fromPool(f.ben, f.fee - f.legs * f.decoyFee);
        if (f.decoyFee != 0) {
            for (uint256 j; j < f.legs; ++j) _fromPool(t.legs[j].ua, f.decoyFee);
        }
    }

    // What a signed entry hashes (TS-D17) and the op's call.

    function _multiWords(IPqzToken.PqzMultiArgs calldata t, bytes calldata proof, bytes calldata accHint)
        private pure returns (bytes memory)
    {
        return abi.encode(PqzViewLib.hashMulti(t), keccak256(proof), keccak256(accHint));
    }

    function _singleWords(IPqzToken.PqzTransferArgs calldata t, bytes calldata proof, bytes calldata accHint)
        private pure returns (bytes memory)
    {
        return abi.encode(PqzViewLib.hashTransfer(t), keccak256(proof), keccak256(accHint));
    }

    function _multiData(bytes4 sel, IPqzToken.PqzMultiArgs calldata t, bytes calldata proof, IUARegistry.UASig calldata pqzAuth,
        bytes calldata accHint, IPqzToken.PqzSignedVerdict calldata pqzVerdict) private pure returns (bytes memory)
    {
        return abi.encodeWithSelector(sel, t, proof, pqzAuth, accHint, pqzVerdict);
    }

    function _singleData(bytes4 sel, IPqzToken.PqzTransferArgs calldata t, bytes calldata proof, IUARegistry.UASig calldata pqzAuth,
        bytes calldata accHint, IPqzToken.PqzSignedVerdict calldata pqzVerdict) private pure returns (bytes memory)
    {
        return abi.encodeWithSelector(sel, t, proof, pqzAuth, accHint, pqzVerdict);
    }

    /// @dev The entry reference the self-call returned.
    function _ref(bytes memory ret) private pure returns (bytes32) {
        return abi.decode(ret, (bytes32));
    }

    // ------------------------------------------------------------------ burn and refresh (§7.5)

    /// @notice Burn `amount` into `amount · shieldScale` public units moved from `SHIELD_POOL` to `recipient` (D19): a
    ///         padded address (the pools refused) or a registered SIGNING UA, credited on the UA ledger (UA-5c);
    ///         `amount = 0` with `recipient = 0` is a refresh.
    function _mtxUnshieldBody(IPqzToken.PqzBurnArgs calldata b, uint256 amount, bytes32 recipient, bytes calldata proof,
        IUARegistry.UASig calldata pqzAuth, bytes calldata accHint, IPqzToken.PqzSignedVerdict calldata pqzVerdict) internal {
        if (amount != 0) _regReceiver(recipient);
        if (!UAKinds.inNativeSpace(recipient)) _requireDerivedReceiver(recipient);
        _burn(_envBurn(amount, recipient), b, proof, pqzAuth, accHint, pqzVerdict);
        _fromPool(recipient, amount);
    }

    /// @notice The signed `mtxUnshield`: `amount` and `recipient` flat in the struct, one `Payout` here.
    function _mtxUnshieldBody(MetaTxLib.UAEnvelope calldata e, IPqzToken.PqzBurnArgs calldata b, IPqzToken.Payout calldata p, bytes calldata proof,
        IUARegistry.UASig calldata pqzAuth, bytes calldata accHint, IUARegistry.UASig calldata auth,
        IPqzToken.PqzSignedVerdict calldata pqzVerdict) internal returns (bytes memory)
    {
        (bytes memory words, bytes memory data) = _unshieldCall(b, p, proof, pqzAuth, accHint, pqzVerdict);
        return _namedCallUA(UA_UNSHIELD_TYPEHASH, e, words, data, auth);
    }

    function _unshieldCall(IPqzToken.PqzBurnArgs calldata b, IPqzToken.Payout calldata p, bytes calldata proof, IUARegistry.UASig calldata pqzAuth,
        bytes calldata accHint, IPqzToken.PqzSignedVerdict calldata pqzVerdict) private pure returns (bytes memory, bytes memory)
    {
        return (abi.encode(PqzViewLib.hashBurn(b), p.amount, p.recipient, keccak256(proof), keccak256(accHint)),
            abi.encodeCall(IPqzToken.mtxUnshield, (b, p.amount, p.recipient, proof, pqzAuth, accHint, pqzVerdict)));
    }

    /// @dev The burn / refresh debit of `e` (also `mtxUnshieldUnwrap`'s); the token pays what the library moved.
    function _burn(PqzCore.Env memory e, IPqzToken.PqzBurnArgs calldata b, bytes calldata proof, IUARegistry.UASig calldata pqzAuth,
        bytes calldata accHint, IPqzToken.PqzSignedVerdict calldata pqzVerdict) internal
    {
        if (e.amount != 0) _regSender(b.fromUA); // a refresh (amount 0) names no sender (spec §4.2)
        if (b.shieldIn != 0) _regPayer();
        _regName(b.beneficiaryUA);
        _pullShieldIn(b.shieldIn);
        PqzCore.Paid memory f = PqzBurnLib.unshield(e, b, accHint, proof, pqzAuth, pqzVerdict);
        _fromPool(f.ben, f.fee);
    }

    // ------------------------------------------------------------------ rollover (§7.6, plan 5h D8)

    /// @notice Anyone: the next `min(n, K_MAX − 1 − accUnits)` entries of `(ua, keyVersion)` into its `acc`, in order, each
    ///         at least `ROLL_AGE` blocks old; `1 ≤ n ≤ ROLL_MAX` (group 3g KV-10: any version whose key passes the check).
    function _mtxRollOverBody(bytes32 ua, uint64 keyVersion, uint256 n) internal {
        PqzStateLib.rollOver(ua, keyVersion, n);
    }

    /// @notice Anyone, once per account and half (0, 1) before its first rollover (idempotent), per key version.
    function _mtxPrepareAccBody(bytes32 ua, uint64 keyVersion, uint256 half) internal {
        PqzStateLib.prepareAcc(ua, keyVersion, half, _registry());
    }

    /// @notice The signed rollover and prepare, as `mtxShield`'s (`UARollOver`, `UAPrepareAcc` with `keyVersion`).
    function _mtxRollOverBody(MetaTxLib.UAEnvelope calldata e, bytes32 ua, uint64 keyVersion, uint256 n,
        IUARegistry.UASig calldata auth) internal returns (bytes memory)
    {
        return _namedUA(UA_ROLL_OVER_TYPEHASH, IPqzToken.mtxRollOver.selector, e, abi.encode(ua, keyVersion, n), auth);
    }

    function _mtxPrepareAccBody(MetaTxLib.UAEnvelope calldata e, bytes32 ua, uint64 keyVersion, uint256 half,
        IUARegistry.UASig calldata auth) internal returns (bytes memory)
    {
        return _namedUA(UA_PREPARE_ACC_TYPEHASH, IPqzToken.mtxPrepareAcc.selector, e, abi.encode(ua, keyVersion, half), auth);
    }

    // ------------------------------------------------------------------ internals

    function _env() internal view returns (PqzCore.Env memory) {
        return _envOf(_ticketBinding());
    }

    function _envOf(bytes32 binding) internal view returns (PqzCore.Env memory) {
        ChainEnvCode.Head memory h = ChainEnvCode.head();
        if (h.chainUid == bytes32(0)) revert ChainUidZero();
        return PqzCore.Env(h.registry, h.chainUid, binding, 0, 0, ZetherTypes.TransferMode.BUNDLE, _separator(h.chainUid));
    }

    /// @dev `mtxConfidentialTransfer`'s form: BUNDLE on a BUNDLE token, commit-reveal (HASH) on a COMPACT one.
    function _defaultMode() internal view returns (ZetherTypes.TransferMode) {
        return PqzCore.$().disclosureMode == ZetherTypes.DisclosureMode.COMPACT
            ? ZetherTypes.TransferMode.HASH
            : ZetherTypes.TransferMode.BUNDLE;
    }

    function _envTransfer(ZetherTypes.TransferMode mode) internal view returns (PqzCore.Env memory e) {
        e = _env();
        e.mode = mode;
    }

    /// @dev `units · shieldScale` public units of the signer (a derived UA signer: its UA-ledger balance) to
    ///      `SHIELD_POOL` (D19). The caller is read only when there is something to pull: with `units = 0` the
    ///      submitter is an open role, so a designator relayer is not refused (D3, CTR-UA-24).
    function _toPool(uint256 units) internal {
        if (units != 0) {
            address m = _msgSender();
            _poolMove(m == MetaTxLib.UA_POOL ? _ticketSubject() : MetaTxLib.pad(m), MetaTxLib.pad(MetaTxLib.SHIELD_POOL),
                units * PqzCore.$().shieldScale);
        }
    }

    /// @dev `units · shieldScale` public units from `SHIELD_POOL` to `to` (a UA: its public UA-ledger balance; D19).
    function _fromPool(bytes32 to, uint256 units) internal {
        if (units != 0) _poolMove(MetaTxLib.pad(MetaTxLib.SHIELD_POOL), to, units * PqzCore.$().shieldScale);
    }

    /// @dev C2-5 (owner 2026-10-27, controller proposal): `shieldIn` goes into the pool before the authorization and the
    ///      precompile, so a signer who front-ran its own op with a public transfer costs the relayer a cheap revert, not a
    ///      9–13 M gas one. The cap is the library's own check (`AmountOutOfRange`), made here first so an absurd word never
    ///      overflows the scaling. No outer-fee pre-check (`mtxUnshield` may pay its fee from its own output).
    function _pullShieldIn(uint256 units) internal {
        PqzCore.PqzStorage storage s = PqzCore.$();
        uint256 room = s.maxShielded - s.totalShielded;
        if (units > room) revert IPqzToken.AmountOutOfRange(units, room);
        _toPool(units);
    }

    function _envBurn(uint256 amount, bytes32 recipient) internal view returns (PqzCore.Env memory e) {
        e = _env();
        (e.amount, e.recipient) = (amount, recipient);
    }

    /// @dev The base stores it in the ticket for the self-call of every `executeMetaTransaction` on this token (R3):
    ///      `TAG_ENVELOPE`, `from` an address.
    function _envelopeBinding(MetaTxLib.MetaTransaction memory m) internal view virtual override returns (bytes32) {
        (address r, address f) = MetaTxLib.canon(m);
        return keccak256(abi.encode(PqzCore.TAG_ENVELOPE, block.chainid, _chainUid(), address(this), m.from, m.batch,
            m.nonce, m.validUntil, m.mode, r, m.fee, f));
    }

    /// @dev Likewise for every merged entry and `mtxExecute` (R36): `TAG_UA_ENVELOPE`, `from` as `bytes32`.
    function _uaEnvelopeBinding(MetaTxLib.UAMetaTransaction memory m)
        internal view virtual override returns (bytes32)
    {
        address r = (m.mode & MetaTxLib.MODE_RESTRICT_RELAYER) != 0 ? m.relayer : address(0);
        address f = (m.mode & MetaTxLib.MODE_RESTRICT_FEE_RECIPIENT) != 0 ? m.feeRecipient : address(0);
        return keccak256(abi.encode(PqzCore.TAG_UA_ENVELOPE, block.chainid, _chainUid(), address(this), m.from, m.batch,
            m.nonce, m.validUntil, m.mode, r, m.fee, f));
    }

    /// @dev The PQZ ops of both kinds (CTR-PQZ-21): allowlisted `ABSOLUTE` on both paths, never batched; includes the
    ///      permissionless `mtxRollOver` / `mtxPrepareAcc` (relayed, owner 2026-10-20; the fee may be 0).
    function _isPqzOp(bytes4 sel) internal pure virtual returns (bool) {
        return sel == IConfidentialToken.mtxShield.selector || sel == IPqzToken.mtxConfidentialTransfer.selector
            || sel == IPqzToken.mtxConfidentialTransferCompact.selector
            || sel == IPqzToken.mtxConfidentialTransferSingle.selector
            || sel == IPqzToken.mtxConfidentialTransferSingleCompact.selector || sel == IPqzToken.mtxUnshield.selector
            || sel == IPqzToken.mtxRollOver.selector || sel == IPqzToken.mtxPrepareAcc.selector;
    }

    function _batchable(bytes4 sel) internal view virtual override returns (bool) {
        return !_isPqzOp(sel);
    }

    /// @dev Static shapes: `mtxShield` 68 bytes, `mtxRollOver` / `mtxPrepareAcc` 100 (group 3g: `keyVersion`); the others
    ///      carry `bytes`.
    function _pqzRule(bytes4 sel) internal pure returns (MtxRule memory) {
        return MtxRule(FEE_CLASS_ABSOLUTE, 0, sel == IConfidentialToken.mtxShield.selector ? 68
            : (sel == IPqzToken.mtxRollOver.selector || sel == IPqzToken.mtxPrepareAcc.selector) ? 100 : 0);
    }
}

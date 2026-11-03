// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {stdJson} from "forge-std/StdJson.sol";
import {PqzFixture} from "./helpers/PqzFixture.sol";
import {PQZ_UID} from "./helpers/PqzRegistryBase.sol";
import {PqzPackedRef} from "./helpers/PqzPackedRef.sol";
import {VM, TYPED_OPS, n, a, h, eJson, ecdsa, checkRow, onChain, domainOf, rowEnvelope, rowEnvelope2, msgField, domainField}
    from "../metatx/NamedEntry.t.sol";
import {typedDigest, hexJson} from "../zether/ZetherTyped.t.sol";
import {MockERC20} from "../helpers/Mocks.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
import {IUALedger} from "../../src/metatx/IUALedger.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {IConfidentialToken, IConfidentialWrappedToken} from "../../src/confidential/IConfidentialToken.sol";
import {ZetherTypes} from "../../src/zether/ZetherTypes.sol";
import {IPqzToken, IPqzWrappedToken} from "../../src/pqz/IPqzToken.sol";
import {NormalPqzToken} from "../../src/pqz/NormalPqzToken.sol";
import {PqzCore} from "../../src/pqz/PqzCore.sol";
import {PqzCt} from "../../src/pqz/PqzCt.sol";
import {PqzLayer} from "../../src/pqz/PqzLayer.sol";
import {PqzSet} from "../../src/pqz/PqzSet.sol";
import {WrappedPqzToken} from "../../src/pqz/WrappedPqzToken.sol";

string constant T_TRANSFER = '"PqzTransferArgs":[{"name":"p","type":"uint64"},{"name":"validUntilBlock","type":"uint256"},{"name":"shieldIn","type":"uint256"},'
    '{"name":"fromUA","type":"bytes32"},{"name":"toUA","type":"bytes32"},{"name":"beneficiaryUA","type":"bytes32"},{"name":"salt","type":"bytes16"},'
    '{"name":"u","type":"bytes"},{"name":"vTo","type":"bytes"},{"name":"vFrom","type":"bytes"},{"name":"vAuditor","type":"bytes"},{"name":"sealedMemo","type":"bytes"}]';
string constant T_LEG = '"PqzLeg":[{"name":"ua","type":"bytes32"},{"name":"v","type":"bytes"},{"name":"vAuditor","type":"bytes"}]';
string constant T_MULTI = '"PqzMultiArgs":[{"name":"p","type":"uint64"},{"name":"validUntilBlock","type":"uint256"},{"name":"shieldIn","type":"uint256"},'
    '{"name":"fromUA","type":"bytes32"},{"name":"beneficiaryUA","type":"bytes32"},{"name":"decoyFee","type":"uint256"},{"name":"salt","type":"bytes16"},'
    '{"name":"u","type":"bytes[]"},{"name":"legs","type":"PqzLeg[]"},{"name":"vFrom","type":"bytes"},{"name":"sealedMemo","type":"bytes"}]';
string constant T_BURN = '"PqzBurnArgs":[{"name":"p","type":"uint64"},{"name":"validUntilBlock","type":"uint256"},{"name":"shieldIn","type":"uint256"},'
    '{"name":"fromUA","type":"bytes32"},{"name":"beneficiaryUA","type":"bytes32"},{"name":"u","type":"bytes"},{"name":"vFrom","type":"bytes"}]';
string constant T_UNWRAP = '"Unwrap":[{"name":"underlying","type":"address"},{"name":"recipient","type":"bytes32"},{"name":"amount","type":"uint256"},{"name":"minOut","type":"uint256"}]';

function transferJson(IPqzToken.PqzTransferArgs memory t) pure returns (string memory) {
    return string.concat(
        string.concat('{"p":', n(t.p), ',"validUntilBlock":', n(t.validUntilBlock), ',"shieldIn":', n(t.shieldIn), ',"fromUA":', h(t.fromUA),
            ',"toUA":', h(t.toUA), ',"beneficiaryUA":', h(t.beneficiaryUA), ',"salt":', hexJson(abi.encodePacked(t.salt))),
        string.concat(',"u":', hexJson(t.u), ',"vTo":', hexJson(t.vTo), ',"vFrom":', hexJson(t.vFrom), ',"vAuditor":', hexJson(t.vAuditor),
            ',"sealedMemo":', hexJson(t.sealedMemo), '}'));
}

function multiJson(IPqzToken.PqzMultiArgs memory t) pure returns (string memory) {
    string memory us;
    for (uint256 g; g < t.u.length; ++g) us = string.concat(us, g == 0 ? '' : ',', hexJson(t.u[g]));
    string memory legs;
    for (uint256 j; j < t.legs.length; ++j) {
        IPqzToken.PqzLeg memory l = t.legs[j];
        legs = string.concat(legs, j == 0 ? '' : ',', '{"ua":', h(l.ua), ',"v":', hexJson(l.v), ',"vAuditor":', hexJson(l.vAuditor), '}');
    }
    return string.concat(
        string.concat('{"p":', n(t.p), ',"validUntilBlock":', n(t.validUntilBlock), ',"shieldIn":', n(t.shieldIn), ',"fromUA":', h(t.fromUA),
            ',"beneficiaryUA":', h(t.beneficiaryUA), ',"decoyFee":', n(t.decoyFee), ',"salt":', hexJson(abi.encodePacked(t.salt))),
        string.concat(',"u":[', us, '],"legs":[', legs, '],"vFrom":', hexJson(t.vFrom), ',"sealedMemo":', hexJson(t.sealedMemo), '}'));
}

function burnJson(IPqzToken.PqzBurnArgs memory b) pure returns (string memory) {
    return string.concat('{"p":', n(b.p), ',"validUntilBlock":', n(b.validUntilBlock), ',"shieldIn":', n(b.shieldIn), ',"fromUA":', h(b.fromUA),
        ',"beneficiaryUA":', h(b.beneficiaryUA), ',"u":', hexJson(b.u), ',"vFrom":', hexJson(b.vFrom), '}');
}

/// typed-signing C4 (TS-D14, TS-D17, TS-D19): the explicit parameters are the packed bytes the token assembled before, in the
/// statement and in state; the authority is the typed `PqzAuth`; every signed PQZ entry takes a wallet's typed signature, on the
/// kept pipeline and the proof's envelope binding.
abstract contract PqzNamedBase is PqzFixture {
    uint256 internal constant PK = 0xA11CE;
    address internal signer = vm.addr(PK);
    address internal relayer = address(0xBEEF);
    uint256 internal constant LANE = 7;
    PqzPackedRef internal ref_;
    WrappedPqzToken internal w;
    MockERC20 internal usd;
    bytes32[8] internal more; // the legs after `bob`, `carol`

    function _named() internal {
        _stack();
        _mockOp(7, 1);
        for (uint256 j = 2; j < 8; ++j) more[j] = _pqzUA(_pk(uint8(60 + j)), uint8(60 + j));
        ref_ = new PqzPackedRef();
        tok = _newToken("typed");
        _releaseWrapped();
        w = _newWrapped("typedw");
        usd = MockERC20(w.underlying());
    }

    function _env(uint256 nonce) internal view returns (MetaTxLib.Envelope memory e) {
        e.from = signer;
        e.batch = LANE;
        e.nonce = nonce;
        e.validUntil = block.timestamp + 300;
    }

    function _uaEnv(uint256 nonce) internal view returns (MetaTxLib.UAEnvelope memory u) {
        u.from = MetaTxLib.pad(signer);
        u.batch = LANE;
        u.nonce = nonce;
        u.validUntil = block.timestamp + 300;
    }

    function _bindingOf(PqzLayer t, MetaTxLib.Envelope memory e) internal view returns (bytes32) {
        return t.envelopeBinding(MetaTxLib.MetaTransaction(e.from, "", e.batch, e.nonce, e.validUntil, e.mode, e.relayer, e.fee, e.feeRecipient));
    }

    function _uaBindingOf(PqzLayer t, MetaTxLib.UAEnvelope memory u) internal view returns (bytes32) {
        return t.uaEnvelopeBinding(MetaTxLib.UAMetaTransaction(u.from, "", u.batch, u.nonce, u.validUntil, u.mode, u.relayer, u.fee, u.feeRecipient));
    }

    function _msg(string memory op, uint256 nonce, bool ua, uint256 validUntil) internal view returns (string memory) {
        return string.concat('"from":', ua ? h(MetaTxLib.pad(signer)) : a(signer), ',', op, ',', eJson(LANE, nonce, validUntil, 0, 0));
    }

    function _uaSig(bytes memory sig) internal pure returns (IUARegistry.UASig memory s) {
        s.signature = sig;
    }

    function _from(bool ua) internal pure returns (string memory) {
        return ua ? '{"name":"from","type":"bytes32"}' : '{"name":"from","type":"address"}';
    }

    /// The fields and message of a confidential struct, `args` first, `extra` the op's own after it.
    function _argFields(bool ua, string memory arg, string memory extra) internal pure returns (string memory) {
        return string.concat(_from(ua), ',{"name":"args","type":"', arg, '"},', extra, '{"name":"proof","type":"bytes"},{"name":"accHint","type":"bytes"}');
    }

    function _argMsg(string memory args, string memory extra, bytes memory proof, bytes memory hint) internal pure returns (string memory) {
        return string.concat('"args":', args, ',', extra, '"proof":', hexJson(proof), ',"accHint":', hexJson(hint));
    }

    function _legsN(uint256 m) internal view returns (bytes32[] memory r) {
        r = new bytes32[](m);
        (r[0], r[m > 1 ? 1 : 0]) = (bob, m > 1 ? carol : bob);
        for (uint256 j = 2; j < m; ++j) r[j] = more[j];
    }

    function _entryRef(PqzLayer t, uint256 counter) internal view returns (bytes32) {
        return keccak256(abi.encode(PqzCore.TAG_ENTRY, block.chainid, PQZ_UID, address(t), alice, counter));
    }

    function _mPl(PqzLayer t, bytes32 from, bytes32[] memory rec, bool aud, bytes memory memo, uint256 seed) internal view returns (bytes memory) {
        return _mpayload(t.pqzAccount(from).pendingCount, 0, from, bytes32(0), rec, _blob(seed, _outLen(rec.length, aud)), memo);
    }

    function _sPl(PqzLayer t, bytes32 from, bool aud, bytes memory memo, uint256 seed) internal view returns (bytes memory) {
        return _payload(t.pqzAccount(from).pendingCount, 0, from, bob, bytes32(0), _out(seed, aud), memo);
    }

    function _bPl(PqzLayer t, bytes32 from, uint256 seed) internal view returns (bytes memory) {
        return bytes.concat(abi.encode(uint256(t.pqzAccount(from).pendingCount), block.number + 5, uint256(0), from, bytes32(0)), _blob(seed, PqzCt.CT));
    }

    function _mem(uint256 m) internal view returns (bytes memory) {
        return bytes.concat(salt, _slice(_blob(0x3e31, 352), 0, 2 + 40 * m));
    }

    /// `call` run on `t` with the reference etched over it: `t`'s state, `address(this) == t`.
    function _onRef(address t, bytes memory call) internal returns (bytes memory r) {
        bytes memory code = t.code;
        vm.etch(t, address(ref_).code);
        (bool ok, bytes memory ret) = t.staticcall(call);
        vm.etch(t, code);
        if (!ok) assembly ("memory-safe") { revert(add(ret, 32), mload(ret)) }
        r = abi.decode(ret, (bytes));
    }

    function _envAt(PqzLayer t, bytes32 binding, uint256 amount, bytes32 recipient, ZetherTypes.TransferMode m) internal view returns (PqzCore.Env memory) {
        return PqzCore.Env(address(reg), PQZ_UID, binding, amount, recipient, m, domainOf(address(t)));
    }

    function _wrapFund(bytes32 ua, uint256 amount) internal {
        usd.mint(address(this), amount * SCALE);
        usd.approve(address(w), amount * SCALE);
        w.mtxWrapShield(address(usd), amount * SCALE, ua);
        _mirrorTrivial(w, ua, amount);
    }
}

contract PqzAuthDigestTest is PqzNamedBase {
    function setUp() public {
        _named();
    }

    /// The word of a row's typehash in the code and in `typed_ops.json`, and the type string pinned by value.
    function test_pqzAuthTypehashPinned() public view {
        assertEq(PqzCore.AUTH_TYPEHASH, bytes32(0x380b0de633c2ea09a49e310934f44bd07cd4068117b4bc523553757742644e6f));
        assertEq(PqzCore.AUTH_TYPEHASH, VM.parseJsonBytes32(vm.readFile(TYPED_OPS), ".ops.PqzAuth.typehash"));
    }

    /// The row by its message: `op`, the 20 words, `bodyHash`: the struct hash and digest clientkeys pinned.
    function test_typedOpsVectors_PqzAuth() public view {
        string memory j = vm.readFile(TYPED_OPS);
        checkRow(j, "PqzAuth", "pqz");
        string memory m = ".ops.PqzAuth.message.";
        bytes memory words = bytes.concat(
            abi.encode(PqzCore.AUTH_TYPEHASH, uint8(VM.parseJsonUint(j, string.concat(m, "op"))), VM.parseJsonBytes32(j, string.concat(m, "opTag")),
                VM.parseJsonBytes32(j, string.concat(m, "psid")), VM.parseJsonUint(j, string.concat(m, "chainId")),
                VM.parseJsonAddress(j, string.concat(m, "token")), VM.parseJsonAddress(j, string.concat(m, "registry"))),
            abi.encode(VM.parseJsonBytes32(j, string.concat(m, "from")), VM.parseJsonBytes32(j, string.concat(m, "to")),
                VM.parseJsonBytes32(j, string.concat(m, "beneficiary")), VM.parseJsonUint(j, string.concat(m, "fee")),
                VM.parseJsonUint(j, string.concat(m, "amount")), VM.parseJsonBytes32(j, string.concat(m, "recipient"))),
            abi.encode(VM.parseJsonUint(j, string.concat(m, "sendCounter")), VM.parseJsonUint(j, string.concat(m, "p")),
                VM.parseJsonUint(j, string.concat(m, "validUntilBlock")), VM.parseJsonBool(j, string.concat(m, "auditorOn")),
                VM.parseJsonUint(j, string.concat(m, "shieldIn")), VM.parseJsonBytes32(j, string.concat(m, "chainUid"))),
            abi.encode(VM.parseJsonBytes32(j, string.concat(m, "binding")), VM.parseJsonUint(j, string.concat(m, "salt")),
                VM.parseJsonBytes32(j, string.concat(m, "memoHash")), VM.parseJsonBytes32(j, string.concat(m, "bodyHash")))
        );
        assertEq(keccak256(words), VM.parseJsonBytes32(j, ".ops.PqzAuth.structHash"));
    }

    /// A statement row's own domain, from its header words: `chainId`, `token`, `chainUid` (the salt).
    function _rowDomain(bytes memory st) internal pure returns (bytes32) {
        return keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)"),
            keccak256("SCaaS PqzToken"), keccak256("1"), uint256(_word(st, 64)), address(uint160(uint256(_word(st, 96)))), _word(st, 512)));
    }

    function _withId(bytes memory st, bytes32 id) internal pure returns (bytes memory) {
        bytes memory c = bytes.concat(st);
        assembly ("memory-safe") { mstore(add(c, 64), id) }
        return c;
    }

    /// One row, in a frame of its own (a statement file of megabytes costs quadratic memory in one frame); false: no such row.
    /// A row without a PQZL digest fails here, it does not end the file.
    function checkRowDigest(string memory file, uint256 i) external view returns (bool) {
        string memory j = vm.readFile(string.concat(_vecDir(), file));
        string memory r = string.concat(".rows[", vm.toString(i), "]");
        if (!vm.keyExistsJson(j, r)) return false;
        assertTrue(vm.keyExistsJson(j, string.concat(r, ".auth_digest.pqzl")), string.concat(file, r, ": no digest"));
        bytes memory st = vm.parseBytes(string.concat("0x", VM.parseJsonString(j, string.concat(r, ".stmt"))));
        uint8 op = uint8(VM.parseJsonUint(j, string.concat(r, ".op")));
        for (uint256 k; k < 2; ++k) {
            string memory id = k == 0 ? "pqzl" : "pqzh";
            string memory key = string.concat(r, ".auth_digest.", id);
            if (!vm.keyExistsJson(j, key)) continue;
            bytes memory s = _withId(st, k == 0 ? PqzSet.PQZL_ID : PqzSet.PQZH_ID);
            assertEq(ref_.digest(op, s, _rowDomain(s)), vm.parseBytes32(string.concat("0x", VM.parseJsonString(j, key))), string.concat(file, r, " ", id));
        }
        return true;
    }

    /// Every debit statement of the set, the row count pinned: the vector's `auth_digest` (`pqz-vectors`, re-derived by
    /// `pqz_kat.py`) per proof system is `PqzCore.authDigest`. A register or disclosure statement authorises nothing, so it has none.
    function test_pqzAuthDigestVectors() public view {
        string[5] memory files = ["statement_transfer.json", "statement_burn.json", "statement_refresh.json", "statement_transfer_multi.json", "fee0.json"];
        uint8[5] memory rows = [2, 1, 1, 11, 4];
        for (uint256 f; f < 5; ++f) {
            uint256 i;
            while (this.checkRowDigest(files[f], i)) ++i;
            assertEq(i, rows[f], files[f]);
        }
    }

    /// The token's digest is the wallet's: what a wallet computes from the statement's fields as `eth_signTypedData_v4` JSON
    /// reaches the registry as the `requireAuthorized` digest, purpose `zether-auth`, under the token's domain.
    function test_pqzAuthWalletDigest() public {
        _fund(tok, alice, 100);
        bytes memory pl = _sPl(tok, alice, true, "", 1);
        bytes memory st = tok.transferSingleStatement(_ts(pl), 0);
        bytes32 d = VM.eip712HashTypedData(string.concat(
            '{"types":{"EIP712Domain":[{"name":"name","type":"string"},{"name":"version","type":"string"},{"name":"chainId","type":"uint256"},',
            '{"name":"verifyingContract","type":"address"},{"name":"salt","type":"bytes32"}],"PqzAuth":[',
            string.concat('{"name":"op","type":"uint8"},{"name":"opTag","type":"bytes32"},{"name":"psid","type":"bytes32"},{"name":"chainId","type":"uint256"},',
                '{"name":"token","type":"address"},{"name":"registry","type":"address"},{"name":"from","type":"bytes32"},{"name":"to","type":"bytes32"},',
                '{"name":"beneficiary","type":"bytes32"},{"name":"fee","type":"uint256"},{"name":"amount","type":"uint256"},{"name":"recipient","type":"bytes32"},'),
            string.concat('{"name":"sendCounter","type":"uint64"},{"name":"p","type":"uint64"},{"name":"validUntilBlock","type":"uint256"},{"name":"auditorOn","type":"bool"},',
                '{"name":"shieldIn","type":"uint256"},{"name":"chainUid","type":"bytes32"},{"name":"binding","type":"bytes32"},{"name":"salt","type":"uint128"},',
                '{"name":"memoHash","type":"bytes32"},{"name":"bodyHash","type":"bytes32"}'),
            ']},"primaryType":"PqzAuth","domain":', _domainJson(), ',"message":', _authJson(st), '}'
        ));
        assertEq(d, ref_.digest(1, st, domainOf(address(tok))), "the code's digest of the statement");
        vm.expectCall(address(reg), abi.encodeCall(IUARegistry.requireAuthorized, (alice, UAKinds.PURPOSE_ZETHER_AUTH, d, _pqAuth())));
        tok.mtxConfidentialTransferSingle(_ts(pl), hex"c0de", _pqAuth(), "");
    }

    function _domainJson() internal view returns (string memory) {
        return string.concat('{"name":"SCaaS PqzToken","version":"1","chainId":', n(block.chainid), ',"verifyingContract":', a(address(tok)),
            ',"salt":', h(PQZ_UID), '}');
    }

    function _authJson(bytes memory st) internal pure returns (string memory) {
        return string.concat(
            string.concat('{"op":1,"opTag":', h(_word(st, 0)), ',"psid":', h(_word(st, 32)), ',"chainId":', n(uint256(_word(st, 64))),
                ',"token":', a(address(uint160(uint256(_word(st, 96))))), ',"registry":', a(address(uint160(uint256(_word(st, 128))))),
                ',"from":', h(_word(st, 160)), ',"to":', h(_word(st, 192)), ',"beneficiary":', h(_word(st, 224))),
            string.concat(',"fee":', n(uint256(_word(st, 256))), ',"amount":', n(uint256(_word(st, 288))), ',"recipient":', h(_word(st, 320)),
                ',"sendCounter":', n(uint256(_word(st, 352))), ',"p":', n(uint256(_word(st, 384))), ',"validUntilBlock":', n(uint256(_word(st, 416)))),
            string.concat(',"auditorOn":', uint256(_word(st, 448)) == 1 ? 'true' : 'false', ',"shieldIn":', n(uint256(_word(st, 480))),
                ',"chainUid":', h(_word(st, 512)), ',"binding":', h(_word(st, 544)), ',"salt":', n(uint256(_word(st, 576))),
                ',"memoHash":', h(_word(st, 608)), ',"bodyHash":', h(keccak256(_slice(st, 640, st.length - 640))), '}'));
    }

    /// A signature over the old digest `keccak256("SCAAS-PQZ-AUTH-V1" ‖ keccak256(stmt))` is another digest now.
    function test_pqzAuthDigestIsNotTheOldDigest() public {
        _fund(tok, alice, 100);
        bytes memory st = tok.transferSingleStatement(_ts(_sPl(tok, alice, true, "", 2)), 0);
        assertTrue(ref_.digest(1, st, domainOf(address(tok))) != keccak256(abi.encodePacked("SCAAS-PQZ-AUTH-V1", keccak256(st))));
    }
}

/// The token's statement from the explicit parameters against the packed reference on the same state (`PqzPackedRef`).
contract PqzExplicitStatementTest is PqzNamedBase {
    function setUp() public {
        _named();
        _fund(tok, alice, 1000);
    }

    function _checkSingle(PqzLayer t, bool aud, bool hash, bytes32 binding) internal {
        bytes memory pl = _sPl(t, alice, aud, hash ? _memo() : bytes(""), 11);
        ZetherTypes.TransferMode m = hash ? ZetherTypes.TransferMode.HASH : ZetherTypes.TransferMode.BUNDLE;
        assertEq(t.transferSingleStatement(_ts(pl), binding),
            _onRef(address(t), abi.encodeCall(PqzPackedRef.single, (_envAt(t, binding, 0, 0, m), pl))), "op 1");
    }

    function _checkMulti(PqzLayer t, uint256 m, bool aud, bool hash, bytes32 binding) internal {
        bytes memory pl = _mPl(t, alice, _legsN(m), aud, hash ? _mem(m) : bytes(""), 12 + m);
        ZetherTypes.TransferMode md = hash ? ZetherTypes.TransferMode.HASH : ZetherTypes.TransferMode.BUNDLE;
        assertEq(t.transferStatement(_ms(pl), binding),
            _onRef(address(t), abi.encodeCall(PqzPackedRef.multi, (_envAt(t, binding, 0, 0, md), pl))), "op 7");
    }

    /// `mtxConfidentialTransferSingle`: op 1, auditor on and off, direct and relayed binding.
    function test_pqzExplicitStatementBytes_single() public {
        _checkSingle(tok, true, false, 0);
        _checkSingle(tok, false, false, 0);
        _checkSingle(tok, true, false, keccak256("envelope"));
    }

    /// `…SingleCompact`: the memo's hash from `salt ‖ sealedMemo`.
    function test_pqzExplicitStatementBytes_singleCompact() public {
        _checkSingle(tok, true, true, 0);
        _checkSingle(tok, false, true, keccak256("envelope"));
    }

    /// `mtxConfidentialTransfer`, M = 1 in the token's default form, every field set.
    function test_pqzExplicitStatementBytes_transfer() public {
        _public(tok, address(this), 7 * SCALE);
        bytes memory pl = _mpayload(1, 7, alice, carol, _legsN(1), _blob(9, _outLen(1, true)), "");
        assertEq(tok.transferStatement(_ms(pl), 0),
            _onRef(address(tok), abi.encodeCall(PqzPackedRef.multi, (_envAt(tok, 0, 0, 0, ZetherTypes.TransferMode.BUNDLE), pl))));
    }

    /// `…Compact`: op 7 commit-reveal.
    function test_pqzExplicitStatementBytes_compact() public {
        _checkMulti(tok, 2, true, true, 0);
        _checkMulti(tok, 2, false, true, keccak256("envelope"));
    }

    /// Op 7 at every built `M`, auditor on and off, both stored forms.
    function test_pqzExplicitStatementBytes_op7() public {
        for (uint256 i; i < 4; ++i) {
            for (uint256 k; k < 4; ++k) _checkMulti(tok, 1 << i, k & 1 == 0, k & 2 == 0, bytes32(k));
        }
    }

    function test_pqzExplicitStatementBytes_burn() public {
        bytes memory pl = _bPl(tok, alice, 13);
        bytes32 to = MetaTxLib.pad(address(0xD00D));
        assertEq(tok.burnStatement(_bs(pl), 7, to, 0), _onRef(address(tok), abi.encodeCall(PqzPackedRef.burn, (_envAt(tok, 0, 7, to, ZetherTypes.TransferMode.BUNDLE), pl))));
        assertEq(tok.burnStatement(_bs(pl), 0, 0, keccak256("b")),
            _onRef(address(tok), abi.encodeCall(PqzPackedRef.burn, (_envAt(tok, keccak256("b"), 0, 0, ZetherTypes.TransferMode.BUNDLE), pl))), "refresh");
    }

    /// The burn the unwrap debits: the leg and `minOut` in the binding word, the amount and recipient in the header.
    function test_pqzExplicitStatementBytes_unshieldUnwrap() public {
        _wrapFund(alice, 100);
        bytes memory pl = _bPl(w, alice, 14);
        IConfidentialWrappedToken.Unwrap memory x = IConfidentialWrappedToken.Unwrap(address(usd), MetaTxLib.pad(address(0xD00D)), 40, 40 * SCALE);
        bytes32 word = w.unwrapBinding(address(usd), x.minOut);
        assertEq(w.unshieldUnwrapStatement(_bs(pl), x, 0),
            _onRef(address(w), abi.encodeCall(PqzPackedRef.burn, (_envAt(w, word, 40, x.recipient, ZetherTypes.TransferMode.BUNDLE), pl))));
        bytes32 b = keccak256("envelope");
        assertEq(w.unshieldUnwrapStatement(_bs(pl), x, b),
            _onRef(address(w), abi.encodeCall(PqzPackedRef.burn, (_envAt(w, keccak256(abi.encode(b, word)), 40, x.recipient, ZetherTypes.TransferMode.BUNDLE), pl))));
    }

    /// Never lose ciphertext: what a debit leaves in state from the explicit parts is what the packed form stored: the op
    /// blob byte for byte (op 1, op 7, auditor on and off, both forms), the memo, the pending ciphertexts, a burn's `acc`.
    function test_pqzStoredCiphertextUnchanged() public {
        bytes memory pl = _sPl(tok, alice, true, "", 21);
        bytes memory blob = ref_.blobSingle(pl, false);
        bytes32 ref = tok.mtxConfidentialTransferSingle(_ts(pl), hex"01", _pqAuth(), "");
        assertEq(tok.pqzEntryBlob(ref), blob, "op 1 BUNDLE auditor");
        assertEq(tok.pqzPendingCt(bob, tok.pqzAccount(bob).pendingCount - 1), _cut(_ct(pl, T_OUT), 0, PqzCt.CT), "the credit is u || v_t");
        assertEq(tok.pqzAcc(alice), bytes.concat(_cut(pl, T_OUT, PqzCt.PK), _cut(pl, T_OUT + PqzCt.CT, PqzCt.V)), "acc is u || v_f");

        pl = _sPl(tok, alice, false, _memo(), 22);
        blob = ref_.blobSingle(pl, true);
        ref = tok.mtxConfidentialTransferSingleCompact(_ts(pl), hex"01", _pqAuth(), "");
        assertEq(tok.pqzEntryBlob(ref), blob, "op 1 HASH");
        bytes memory r = _slice(blob, 0, blob.length - PqzCt.VP);
        assertEq(tok.transferEntry(ref), bytes.concat(keccak256(r), _memo()), "hash || memo");

        for (uint256 k; k < 4; ++k) {
            uint256 m = k < 2 ? 2 : 8;
            (bool aud, bool hash) = (k & 1 == 0, k >= 2);
            pl = _mPl(tok, alice, _legsN(m), aud, hash ? _mem(m) : bytes(""), 30 + k);
            blob = ref_.blobMulti(pl, hash);
            ref = hash ? tok.mtxConfidentialTransferCompact(_ms(pl), hex"01", _pqAuth(), "") : tok.mtxConfidentialTransfer(_ms(pl), hex"01", _pqAuth(), "");
            assertEq(tok.pqzEntryBlob(ref), blob, "op 7");
            if (hash) assertEq(_cut(tok.transferEntry(ref), 32, 18 + 40 * m), _mem(m), "the memo");
        }

        pl = _bPl(tok, alice, 40);
        tok.mtxUnshield(_bs(pl), 0, bytes32(0), hex"01", _pqAuth(), "");
        assertEq(tok.pqzAcc(alice), _cut(pl, B_OUT, PqzCt.CT), "a burn's u' || v_f");
    }

    function _ct(bytes memory pl, uint256 off) internal pure returns (bytes memory) {
        return _slice(pl, off, PqzCt.CT);
    }
}

/// Every signed PQZ entry, its `ua*` twin and the kept op: the wallet's digest of the JSON it is handed, the proof's envelope
/// binding in the statement, the lane's nonce, the replay.
contract PqzNamedTest is PqzNamedBase {
    function setUp() public {
        _named();
        _fund(tok, alice, 1000);
        _public(tok, signer, 100 * SCALE);
    }

    function _name(bool ua, string memory base) internal pure returns (string memory) {
        return ua ? string.concat("UA", base) : base;
    }

    // ------------------------------------------------------------------ op 1

    function _singleSig(bool ua, string memory base, uint256 nonce, uint256 until, IPqzToken.PqzTransferArgs memory t, bytes memory proof, bytes memory hint)
        internal view returns (bytes memory)
    {
        string memory m = _msg(_argMsg(transferJson(t), "", proof, hint), nonce, ua, until);
        return ecdsa(PK, typedDigest(address(tok), _name(ua, base), _argFields(ua, "PqzTransferArgs", ""), string.concat(',', T_TRANSFER), m));
    }

    function _runSingle(bool compact, bool ua) internal {
        IPqzToken.PqzTransferArgs memory t = _ts(_sPl(tok, alice, true, compact ? _memo() : bytes(""), 50));
        (bytes memory proof, bytes memory hint) = (hex"c0de", hex"");
        string memory base = compact ? "PqzTransferSingleCompact" : "PqzTransferSingle";
        MetaTxLib.Envelope memory e = _env(0);
        MetaTxLib.UAEnvelope memory u = _uaEnv(0);
        bytes memory sig = _singleSig(ua, base, 0, e.validUntil, t, proof, hint);
        bytes memory st = tok.transferSingleStatement(t, ua ? _uaBindingOf(tok, u) : _bindingOf(tok, e));
        vm.expectCall(PQZ, abi.encodePacked(uint8(1), uint32(st.length), st, proof));
        vm.prank(relayer);
        bytes32 ref;
        if (ua) ref = compact ? tok.uaConfidentialTransferSingleCompact(u, t, proof, _pqAuth(), hint, _uaSig(sig))
            : tok.uaConfidentialTransferSingle(u, t, proof, _pqAuth(), hint, _uaSig(sig));
        else ref = compact ? tok.mtxConfidentialTransferSingleCompact(e, t, proof, _pqAuth(), hint, sig)
            : tok.mtxConfidentialTransferSingle(e, t, proof, _pqAuth(), hint, sig);
        assertEq(ref, _entryRef(tok, 0), "the entry's reference");
        assertEq(tok.pqzAccount(alice).sendCounter, 1);
        assertEq(ua ? tok.uaNonce(u.from, LANE) : tok.mtxNonce(signer, LANE), 1);
        // the replay
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 1, 0));
        _callSingle(compact, ua, e, u, t, proof, hint, sig);
        _bindsSingle(compact, ua, t, proof, hint);
    }

    function _callSingle(bool compact, bool ua, MetaTxLib.Envelope memory e, MetaTxLib.UAEnvelope memory u, IPqzToken.PqzTransferArgs memory t,
        bytes memory proof, bytes memory hint, bytes memory sig) internal
    {
        if (ua) {
            if (compact) tok.uaConfidentialTransferSingleCompact(u, t, proof, _pqAuth(), hint, _uaSig(sig));
            else tok.uaConfidentialTransferSingle(u, t, proof, _pqAuth(), hint, _uaSig(sig));
        } else {
            if (compact) tok.mtxConfidentialTransferSingleCompact(e, t, proof, _pqAuth(), hint, sig);
            else tok.mtxConfidentialTransferSingle(e, t, proof, _pqAuth(), hint, sig);
        }
    }

    /// Signed at the lane's next nonce over `t`: one field changed fails the signature and nothing else, the nonce unused;
    /// the unchanged call then passes, so the refusals were the field's.
    function _bindsSingle(bool compact, bool ua, IPqzToken.PqzTransferArgs memory t, bytes memory proof, bytes memory hint) internal {
        MetaTxLib.Envelope memory e = _env(1);
        MetaTxLib.UAEnvelope memory u = _uaEnv(1);
        bytes memory sig = _singleSig(ua, compact ? "PqzTransferSingleCompact" : "PqzTransferSingle", 1, e.validUntil, t, proof, hint);
        bytes16 s0 = t.salt;
        t.salt = bytes16(uint128(s0) ^ 1);
        vm.prank(relayer);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        _callSingle(compact, ua, e, u, t, proof, hint, sig);
        t.salt = s0;
        vm.prank(relayer);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        _callSingle(compact, ua, e, u, t, proof, bytes.concat(hint, hex"01"), sig);
        t.vTo[7] ^= 0x01;
        vm.prank(relayer);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        _callSingle(compact, ua, e, u, t, proof, hint, sig);
        t.vTo[7] ^= 0x01;
        vm.prank(relayer);
        _callSingle(compact, ua, e, u, t, proof, hint, sig);
        assertEq(ua ? tok.uaNonce(u.from, LANE) : tok.mtxNonce(signer, LANE), 2, "only the unchanged call used the nonce");
    }

    function test_pqzNamedTransferSingle() public { _runSingle(false, false); }
    function test_pqzNamedTransferSingleUA() public { _runSingle(false, true); }
    function test_pqzNamedTransferSingleCompact() public { _runSingle(true, false); }
    function test_pqzNamedTransferSingleCompactUA() public { _runSingle(true, true); }

    // ------------------------------------------------------------------ op 7

    function _multiSig(bool ua, string memory base, uint256 nonce, uint256 until, IPqzToken.PqzMultiArgs memory t, bytes memory proof, bytes memory hint)
        internal view returns (bytes memory)
    {
        string memory m = _msg(_argMsg(multiJson(t), "", proof, hint), nonce, ua, until);
        return ecdsa(PK, typedDigest(address(tok), _name(ua, base), _argFields(ua, "PqzMultiArgs", ""), string.concat(',', T_LEG, ',', T_MULTI), m));
    }

    function _runMulti(bool compact, bool ua) internal {
        bytes32[] memory rec = _legsN(4);
        IPqzToken.PqzMultiArgs memory t = _ms(_mPl(tok, alice, rec, true, compact ? _mem(4) : bytes(""), 51));
        bytes memory proof = hex"c0de";
        MetaTxLib.Envelope memory e = _env(0);
        MetaTxLib.UAEnvelope memory u = _uaEnv(0);
        bytes memory sig = _multiSig(ua, compact ? "PqzTransferCompact" : "PqzTransfer", 0, e.validUntil, t, proof, "");
        bytes memory st = tok.transferStatement(t, ua ? _uaBindingOf(tok, u) : _bindingOf(tok, e));
        vm.expectCall(PQZ, abi.encodePacked(uint8(7), uint32(st.length), st, proof));
        vm.prank(relayer);
        bytes32 ref;
        if (ua) ref = compact ? tok.uaConfidentialTransferCompact(u, t, proof, _pqAuth(), "", _uaSig(sig))
            : tok.uaConfidentialTransfer(u, t, proof, _pqAuth(), "", _uaSig(sig));
        else ref = compact ? tok.mtxConfidentialTransferCompact(e, t, proof, _pqAuth(), "", sig)
            : tok.mtxConfidentialTransfer(e, t, proof, _pqAuth(), "", sig);
        assertEq(ref, _entryRef(tok, 0));
        for (uint256 j; j < 4; ++j) assertEq(tok.pqzAccount(rec[j]).pendingCount, 1, "a credit per leg");
        assertEq(ua ? tok.uaNonce(u.from, LANE) : tok.mtxNonce(signer, LANE), 1);
        _bindsMulti(compact, ua, t, proof);
    }

    function _callMulti(bool compact, bool ua, IPqzToken.PqzMultiArgs memory t, bytes memory proof, bytes memory hint, bytes memory sig) internal {
        if (ua) {
            if (compact) tok.uaConfidentialTransferCompact(_uaEnv(1), t, proof, _pqAuth(), hint, _uaSig(sig));
            else tok.uaConfidentialTransfer(_uaEnv(1), t, proof, _pqAuth(), hint, _uaSig(sig));
        } else {
            if (compact) tok.mtxConfidentialTransferCompact(_env(1), t, proof, _pqAuth(), hint, sig);
            else tok.mtxConfidentialTransfer(_env(1), t, proof, _pqAuth(), hint, sig);
        }
    }

    /// As `_bindsSingle`: the salt, the hint, a leg's `v`.
    function _bindsMulti(bool compact, bool ua, IPqzToken.PqzMultiArgs memory t, bytes memory proof) internal {
        bytes memory sig = _multiSig(ua, compact ? "PqzTransferCompact" : "PqzTransfer", 1, block.timestamp + 300, t, proof, "");
        bytes16 s0 = t.salt;
        t.salt = bytes16(uint128(s0) ^ 1);
        vm.prank(relayer);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        _callMulti(compact, ua, t, proof, "", sig);
        t.salt = s0;
        vm.prank(relayer);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        _callMulti(compact, ua, t, proof, hex"01", sig);
        t.legs[2].v[7] ^= 0x01;
        vm.prank(relayer);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        _callMulti(compact, ua, t, proof, "", sig);
        t.legs[2].v[7] ^= 0x01;
        vm.prank(relayer);
        _callMulti(compact, ua, t, proof, "", sig);
        assertEq(ua ? tok.uaNonce(MetaTxLib.pad(signer), LANE) : tok.mtxNonce(signer, LANE), 2, "only the unchanged call used the nonce");
    }

    function test_pqzNamedTransfer() public { _runMulti(false, false); }
    function test_pqzNamedTransferUA() public { _runMulti(false, true); }
    function test_pqzNamedTransferCompact() public { _runMulti(true, false); }
    function test_pqzNamedTransferCompactUA() public { _runMulti(true, true); }

    // ------------------------------------------------------------------ burn

    function _unshieldSig(bool ua, uint256 until, IPqzToken.PqzBurnArgs memory b, IPqzToken.Payout memory p, bytes memory proof)
        internal view returns (bytes memory)
    {
        string memory m = _msg(_argMsg(burnJson(b), string.concat('"amount":', n(p.amount), ',"recipient":', h(p.recipient), ','), proof, ""), 0, ua, until);
        return ecdsa(PK, typedDigest(address(tok), _name(ua, "PqzUnshield"),
            _argFields(ua, "PqzBurnArgs", '{"name":"amount","type":"uint256"},{"name":"recipient","type":"bytes32"},'), string.concat(',', T_BURN), m));
    }

    function _runUnshield(bool ua) internal {
        IPqzToken.PqzBurnArgs memory b = _bs(_bPl(tok, alice, 52));
        IPqzToken.Payout memory p = IPqzToken.Payout(5, MetaTxLib.pad(address(0xD00D)));
        bytes memory proof = hex"c0de";
        MetaTxLib.Envelope memory e = _env(0);
        MetaTxLib.UAEnvelope memory u = _uaEnv(0);
        bytes memory sig = _unshieldSig(ua, e.validUntil, b, p, proof);
        bytes memory st = tok.burnStatement(b, p.amount, p.recipient, ua ? _uaBindingOf(tok, u) : _bindingOf(tok, e));
        vm.expectCall(PQZ, abi.encodePacked(uint8(2), uint32(st.length), st, proof));
        vm.prank(relayer);
        if (ua) tok.uaUnshield(u, b, p, proof, _pqAuth(), "", _uaSig(sig));
        else tok.mtxUnshield(e, b, p, proof, _pqAuth(), "", sig);
        assertEq(tok.balanceOf(address(0xD00D)), 5 * SCALE, "the amount reached the recipient");
    }

    function test_pqzNamedUnshield() public { _runUnshield(false); }
    function test_pqzNamedUnshieldUA() public { _runUnshield(true); }

    // ------------------------------------------------------------------ unshield-unwrap

    function _unwrapSig(bool ua, uint256 until, IPqzToken.PqzBurnArgs memory b, IConfidentialWrappedToken.Unwrap memory x, bytes memory proof)
        internal view returns (bytes memory)
    {
        string memory xj = string.concat('"unwrap":{"underlying":', a(x.underlying), ',"recipient":', h(x.recipient), ',"amount":', n(x.amount), ',"minOut":', n(x.minOut), '},');
        string memory m = _msg(_argMsg(burnJson(b), xj, proof, ""), 0, ua, until);
        return ecdsa(PK, typedDigest(address(w), _name(ua, "PqzUnshieldUnwrap"), _argFields(ua, "PqzBurnArgs", '{"name":"unwrap","type":"Unwrap"},'),
            string.concat(',', T_BURN, ',', T_UNWRAP), m));
    }

    function _runUnwrap(bool ua) internal {
        _wrapFund(alice, 100);
        IPqzToken.PqzBurnArgs memory b = _bs(_bPl(w, alice, 53));
        IConfidentialWrappedToken.Unwrap memory x = IConfidentialWrappedToken.Unwrap(address(usd), MetaTxLib.pad(address(0xD00D)), 40, 40 * SCALE);
        bytes memory proof = hex"c0de";
        MetaTxLib.Envelope memory e = _env(0);
        MetaTxLib.UAEnvelope memory u = _uaEnv(0);
        bytes memory sig = _unwrapSig(ua, e.validUntil, b, x, proof);
        bytes memory st = w.unshieldUnwrapStatement(b, x, ua ? _uaBindingOf(w, u) : _bindingOf(w, e));
        vm.expectCall(PQZ, abi.encodePacked(uint8(2), uint32(st.length), st, proof));
        vm.prank(relayer);
        if (ua) w.uaUnshieldUnwrap(u, b, x, proof, _pqAuth(), "", _uaSig(sig));
        else w.mtxUnshieldUnwrap(e, b, x, proof, _pqAuth(), "", sig);
        assertEq(usd.balanceOf(address(0xD00D)), 40 * SCALE, "the leg paid");
    }

    function test_pqzNamedUnshieldUnwrap() public { _runUnwrap(false); }
    function test_pqzNamedUnshieldUnwrapUA() public { _runUnwrap(true); }

    // ------------------------------------------------------------------ the static ops

    function test_pqzNamedWrapShield() public {
        usd.mint(signer, 10 * SCALE);
        vm.prank(signer);
        usd.approve(address(w), 10 * SCALE);
        MetaTxLib.Envelope memory e = _env(0);
        bytes memory sig = ecdsa(PK, typedDigest(address(w), "WrapShield",
            '{"name":"from","type":"address"},{"name":"underlying","type":"address"},{"name":"amountIn","type":"uint256"},{"name":"toUA","type":"bytes32"}', '',
            _msg(string.concat('"underlying":', a(address(usd)), ',"amountIn":', n(10 * SCALE), ',"toUA":', h(alice)), 0, false, e.validUntil)));
        vm.prank(relayer);
        w.mtxWrapShield(e, address(usd), 10 * SCALE, alice, sig);
        assertEq((w.pqzPending(alice, 0) >> 96) & type(uint64).max, 10);
    }

    function _statics(bool ua, string memory base, string memory field, bytes32 x, uint256 v) internal view returns (bytes memory) {
        return ecdsa(PK, typedDigest(address(tok), _name(ua, base),
            string.concat(_from(ua), ',{"name":"ua","type":"bytes32"},{"name":"', field, '","type":"uint256"}'), '',
            _msg(string.concat('"ua":', h(x), ',"', field, '":', n(v)), 0, ua, block.timestamp + 300)));
    }

    function _prepareRow(bool ua) internal {
        bytes memory sig = _statics(ua, "PrepareAcc", "half", bob, 0);
        vm.prank(relayer);
        if (ua) tok.uaPrepareAcc(_uaEnv(0), bob, 0, _uaSig(sig));
        else tok.mtxPrepareAcc(_env(0), bob, 0, sig);
        assertEq(tok.pqzAccount(bob).flags, 2);
    }

    function test_pqzNamedPrepareAcc() public { _prepareRow(false); }
    function test_pqzNamedPrepareAccUA() public { _prepareRow(true); }

    function _rollRow(bool ua) internal {
        _prepare(tok, alice);
        vm.roll(block.number + ROLL_AGE);
        bytes memory sig = _statics(ua, "RollOver", "n", alice, 1);
        vm.prank(relayer);
        if (ua) tok.uaRollOver(_uaEnv(0), alice, 1, _uaSig(sig));
        else tok.mtxRollOver(_env(0), alice, 1, sig);
        assertEq(tok.pqzAccount(alice).rolled, 1);
    }

    function test_pqzNamedRollOver() public { _rollRow(false); }
    function test_pqzNamedRollOverUA() public { _rollRow(true); }

    /// A named entry is no allowlisted op (TS-D14): its selector inside a validly signed `mtxExecute` or `uaExecute` is refused at
    /// the gate of each path, `MtxSelectorNotAllowed` and `MetaTxUnknownOp`.
    function _refused(PqzLayer t, string memory j, string memory op) internal {
        bytes4 sel = bytes4(VM.parseJsonBytes(j, domainField(op, "pqz", "selector")));
        bytes memory data = bytes.concat(sel, new bytes(64));
        MetaTxLib.MetaTransaction memory m = MetaTxLib.MetaTransaction(signer, data, LANE, 0, block.timestamp + 300, 0, address(0), 0, address(0));
        bytes memory sig = ecdsa(PK, t.mtxDigest(m));
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MtxSelectorNotAllowed.selector, sel));
        t.mtxExecute(m, sig);
        MetaTxLib.UAMetaTransaction memory u = MetaTxLib.UAMetaTransaction(MetaTxLib.pad(signer), data, LANE, 0, block.timestamp + 300, 0, address(0), 0, address(0));
        sig = ecdsa(PK, t.uaDigest(u));
        vm.expectRevert(abi.encodeWithSelector(IUALedger.MetaTxUnknownOp.selector, sel));
        t.uaExecute(u, sig);
    }

    function test_pqzNamedEntryNotAllowlisted() public {
        string memory j = vm.readFile(TYPED_OPS);
        string[9] memory ops = ["PqzTransferSingle", "PqzTransferSingleCompact", "PqzTransfer", "PqzTransferCompact", "PqzUnshield", "Shield", "RollOver",
            "PrepareAcc", "WrapShield"];
        for (uint256 i; i < ops.length; ++i) {
            _refused(w, j, ops[i]);
            if (i != 8) _refused(tok, j, ops[i]);
            if (i != 8) _refused(w, j, string.concat("UA", ops[i]));
        }
        _refused(w, j, "PqzUnshieldUnwrap");
        _refused(w, j, "UAPqzUnshieldUnwrap");
    }

    // ------------------------------------------------------------------ an outer fee

    function _runFee(bool ua) internal {
        IPqzToken.PqzTransferArgs memory t = _ts(_sPl(tok, alice, true, "", 54));
        bytes memory proof = hex"c0de";
        MetaTxLib.Envelope memory e = _env(0);
        MetaTxLib.UAEnvelope memory u = _uaEnv(0);
        (e.mode, e.fee, u.mode, u.fee) = (MetaTxLib.MODE_FEE_FIXED, 7, MetaTxLib.MODE_FEE_FIXED, 7);
        string memory m = string.concat('"from":', ua ? h(u.from) : a(signer), ',', _argMsg(transferJson(t), "", proof, ""), ',',
            eJson(LANE, 0, e.validUntil, e.mode, e.fee));
        bytes memory sig = ecdsa(PK, typedDigest(address(tok), _name(ua, "PqzTransferSingle"), _argFields(ua, "PqzTransferArgs", ""), string.concat(',', T_TRANSFER), m));
        uint256 before = tok.balanceOf(signer);
        vm.prank(relayer);
        _callSingle(false, ua, e, u, t, proof, "", sig);
        assertEq(tok.pqzAccount(alice).sendCounter, 1, "the op ran");
        assertEq(tok.balanceOf(relayer), 7, "the relayer's fee");
        assertEq(tok.balanceOf(signer), before - 7, "paid by the signer");
    }

    function test_pqzNamedFeePaid() public { _runFee(false); }
    function test_pqzNamedFeePaidUA() public { _runFee(true); }
}

/// The one packed length check became a check per part (Appendix X.1): each part at each wrong length is `BadPayload` of that
/// length, the unchanged struct passes, and what the ABI decoder refuses is refused on the raw calldata.
contract PqzPartLengthsTest is PqzNamedBase {
    function setUp() public {
        _named();
        _fund(tok, alice, 1000);
    }

    function _bad(uint256 want) internal pure returns (uint256[4] memory) {
        return [0, want - 32, want + 32, want + 1];
    }

    function _badAud() internal pure returns (uint256[4] memory) {
        return [32, PqzCt.V - 32, PqzCt.V + 32, PqzCt.V + 1];
    }

    function _nonEmpty(uint256 want) internal pure returns (uint256[4] memory) {
        return [1, 41, 42, want];
    }

    function _expect(uint256 len) internal {
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.BadPayload.selector, len));
    }

    function _t(IPqzToken.PqzTransferArgs memory t, uint256 len, bool compact) internal {
        _expect(len);
        if (compact) tok.mtxConfidentialTransferSingleCompact(t, hex"01", _pqAuth(), "");
        else tok.mtxConfidentialTransferSingle(t, hex"01", _pqAuth(), "");
    }

    function test_partLengths_op1() public {
        IPqzToken.PqzTransferArgs memory t = _ts(_sPl(tok, alice, true, "", 70));
        bytes memory x;
        for (uint256 i; i < 4; ++i) {
            (x, t.u) = (t.u, new bytes(_bad(PqzCt.PK)[i]));
            _t(t, t.u.length, false);
            t.u = x;
            (x, t.vTo) = (t.vTo, new bytes(_bad(PqzCt.V)[i]));
            _t(t, t.vTo.length, false);
            t.vTo = x;
            (x, t.vFrom) = (t.vFrom, new bytes(_bad(PqzCt.V)[i]));
            _t(t, t.vFrom.length, false);
            t.vFrom = x;
            (x, t.vAuditor) = (t.vAuditor, new bytes(_badAud()[i]));
            _t(t, t.vAuditor.length, false);
            t.vAuditor = x;
            // no memo on BUNDLE, 41 bytes on commit-reveal
            t.sealedMemo = new bytes(_nonEmpty(57)[i]);
            _t(t, t.sealedMemo.length, false);
            if (t.sealedMemo.length != PqzCore.SEALED) _t(t, t.sealedMemo.length, true);
            t.sealedMemo = "";
        }
        _t(t, 0, true); // commit-reveal without the memo
        tok.mtxConfidentialTransferSingle(t, hex"01", _pqAuth(), "");
        assertEq(tok.pqzAccount(alice).sendCounter, 1, "the unchanged struct passes");
    }

    function _m(IPqzToken.PqzMultiArgs memory t, uint256 len, bool compact) internal {
        _expect(len);
        if (compact) tok.mtxConfidentialTransferCompact(t, hex"01", _pqAuth(), "");
        else tok.mtxConfidentialTransfer(t, hex"01", _pqAuth(), "");
    }

    function test_partLengths_op7() public {
        IPqzToken.PqzMultiArgs memory t = _ms(_mPl(tok, alice, _legsN(2), true, "", 71));
        uint256 memoLen = 2 + 40 * 2;
        bytes memory x;
        for (uint256 i; i < 4; ++i) {
            (x, t.u[0]) = (t.u[0], new bytes(_bad(PqzCt.PK)[i]));
            _m(t, t.u[0].length, false);
            t.u[0] = x;
            (x, t.legs[1].v) = (t.legs[1].v, new bytes(_bad(PqzCt.V)[i]));
            _m(t, t.legs[1].v.length, false);
            t.legs[1].v = x;
            (x, t.legs[1].vAuditor) = (t.legs[1].vAuditor, new bytes(_bad(PqzCt.V)[i]));
            _m(t, t.legs[1].vAuditor.length, false); // length 0 here is the mix: leg 0 has its copy, leg 1 none
            t.legs[1].vAuditor = x;
            (x, t.vFrom) = (t.vFrom, new bytes(_bad(PqzCt.V)[i]));
            _m(t, t.vFrom.length, false);
            t.vFrom = x;
            t.sealedMemo = new bytes(_nonEmpty(memoLen)[i]);
            _m(t, t.sealedMemo.length, false);
            if (t.sealedMemo.length != memoLen) _m(t, t.sealedMemo.length, true);
            t.sealedMemo = "";
        }
        // the mirror mix: leg 0 without its copy, leg 1 with one
        (x, t.legs[0].vAuditor) = (t.legs[0].vAuditor, "");
        _m(t, PqzCt.V, false);
        t.legs[0].vAuditor = x;
        // the group count
        bytes[] memory us = t.u;
        t.u = new bytes[](us.length + 1);
        _m(t, us.length + 1, false);
        t.u = new bytes[](0);
        _m(t, 0, false);
        t.u = us;
        _m(t, 0, true); // commit-reveal without the memo
        tok.mtxConfidentialTransfer(t, hex"01", _pqAuth(), "");
        assertEq(tok.pqzAccount(alice).sendCounter, 1, "the unchanged struct passes");
    }

    function test_partLengths_burn() public {
        IPqzToken.PqzBurnArgs memory b = _bs(_bPl(tok, alice, 72));
        bytes memory x;
        for (uint256 i; i < 4; ++i) {
            (x, b.u) = (b.u, new bytes(_bad(PqzCt.PK)[i]));
            _expect(b.u.length);
            tok.mtxUnshield(b, 0, 0, hex"01", _pqAuth(), "");
            b.u = x;
            (x, b.vFrom) = (b.vFrom, new bytes(_bad(PqzCt.V)[i]));
            _expect(b.vFrom.length);
            tok.mtxUnshield(b, 0, 0, hex"01", _pqAuth(), "");
            b.vFrom = x;
        }
        tok.mtxUnshield(b, 0, 0, hex"01", _pqAuth(), "");
        assertEq(tok.pqzAccount(alice).sendCounter, 1, "the unchanged struct passes");
    }

    /// `cd` with the struct at its head word `slot` and word `field` of the struct replaced by `word`.
    function _patched(bytes memory cd, uint256 slot, uint256 field, bytes32 word) internal pure returns (bytes memory r) {
        r = bytes.concat(cd);
        uint256 o = 4 + uint256(_word(_slice(r, 4, 32 * (slot + 1)), 32 * slot)) + 32 * field;
        assembly ("memory-safe") { mstore(add(add(r, 32), o), word) }
    }

    /// The word is refused by the decoder: an empty revert, before any check of the token's.
    function _refusedRaw(bytes memory cd) internal {
        (bool ok, bytes memory ret) = address(tok).call(cd);
        assertFalse(ok, "a word outside its type");
        assertEq(ret.length, 0, "the ABI decoder's own revert");
    }

    /// `p` is `uint64` and `salt` `bytes16`: `p ≥ 2^64` and a dirty low half of the salt word never reach the statement.
    function test_rawCalldata_pAndSaltOutOfType() public {
        bytes32 tooBig = bytes32(uint256(1) << 64);
        bytes32 dirty = bytes32(uint256(bytes32(salt)) | 1);
        bytes memory cd = abi.encodeCall(IPqzToken.mtxConfidentialTransferSingle, (_ts(_sPl(tok, alice, true, "", 73)), hex"01", _pqAuth(), ""));
        _refusedRaw(_patched(cd, 0, 0, tooBig));
        _refusedRaw(_patched(cd, 0, 6, dirty));
        bytes memory cm = abi.encodeCall(IPqzToken.mtxConfidentialTransfer, (_ms(_mPl(tok, alice, _legsN(2), true, "", 74)), hex"01", _pqAuth(), ""));
        _refusedRaw(_patched(cm, 0, 0, tooBig));
        _refusedRaw(_patched(cm, 0, 6, dirty));
        bytes memory cb = abi.encodeCall(IPqzToken.mtxUnshield, (_bs(_bPl(tok, alice, 75)), 0, 0, hex"01", _pqAuth(), ""));
        _refusedRaw(_patched(cb, 0, 0, tooBig));
        // the same calldata with the words in type passes: `_patched` hit the field
        bytes memory good = _patched(cd, 0, 6, bytes32(salt));
        (bool ok,) = address(tok).call(good);
        assertTrue(ok, "the unpatched call");
    }
}

/// Every PQZ row of `typed_ops.json`, on `NormalPqzToken` and `WrappedPqzToken`: its calldata is the fields on this ABI, and
/// under a token's own domain the row's struct hash is the one the entry hashes: the entry passes the signature and runs into
/// the op's own check.
contract PqzTypedRowsTest is PqzNamedBase {
    using stdJson for string;

    string internal j;
    address internal rowKey;

    function setUp() public {
        _named();
        j = vm.readFile(TYPED_OPS);
        rowKey = j.readAddress(".key.address");
        _public(tok, rowKey, 1 << 50); // `shieldIn` and the outer fee
        usd.mint(rowKey, 1 << 50);
        vm.startPrank(rowKey);
        usd.approve(address(w), 1 << 50);
        w.wrap(1 << 50);
        vm.stopPrank();
    }

    function _p(string memory op, string memory f) internal pure returns (string memory) {
        return msgField(op, f);
    }

    function _uaE(string memory op) internal view returns (MetaTxLib.UAEnvelope memory u) {
        MetaTxLib.Envelope memory e = rowEnvelope2(j, op);
        u = MetaTxLib.UAEnvelope(j.readBytes32(_p(op, "from")), e.batch, e.nonce, e.validUntil, e.mode, e.relayer, e.fee, e.feeRecipient);
    }

    function _sig(string memory op) internal view returns (bytes memory) {
        return j.readBytes(domainField(op, "pqz", "signature"));
    }

    function _auth(string memory op) internal view returns (IUARegistry.UASig memory s) {
        s.signature = _sig(op);
    }

    function _pa(string memory op) internal view returns (IUARegistry.UASig memory s) {
        string memory q = string.concat(".ops.", op, ".domains.pqz.extra.pqzAuth.members");
        s.members = new IUARegistry.MemberSig[](2);
        for (uint256 i; i < 2; ++i) {
            string memory m = string.concat(q, "[", vm.toString(i), "]");
            s.members[i] = IUARegistry.MemberSig(uint16(j.readUint(string.concat(m, ".index"))), _innerList(m), j.readBytes(string.concat(m, ".sig")));
        }
    }

    /// Slot `m`'s list: slot 0 of the row is an `msig` member (spec 2026-11-02-msig-nested), and only it.
    function _innerList(string memory m) internal view returns (IUARegistry.InnerSig[] memory l) {
        uint256 n;
        while (vm.keyExistsJson(j, string.concat(m, ".members[", vm.toString(n), "]"))) ++n;
        l = new IUARegistry.InnerSig[](n);
        for (uint256 k; k < n; ++k) {
            string memory e = string.concat(m, ".members[", vm.toString(k), "]");
            l[k] = IUARegistry.InnerSig(uint16(j.readUint(string.concat(e, ".index"))), j.readBytes(string.concat(e, ".sig")));
        }
    }

    function _head(string memory op) internal view returns (string memory) {
        return j.readString(domainField(op, "pqz", "abi"));
    }

    /// From the row's calldata (a `bytes[]` and legs of the JSON each copy the whole file): the entry hashes what it decodes, so a
    /// calldata that differs from the row's message fails the signature in `_reach`.
    function _args(string memory op) internal view returns (bytes memory cd) {
        cd = j.readBytes(domainField(op, "pqz", "calldata"));
        assembly ("memory-safe") {
            mstore(add(cd, 4), sub(mload(cd), 4)) // the arguments, past the selector
            cd := add(cd, 4)
        }
    }

    function _single(string memory op) internal view returns (IPqzToken.PqzTransferArgs memory t) {
        (, t) = abi.decode(_args(op), (bytes32[8], IPqzToken.PqzTransferArgs));
    }

    function _multiOf(string memory op) internal view returns (IPqzToken.PqzMultiArgs memory t) {
        (, t) = abi.decode(_args(op), (bytes32[8], IPqzToken.PqzMultiArgs));
    }

    function _burn(string memory op) internal view returns (IPqzToken.PqzBurnArgs memory b) {
        string memory q = _p(op, "args");
        b.p = uint64(j.readUint(string.concat(q, ".p")));
        b.validUntilBlock = j.readUint(string.concat(q, ".validUntilBlock"));
        b.shieldIn = j.readUint(string.concat(q, ".shieldIn"));
        b.fromUA = j.readBytes32(string.concat(q, ".fromUA"));
        b.beneficiaryUA = j.readBytes32(string.concat(q, ".beneficiaryUA"));
        b.u = j.readBytes(string.concat(q, ".u"));
        b.vFrom = j.readBytes(string.concat(q, ".vFrom"));
    }

    function _payout(string memory op) internal view returns (IPqzToken.Payout memory) {
        return IPqzToken.Payout(j.readUint(_p(op, "amount")), j.readBytes32(_p(op, "recipient")));
    }

    function _unwrap(string memory op) internal view returns (IConfidentialWrappedToken.Unwrap memory x) {
        x.underlying = j.readAddress(_p(op, "unwrap.underlying"));
        x.recipient = j.readBytes32(_p(op, "unwrap.recipient"));
        x.amount = j.readUint(_p(op, "unwrap.amount"));
        x.minOut = j.readUint(_p(op, "unwrap.minOut"));
    }

    function _hint(string memory op) internal view returns (bytes memory) {
        return j.readBytes(_p(op, "accHint"));
    }

    function _proofOf(string memory op) internal view returns (bytes memory) {
        return j.readBytes(_p(op, "proof"));
    }

    /// The row's calldata, the fields' call, and the row's own call under `c`'s domain passing the signature: the revert is the
    /// op's, `want`.
    function _reach(string memory op, address c, bytes memory built, bytes4 want) internal {
        checkRow(j, op, "pqz");
        bytes memory cd = j.readBytes(domainField(op, "pqz", "calldata"));
        assertEq(built, cd, string.concat(op, ": calldata"));
        bytes memory rowSig = _sig(op);
        bytes memory sig = onChain(j, op, c);
        for (uint256 i = cd.length - 65; i > 0; --i) {
            bool same = true;
            for (uint256 k; k < 65 && same; ++k) same = cd[i + k] == rowSig[k];
            if (same) {
                for (uint256 k; k < 65; ++k) cd[i + k] = sig[k];
                break;
            }
        }
        vm.prank(j.readAddress(_p(op, "relayer")));
        (bool ok, bytes memory ret) = c.call(cd);
        assertFalse(ok, op);
        assertEq(bytes4(ret), want, string.concat(op, ": the op's own check, the signature passed"));
    }

    function _both(string memory op, bytes memory built, bytes4 want) internal {
        _reach(op, address(tok), built, want);
        _reach(op, address(w), built, want);
    }

    function test_typedOpsVectors_PqzTransferSingle() public {
        for (uint256 k; k < 2; ++k) {
            string memory op = k == 0 ? "PqzTransferSingle" : "PqzTransferSingleCompact";
            _both(op, abi.encodeWithSignature(_head(op), rowEnvelope(j, op), _single(op), _proofOf(op), _pa(op), _hint(op), _sig(op)), IPqzToken.BadPayload.selector);
        }
    }

    function test_typedOpsVectors_UAPqzTransferSingle() public {
        for (uint256 k; k < 2; ++k) {
            string memory op = k == 0 ? "UAPqzTransferSingle" : "UAPqzTransferSingleCompact";
            _both(op, abi.encodeWithSignature(_head(op), _uaE(op), _single(op), _proofOf(op), _pa(op), _hint(op), _auth(op)), IPqzToken.BadPayload.selector);
        }
    }

    function test_typedOpsVectors_PqzTransfer() public {
        for (uint256 k; k < 2; ++k) {
            string memory op = k == 0 ? "PqzTransfer" : "PqzTransferCompact";
            _both(op, abi.encodeWithSignature(_head(op), rowEnvelope(j, op), _multiOf(op), _proofOf(op), _pa(op), _hint(op), _sig(op)), IPqzToken.BadPayload.selector);
        }
    }

    function test_typedOpsVectors_UAPqzTransfer() public {
        for (uint256 k; k < 2; ++k) {
            string memory op = k == 0 ? "UAPqzTransfer" : "UAPqzTransferCompact";
            _both(op, abi.encodeWithSignature(_head(op), _uaE(op), _multiOf(op), _proofOf(op), _pa(op), _hint(op), _auth(op)), IPqzToken.BadPayload.selector);
        }
    }

    function test_typedOpsVectors_PqzUnshield() public {
        string memory op = "PqzUnshield";
        _both(op, abi.encodeWithSignature(_head(op), rowEnvelope(j, op), _burn(op), _payout(op), _proofOf(op), _pa(op), _hint(op), _sig(op)), IUALedger.UANotRegistered.selector);
    }

    function test_typedOpsVectors_UAPqzUnshield() public {
        string memory op = "UAPqzUnshield";
        _both(op, abi.encodeWithSignature(_head(op), _uaE(op), _burn(op), _payout(op), _proofOf(op), _pa(op), _hint(op), _auth(op)), IUALedger.UANotRegistered.selector);
    }

    function test_typedOpsVectors_PqzUnshieldUnwrap() public {
        string memory op = "PqzUnshieldUnwrap";
        _reach(op, address(w), abi.encodeWithSignature(_head(op), rowEnvelope(j, op), _burn(op), _unwrap(op), _proofOf(op), _pa(op), _hint(op), _sig(op)), IPqzToken.BadPayload.selector);
    }

    function test_typedOpsVectors_UAPqzUnshieldUnwrap() public {
        string memory op = "UAPqzUnshieldUnwrap";
        _reach(op, address(w), abi.encodeWithSignature(_head(op), _uaE(op), _burn(op), _unwrap(op), _proofOf(op), _pa(op), _hint(op), _auth(op)), IPqzToken.BadPayload.selector);
    }

    function test_typedOpsVectors_WrapShield() public {
        string memory op = "WrapShield";
        _reach(op, address(w), abi.encodeWithSignature(_head(op), rowEnvelope(j, op), j.readAddress(_p(op, "underlying")), j.readUint(_p(op, "amountIn")),
            j.readBytes32(_p(op, "toUA")), _sig(op)), bytes4(keccak256("UnknownUnderlying(address)")));
    }

    function test_typedOpsVectors_RollOver() public {
        string memory op = "RollOver";
        _both(op, abi.encodeWithSignature(_head(op), rowEnvelope(j, op), j.readBytes32(_p(op, "ua")), j.readUint(_p(op, "n")), _sig(op)), IPqzToken.RollOverRange.selector);
    }

    function test_typedOpsVectors_UARollOver() public {
        string memory op = "UARollOver";
        _both(op, abi.encodeWithSignature(_head(op), _uaE(op), j.readBytes32(_p(op, "ua")), j.readUint(_p(op, "n")), _auth(op)), IPqzToken.RollOverRange.selector);
    }

    function test_typedOpsVectors_PrepareAcc() public {
        string memory op = "PrepareAcc";
        _both(op, abi.encodeWithSignature(_head(op), rowEnvelope(j, op), j.readBytes32(_p(op, "ua")), j.readUint(_p(op, "half")), _sig(op)), IPqzToken.BadPayload.selector);
    }

    function test_typedOpsVectors_UAPrepareAcc() public {
        string memory op = "UAPrepareAcc";
        _both(op, abi.encodeWithSignature(_head(op), _uaE(op), j.readBytes32(_p(op, "ua")), j.readUint(_p(op, "half")), _auth(op)), IPqzToken.BadPayload.selector);
    }
}

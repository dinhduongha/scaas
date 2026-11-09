// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {NormalZetherToken} from "../src/zether/NormalZetherToken.sol";

import {Script, console} from "forge-std/Script.sol";
import {Vm} from "forge-std/Vm.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {MetaTxLib} from "../src/common/MetaTxLib.sol";
import {OpenFactory} from "../src/factory/OpenFactory.sol";
import {IOpenFactory} from "../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../src/factory/IFactoryToken.sol";
import {GovernanceLib} from "../src/governance/GovernanceLib.sol";
import {GovernanceBits} from "../src/governance/GovernanceBits.sol";
import {TokenStore} from "../src/metatx/TokenStore.sol";
import {IUARegistry} from "../src/ua/IUARegistry.sol";
import {UAKinds} from "../src/ua/UAKinds.sol";
import {ZetherLayer} from "../src/zether/ZetherLayer.sol";
import {WrappedZetherToken} from "../src/zether/WrappedZetherToken.sol";
import {IZetherToken} from "../src/zether/IZetherToken.sol";
import {ITransferDisclosure} from "../src/zether/ITransferDisclosure.sol";
import {ZetherTypes} from "../src/zether/ZetherTypes.sol";
import {MockERC20} from "../test/helpers/Mocks.sol";

/// @title The classical Zether e2e (`scripts/e2e-zether.sh`) on a chain deployed by `deploy.sh evm` with `DEPLOY_ZETHER=1`
///        (`deployments/<chainid>.json`): an anvil, or the SCaaS testnet. Needs `--ffi`: the proofs come from the Rust
///        prover (`zether-cli`, env `ZETHER_CLI`, default `clients/zether-prover/target/release/zether-cli`), the
///        registration PoPs from clientkeys (`zetherPop`, node). **UNAUDITED** contracts.
/// @notice `run()` (broadcast): six `zether-bls12381` UAs registered with clientkeys PoPs (relayed by the deployer;
///         skipped when already registered); a `NORMAL_ZETHER` token (BUNDLE, no auditor, scale 1): shield 1234 to
///         alice, roll-over, a single transfer alice → bob 100, a multi-recipient commit-reveal (Compact) transfer M = 4
///         (bob 50 + 3 decoys at 0), a multi-recipient BUNDLE transfer M = 2 (carol 25 + 1 decoy), bob's roll-over, an
///         unshield of 200 to the deployer; three relayed proofs through the generic merged entry `mtxExecute(UAMetaTransaction,
///         UASig)` (ua-mtx-merge R47; the proof bound to the UA binding the script computes, R35): a single transfer of 40
///         to bob, a Compact M = 2 of 30 to bob, an unshield of 20, each signed by a payer EOA with its own key (no registry
///         call) and submitted by the deployer for a fixed fee; the same three on the named merged entries
///         (`mtxConfidentialTransferSingle(UAEnvelope, …, UASig)`, `…Compact`, `mtxUnshield`; ua-mtx-merge T12, the calldata
///         from `zether-cli namedCall`): 15, 10 and 5; every UA binding also from `zether-cli uaEnvelope`, checked against the
///         script's and the token's `envelopeBinding`; then a test ERC-20 (`MockERC20`) and a `WRAPPED_ZETHER` token over it
///         (1:1): wrap-shield 500 to alice, roll-over. Each step is checked by decryption (`zether-cli decrypt`) in the
///         simulation, and the single transfer by the disclosure view (`ZetherDisclosure.verifyTransferAmount`,
///         `SENDER_S`). Writes `deployments/<chainid>-zether-e2e.json` (tokens, entry refs, the sender's `s`).
///         `check()` (no broadcast): the same final balances and the disclosure view against the chain's state.
///         env PRIVATE_KEY (the deployer: holds the tokens' initial supply, relays the registrations), E2E_SALT
///         (optional, the token salts; default from the block number).
contract ZetherE2E is Script {
    using stdJson for string;

    uint8 internal constant N = 6; // alice, bob, carol, three decoys
    uint256 internal constant SHIELDED = 1234;
    uint256 internal constant SINGLE = 100;
    uint256 internal constant MULTI4 = 50; // to bob, M = 4 Compact
    uint256 internal constant MULTI2 = 25; // to carol, M = 2 BUNDLE
    uint256 internal constant UNSHIELD = 200;
    uint256 internal constant RELAYED_SINGLE = 40;
    uint256 internal constant RELAYED_MULTI = 30; // to bob, M = 2 Compact
    uint256 internal constant RELAYED_UNSHIELD = 20;
    uint256 internal constant NAMED_SINGLE = 15;
    uint256 internal constant NAMED_MULTI = 10; // to bob, M = 2 Compact
    uint256 internal constant NAMED_UNSHIELD = 5;
    uint256 internal constant RELAY_FEE = 3; // to the deployer, per relayed op
    uint256 internal constant PAYER_PK = uint256(keccak256("scaas.e2e.zether.payer"));
    uint256 internal constant WRAPPED = 500;

    string internal dep;
    IUARegistry internal reg;
    OpenFactory internal fac;
    ITransferDisclosure internal dis;
    string internal cli;
    uint256[N] internal xs;
    bytes[N] internal ys;
    bytes32[N] internal uas;

    function _load() internal {
        dep = vm.readFile(string.concat("./deployments/", vm.toString(block.chainid), ".json"));
        reg = IUARegistry(dep.readAddress(".zether_registry"));
        fac = OpenFactory(dep.readAddress(".token_factory"));
        dis = ITransferDisclosure(dep.readAddress(".zether_disclosure"));
        cli = vm.envOr("ZETHER_CLI", string.concat(vm.projectRoot(), "/../../clients/zether-prover/target/release/zether-cli"));
        for (uint256 i; i < N; ++i) xs[i] = uint256(keccak256(abi.encode("scaas.e2e.zether.x", i))) >> 8; // test keys, < r
    }

    // ------------------------------------------------------------------ ffi

    function _cli(string memory cmd, string memory req) internal returns (string memory out) {
        string[] memory a = new string[](6);
        (a[0], a[1], a[2]) = ("bash", "-c", "printf '%s' \"$2\" | \"$0\" \"$1\"");
        (a[3], a[4], a[5]) = (cli, cmd, req);
        out = string(vm.ffi(a));
        require(bytes(out).length != 0, string.concat("zether-cli ", cmd, " failed"));
    }

    /// clientkeys: `Y`, `UA`, the portable PoP of `x` (UA-8: no chain context).
    function _pop(uint256 x) internal returns (bytes memory y, bytes32 ua, bytes memory pop) {
        string[] memory a = new string[](4);
        (a[0], a[1], a[2]) = ("node", "--input-type=module", "-e");
        a[3] = string.concat(
            "import { zetherPop } from '", vm.projectRoot(), "/../../clients/clientkeys/src/zether.js';",
            "import { fromHex } from '", vm.projectRoot(), "/../../clients/clientkeys/src/bytes.js';",
            "const p = zetherPop('bls12381', fromHex('", vm.toString(bytes32(x)), "'));",
            "console.log(JSON.stringify({Y: p.Y, UA: p.UA, pop: p.pop}));"
        );
        string memory o = string(vm.ffi(a));
        (y, ua, pop) = (o.readBytes(".Y"), o.readBytes32(".UA"), o.readBytes(".pop"));
    }

    function _q(string memory k, string memory v) internal pure returns (string memory) {
        return string.concat('"', k, '":"', v, '"');
    }

    function _key(uint256 i) internal view returns (string memory) {
        return string.concat('"curve":"bls12381","key":{', _q("x", vm.toString(bytes32(xs[i]))), "}");
    }

    /// The decrypted acc and pending of user `i` on `t` (BSGS, 2^18 table, 32-bit bound).
    function _balances(address t, uint256 i) internal returns (uint256 acc, uint256 pend) {
        IZetherToken.AccountState memory s = IZetherToken(t).accountState(ZetherTypes.UA.wrap(uas[i]));
        acc = _decrypt(i, s.accC, s.accD);
        pend = _decrypt(i, s.pendingC, s.pendingD);
    }

    function _decrypt(uint256 i, bytes memory c, bytes memory d) internal returns (uint256) {
        if (c.length == 0) return 0;
        string memory o = _cli("decrypt", string.concat("{", _key(i), ',"ct":{', _q("C", vm.toString(c)), ",",
            _q("D", vm.toString(d)), '},"tableBits":18,"boundBits":32}'));
        return vm.parseUint(o.readString(".amount"));
    }

    function _expect(address t, uint256 i, uint256 acc, uint256 pend, string memory what) internal {
        (uint256 a, uint256 p) = _balances(t, i);
        require(a == acc && p == pend, string.concat(what, ": decrypted acc ", vm.toString(a), " pending ", vm.toString(p),
            ", expected ", vm.toString(acc), " / ", vm.toString(pend)));
        console.log(string.concat("ok    ", what, ": decrypted acc ", vm.toString(a), ", pending ", vm.toString(p)));
    }

    /// The prove request of alice (user 0) on `t`: her state, no beneficiary, `vub`, BUNDLE / no auditor.
    function _req(address t, uint256 bal, string memory extra) internal view returns (string memory) {
        IZetherToken.AccountState memory st = IZetherToken(t).accountState(ZetherTypes.UA.wrap(uas[0]));
        return string.concat(
            "{", _key(0), ',"chainId":', vm.toString(block.chainid), ",", _q("chainUid", vm.toString(dep.readBytes32(".chain_uid"))),
            ",", _q("token", vm.toString(t)), ',"sendCounter":', vm.toString(st.sendCounter), ',"accSeq":',
            vm.toString(st.accSeq), ',"validUntilBlock":', vm.toString(block.number + 100_000), ',"acc":{',
            string.concat(_q("C", vm.toString(st.accC)), ",", _q("D", vm.toString(st.accD)), '},"balance":', vm.toString(bal)),
            ',"fee":0,"disclosureMode":"bundle","auditorMode":"none","yAud":null,"includeWitness":true', extra, "}"
        );
    }

    function _recipients(uint256[] memory who, uint256[] memory amt) internal view returns (string memory r) {
        r = ',"recipients":[';
        for (uint256 j; j < who.length; ++j) {
            r = string.concat(r, j == 0 ? "{" : ",{", _q("yTo", vm.toString(ys[who[j]])), ',"amount":', vm.toString(amt[j]), "}");
        }
        r = string.concat(r, "]");
    }

    /// Sends the prover's direct calldata; returns the entry ref (checked against the prover's).
    function _send(address t, string memory out, string memory label) internal returns (bytes32 ref) {
        (bool ok, bytes memory ret) = t.call(out.readBytes(".directCalldata"));
        require(ok, string.concat(label, " reverted"));
        ref = abi.decode(ret, (bytes32));
        require(ref == out.readBytes32(".entryRef"), string.concat(label, ": entryRef"));
        console.log(string.concat("ok    ", label, " entryRef ", vm.toString(ref)));
    }

    /// The envelope of the next relayed op: the payer's (`from` its address zero-padded, R1), this script's sender bound,
    /// fixed fee.
    function _envelope() internal view returns (MetaTxLib.UAMetaTransaction memory m) {
        bytes32 from = MetaTxLib.pad(vm.addr(PAYER_PK));
        m = MetaTxLib.UAMetaTransaction(from, "", 7, NormalZetherToken(t).mtxNonce(from, 7), block.timestamp + 1 days,
            MetaTxLib.MODE_RESTRICT_RELAYER | MetaTxLib.MODE_FEE_FIXED, me, RELAY_FEE, address(0));
    }

    /// The UA binding of `m` (CTR-ZTH-51, R35: `SCAAS-ZETHER-UA-ENVELOPE-V1`, `from` as `bytes32`, every field but `data`, an
    /// unbound relayer or fee recipient as 0), computed here as a client does and checked against the token's
    /// `envelopeBinding` view and the prover's (`zether-cli uaEnvelope`); the prover takes it as `envelopeBinding`.
    function _bindingOf(MetaTxLib.UAMetaTransaction memory m) internal returns (string memory) {
        address r = (m.mode & MetaTxLib.MODE_RESTRICT_RELAYER) != 0 ? m.relayer : address(0);
        address f = (m.mode & MetaTxLib.MODE_RESTRICT_FEE_RECIPIENT) != 0 ? m.feeRecipient : address(0);
        bytes32 b = keccak256(abi.encode(keccak256("SCAAS-ZETHER-UA-ENVELOPE-V1"), block.chainid, dep.readBytes32(".chain_uid"),
            t, m.from, m.batch, m.nonce, m.validUntil, m.mode, r, m.fee, f));
        require(b == IZetherToken(t).envelopeBinding(m), "the UA binding differs from the token's envelopeBinding");
        string memory u = string.concat(
            '{"chainId":', vm.toString(block.chainid), ",", _q("chainUid", vm.toString(dep.readBytes32(".chain_uid"))), ",",
            _q("token", vm.toString(t)), ',"meta":{', _q("from", vm.toString(m.from)), ",", _q("batch", vm.toString(bytes32(m.batch))));
        u = string.concat(u, ',"nonce":', vm.toString(m.nonce), ',"validUntil":', vm.toString(m.validUntil), ',"mode":', vm.toString(m.mode),
            ",", _q("relayer", vm.toString(m.relayer)), ',"fee":', vm.toString(m.fee));
        u = _cli("uaEnvelope", string.concat(u, ",", _q("feeRecipient", vm.toString(m.feeRecipient)), "}}"));
        require(u.readBytes32(".binding") == b, "zether-cli uaEnvelope: the UA binding differs");
        return string.concat(",", _q("envelopeBinding", vm.toString(b)));
    }

    /// The prover's direct call `out` relayed through the generic merged entry `mtxExecute(UAMetaTransaction, UASig)`
    /// (R47): the payer signs the token's `mtxDigest` with its own key (an EOA: `UASig.signature`, no registry call, R1 / B),
    /// the deployer submits. Returns the op's own return data.
    function _relay(MetaTxLib.UAMetaTransaction memory m, string memory out, string memory label)
        internal returns (bytes memory ret)
    {
        m.data = out.readBytes(".directCalldata");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PAYER_PK, NormalZetherToken(t).mtxDigest(m));
        IUARegistry.UASig memory auth;
        auth.signature = abi.encodePacked(r, s, v);
        ret = NormalZetherToken(t).mtxExecute(m, auth);
        console.log(string.concat("ok    ", label, " (mtxExecute, the payer's UASig)"));
    }

    function _conf() internal pure returns (IFactoryToken.ConfidentialConfig memory) {
        // version 1 of each Zether kind is the BLS12-381 release (CTR-ZTH-20, CTR-ZTH-32): BUNDLE, no auditor, scale 1
        return IFactoryToken.ConfidentialConfig("", 1, 1 << 40, 0, 0, 0, 0, 0, bytes32(0), false, 0);
    }

    // ------------------------------------------------------------------ run

    address internal me;
    bytes32 internal salt;
    address internal t; // NORMAL_ZETHER
    address internal wt; // WRAPPED_ZETHER
    address internal und; // its underlying, a NORMAL token
    bytes32 internal refSingle;
    bytes32 internal refCompact;
    bytes32 internal refBundle;
    bytes32 internal sSingle;
    uint256 internal bal; // alice's acc on t

    function run() external {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        me = vm.addr(pk);
        _load();
        salt = vm.envOr("E2E_SALT", keccak256(abi.encode("scaas.e2e.zether", block.number)));
        vm.startBroadcast(pk);
        _register();
        _normal();
        _transfers();
        _unshield();
        _relayed();
        _wrapped();
        vm.stopBroadcast();

        string memory k = "e2e";
        vm.serializeAddress(k, "normal_zether_token", t);
        vm.serializeAddress(k, "wrapped_zether_token", wt);
        vm.serializeAddress(k, "underlying_erc20", und);
        vm.serializeBytes32(k, "entry_single", refSingle);
        vm.serializeBytes32(k, "entry_compact_m4", refCompact);
        vm.serializeBytes32(k, "entry_bundle_m2", refBundle);
        string memory j = vm.serializeBytes32(k, "s_single", sSingle);
        vm.writeJson(j, string.concat("./deployments/", vm.toString(block.chainid), "-zether-e2e.json"));
        console.log(j);
    }

    function _register() internal {
        for (uint256 i; i < N; ++i) {
            bytes memory pop;
            (ys[i], uas[i], pop) = _pop(xs[i]);
            if (reg.kindOf(uas[i]) == 0) {
                IUARegistry.UAAttrs memory none; // no attributes (typed-signing R1: no KEM version word)
                require(reg.register(UAKinds.ZETHER_BLS12381, ys[i], none, pop, "") == uas[i], "register");
            }
            require(reg.kindOf(uas[i]) == UAKinds.ZETHER_BLS12381, "the Zether UA is not registered");
        }
        console.log("ok    6 zether-bls12381 UAs registered (clientkeys PoPs)");
    }

    function _normal() internal {
        IFactoryToken.TokenConfig memory c;
        (c.name, c.symbol, c.decimals, c.features) = ("Zether E2E", "zE2E", 6, 1 << GovernanceBits.PAYABLE);
        (c.initialSupply, c.initialHolder, c.conf) = (1_000_000, me, _conf());
        t = fac.createToken(IOpenFactory.TokenKind.NORMAL_ZETHER, 1, abi.encode(c), salt);
        console.log(string.concat("      NORMAL_ZETHER token at ", vm.toString(t)));
        NormalZetherToken(t).mtxShield(uas[0], SHIELDED);
        _expect(t, 0, 0, SHIELDED, "shield 1234 to alice");
        NormalZetherToken(t).mtxRollOver(uas[0], 1);
        _expect(t, 0, SHIELDED, 0, "alice roll-over");
        bal = SHIELDED;
    }

    function _transfers() internal {
        string memory out = _cli("proveTransfer", _req(t, bal, string.concat(",", _q("yTo", vm.toString(ys[1])), ',"amount":100')));
        refSingle = _send(t, out, "single transfer alice -> bob 100");
        sSingle = out.readBytes32(".witness.s");
        bal -= SINGLE;
        _expect(t, 0, bal, 0, "alice after the single transfer");
        _expect(t, 1, 0, SINGLE, "bob after the single transfer");
        require(dis.verifyTransferAmount(t, refSingle, 0, SINGLE, ITransferDisclosure.OpeningKind.SENDER_S, abi.encode(sSingle)),
            "disclosure view");
        require(!dis.verifyTransferAmount(t, refSingle, 0, SINGLE + 1, ITransferDisclosure.OpeningKind.SENDER_S, abi.encode(sSingle)),
            "disclosure view (wrong amount)");
        console.log("ok    disclosure view: verifyTransferAmount(single, 100, SENDER_S) = true, 101 = false");

        uint256[] memory who = new uint256[](4);
        uint256[] memory amt = new uint256[](4);
        (who[0], who[1], who[2], who[3], amt[0]) = (1, 3, 4, 5, MULTI4);
        out = _cli("proveTransferMulti", _req(t, bal, string.concat(',"mode":"compact"', _recipients(who, amt))));
        refCompact = _send(t, out, "multi transfer Compact M = 4 (bob 50 + 3 decoys)");
        bal -= MULTI4;
        _expect(t, 0, bal, 0, "alice after the Compact M = 4 transfer");
        _expect(t, 1, 0, SINGLE + MULTI4, "bob after the Compact M = 4 transfer");
        for (uint256 i = 3; i < N; ++i) _expect(t, i, 0, 0, string.concat("decoy ", vm.toString(i - 2), " (Compact)"));

        who = new uint256[](2);
        amt = new uint256[](2);
        (who[0], who[1], amt[0]) = (2, 3, MULTI2);
        out = _cli("proveTransferMulti", _req(t, bal, string.concat(',"mode":"bundle"', _recipients(who, amt))));
        refBundle = _send(t, out, "multi transfer BUNDLE M = 2 (carol 25 + 1 decoy)");
        bal -= MULTI2;
        _expect(t, 0, bal, 0, "alice after the BUNDLE M = 2 transfer");
        _expect(t, 2, 0, MULTI2, "carol after the BUNDLE M = 2 transfer");

        NormalZetherToken(t).mtxRollOver(uas[1], 1);
        _expect(t, 1, SINGLE + MULTI4, 0, "bob roll-over");
    }

    function _unshield() internal {
        uint256 pub = IERC20(t).balanceOf(me);
        string memory out = _cli("proveBurn", _req(t, bal, string.concat(',"amount":200,', _q("recipient", vm.toString(me)))));
        (bool ok,) = t.call(out.readBytes(".directCalldata"));
        require(ok, "unshield reverted");
        bal -= UNSHIELD;
        require(IERC20(t).balanceOf(me) == pub + UNSHIELD, "unshield: public balance");
        _expect(t, 0, bal, 0, "unshield 200 to the deployer (public +200)");
        require(NormalZetherToken(t).totalShielded() == SHIELDED - UNSHIELD, "totalShielded");
    }

    /// The relayed proofs: every one a payer EOA's signature, the deployer the relayer: three over the merged generic entry
    /// (`_relay`), three on the named merged entries (`_named`).
    function _relayed() internal {
        address payer = vm.addr(PAYER_PK);
        uint256 before = IERC20(t).balanceOf(me);
        IERC20(t).transfer(payer, 6 * RELAY_FEE);
        _relayedSingle();
        _relayedCompact();
        _relayedUnshield();
        _namedSingle();
        _namedCompact();
        _namedUnshield();
        require(IERC20(t).balanceOf(payer) == 0, "relayed: six fees from the payer");
        require(IERC20(t).balanceOf(me) == before + RELAYED_UNSHIELD + NAMED_UNSHIELD,
            "relayed: the fees back to the deployer, the unshields");
        require(NormalZetherToken(t).totalShielded() == SHIELDED - UNSHIELD - RELAYED_UNSHIELD - NAMED_UNSHIELD, "relayed: totalShielded");
    }

    function _relayedSingle() internal {
        MetaTxLib.UAMetaTransaction memory m = _envelope();
        string memory out = _cli("proveTransfer", _req(t, bal, string.concat(_bindingOf(m), ',"uaSigner":"ecdsa",', _q("yTo", vm.toString(ys[1])),
            ',"amount":', vm.toString(RELAYED_SINGLE))));
        bytes memory ret = _relay(m, out, "relayed single transfer alice -> bob 40");
        require(abi.decode(ret, (bytes32)) == out.readBytes32(".entryRef"), "relayed single: entryRef");
        bal -= RELAYED_SINGLE;
        _expect(t, 0, bal, 0, "alice after the relayed single transfer");
        _expect(t, 1, SINGLE + MULTI4, RELAYED_SINGLE, "bob after the relayed single transfer");
    }

    function _relayedCompact() internal {
        MetaTxLib.UAMetaTransaction memory m = _envelope();
        uint256[] memory who = new uint256[](2);
        uint256[] memory amt = new uint256[](2);
        (who[0], who[1], amt[0]) = (1, 3, RELAYED_MULTI);
        string memory out = _cli("proveTransferMulti", _req(t, bal, string.concat(',"mode":"compact"', _bindingOf(m), ',"uaSigner":"ecdsa"',
            _recipients(who, amt))));
        _relay(m, out, "relayed multi transfer Compact M = 2 (bob 30 + 1 decoy)");
        bal -= RELAYED_MULTI;
        _expect(t, 0, bal, 0, "alice after the relayed Compact transfer");
        _expect(t, 1, SINGLE + MULTI4, RELAYED_SINGLE + RELAYED_MULTI, "bob after the relayed Compact transfer");
    }

    function _relayedUnshield() internal {
        MetaTxLib.UAMetaTransaction memory m = _envelope();
        uint256 pub = IERC20(t).balanceOf(me);
        string memory out = _cli("proveBurn", _req(t, bal, string.concat(_bindingOf(m), ',"amount":20,', _q("recipient", vm.toString(me)))));
        _relay(m, out, "relayed unshield 20 to the deployer");
        bal -= RELAYED_UNSHIELD;
        _expect(t, 0, bal, 0, "alice after the relayed unshield");
        require(IERC20(t).balanceOf(me) == pub + RELAYED_UNSHIELD + RELAY_FEE, "relayed unshield: public balance and fee");
    }

    function _n(string memory k, uint256 v) internal pure returns (string memory) {
        return string.concat('"', k, '":"', vm.toString(v), '"');
    }

    /// `namedCall` of `op` (a merged entry, R35) through the real prover: its digest signed by the payer here (a raw signature:
    /// `UASig{signature}`), then the entry's calldata, submitted by the deployer.
    function _named(string memory op, MetaTxLib.UAMetaTransaction memory m, string memory out, string memory extra, string memory label)
        internal returns (bytes memory ret)
    {
        string memory q = string.concat(
            '{"op":"', op, '","chainId":', vm.toString(block.chainid), ",", _q("chainUid", vm.toString(dep.readBytes32(".chain_uid"))), ",",
            _q("token", vm.toString(t)), ',"env":{', _q("from", vm.toString(m.from)), ",", _n("batch", m.batch), ",", _n("nonce", m.nonce));
        q = string.concat(q, ",", _n("validUntil", m.validUntil), ",", _n("mode", m.mode), ",", _q("relayer", vm.toString(m.relayer)), ",",
            _n("fee", m.fee), ",", _q("feeRecipient", vm.toString(m.feeRecipient)), "},");
        q = string.concat(q, _q("payload", vm.toString(out.readBytes(".payload"))), ",", _q("proof", vm.toString(out.readBytes(".proof"))),
            ",", _q("beneficiary", vm.toString(bytes32(0))), extra);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PAYER_PK, _cli("namedCall", string.concat(q, "}")).readBytes32(".digest"));
        bytes memory cd = _cli("namedCall", string.concat(q, ',"sig":"', vm.toString(abi.encodePacked(r, s, v)), '"}')).readBytes(".calldata");
        bool ok;
        (ok, ret) = t.call(cd);
        require(ok, string.concat(label, " reverted"));
        console.log(string.concat("ok    ", label, " (", op, ", the payer's UASig)"));
    }

    function _namedSingle() internal {
        MetaTxLib.UAMetaTransaction memory m = _envelope();
        string memory out = _cli("proveTransfer", _req(t, bal, string.concat(_bindingOf(m), ',"uaSigner":"ecdsa",', _q("yTo", vm.toString(ys[1])),
            ',"amount":', vm.toString(NAMED_SINGLE))));
        bytes memory ret = _named("UAZetherTransferSingle", m, out, "", "named single transfer alice -> bob 15");
        require(abi.decode(ret, (bytes32)) == out.readBytes32(".entryRef"), "named single: entryRef");
        bal -= NAMED_SINGLE;
        _expect(t, 0, bal, 0, "alice after the named single transfer");
        _expect(t, 1, SINGLE + MULTI4, RELAYED_SINGLE + RELAYED_MULTI + NAMED_SINGLE, "bob after the named single transfer");
    }

    function _namedCompact() internal {
        MetaTxLib.UAMetaTransaction memory m = _envelope();
        uint256[] memory who = new uint256[](2);
        uint256[] memory amt = new uint256[](2);
        (who[0], who[1], amt[0]) = (1, 3, NAMED_MULTI);
        string memory out = _cli("proveTransferMulti", _req(t, bal, string.concat(',"mode":"compact"', _bindingOf(m), ',"uaSigner":"ecdsa"',
            _recipients(who, amt))));
        _named("UAZetherTransferCompact", m, out, "", "named multi transfer Compact M = 2 (bob 10 + 1 decoy)");
        bal -= NAMED_MULTI;
        _expect(t, 0, bal, 0, "alice after the named Compact transfer");
        _expect(t, 1, SINGLE + MULTI4, RELAYED_SINGLE + RELAYED_MULTI + NAMED_SINGLE + NAMED_MULTI, "bob after the named Compact transfer");
    }

    function _namedUnshield() internal {
        MetaTxLib.UAMetaTransaction memory m = _envelope();
        uint256 pub = IERC20(t).balanceOf(me);
        string memory out = _cli("proveBurn", _req(t, bal, string.concat(_bindingOf(m), ',"amount":5,', _q("recipient", vm.toString(me)))));
        _named("UAZetherUnshield", m, out, string.concat(',"amount":5,', _q("recipient", vm.toString(MetaTxLib.pad(me)))),
            "named unshield 5 to the deployer");
        bal -= NAMED_UNSHIELD;
        _expect(t, 0, bal, 0, "alice after the named unshield");
        require(IERC20(t).balanceOf(me) == pub + NAMED_UNSHIELD + RELAY_FEE, "named unshield: public balance and fee");
    }

    /// WRAPPED_ZETHER over a plain test ERC-20 (`MockERC20`, CREATE), 1:1: an SCaaS token refuses an EOA's `approve`
    ///    (CTR-TOK-01), so the EOA deployer wraps an ordinary ERC-20.
    function _wrapped() internal {
        MockERC20 m = new MockERC20("E2E USD", "eUSD", 6);
        m.mint(me, 1_000_000);
        und = address(m);
        console.log(string.concat("      MockERC20 at ", vm.toString(und)));
        IFactoryToken.TokenConfig memory w;
        (w.name, w.symbol, w.decimals, w.features, w.conf) = ("Zether wrapped E2E USD", "zweUSD", 6, 1 << GovernanceBits.PAYABLE, _conf());
        w.legs = new IFactoryToken.Leg[](1);
        w.legs[0] = IFactoryToken.Leg(und, 1, 1);
        wt = fac.createToken(IOpenFactory.TokenKind.WRAPPED_ZETHER, 1, abi.encode(w), salt);
        console.log(string.concat("      WRAPPED_ZETHER token at ", vm.toString(wt)));
        IERC20(und).approve(wt, WRAPPED);
        WrappedZetherToken(payable(wt)).mtxWrapShield(und, WRAPPED, uas[0]);
        NormalZetherToken(wt).mtxRollOver(uas[0], 1);
        _expect(wt, 0, WRAPPED, 0, "wrap-shield 500 to alice + roll-over (wrapped)");
        require(IERC20(und).balanceOf(wt) == WRAPPED, "wrapped reserve");
    }

    /// The regular / EIP-8037 state split the receipts do not carry: each CALL of the broadcast `path` re-run on a fork
    ///  of the chain just before it (`createSelectFork(rpc, tx)`), one isolated transaction each (`--isolate`,
    ///  `lastCallGas`): regular (intrinsic and calldata included), state, refund; `net` = regular + state − refund is
    ///  the receipt's gasUsed. Env RPC.
    function gasSplit(string calldata path) external {
        string memory b = vm.readFile(path);
        string memory rpc = vm.envString("RPC");
        for (uint256 i; vm.keyExistsJson(b, string.concat(".transactions[", vm.toString(i), "]")); ++i) {
            string memory k = string.concat(".transactions[", vm.toString(i), "]");
            if (keccak256(bytes(b.readString(string.concat(k, ".transactionType")))) != keccak256("CALL")) continue;
            bytes32 h = b.readBytes32(string.concat(k, ".hash"));
            vm.createSelectFork(rpc, h);
            address to = b.readAddress(string.concat(k, ".transaction.to"));
            vm.prank(b.readAddress(string.concat(k, ".transaction.from")));
            (bool ok,) = to.call(b.readBytes(string.concat(k, ".transaction.input")));
            Vm.Gas memory g = vm.lastCallGas();
            console.log(string.concat(ok ? "ok    " : "FAIL  ", b.readString(string.concat(k, ".function")), " ",
                vm.toString(h), " regular ", vm.toString(g.gasTotalUsed), " state ", vm.toString(g.gasStateUsed),
                " refund ", vm.toString(g.gasRefunded), " net ",
                vm.toString(int256(uint256(g.gasTotalUsed)) + g.gasStateUsed - g.gasRefunded)));
        }
    }

    /// The final state on chain (no broadcast): every balance by decryption, the disclosure view.
    function check() external {
        _load();
        for (uint256 i; i < N; ++i) (ys[i], uas[i],) = _pop(xs[i]);
        string memory e = vm.readFile(string.concat("./deployments/", vm.toString(block.chainid), "-zether-e2e.json"));
        (t, wt) = (e.readAddress(".normal_zether_token"), e.readAddress(".wrapped_zether_token"));
        _expect(t, 0, SHIELDED - SINGLE - MULTI4 - MULTI2 - UNSHIELD - RELAYED_SINGLE - RELAYED_MULTI - RELAYED_UNSHIELD - NAMED_SINGLE
            - NAMED_MULTI - NAMED_UNSHIELD, 0, "chain: alice");
        _expect(t, 1, SINGLE + MULTI4, RELAYED_SINGLE + RELAYED_MULTI + NAMED_SINGLE + NAMED_MULTI, "chain: bob");
        _expect(t, 2, 0, MULTI2, "chain: carol");
        for (uint256 i = 3; i < N; ++i) _expect(t, i, 0, 0, string.concat("chain: decoy ", vm.toString(i - 2)));
        require(NormalZetherToken(t).totalShielded() == SHIELDED - UNSHIELD - RELAYED_UNSHIELD - NAMED_UNSHIELD, "chain: totalShielded");
        _expect(wt, 0, WRAPPED, 0, "chain: alice (wrapped)");
        require(dis.verifyTransferAmount(t, e.readBytes32(".entry_single"), 0, SINGLE, ITransferDisclosure.OpeningKind.SENDER_S,
            abi.encode(e.readBytes32(".s_single"))), "chain: disclosure view");
        console.log("ok    chain: disclosure view verifyTransferAmount(single, 100, SENDER_S) = true");
    }
}

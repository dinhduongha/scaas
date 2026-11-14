// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {console2} from "forge-std/console2.sol";
import {PqzKeysKit} from "./PqzKeys.s.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {IPqzToken} from "../../src/pqz/IPqzToken.sol";
import {PqzCore} from "../../src/pqz/PqzCore.sol";
import {PqzCt} from "../../src/pqz/PqzCt.sol";
import {NormalPqzToken} from "../../src/pqz/NormalPqzToken.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {GovernanceBits} from "../../src/governance/GovernanceBits.sol";

/// @notice Group `pqzwallet` (spec 2026-11-13-pqz-three-keys §15.2, the wallet-side rows; CLI-SGN-51): real ciphertexts and sealed
///         openings on two opening tokens of the pqzkeys group's factory, class 2 (`offchain-shared`) and class 3 with the
///         opening, each with an auditor (`erin`, `OPTIONAL`). The wallet is `script/pqz/wallet` (`pqz-wallet-sim`, through
///         `vm.ffi`): the sender side by pqz-ffi (split randomness, the openings, planted bad credits); the holder side ALL through
///         ua-rs `pqz3k::PqzKeyHandle` (each credit checked into an acceptance or a skip, the marks it may sign, the debit window
///         that alone hands the PQZ secret to the decryption of `T`); the auditor tool by pqz-ffi `check_auditor`. Two runs
///         (`pqzwallet.sh`, after pqzkeys): `setup()` the holders dave (recipient) and erin (auditor) with real scoped keys, the
///         tokens, bob's credits to dave (honest; planted: junk opening, a valid KEM ciphertext of another seed, a moved `v_t`;
///         with the auditor: honest, junk `O_a`, junk `O_t`, `O_a` under other coins); after `ROLL_AGE` blocks `roll()`: the
///         wallet refuses the window while a skip is unmarked (no secret loaded), marks the skips by the signed rollover
///         (`n = 0`), opens the window (the balance decrypted = the accepted amounts), refreshes; the auditor tool's outcomes;
///         on the class-3 token a modified wallet refreshes past an unreadable entry unmarked: `unreadable, taken`.
///         Reads: the matrix's chain is one anvil node with instant finality, so the wallet's reads are that node's at the
///         latest block, given to the handle as finalized and strict-majority (the rule of CLI-SGN-51 for one node of one).
///         Test keys and seeds only. UNAUDITED.
abstract contract PqzWalletKit is PqzKeysKit {
    string internal constant TOOL = "script/pqz/wallet/target/release/pqz-wallet-sim";
    address internal c2w; // kind 4, class 2, auditor erin
    address internal c3w; // kind 4, class 3 with the opening, auditor erin
    bytes32 internal dave;
    bytes32 internal daveMl;
    bytes32 internal erin;
    bytes32 internal erinMl;
    bytes internal dave64; // the BIP-39 seeds of the PQZ keys (test only)
    bytes internal erin64;

    function _wstate() internal view returns (string memory) {
        return string.concat("deployments/pqzwallet-", net, "-state.json");
    }

    /// One wallet call: its input through a file (git-ignored deployments/; an argument holds at most 128 KiB), its JSON answer.
    function _tool(string memory json) internal returns (string memory out) {
        string memory f = string.concat("deployments/pqzwallet-", net, "-in.json");
        vm.writeFile(f, json);
        string[] memory c = new string[](3);
        (c[0], c[1], c[2]) = ("sh", "-c", string.concat(TOOL, " < ", f));
        out = string(vm.ffi(c));
        require(bytes(out).length > 0 && bytes(out)[0] == "{", "pqz-wallet-sim gave no JSON");
    }

    function _scope(address t) internal view returns (address) {
        return IPqzToken(t).pqzVerifyConfig().pqzOwnKey ? t : address(0);
    }

    function _rec(bytes memory seed64, bytes32 ua, address scope) internal view returns (string memory) {
        return string.concat('"seed":"', vm.toString(seed64), '","ua":"', vm.toString(ua), '","chainUid":"',
            vm.toString(IUARegistry(registry).chainUid()), '","scope":', scope == address(0) ? "null" : string.concat('"',
            vm.toString(scope), '"'), ',"version":0');
    }

    function _keyOf(bytes32 ua, address scope) internal view returns (bytes memory k) {
        (address p,,) = IUARegistry(registry).pqzScopedKeyAt(ua, scope, 0);
        bytes memory c = p.code;
        k = new bytes(c.length - 1);
        for (uint256 i; i < k.length; ++i) k[i] = c[i + 1];
    }

    function _kemOf(bytes32 ua, address scope) internal view returns (bytes memory) {
        return UAKinds.kemPk(IUARegistry(registry).pqzOpenKemAt(ua, scope, 0));
    }

    function _authBy(bytes32 mlSeed_, address t, uint8 op, bytes memory st) internal returns (IUARegistry.UASig memory) {
        return _uaSig(mlSeed_, UAKinds.PURPOSE_ZETHER_AUTH, _authDigest(t, op, st));
    }

    // as PqzKeysSetup / PqzKeysRoll (their helpers live in those contracts, not in the kit)

    /// An ML-DSA-65 UA registered as `_registerMl` (Tokens), its seed from this run.
    function _holder(string memory who) internal returns (bytes32 seed, bytes32 ua) {
        seed = keccak256(abi.encode(runSalt, "pqzwallet", who));
        bytes memory pk = _ml(string.concat("keygen 65 ", _bare(seed)));
        ua = UAKinds.uaOf(ML65, pk);
        bytes32 rd = UAKinds.registrationDigest(ua, ML65, 0, UAKinds.kemRecordHash(ua, 0, bytes("")), 0);
        bytes memory pop = _mlBy(seed, IUARegistry(registry).uaMessage(ML65, UAKinds.PURPOSE_POP_V2, rd));
        IUARegistry.UAAttrs memory none;
        vm.startBroadcast(k1);
        IUARegistry(registry).cacheExpandedKey{gas: 56_000_000}(ML65, pk, 0);
        IUARegistry(registry).cacheExpandedKey{gas: 56_000_000}(ML65, pk, 1);
        require(IUARegistry(registry).register{gas: 56_000_000}(ML65, pk, none, pop, "") == ua, "holder UA");
        vm.stopBroadcast();
    }

    function _shield(address t, bytes32 ua, uint256 amount) internal {
        vm.broadcast(k1);
        NormalPqzToken(t).mtxShield(ua, amount);
    }

}

/// @notice Run 1: the holders, their real scoped keys, the two tokens, bob's credits to dave.
contract PqzWalletSetup is PqzWalletKit {
    function setup() external {
        _init("pqzwallet");
        _vInit();
        registry = _dep("ua_registry");
        string memory j = vm.readFile(_state()); // pqzkeys' run 1: its factory, bob
        fp = OpenFactory(vm.parseJsonAddress(j, ".fp"));
        (bob, bobSeed) = (vm.parseJsonBytes32(j, ".bob"), vm.parseJsonBytes32(j, ".bobSeed"));
        (carol, carolSeed) = (vm.parseJsonBytes32(j, ".carol"), vm.parseJsonBytes32(j, ".carolSeed"));
        (daveMl, dave) = _holder("dave");
        (erinMl, erin) = _holder("erin");
        dave64 = abi.encodePacked(keccak256(abi.encode(runSalt, "dave64a")), keccak256(abi.encode(runSalt, "dave64b")));
        erin64 = abi.encodePacked(keccak256(abi.encode(runSalt, "erin64a")), keccak256(abi.encode(runSalt, "erin64b")));
        _real(dave, daveMl, dave64, address(0));
        _real(erin, erinMl, erin64, address(0)); // class 2 reads the auditor's scope-0 record at init
        c2w = _tok(false, "c2w");
        c3w = _tok(true, "c3w");
        _real(dave, daveMl, dave64, c3w);
        _real(erin, erinMl, erin64, c3w);
        _real(bob, bobSeed, abi.encodePacked(keccak256(abi.encode(runSalt, "bob64a")), keccak256(abi.encode(runSalt, "bob64b"))), c3w);
        _credits(c2w, true);
        _credits(c3w, false);
        _wsave();
        _writeBook();
    }

    /// `ua`'s record of `scope` with its real PQZ key and opening KEM key from the wallet (`keys`), signed by its ML-DSA key.
    function _real(bytes32 ua, bytes32 mlSeed_, bytes memory seed64, address scope) internal {
        string memory o = _tool(string.concat('{"cmd":"keys",', _rec(seed64, ua, scope), "}"));
        bytes memory key = vm.parseJsonBytes(o, ".pqzKey");
        bytes memory kp = vm.parseJsonBytes(o, ".openKem");
        IUARegistry.KemKey memory k;
        k.scheme = 1;
        k.mlkemEk = new bytes(1568);
        for (uint256 i; i < 1568; ++i) k.mlkemEk[i] = kp[1 + i];
        bytes32 x;
        assembly ("memory-safe") { x := mload(add(kp, add(32, 1569))) }
        k.x25519 = x;
        bytes memory pop = abi.encodePacked(keccak256(abi.encode(runSalt, ua, scope, "wallet")));
        uint64 vub = uint64(block.number + WIN);
        RecDigest memory r = RecDigest(ua, scope, 0, UAKinds.keyHashOf(UAKinds.PQZ_MLWE, key), keccak256(pop), keccak256(kp), vub,
            IUARegistry(registry).chainUid());
        IUARegistry.UASig memory s = _uaSig(mlSeed_, UAKinds.PURPOSE_PQZ_SCOPED_KEY, _rd(r));
        vm.startBroadcast(k1);
        IUARegistry(registry).setPqzScopedKey{gas: 56_000_000}(ua, scope, 0, key, keccak256(pop), k, vub, s);
        IUARegistry(registry).storePqzScopedPop{gas: 56_000_000}(ua, scope, 0, pop);
        vm.stopBroadcast();
    }

    struct RecDigest {
        bytes32 ua;
        address scope;
        uint64 v;
        bytes32 keyHash;
        bytes32 popHash;
        bytes32 kemHash;
        uint64 vub;
        bytes32 uid;
    }

    function _rd(RecDigest memory r) internal view returns (bytes32) {
        return IUARegistry(registry).pqzScopedKeyRecordDigest(r.ua, r.scope == address(0) ? 2 : 3, r.uid, r.scope, r.v,
            r.keyHash, r.popHash, r.kemHash, r.vub);
    }

    /// A kind-4 opening token, auditor erin (`OPTIONAL`), class 3 (`own`) or 2.
    function _tok(bool own, string memory what) internal returns (address x) {
        IFactoryToken.TokenConfig memory c;
        (c.name, c.symbol, c.decimals, c.admin) = (string.concat("Onchain PQZ wallet ", what), "oPQW", 6, _pad(a1));
        c.features = (1 << GovernanceBits.PAYABLE) | (1 << GovernanceBits.PQZ_PROOF);
        (c.initialSupply, c.initialHolder) = (1e15, a1);
        c.conf = IFactoryToken.ConfidentialConfig(abi.encode(erin), 10_000, uint256(1) << 40, 0, 0, 2, 0, 1, vA, false, 0, 0, 3, own,
            true);
        vm.broadcast(k1);
        x = fp.createToken(IOpenFactory.TokenKind.NORMAL_PQZ, 1, abi.encode(c), _salt(string.concat("pqzwallet-", what)));
        _book(x, "NormalPqzToken");
    }

    /// bob's op 1 credits to dave on `t`: the variants without the auditor (class 2 only: all four), then with it.
    function _credits(address t, bool all) internal {
        _shield(t, bob, 200);
        string[4] memory plain = ["honest", "junk", "wrongseed", "craftedv"];
        string[4] memory aud = ["honest", "junk_oa", "junk_ot", "oa_coins"];
        for (uint256 i; i < (all ? 4 : 2); ++i) _credit(t, plain[i], false, 5);
        for (uint256 i; i < (all ? 4 : 2); ++i) _credit(t, aud[i], true, 3);
    }

    function _credit(address t, string memory variant, bool withAud, uint256 amount) internal {
        address sc = _scope(t);
        bytes memory pkF = _keyOf(bob, sc);
        string memory q = string.concat('{"cmd":"credit","chainUid":"', vm.toString(IUARegistry(registry).chainUid()), '","token":"',
            vm.toString(t), '","toUA":"', vm.toString(dave), '","toVersion":0,"pkT":"', vm.toString(_keyOf(dave, sc)), '","kemPkT":"',
            vm.toString(_kemOf(dave, sc)));
        q = string.concat(q, '","pkF":"', vm.toString(pkF), '","balanceF":0,"amount":', vm.toString(amount), ',"seedEnc":"',
            vm.toString(keccak256(abi.encode(runSalt, t, variant, withAud))), '","variant":"', variant, '","auditor":',
            withAud ? string.concat('{"ua":"', vm.toString(erin), '","version":0,"pk":"', vm.toString(_keyOf(erin, sc)), '","kemPk":"',
                vm.toString(_kemOf(erin, sc)), '"}') : "null", "}");
        string memory o = _tool(q);
        IPqzToken.PqzTransferArgs memory a;
        (a.p, a.validUntilBlock, a.fromUA, a.toUA) = (IPqzToken(t).pqzAccount(bob, 0).pendingCount, block.number + WIN, bob, dave);
        a.salt = bytes16(keccak256(abi.encode(runSalt, variant, withAud)));
        (a.u, a.vTo, a.vFrom, a.uFrom) = (vm.parseJsonBytes(o, ".u"), vm.parseJsonBytes(o, ".vTo"), vm.parseJsonBytes(o, ".vFrom"),
            vm.parseJsonBytes(o, ".uFrom"));
        if (withAud) a.vAuditor = vm.parseJsonBytes(o, ".vAuditor");
        a.openingTo = _opening(o, ".openingTo");
        if (withAud) a.openingAuditor = _opening(o, ".openingAuditor");
        _send1(t, a, false);
        console2.log(string.concat("pqzwallet credit ", variant, withAud ? " (auditor)" : "", " to dave at index ",
            vm.toString(IPqzToken(t).pqzAccount(dave, 0).pendingCount - 1)));
    }

    function _opening(string memory o, string memory k) internal pure returns (IPqzToken.PqzOpening memory x) {
        (x.mlkemCt, x.x25519Eph, x.sealedSeed) = (vm.parseJsonBytes(o, string.concat(k, ".mlkemCt")),
            vm.parseJsonBytes32(o, string.concat(k, ".x25519Eph")), vm.parseJsonBytes(o, string.concat(k, ".sealedSeed")));
    }

    function _wsave() internal {
        vm.serializeAddress("pw", "c2w", c2w);
        vm.serializeAddress("pw", "c3w", c3w);
        vm.serializeBytes32("pw", "dave", dave);
        vm.serializeBytes32("pw", "daveMl", daveMl);
        vm.serializeBytes32("pw", "erin", erin);
        vm.serializeBytes32("pw", "erinMl", erinMl);
        vm.serializeBytes("pw", "dave64", dave64);
        string memory j = vm.serializeBytes("pw", "erin64", erin64);
        vm.writeJson(j, _wstate());
    }
}

/// @notice Run 2 (after `ROLL_AGE` blocks): the holder's wallet and the auditor tool on the credits of run 1.
contract PqzWalletRoll is PqzWalletKit {
    function roll() external {
        _init("pqzwallet");
        _vInit();
        registry = _dep("ua_registry");
        string memory j = vm.readFile(_wstate());
        (c2w, c3w) = (vm.parseJsonAddress(j, ".c2w"), vm.parseJsonAddress(j, ".c3w"));
        (dave, daveMl, erin, erinMl) = (vm.parseJsonBytes32(j, ".dave"), vm.parseJsonBytes32(j, ".daveMl"),
            vm.parseJsonBytes32(j, ".erin"), vm.parseJsonBytes32(j, ".erinMl"));
        (dave64, erin64) = (vm.parseJsonBytes(j, ".dave64"), vm.parseJsonBytes(j, ".erin64"));
        _honest(c2w, 8); // 5 + 3 accepted; six planted credits marked first
        _modified(c3w); // unmarked past its unreadable credit: the auditor's `unreadable, taken`
    }

    /// The entries of dave's `[0, pendingCount)` on `t` as the wallet's input (slot, code, the auditor's keys).
    function _wEntries(address t) internal view returns (string memory s) {
        address sc = _scope(t);
        string memory aud = string.concat('{"ua":"', vm.toString(erin), '","pk":"', vm.toString(_keyOf(erin, sc)), '","kemPk":"',
            vm.toString(_kemOf(erin, sc)), '"}');
        uint64 n = IPqzToken(t).pqzAccount(dave, 0).pendingCount;
        s = "[";
        for (uint64 i; i < n; ++i) {
            uint256 e = IPqzToken(t).pqzPending(dave, 0, i);
            bytes memory code = uint16(e >> 64) == 0 ? bytes("") : address(uint160(e >> 96)).code;
            bool audited = code.length > 1 && uint8(code[code.length - 1]) == 2;
            s = string.concat(s, i == 0 ? "" : ",", '{"index":', vm.toString(i), ',"slot":"', vm.toString(bytes32(e)), '","code":"',
                vm.toString(code), '","auditor":', audited ? aud : "null", "}");
        }
        s = string.concat(s, "]");
    }

    /// A refresh of dave at `pendingCount` on `t`: its burn args and statement.
    function _refreshArgs(address t, uint256 seed) internal view returns (IPqzToken.PqzBurnArgs memory b, bytes memory st) {
        b = _burnArgs(t, dave, seed);
        st = NormalPqzToken(t).burnStatement(b, 0, bytes32(0), 0);
    }

    /// `T` of a debit statement: header ‖ pk_f ‖ [pk_a] ‖ T ‖ u ‖ v_f ‖ [v_a] (pk_a and v_a with the auditor on).
    function _t(bytes memory st) internal pure returns (bytes memory x) {
        uint256 off = 640 + PqzCt.PK + (st.length > 640 + 2 * PqzCt.PK + PqzCt.CT + PqzCt.V ? PqzCt.PK : 0);
        x = new bytes(PqzCt.CT);
        for (uint256 i; i < x.length; ++i) x[i] = st[off + i];
    }

    function _wallet(address t, bytes memory st) internal returns (string memory) {
        return _tool(string.concat('{"cmd":"wallet",', _rec(dave64, dave, _scope(t)), ',"token":"', vm.toString(t), '","entries":',
            _wEntries(t), ',"reads":{"block":', vm.toString(block.number), ',"finalized":true,"strictMajority":true},"window":{"from":',
            vm.toString(IPqzToken(t).pqzAccount(dave, 0).rolled), ',"to":', vm.toString(IPqzToken(t).pqzAccount(dave, 0).pendingCount),
            '},"t":"', vm.toString(_t(st)), '"}'));
    }

    function _refresh(address t, IPqzToken.PqzBurnArgs memory b, bytes memory st) internal {
        IUARegistry.UASig memory au = _authBy(daveMl, t, 2, st);
        IPqzToken.PqzSignedVerdict memory sv = _sv(t, st);
        vm.broadcast(k2);
        IPqzToken(t).mtxUnshield(b, 0, bytes32(0), VPROOF, au, "", sv);
    }

    function _audit(address t) internal returns (string memory) {
        address sc = _scope(t);
        IPqzToken.AccountState memory s = IPqzToken(t).pqzAccount(dave, 0);
        return _tool(string.concat('{"cmd":"audit",', _rec(erin64, erin, sc), ',"pk":"', vm.toString(_keyOf(erin, sc)), '","token":"',
            vm.toString(t), '","rolled":', vm.toString(s.rolled), ',"floor":', vm.toString(s.floor), ',"recipient":{"ua":"',
            vm.toString(dave), '","pk":"', vm.toString(_keyOf(dave, sc)), '","kemPk":"', vm.toString(_kemOf(dave, sc)), '"},"entries":',
            _wEntries(t), "}"));
    }

    /// The honest wallet on `t`: the window refused (no secret loaded) while skips are unmarked; the marks (n = 0) by dave's
    /// signed rollover; the window opened, its balance `want`; a refresh lands; then the auditor tool.
    function _honest(address t, uint256 want) internal {
        (IPqzToken.PqzBurnArgs memory b, bytes memory st) = _refreshArgs(t, 0x9a01);
        string memory o = _wallet(t, st);
        console2.log(string.concat("pqzwallet ", vm.toString(t), " check: ", o));
        require(!vm.parseJsonBool(o, ".window.opened") && vm.parseJsonUint(o, ".secretLoads") == 0, "window refused, no secret");
        _mark(t, vm.parseJsonUintArray(o, ".marks"));
        (b, st) = _refreshArgs(t, 0x9a01);
        o = _wallet(t, st);
        console2.log(string.concat("pqzwallet ", vm.toString(t), " after the marks: ", o));
        require(vm.parseJsonBool(o, ".window.opened") && vm.parseJsonUint(o, ".secretLoads") == 1, "window opened once");
        require(vm.parseJsonUint(o, ".window.balance") == want, "the balance decrypted = the accepted amounts");
        _refresh(t, b, st);
        console2.log(string.concat("pqzwallet ", vm.toString(t), " auditor: ", _audit(t)));
    }

    /// The wallet's marks by dave's signed mark-only rollover (`n = 0`, relayed by test key 2).
    function _mark(address t, uint256[] memory m) internal {
        uint64[] memory skip = new uint64[](m.length);
        for (uint256 i; i < m.length; ++i) skip[i] = uint64(m[i]);
        uint64 vub = uint64(block.number + WIN);
        bytes32 d = _rollDigest(t, dave, 0, skip, vub, _entries(t, dave, 0, skip));
        IUARegistry.UASig memory rs = _uaSig(daveMl, UAKinds.PURPOSE_ZETHER_AUTH, d);
        vm.broadcast(k2);
        IPqzToken(t).mtxRollOverSigned(dave, 0, 0, skip, vub, rs);
        for (uint256 i; i < skip.length; ++i) require(IPqzToken(t).pqzSkipped(dave, 0, skip[i]), "marked");
    }

    /// A modified wallet on `t`: it refreshes past the credits without the check (no marks); the auditor tool then reports the
    /// unreadable credit `unreadable, taken`.
    function _modified(address t) internal {
        (IPqzToken.PqzBurnArgs memory b, bytes memory st) = _refreshArgs(t, 0x9b01);
        _refresh(t, b, st);
        string memory o = _audit(t);
        console2.log(string.concat("pqzwallet ", vm.toString(t), " auditor after a modified wallet: ", o));
    }
}

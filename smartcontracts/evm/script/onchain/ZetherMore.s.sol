// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {ZetherE2E} from "../ZetherE2E.s.sol";
import {console} from "forge-std/Script.sol";
import {Vm} from "forge-std/Vm.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC5267} from "@openzeppelin/contracts/interfaces/IERC5267.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {IZetherToken} from "../../src/zether/IZetherToken.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {GovernanceBits} from "../../src/governance/GovernanceBits.sol";
import {IGovernance} from "../../src/governance/IGovernance.sol";
import {ZetherTypes} from "../../src/zether/ZetherTypes.sol";
import {NormalZetherToken} from "../../src/zether/NormalZetherToken.sol";
import {WrappedZetherToken} from "../../src/zether/WrappedZetherToken.sol";
import {IConfidentialWrappedToken} from "../../src/confidential/IConfidentialToken.sol";
import {ITransferDisclosure} from "../../src/zether/ITransferDisclosure.sol";
import {GovernanceRouter} from "../../src/governance/GovernanceRouter.sol";
import {GovernanceRouterTypes} from "../../src/governance/GovernanceRouterBase.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";

/// @notice T66b Step 5b, group `zether`: the Zether entries `ZetherE2E.run()` does not reach, on a NORMAL_ZETHER and a
///         WRAPPED_ZETHER token of its own (the e2e's `_normal` / `_wrapped`: alice shielded and rolled over first), each
///         step checked by decryption (alice, bob): the direct single / Compact / BUNDLE transfers and unshield, the direct
///         unshield-unwrap (wrapped; its proof bound to `unwrapBinding`), `mtxRollOverBatch`, the named UA-envelope forms
///         through `zether-cli namedCall` (single, Compact, BUNDLE, unshield, unshield-unwrap), the named UA-envelope
///         shield / roll-over / roll-over batch / signed roll-over / roll-over mode (signed here by the payer EOA over the
///         entry's own struct in the token's domain), the account-owner ops `mtxRollOverSigned` / `mtxSetRollOverMode`
///         (Schnorr by the Zether key, `zether-cli ownerAuth`), the direct shield of the wrapped kind and its named
///         `mtxWrapShield` (address `WrapShield` envelope). The regulated twin (kinds 10, 11) is generated from this file by
///         zether_reg.py. Set-auditor (CTR-GOV-31, CTR-ZTH-95, plan A9): bit 32 on an OPTIONAL-auditor token of its own
///         (`_auditor`): granted to the sender's native id and to an `msig` of the sender and the payer, the new key's proof of
///         possession (`zether-cli auditorPop`), propose and apply, an audited transfer at epochs 0 and 1, an `AUDITOR`
///         disclosure of each by its epoch's key (the other key refused), then the msig's replacement through the router. Writes `deployments/<key>-zether-more.json` (its header first, NET-EVM-13). Needs --ffi, `PRIVATE_KEY` (the sender).
///         UNAUDITED contracts.
contract ZetherMore is ZetherE2E {
    using stdJson for string;

    bytes32 internal constant SALTED =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)");
    string internal constant ENV_TAIL =
        "uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)";
    bytes32 internal constant TH_ROLL_OVER =
        keccak256("ZetherRollOver(bytes32 ua,uint64 accSeq,uint64 expectedPendingSeq,uint64 validUntilBlock)");
    bytes32 internal constant TH_SET_MODE =
        keccak256("ZetherSetRollOverMode(bytes32 ua,uint8 mode,uint64 modeNonce,uint64 validUntilBlock)");

    // alice (user 0) and bob (user 1) on the token under test: acc, pending
    uint256 internal aAcc;
    uint256 internal aPend;
    uint256 internal bAcc;
    uint256 internal bPend;

    function more() external {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        me = vm.addr(pk);
        _load();
        salt = keccak256(abi.encode("scaas.onchain.zether.more", block.number));
        address payer = vm.addr(PAYER_PK);
        vm.startBroadcast(pk);
        _register();
        _normal();
        address tn = t;
        IERC20(t).transfer(payer, 200);
        _all(false);
        _wrapped();
        t = wt;
        IERC20(und).approve(wt, 1000);
        WrappedZetherToken(payable(wt)).wrap(1000);
        IERC20(wt).transfer(payer, 300);
        IERC20(und).transfer(payer, 100);
        (bool ok,) = payable(payer).call{value: 0.01 ether}(""); // gas for the payer's own approve below
        require(ok, "fund the payer");
        _all(true);
        vm.stopBroadcast();
        _wrapShieldNamed(pk, payer);
        address tb = _burner(pk, payer);
        address ta = _auditor(pk, payer);

        string memory k = "more";
        vm.serializeAddress(k, "burner_zether_token", tb);
        vm.serializeAddress(k, "auditor_zether_token", ta);
        vm.serializeAddress(k, "normal_zether_token", tn);
        vm.serializeAddress(k, "wrapped_zether_token", wt);
        string memory j = vm.serializeAddress(k, "underlying_erc20", und);
        _writeBook(bookUid, _bookPath(bookUid, "-zether-more.json"), j);
    }

    // ------------------------------------------------------------------ BURNER (round 3zb, CTR-GOV-29, O1)

    /// @dev `deployments/onchain-<net>-<script>-neg.txt` (OnchainBase's format: from to data expected what), checked by
    ///      `coverage.py neg` in zether.sh after the broadcast.
    function _negFile() internal view returns (string memory) {
        return string.concat("deployments/onchain-", vm.envOr("NET", string("local")), "-zethermore-neg.txt");
    }

    /// @dev A Normal Zether token with bit 30 (`BURNABLE` off), the seat the sender (no admin: the bit locked, as
    ///      GovBurnerKinds' kind-2 token). alice (a Zether UA, no role) is shielded 100 and unshields 30 to the payer, the
    ///      unshield sent by the payer (an EOA without the role): not gated (O1), `totalSupply()` unchanged. Then the seat's
    ///      `burn(10)` lowers it by 10; the payer's `burn` (a balance, no role) is the negative `MissingRole(30, id)`.
    function _burner(uint256 pk, address payer) internal returns (address tb) {
        tb = _burnerMake(pk, payer);
        _burnerUse(pk, payer, tb);
    }

    function _burnerMake(uint256 pk, address payer) internal returns (address tb) {
        if (vm.exists(_negFile())) vm.removeFile(_negFile());
        IFactoryToken.TokenConfig memory c;
        (c.name, c.symbol, c.decimals) = ("Zether burner", "zBRN", 6);
        c.features = 1 << GovernanceBits.PAYABLE | uint256(1) << GovernanceBits.BURNER;
        c.lockedFeatures = uint256(1) << GovernanceBits.BURNER;
        c.roles.burner = bytes32(uint256(uint160(me)));
        (c.initialSupply, c.initialHolder) = (1_000_000, me);
        c.conf = _conf(); // the burner's conf
        vm.startBroadcast(pk);
        tb = fac.createToken(
            IOpenFactory.TokenKind.NORMAL_ZETHER, 1, abi.encode(c), keccak256(abi.encode(salt, "burner"))
        );
        console.log(string.concat("      BURNER Zether token at ", vm.toString(tb)));
        NormalZetherToken(tb).mtxShield(uas[0], 100);
        NormalZetherToken(tb).mtxRollOver(uas[0], 1);
        IERC20(tb).transfer(payer, 50);
        (bool ok,) = payable(payer).call{value: 0.05 ether}(""); // the payer's gas for its unshield
        require(ok, "fund the payer");
        vm.stopBroadcast();
        _expect(tb, 0, 100, 0, "BURNER token: alice shielded 100");
    }

    function _burnerUse(uint256 pk, address payer, address tb) internal {
        uint256 s0 = IERC20(tb).totalSupply();
        bytes memory cd = _cli(
                "proveBurn", _req(tb, 100, string.concat(',"amount":30,', _q("recipient", vm.toString(payer))))
            )
            .readBytes(".directCalldata");
        vm.broadcast(PAYER_PK);
        (bool ok,) = tb.call(cd);
        require(ok, "BURNER token: the non-holder's unshield reverted");
        require(
            IERC20(tb).totalSupply() == s0 && IERC20(tb).balanceOf(payer) == 80,
            "BURNER token: unshield not gated, supply kept"
        );
        _expect(tb, 0, 70, 0, "BURNER token: alice after unshielding 30 (sent by the payer, no role)");
        vm.broadcast(pk);
        NormalZetherToken(tb).burn(10);
        require(IERC20(tb).totalSupply() == s0 - 10, "BURNER token: the seat's burn");
        console.log("ok    BURNER token: unshield by a non-holder (supply unchanged), the seat's burn(10) (supply -10)");
        vm.writeLine(
            _negFile(),
            string.concat(
                vm.toString(payer),
                " ",
                vm.toString(tb),
                " ",
                vm.toString(abi.encodeCall(NormalZetherToken.burn, (uint256(1)))),
                " ",
                vm.toString(
                    abi.encodeWithSelector(
                        IGovernance.MissingRole.selector, GovernanceBits.BURNER, bytes32(uint256(uint160(payer)))
                    )
                ),
                " burn by a non-holder with a balance (Zether, BURNER): MissingRole(30, id)"
            )
        );
    }

    // ------------------------------------------------------------------ AUDITOR (set-auditor: CTR-GOV-31, CTR-ZTH-95)

    uint256 internal constant XA0 = uint256(keccak256("scaas.onchain.zether.auditor.0")) >> 8; // test keys, < r
    uint256 internal constant XA1 = uint256(keccak256("scaas.onchain.zether.auditor.1")) >> 8;

    /// @dev A NORMAL_ZETHER token of its own: OPTIONAL auditor with key A0, bit 32, admin the sender, grantDelay 0. Bit 32
    ///      granted to the sender's native id and to an `msig` of the sender and the payer (threshold 1, both accepted). The
    ///      sender proposes A1 with A1's proof of possession over the token's `AuditorConsent`; the delay is
    ///      `max(noticePeriod, 0)`: 0 on a local chain, where the proposal applies at once (the same call confirms it after a
    ///      delay, CTR-ZTH-95); on a chain with a notice period the proposal is checked waiting and the rest is reported not run.
    ///      An audited transfer at epoch 0 (before) and one at epoch 1 (after): `auditorKeyOf` answers each entry's key, an
    ///      `AUDITOR` opening by that key verifies and one by the other key does not. Then the msig proposes A0 back through
    ///      the router (`mtxSetAuditorKey`, its native member's signature over the router's typed struct, fee 0): epoch 2.
    function _auditor(uint256 pk, address payer) internal returns (address ta) {
        bytes memory y0 = _cli(
                "keygen", string.concat('{"curve":"bls12381","key":{', _q("x", vm.toString(bytes32(XA0))), "}}")
            )
            .readBytes(".Y");
        bytes memory y1 = _cli(
                "keygen", string.concat('{"curve":"bls12381","key":{', _q("x", vm.toString(bytes32(XA1))), "}}")
            )
            .readBytes(".Y");
        bytes32 uid = dep.readBytes32(".chain_uid");
        IFactoryToken.TokenConfig memory c;
        (c.name, c.symbol, c.decimals) = ("Zether auditor", "zAUD", 6);
        c.features = 1 << GovernanceBits.PAYABLE | uint256(1) << GovernanceBits.AUDITOR;
        (c.admin, c.initialSupply, c.initialHolder) = (bytes32(uint256(uint160(me))), 1_000_000, me);
        c.conf = _conf(); // the auditor token's conf
        (c.conf.auditorKey, c.conf.auditorMode) = (y0, uint8(ZetherTypes.AuditorMode.OPTIONAL));
        vm.startBroadcast(pk);
        ta = fac.createToken(
            IOpenFactory.TokenKind.NORMAL_ZETHER, 1, abi.encode(c), keccak256(abi.encode(salt, "auditor"))
        );
        console.log(string.concat("      AUDITOR Zether token at ", vm.toString(ta)));
        bytes32 mu = _auditorMsig(pk, payer);
        IGovernance(ta).grantRole(GovernanceBits.AUDITOR, bytes32(uint256(uint160(me))), uid);
        IGovernance(ta).grantRole(GovernanceBits.AUDITOR, mu, uid);
        NormalZetherToken(ta).mtxShield(uas[0], 100);
        NormalZetherToken(ta).mtxRollOver(uas[0], 1);
        vm.stopBroadcast();
        require(IGovernance(ta).hasRole(GovernanceBits.AUDITOR, mu), "AUDITOR token: the msig holds bit 32");
        console.log("ok    AUDITOR token: bit 32 granted to the sender's native id and to the msig");
        (t, aAcc, aPend) = (ta, 100, 0); // shielded 100 and rolled over: nothing pending
        bytes32 r0 = _audSend(y0, 10, "AUDITOR token: audited transfer at epoch 0");
        bytes memory pop = _auditorPop(XA1, ta, uid, 1);
        vm.broadcast(pk);
        NormalZetherToken(ta).setAuditorKey(y1, 1, pop, uid);
        (uint32 epoch,, uint64 eta,, uint8 st) = NormalZetherToken(ta).auditorState();
        if (epoch == 0) {
            require(st == 1, "AUDITOR token: the proposal waits");
            console.log(
                string.concat(
                    "ok    AUDITOR token: setAuditorKey proposed, waiting until ",
                    vm.toString(eta),
                    " (the factory's notice period); not run here: the confirm, the epoch-1 transfer and disclosures, the msig's op"
                )
            );
            return ta;
        }
        require(
            epoch == 1 && keccak256(NormalZetherToken(ta).auditorKey()) == keccak256(y1),
            "AUDITOR token: applied at once"
        );
        console.log("ok    AUDITOR token: setAuditorKey(A1, epoch 1) applied at once (delay 0)");
        bytes32 r1 = _audSend(y1, 10, "AUDITOR token: audited transfer at epoch 1");
        require(
            keccak256(NormalZetherToken(ta).auditorKeyOf(r0)) == keccak256(y0)
                && keccak256(NormalZetherToken(ta).auditorKeyOf(r1)) == keccak256(y1),
            "AUDITOR token: auditorKeyOf by epoch"
        );
        require(
            _audOpens(ta, r0, 10, XA0) && !_audOpens(ta, r0, 10, XA1), "AUDITOR token: epoch 0's entry opens by A0 only"
        );
        require(
            _audOpens(ta, r1, 10, XA1) && !_audOpens(ta, r1, 10, XA0), "AUDITOR token: epoch 1's entry opens by A1 only"
        );
        console.log("ok    AUDITOR token: AUDITOR disclosure at epochs 0 and 1, each by its epoch's key only");
        _auditorRouter(ta, mu, y0, uid);
        require(keccak256(NormalZetherToken(ta).auditorKey()) == keccak256(y0), "AUDITOR token: the msig's op applied");
        console.log("ok    AUDITOR token: the msig's mtxSetAuditorKey(A0, epoch 2) through the router applied");
    }

    /// @dev The new key's proof of possession over the token's `AuditorConsent` at `epoch` (`zether-cli auditorPop`, BLS12-381).
    function _auditorPop(uint256 x, address ta, bytes32 uid, uint32 epoch) internal returns (bytes memory) {
        return _cli(
                "auditorPop",
                string.concat(
                    '{"curve":"bls12381","key":{',
                    _q("x", vm.toString(bytes32(x))),
                    '},"chainId":',
                    vm.toString(block.chainid),
                    ",",
                    _q("chainUid", vm.toString(uid)),
                    ",",
                    _q("token", vm.toString(ta)),
                    ',"epoch":',
                    vm.toString(epoch),
                    "}"
                )
            )
            .readBytes(".pop");
    }

    /// @dev An msig of the sender and the payer (native ids, ascending), threshold 1, both slots accepted by their own keys;
    ///      registered once per chain (the regulated twin runs on the same chain: it reuses the record and its accepted slots).
    function _auditorMsig(uint256 pk, address payer) internal returns (bytes32 mu) {
        (address lo, address hi) = me < payer ? (me, payer) : (payer, me);
        IUARegistry.MsigStructure memory ms;
        ms.threshold = 1;
        ms.members = new IUARegistry.MsigMember[](2);
        ms.members[0] = IUARegistry.MsigMember(UAKinds.EVM_EOA, bytes32(uint256(uint160(lo))), 1);
        ms.members[1] = IUARegistry.MsigMember(UAKinds.EVM_EOA, bytes32(uint256(uint160(hi))), 1);
        IUARegistry.UAAttrs memory none;
        IUARegistry.MemberSig[] memory nopop;
        mu = UAKinds.uaOf(
            UAKinds.MSIG,
            abi.encodePacked(
                uint16(1),
                uint16(2),
                UAKinds.EVM_EOA,
                ms.members[0].id,
                uint16(1),
                UAKinds.EVM_EOA,
                ms.members[1].id,
                uint16(1)
            )
        );
        if (!reg.isRegistered(mu)) {
            require(reg.registerMsig(ms, none, nopop, "") == mu, "AUDITOR token: the msig's id");
        }
        for (uint16 i; i < 2; ++i) {
            if (reg.memberAccepted(mu, i)) continue;
            address a = i == 0 ? lo : hi;
            IUARegistry.MemberSig memory s;
            (uint8 v, bytes32 r, bytes32 ss) =
                vm.sign(a == me ? pk : PAYER_PK, UAKinds.membershipDigest(mu, bytes32(uint256(uint160(a)))));
            (s.index, s.sig) = (i, abi.encodePacked(r, ss, v));
            reg.acceptMembership(mu, s);
        }
    }

    /// @dev alice -> bob `v` on `t` audited by `y` (OPTIONAL mode, the sender's choice), checked by decryption.
    function _audSend(bytes memory y, uint256 v, string memory what) internal returns (bytes32 ref) {
        (bAcc, bPend) = _balances(t, 1);
        string memory out = _cli(
            "proveTransfer",
            _req(
                t,
                aAcc,
                string.concat(
                    ",",
                    _q("yTo", vm.toString(ys[1])),
                    ',"amount":',
                    vm.toString(v),
                    ',"auditorMode":"optional",',
                    _q("yAud", vm.toString(y))
                )
            )
        );
        vm.broadcast(vm.envUint("PRIVATE_KEY"));
        ref = _send(t, out, what);
        _moved(v, v, what);
    }

    /// @dev Does an `AUDITOR` opening of leg 0 of `ref` for `amount` by the key `x` (`zether-cli openDisclosure`) verify?
    function _audOpens(address ta, bytes32 ref, uint256 amount, uint256 x) internal returns (bool) {
        (bytes memory ct, bytes memory yt) = dis.transferCiphertext(ta, ref, 0);
        string memory r = string.concat(
            '{"curve":"bls12381","key":{',
            _q("x", vm.toString(bytes32(x))),
            '},"kind":"auditor","chainId":',
            vm.toString(block.chainid),
            ",",
            _q("chainUid", vm.toString(dep.readBytes32(".chain_uid"))),
            ",",
            _q("token", vm.toString(ta)),
            ",",
            _q("entryRef", vm.toString(ref)),
            ',"index":0,"amount":',
            vm.toString(amount)
        );
        r = string.concat(r, ",", _audParts(ct, yt, NormalZetherToken(ta).auditorKeyOf(ref)), "}");
        (bool built, bytes memory o) = _openOrRefused(r);
        if (!built) return false;
        try dis.verifyTransferAmount(ta, ref, 0, amount, ITransferDisclosure.OpeningKind.AUDITOR, o) returns (bool ok) {
            return ok;
        } catch {
            return false;
        }
    }

    /// @dev `zether-cli openDisclosure` on `r`: the opening, or `built` false when the CLI refuses a key that is not the entry's
    ///      auditor key (that refusal only; any other CLI error stops the script).
    function _openOrRefused(string memory r) internal returns (bool built, bytes memory o) {
        string[] memory a = new string[](6);
        (a[0], a[1], a[2]) = ("bash", "-c", "printf '%s' \"$2\" | \"$0\" \"$1\"");
        (a[3], a[4], a[5]) = (cli, "openDisclosure", r);
        Vm.FfiResult memory f = vm.tryFfi(a);
        if (f.exitCode != 0) {
            require(vm.contains(string(f.stderr), "opening key does not match the entry"), string(f.stderr));
            return (false, o);
        }
        return (true, string(f.stdout).readBytes(".opening"));
    }

    /// @dev The opening request's points: the recipient key, the leg's outgoing and auditor ciphertext parts, the auditor key.
    function _audParts(bytes memory ct, bytes memory yt, bytes memory ya) internal returns (string memory r) {
        r = string.concat(
            _q("Yt", vm.toString(yt)),
            ",",
            _q("Cout", vm.toString(_part(ct, 0))),
            ",",
            _q("Dout", vm.toString(_part(ct, 1))),
            ","
        );
        r = string.concat(
            r,
            _q("Ya", vm.toString(ya)),
            ",",
            _q("Caud", vm.toString(_part(ct, 2))),
            ",",
            _q("Daud", vm.toString(_part(ct, 3)))
        );
    }

    function _part(bytes memory ct, uint256 i) internal pure returns (bytes memory p) {
        p = new bytes(128);
        for (uint256 j; j < 128; ++j) {
            p[j] = ct[128 * i + j];
        }
    }

    /// @dev The msig's `mtxSetAuditorKey(key, epoch 2)` on the router: its lower native member signs the router's typed
    ///      `UASetAuditorKey` (fee mode NONE, relayer and fee recipient unbound), the sender relays at fee 0.
    function _auditorRouter(address ta, bytes32 mu, bytes memory key, bytes32 uid) internal {
        GovernanceRouter gr = GovernanceRouter(dep.readAddress(".governance_router"));
        bytes memory pop = _auditorPop(XA0, ta, uid, 2);
        MetaTxLib.UAEnvelope memory u =
            MetaTxLib.UAEnvelope(mu, 0, gr.mtxNonce(mu, 0), block.timestamp + 1 days, 0, address(0), 0, address(0));
        bytes32 sh = keccak256(
            bytes.concat(
                abi.encode(GovernanceRouterTypes.UA_SET_AUDITOR_KEY, u.from, ta, keccak256(key), uint32(2), uid),
                abi.encode(u.batch, u.nonce, u.validUntil, u.mode, address(0), u.fee, address(0))
            )
        );
        IUARegistry.UASig memory a = _auditorSig(address(gr), mu, sh);
        vm.broadcast(vm.envUint("PRIVATE_KEY"));
        gr.mtxSetAuditorKey(u, ta, key, 2, pop, uid, a);
    }

    /// @dev The msig's `UASig`: its lower native member (slot 0) signs the registry's `uaAuthDigest(member, member purpose, md)`,
    ///      `md = memberDigest(mu, uaMessage(msig, metatx, d))`, `d` the router's typed digest of the struct hash `sh` (a native
    ///      member's rule, UARegistry._memberOk / _native).
    function _auditorSig(address gr, bytes32 mu, bytes32 sh) internal returns (IUARegistry.UASig memory a) {
        address payer = vm.addr(PAYER_PK);
        bool meLow = me < payer;
        bytes32 md = UAKinds.memberDigest(
            mu,
            UAKinds.uaMessage(
                UAKinds.MSIG, UAKinds.PURPOSE_METATX, keccak256(abi.encodePacked(hex"1901", _dom(gr), sh))
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            meLow ? vm.envUint("PRIVATE_KEY") : PAYER_PK,
            reg.uaAuthDigest(bytes32(uint256(uint160(meLow ? me : payer))), UAKinds.PURPOSE_MEMBER, md)
        );
        a.members = new IUARegistry.MemberSig[](1);
        (a.members[0].index, a.members[0].sig) = (0, abi.encodePacked(r, s, v));
    }

    // ------------------------------------------------------------------ the sequence on `t`

    function _all(bool wrapped) internal {
        string memory w = wrapped ? " (wrapped)" : "";
        (aAcc, aPend) = _balances(t, 0);
        (bAcc, bPend) = _balances(t, 1);
        // direct: single, Compact M = 2, BUNDLE M = 2, unshield; unshield-unwrap (wrapped)
        _send(
            t,
            _cli("proveTransfer", _req(t, aAcc, string.concat(",", _q("yTo", vm.toString(ys[1])), ',"amount":10'))),
            string.concat("direct single transfer alice -> bob 10", w)
        );
        _moved(10, 10, "direct single");
        _send(
            t,
            _cli("proveTransferMulti", _req(t, aAcc, string.concat(',"mode":"compact"', _two(5)))),
            string.concat("direct Compact M = 2 (bob 5 + 1 decoy)", w)
        );
        _moved(5, 5, "direct Compact");
        _send(
            t,
            _cli("proveTransferMulti", _req(t, aAcc, string.concat(',"mode":"bundle"', _two(5)))),
            string.concat("direct BUNDLE M = 2 (bob 5 + 1 decoy)", w)
        );
        _moved(5, 5, "direct BUNDLE");
        (bool ok,) = t.call(
            _cli("proveBurn", _req(t, aAcc, string.concat(',"amount":7,', _q("recipient", vm.toString(me)))))
                .readBytes(".directCalldata")
        );
        require(ok, "direct unshield reverted");
        _moved(7, 0, "direct unshield 7");
        if (wrapped) _unwrapDirect();
        // the public roll-over of a batch: bob's credits to his acc
        ZetherTypes.UA[] memory b = new ZetherTypes.UA[](2);
        (b[0], b[1]) = (ZetherTypes.UA.wrap(uas[1]), ZetherTypes.UA.wrap(uas[2]));
        NormalZetherToken(t).mtxRollOverBatch(b);
        (bAcc, bPend) = (bAcc + bPend, 0);
        _check(string.concat("mtxRollOverBatch([bob, carol])", w));
        // named transfers and unshields (zether-cli namedCall), the payer's UASig
        _namedTransfers(wrapped);
        // named roll-over of bob, then a credit and the named batch roll-over
        _namedRollOver(w);
        // shields: direct (from the sender's public units), named (the payer's); the owner's signed roll-over
        NormalZetherToken(t).mtxShield(uas[0], 20);
        aPend += 20;
        _check(string.concat("direct mtxShield(alice, 20)", w));
        _namedShield(9, w);
        _rollOverSigned(w);
        _namedShield(4, w);
        _rollOverSignedNamed(w);
        _modes(w);
    }

    function _two(uint256 v) internal view returns (string memory) {
        uint256[] memory who = new uint256[](2);
        uint256[] memory amt = new uint256[](2);
        (who[0], who[1], amt[0]) = (1, 3, v);
        return _recipients(who, amt);
    }

    /// alice's acc down `a`, bob's pending up `b`, then both checked by decryption.
    function _moved(uint256 a, uint256 b, string memory what) internal {
        (aAcc, bPend) = (aAcc - a, bPend + b);
        _check(what);
    }

    function _check(string memory what) internal {
        _expect(t, 0, aAcc, aPend, string.concat(what, ": alice"));
        _expect(t, 1, bAcc, bPend, string.concat(what, ": bob"));
    }

    /// A direct `mtxUnshieldUnwrap` of 6 to the sender in the underlying: the proof bound to `unwrapBinding(leg, minOut)`,
    /// the `ZetherBurn` decoded from the build's payload (`be32 accSeq ‖ be32 sendCounter ‖ be32 validUntilBlock ‖ Y_f`).
    function _unwrapDirect() internal {
        bytes32 ub = IZetherStatementsUnwrap(dep.readAddress(".zether_statements")).unwrapBinding(und, 0);
        string memory out = _cli(
            "proveBurn",
            _req(
                t,
                aAcc,
                string.concat(
                    ',"amount":6,', _q("recipient", vm.toString(me)), ",", _q("unwrapBinding", vm.toString(ub))
                )
            )
        );
        uint256 before = IERC20(und).balanceOf(me);
        WrappedZetherToken(payable(t))
            .mtxUnshieldUnwrap(
                _burnOf(out.readBytes(".payload")),
                IConfidentialWrappedToken.Unwrap(und, MetaTxLib.pad(me), 6, 0),
                out.readBytes(".proof")
            );
        require(IERC20(und).balanceOf(me) == before + 6, "direct unshield-unwrap: underlying");
        _moved(6, 0, "direct mtxUnshieldUnwrap 6 (wrapped)");
    }

    function _burnOf(bytes memory p) internal pure returns (IZetherToken.ZetherBurn memory b) {
        (uint256 acc, uint256 sc, uint256 vub, bytes32 x0, bytes32 x1, bytes32 y0, bytes32 y1) =
            abi.decode(p, (uint256, uint256, uint256, bytes32, bytes32, bytes32, bytes32));
        (b.accSeq, b.sendCounter, b.validUntilBlock) = (uint64(acc), uint64(sc), vub);
        b.yFrom = IZetherToken.G1(x0, x1, y0, y1);
    }

    function _namedTransfers(bool wrapped) internal {
        string memory w = wrapped ? " (wrapped)" : "";
        MetaTxLib.UAMetaTransaction memory m = _envelope();
        string memory out = _cli(
            "proveTransfer",
            _req(
                t,
                aAcc,
                string.concat(_bindingOf(m), ',"uaSigner":"ecdsa",', _q("yTo", vm.toString(ys[1])), ',"amount":4')
            )
        );
        _named("UAZetherTransferSingle", m, out, "", string.concat("named single alice -> bob 4", w));
        _moved(4, 4, "named single");
        m = _envelope();
        out = _cli(
            "proveTransferMulti",
            _req(t, aAcc, string.concat(',"mode":"compact"', _bindingOf(m), ',"uaSigner":"ecdsa"', _two(3)))
        );
        _named("UAZetherTransferCompact", m, out, "", string.concat("named Compact M = 2 (bob 3)", w));
        _moved(3, 3, "named Compact");
        m = _envelope();
        out = _cli(
            "proveTransferMulti",
            _req(t, aAcc, string.concat(',"mode":"bundle"', _bindingOf(m), ',"uaSigner":"ecdsa"', _two(3)))
        );
        _named("UAZetherTransfer", m, out, "", string.concat("named BUNDLE M = 2 (bob 3)", w));
        _moved(3, 3, "named BUNDLE");
        m = _envelope();
        out = _cli(
            "proveBurn", _req(t, aAcc, string.concat(_bindingOf(m), ',"amount":2,', _q("recipient", vm.toString(me))))
        );
        _named(
            "UAZetherUnshield",
            m,
            out,
            string.concat(',"amount":2,', _q("recipient", vm.toString(MetaTxLib.pad(me)))),
            string.concat("named unshield 2", w)
        );
        _moved(2, 0, "named unshield");
        if (!wrapped) return;
        m = _envelope();
        out = _cli(
            "proveBurn", _req(t, aAcc, string.concat(_bindingOf(m), ',"amount":2,', _q("recipient", vm.toString(me))))
        );
        uint256 before = IERC20(und).balanceOf(me);
        _named(
            "UAZetherUnshieldUnwrap",
            m,
            out,
            string.concat(
                ',"unwrap":{',
                _q("underlying", vm.toString(und)),
                ",",
                _q("recipient", vm.toString(MetaTxLib.pad(me))),
                ',"amount":"2","minOut":"0"}'
            ),
            "named unshield-unwrap 2 (wrapped)"
        );
        require(IERC20(und).balanceOf(me) == before + 2, "named unshield-unwrap: underlying");
        _moved(2, 0, "named unshield-unwrap");
    }

    function _namedRollOver(string memory w) internal {
        MetaTxLib.UAMetaTransaction memory m = _envelope();
        NormalZetherToken(t)
            .mtxRollOver(
                _ue(m),
                uas[1],
                1,
                _uaSig(
                    string.concat("UARollOver(bytes32 from,bytes32 ua,uint256 n,", ENV_TAIL),
                    abi.encode(uas[1], uint256(1)),
                    m
                )
            );
        (bAcc, bPend) = (bAcc + bPend, 0);
        _check(string.concat("named mtxRollOver(bob, 1)", w));
        _send(
            t,
            _cli("proveTransfer", _req(t, aAcc, string.concat(",", _q("yTo", vm.toString(ys[1])), ',"amount":1'))),
            string.concat("direct single transfer alice -> bob 1", w)
        );
        _moved(1, 1, "direct single 1");
        ZetherTypes.UA[] memory b = new ZetherTypes.UA[](1);
        b[0] = ZetherTypes.UA.wrap(uas[1]);
        m = _envelope();
        NormalZetherToken(t)
            .mtxRollOverBatch(
                _ue(m),
                b,
                _uaSig(
                    string.concat("UARollOverBatch(bytes32 from,bytes32[] uas,", ENV_TAIL),
                    abi.encode(keccak256(abi.encodePacked(uas[1]))),
                    m
                )
            );
        (bAcc, bPend) = (bAcc + bPend, 0);
        _check(string.concat("named mtxRollOverBatch([bob])", w));
    }

    function _namedShield(uint256 v, string memory w) internal {
        MetaTxLib.UAMetaTransaction memory m = _envelope();
        NormalZetherToken(t)
            .mtxShield(
                _ue(m),
                uas[0],
                v,
                _uaSig(
                    string.concat("UAShield(bytes32 from,bytes32 toUA,uint256 amount,", ENV_TAIL),
                    abi.encode(uas[0], v),
                    m
                )
            );
        aPend += v;
        _check(string.concat("named mtxShield(alice, ", vm.toString(v), "), the payer's UASig", w));
    }

    /// alice's own roll-over (`mtxRollOverSigned`, direct): her Schnorr over typed `ZetherRollOver` in the token's domain.
    function _rollOverSigned(string memory w) internal {
        (uint64 seq, IUARegistry.UASig memory o, uint64 vub) = _ownerRoll();
        NormalZetherToken(t).mtxRollOverSigned(ZetherTypes.UA.wrap(uas[0]), seq, vub, o);
        (aAcc, aPend) = (aAcc + aPend, 0);
        _check(string.concat("mtxRollOverSigned(alice), the owner's Schnorr", w));
    }

    function _rollOverSignedNamed(string memory w) internal {
        (uint64 seq, IUARegistry.UASig memory o, uint64 vub) = _ownerRoll();
        MetaTxLib.UAMetaTransaction memory m = _envelope();
        NormalZetherToken(t)
            .mtxRollOverSigned(
                _ue(m),
                ZetherTypes.UA.wrap(uas[0]),
                seq,
                vub,
                o,
                _uaSig(
                    string.concat(
                        "UARollOverSigned(bytes32 from,bytes32 ua,uint64 expectedPendingSeq,uint64 validUntilBlock,",
                        ENV_TAIL
                    ),
                    abi.encode(uas[0], seq, vub),
                    m
                )
            );
        (aAcc, aPend) = (aAcc + aPend, 0);
        _check(string.concat("named mtxRollOverSigned(alice): the owner's Schnorr inside, the payer's UASig", w));
    }

    function _ownerRoll() internal returns (uint64 seq, IUARegistry.UASig memory o, uint64 vub) {
        IZetherToken.AccountState memory s = IZetherToken(t).accountState(ZetherTypes.UA.wrap(uas[0]));
        (seq, vub) = (s.pendingSeq, uint64(block.number + 100_000));
        o = _owner(keccak256(abi.encode(TH_ROLL_OVER, uas[0], s.accSeq, seq, vub)));
    }

    /// The roll-over mode: OWNER_ONLY by the owner directly, back to PUBLIC by the named entry (its `modeNonce` moved).
    function _modes(string memory w) internal {
        ZetherTypes.UA a = ZetherTypes.UA.wrap(uas[0]);
        uint64 vub = uint64(block.number + 100_000);
        IZetherToken.AccountState memory s = IZetherToken(t).accountState(a);
        NormalZetherToken(t)
            .mtxSetRollOverMode(
                a,
                ZetherTypes.RollOverMode.OWNER_ONLY,
                vub,
                _owner(
                    keccak256(
                        abi.encode(TH_SET_MODE, uas[0], uint8(ZetherTypes.RollOverMode.OWNER_ONLY), s.modeNonce, vub)
                    )
                )
            );
        s = IZetherToken(t).accountState(a);
        require(s.mode == ZetherTypes.RollOverMode.OWNER_ONLY, "mode OWNER_ONLY");
        console.log(string.concat("ok    mtxSetRollOverMode(alice, OWNER_ONLY), the owner's Schnorr", w));
        MetaTxLib.UAMetaTransaction memory m = _envelope();
        NormalZetherToken(t)
            .mtxSetRollOverMode(
                _ue(m),
                a,
                ZetherTypes.RollOverMode.PUBLIC,
                vub,
                _owner(
                    keccak256(abi.encode(TH_SET_MODE, uas[0], uint8(ZetherTypes.RollOverMode.PUBLIC), s.modeNonce, vub))
                ),
                _uaSig(
                    string.concat(
                        "UASetRollOverMode(bytes32 from,bytes32 ua,uint8 rollOverMode,uint64 validUntilBlock,", ENV_TAIL
                    ),
                    abi.encode(uas[0], uint8(ZetherTypes.RollOverMode.PUBLIC), vub),
                    m
                )
            );
        require(IZetherToken(t).accountState(a).mode == ZetherTypes.RollOverMode.PUBLIC, "mode PUBLIC");
        console.log(string.concat("ok    named mtxSetRollOverMode(alice, PUBLIC), the payer's UASig", w));
    }

    /// The named `mtxWrapShield` (an address `Envelope`, the payer's own key, no fee): its underlying pulled from the payer.
    function _wrapShieldNamed(uint256 pk, address payer) internal {
        vm.broadcast(PAYER_PK);
        IERC20(und).approve(wt, 10);
        MetaTxLib.Envelope memory e;
        (e.from, e.batch, e.nonce, e.validUntil) =
        (payer, 8, NormalZetherToken(wt).mtxNonce(MetaTxLib.pad(payer), 8), block.timestamp + 1 days);
        bytes32 d = keccak256(
            abi.encodePacked(
                hex"1901",
                _dom(wt),
                keccak256(
                    abi.encode(
                        keccak256(
                            "WrapShield(address from,address underlying,uint256 amountIn,bytes32 toUA,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"
                        ),
                        payer,
                        und,
                        uint256(10),
                        uas[0],
                        e.batch,
                        e.nonce,
                        e.validUntil,
                        uint32(0),
                        address(0),
                        uint256(0),
                        address(0)
                    )
                )
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PAYER_PK, d);
        vm.broadcast(pk);
        WrappedZetherToken(payable(wt)).mtxWrapShield(e, und, 10, uas[0], abi.encodePacked(r, s, v));
        aPend += 10;
        _check("named mtxWrapShield(payer's 10 -> alice) (wrapped)");
    }

    // ------------------------------------------------------------------ signing

    function _dom(address c) internal view returns (bytes32) {
        (, string memory name, string memory version, uint256 chainId, address vc, bytes32 s,) =
            IERC5267(c).eip712Domain();
        return keccak256(abi.encode(SALTED, keccak256(bytes(name)), keccak256(bytes(version)), chainId, vc, s));
    }

    function _ue(MetaTxLib.UAMetaTransaction memory m) internal pure returns (MetaTxLib.UAEnvelope memory) {
        return MetaTxLib.UAEnvelope(m.from, m.batch, m.nonce, m.validUntil, m.mode, m.relayer, m.fee, m.feeRecipient);
    }

    /// The payer's `UASig` over a named UA-envelope entry's struct `typ` (words = its own fields, a dynamic one hashed) in the
    /// token's domain, relayer / fee recipient canonical (`MetaTxLib.canon`).
    function _uaSig(string memory typ, bytes memory words, MetaTxLib.UAMetaTransaction memory m)
        internal
        view
        returns (IUARegistry.UASig memory a)
    {
        address r = m.mode & MetaTxLib.MODE_RESTRICT_RELAYER != 0 ? m.relayer : address(0);
        address f = m.mode & MetaTxLib.MODE_RESTRICT_FEE_RECIPIENT != 0 ? m.feeRecipient : address(0);
        bytes32 d = keccak256(
            abi.encodePacked(
                hex"1901",
                _dom(t),
                keccak256(
                    bytes.concat(
                        keccak256(bytes(typ)),
                        m.from,
                        words,
                        abi.encode(m.batch, m.nonce, m.validUntil, m.mode, r, m.fee, f)
                    )
                )
            )
        );
        (uint8 v, bytes32 rr, bytes32 s) = vm.sign(PAYER_PK, d);
        a.signature = abi.encodePacked(rr, s, v);
    }

    /// alice's owner signature (`zether-cli ownerAuth`: Schnorr by x under `zether-owner`) over `structHash` in the token's
    /// domain, as `UASig{signature}`.
    function _owner(bytes32 structHash) internal returns (IUARegistry.UASig memory o) {
        bytes32 d = keccak256(abi.encodePacked(hex"1901", _dom(t), structHash));
        o.signature =
            _cli("ownerAuth", string.concat("{", _key(0), ",", _q("digest", vm.toString(d)), "}")).readBytes(".sig");
    }
}

interface IZetherStatementsUnwrap {
    function unwrapBinding(address u, uint256 minOut) external view returns (bytes32);
}

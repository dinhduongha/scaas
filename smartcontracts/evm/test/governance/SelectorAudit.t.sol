// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {kindArgs, dexArgs} from "../../script/KindModules.sol";

import {MtxDigest} from "../helpers/MtxDigest.sol";
import {UACall} from "../ua/UACall.sol";
import {Test} from "forge-std/Test.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {GovernanceBits} from "../../src/governance/GovernanceBits.sol";
import {GovernanceRouter} from "../../src/governance/GovernanceRouter.sol";
import {NormalToken} from "../../src/metatx/NormalToken.sol";
import {WrappedToken} from "../../src/metatx/WrappedToken.sol";
import {MetaTxBase} from "../../src/metatx/MetaTxBase.sol";
import {UAMetaTxBase} from "../../src/metatx/UAMetaTxBase.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
import {IUALedger} from "../../src/metatx/IUALedger.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {SCaaSDex} from "../../src/dex/SCaaSDex.sol";
import {ISCaaSDex} from "../../src/dex/ISCaaSDex.sol";
import {WrappedZetherToken} from "../../src/zether/WrappedZetherToken.sol";
import {MockERC20} from "../helpers/Mocks.sol";
import {Catalogue, plainEnv} from "../helpers/Catalogue.sol";
import {UALedgerBase} from "../ua/UALedgerBase.sol";
import {ZetherFixture} from "../zether/helpers/ZetherFixture.sol";
import {PqzFixture} from "../pqz/helpers/PqzFixture.sol";
import {NormalRegulatedToken} from "../../src/regulated/NormalRegulatedToken.sol";
import {WrappedRegulatedToken} from "../../src/regulated/WrappedRegulatedToken.sol";
import {regArgs} from "../helpers/Catalogue.sol";
import {nid} from "../helpers/Ids.sol";
import {EnvKit} from "../helpers/EnvKit.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";

/// governance T13, the selector audit (spec §10.1; CTR-GOV-11; GD-6). Every external that writes state on the six kinds,
/// `SCaaSDex`, `DexPuller` and `GovernanceRouter`, read from its ABI in `FOUNDRY_OUT` (else `./out`), is a row of
/// `test/vectors/selector_audit.json` with one class: `BIT(n)`, `ADMIN`, `HOLDER_OWN`, `OWN_BALANCE`, `SIGNED`, `FACTORY`,
/// `PERMISSIONLESS(reason)`, `APPROVED(reason)` (round 3r: `OpenFactory`'s release deploys). An unclassified or moved selector fails. The sentence it pins: no entry point moves, freezes or
/// pauses a balance its caller does not own unless gated by a feature bit. Each class is checked by behaviour, a stranger
/// calling every row with zero arguments on a live instance (features on, owner and holders set, the stranger none of
/// them): a `BIT`, `ADMIN`, `HOLDER_OWN` or `FACTORY` row reverts with its named error, the refused subject the stranger's
/// own id and a `MissingRole` its own bit; any other row is refused by no governance gate. So a gated row pinned as
/// another class goes red, and so does a gate removed. No governance selector is on a governed contract's allow-lists
/// (`mtxSelectors()`, and `_uaAllowed` by a signed generic call); the router publishes no allow-list at all.
abstract contract SelectorAuditRows is Test {
    string internal constant PIN = "test/vectors/selector_audit.json";
    address internal constant STRANGER = address(0x5742A9E5);
    bytes32 internal constant OWNER_ID = bytes32(uint256(0x0A11));
    uint256 internal constant SA_PK = 0x5E1EC7; // a native key for the allow-list probes, no role anywhere
    uint256 internal constant WORDS = 64; // zero words after the selector: every entry's head decodes, offsets point at 0

    struct AuditRow {
        string sig;
        string class;
        string error;
    }

    function _pin(string memory name) internal view returns (AuditRow[] memory) {
        return abi.decode(vm.parseJsonTypeArray(vm.readFile(PIN), string.concat(".", name),
            "AuditRow(string sig,string class,string error)"), (AuditRow[]));
    }

    // ------------------------------------------------------------------ the ABI in the build's out

    /// The externals of `name` that are neither `view` nor `pure`, as canonical signatures (`methodIdentifiers`), by the
    /// ABI's names; refused when a name is overloaded across both, which the name alone could not classify. The five
    /// generic entries of `MetaTxBase` / `UAMetaTxBase` are rows whatever their mutability: the router overrides
    /// `uaExecute` and `uaBatch` as `pure` refusals, and they stay entries.
    /// The artifacts of this build: `FOUNDRY_OUT` when set (`script/pqz/at-set.sh` builds into `out/at-set-<set>`),
    /// else `out`; a fixed `out/` read another build's artifacts, or none on a fresh checkout.
    function _writes(string memory name) internal view returns (string[] memory out) {
        string memory a = vm.readFile(string.concat(vm.envOr("FOUNDRY_OUT", string("out")), "/", name, ".sol/", name, ".json"));
        string[] memory sigs = vm.parseJsonKeys(a, ".methodIdentifiers");
        (string[] memory w, string[] memory r) = _byMutability(a);
        out = new string[](sigs.length);
        uint256 n;
        for (uint256 i; i < sigs.length; ++i) {
            string memory fn = _name(sigs[i]);
            bool generic = _eq(fn, "mtxExecute") || _eq(fn, "executeMetaTransaction") || _eq(fn, "mtxBatch")
                || _eq(fn, "uaExecute") || _eq(fn, "uaBatch");
            bool writes = generic || _in(fn, w);
            require(generic || !(writes && _in(fn, r)), string.concat(name, ": ", fn, " is overloaded across view and non-view"));
            if (writes) out[n++] = sigs[i];
        }
        assembly ("memory-safe") { mstore(out, n) }
    }

    /// The ABI's function names, those that write state and those that do not, one entry at a time.
    function _byMutability(string memory a) internal view returns (string[] memory w, string[] memory r) {
        uint256 n;
        while (vm.keyExistsJson(a, string.concat(".abi[", vm.toString(n), "]"))) ++n;
        (w, r) = (new string[](n), new string[](n));
        (uint256 nw, uint256 nr) = (0, 0);
        for (uint256 i; i < n; ++i) {
            string memory e = string.concat(".abi[", vm.toString(i), "].");
            if (!_eq(vm.parseJsonString(a, string.concat(e, "type")), "function")) continue;
            string memory m = vm.parseJsonString(a, string.concat(e, "stateMutability"));
            string memory fn = vm.parseJsonString(a, string.concat(e, "name"));
            if (_eq(m, "view") || _eq(m, "pure")) r[nr++] = fn;
            else w[nw++] = fn;
        }
        assembly ("memory-safe") {
            mstore(w, nw)
            mstore(r, nr)
        }
    }

    function _name(string memory sig) internal pure returns (string memory) {
        bytes memory b = bytes(sig);
        uint256 i;
        while (b[i] != "(") ++i;
        bytes memory n = new bytes(i);
        for (uint256 k; k < i; ++k) n[k] = b[k];
        return string(n);
    }

    function _eq(string memory a, string memory b) internal pure returns (bool) {
        return keccak256(bytes(a)) == keccak256(bytes(b));
    }

    function _in(string memory s, string[] memory list) internal pure returns (bool) {
        for (uint256 i; i < list.length; ++i) if (_eq(s, list[i])) return true;
        return false;
    }

    function _starts(string memory s, string memory p) internal pure returns (bool) {
        bytes memory a = bytes(s);
        bytes memory b = bytes(p);
        if (a.length < b.length) return false;
        for (uint256 i; i < b.length; ++i) if (a[i] != b[i]) return false;
        return true;
    }

    // ------------------------------------------------------------------ the classes

    /// `BIT(n)` → n + 1; 0 for any other class.
    function _bitOf(string memory c) internal pure returns (uint256) {
        if (!_starts(c, "BIT(")) return 0;
        bytes memory b = bytes(c);
        require(b.length > 5 && b[b.length - 1] == ")", c);
        uint256 n;
        for (uint256 i = 4; i < b.length - 1; ++i) {
            require(b[i] >= "0" && b[i] <= "9", c);
            n = n * 10 + uint8(b[i]) - 48;
        }
        require(n < 256, c);
        return n + 1;
    }

    function _named(string memory c) internal pure returns (bool) {
        return _bitOf(c) != 0 || _eq(c, "ADMIN") || _eq(c, "HOLDER_OWN") || _eq(c, "FACTORY");
    }

    function _known(string memory c) internal pure returns (bool) {
        if (_named(c) || _eq(c, "OWN_BALANCE") || _eq(c, "SIGNED")) return true;
        // round 3r (spec 2026-11-10-admin-not-owner.md §5.6, §7): `APPROVED(reason)`, anyone against the admin's approval
        if (_starts(c, "APPROVED(")) return bytes(c).length > 10 && bytes(c)[bytes(c).length - 1] == ")";
        return _starts(c, "PERMISSIONLESS(") && bytes(c).length > 16 && bytes(c)[bytes(c).length - 1] == ")";
    }

    /// The governance gates: the errors that refuse a caller for who it is.
    function _gate(bytes4 e) internal pure returns (bool) {
        return e == bytes4(keccak256("MissingRole(uint8,bytes32)")) || e == bytes4(keccak256("NotAdmin(bytes32)"))
            || e == bytes4(keccak256("NotPendingAdmin(bytes32)")) || e == bytes4(keccak256("NotGuardian()"))
            || e == bytes4(keccak256("NotRateAdmin()"));
    }

    /// The class's own rule on its named error, before anything runs.
    function _classError(string memory where, AuditRow memory r) internal pure {
        bytes4 e = bytes4(keccak256(bytes(r.error)));
        if (_bitOf(r.class) != 0) {
            require(_eq(r.error, "MissingRole(uint8,bytes32)") || _eq(r.error, "NotGuardian()") || _eq(r.error, "NotRateAdmin()"),
                string.concat(where, ": a BIT row names a role's refusal"));
        } else if (_eq(r.class, "ADMIN")) {
            require(_eq(r.error, "NotAdmin(bytes32)"), string.concat(where, ": an ADMIN row names NotAdmin"));
        } else if (_eq(r.class, "HOLDER_OWN")) {
            require(_eq(r.error, "MissingRole(uint8,bytes32)") || _eq(r.error, "NotPendingAdmin(bytes32)"),
                string.concat(where, ": a HOLDER_OWN row names the holder's refusal"));
        } else {
            require(bytes(r.error).length == 0 || !_gate(e), string.concat(where, ": a gate's error on an ungated class"));
            require(!_eq(r.class, "FACTORY") || bytes(r.error).length != 0, string.concat(where, ": a FACTORY row names its error"));
        }
    }

    /// `name`'s ABI against its pin, both directions, each row's class known and its error the class's.
    function _classified(string memory name) internal returns (uint256 bad) {
        string[] memory abiSigs = _writes(name);
        AuditRow[] memory pin = _pin(name);
        string[] memory pinned = new string[](pin.length);
        for (uint256 i; i < pin.length; ++i) {
            pinned[i] = pin[i].sig;
            string memory where = string.concat(name, ".", pin[i].sig);
            if (!_in(pin[i].sig, abiSigs)) {
                emit log_string(string.concat("moved or gone: ", where));
                ++bad;
            }
            if (!_known(pin[i].class)) {
                emit log_string(string.concat("no class: ", where, " ", pin[i].class));
                ++bad;
            }
            _classError(where, pin[i]);
        }
        for (uint256 i; i < abiSigs.length; ++i) {
            if (!_in(abiSigs[i], pinned)) {
                emit log_string(string.concat("unclassified: ", name, ".", abiSigs[i]));
                ++bad;
            }
            require(!_eq(_name(abiSigs[i]), "initHolder"), string.concat(name, ": initHolder has an external entry"));
        }
    }

    // ------------------------------------------------------------------ a stranger on every row

    function _stranger(string memory name, address c) internal {
        AuditRow[] memory pin = _pin(name);
        bytes32 me = bytes32(uint256(uint160(STRANGER)));
        for (uint256 i; i < pin.length; ++i) {
            AuditRow memory r = pin[i];
            string memory where = string.concat(name, ".", r.sig, " ", r.class);
            uint256 snap = vm.snapshotState();
            vm.prank(STRANGER);
            (bool ok, bytes memory ret) = c.call(bytes.concat(bytes4(keccak256(bytes(r.sig))), new bytes(32 * WORDS)));
            vm.revertToState(snap);
            bytes4 e = ret.length >= 4 ? bytes4(ret) : bytes4(0);
            if (bytes(r.error).length == 0) {
                assertTrue(ok || !_gate(e), string.concat(where, ": a governance gate refuses the stranger"));
                continue;
            }
            assertFalse(ok, string.concat(where, ": the stranger passed"));
            assertEq(e, bytes4(keccak256(bytes(r.error))), string.concat(where, ": not its named error"));
            if (_eq(r.error, "MissingRole(uint8,bytes32)")) {
                (uint8 bit, bytes32 who) = abi.decode(_args(ret), (uint8, bytes32));
                assertEq(who, me, where);
                if (_bitOf(r.class) != 0) assertEq(uint256(bit) + 1, _bitOf(r.class), string.concat(where, ": another bit"));
            } else if (_eq(r.error, "NotAdmin(bytes32)") || _eq(r.error, "NotPendingAdmin(bytes32)")) {
                assertEq(abi.decode(_args(ret), (bytes32)), me, where);
            }
        }
    }

    function _args(bytes memory ret) internal pure returns (bytes memory a) {
        a = new bytes(ret.length - 4);
        for (uint256 i; i < a.length; ++i) a[i] = ret[i + 4];
    }

    // ------------------------------------------------------------------ the allow-lists of a governed token

    /// Every gated row (`BIT`, `ADMIN`, `HOLDER_OWN`, `FACTORY`) is off `mtxSelectors()`, and a native signer's own
    /// `executeMetaTransaction` / `mtxExecute` of it is refused by the allow-list, past its valid signature. (ua-mtx-merge
    /// T1, meaning: on the merged `mtxExecute` a native signer reads `_mtxRule` (B), so `MtxSelectorNotAllowed` where
    /// `uaExecute` answered `MetaTxUnknownOp` from `_uaAllowed`; the address `mtxExecute` left tokens, R3's alias stays.)
    function _relay(string memory name, address t) internal {
        AuditRow[] memory pin = _pin(name);
        (bytes4[] memory published,,) = IMetaTx(t).mtxSelectors();
        for (uint256 i; i < pin.length; ++i) {
            if (!_named(pin[i].class)) continue;
            bytes4 sel = bytes4(keccak256(bytes(pin[i].sig)));
            string memory where = string.concat(name, ".", pin[i].sig);
            for (uint256 k; k < published.length; ++k) assertTrue(published[k] != sel, string.concat(where, ": on mtxSelectors()"));
            assertEq(_mtxProbe(t, sel), IMetaTx.MtxSelectorNotAllowed.selector,
                string.concat(where, ": relayable by executeMetaTransaction"));
            assertEq(_uaProbe(t, sel), IMetaTx.MtxSelectorNotAllowed.selector, string.concat(where, ": relayable by mtxExecute"));
        }
    }

    function _sign(bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(SA_PK, digest);
        return abi.encodePacked(r, s, v);
    }

    /// The revert of a signed `executeMetaTransaction` of `sel` (one zero word), or 0 when it ran.
    function _mtxProbe(address t, bytes4 sel) internal returns (bytes4) {
        MetaTxLib.MetaTransaction memory m = MetaTxLib.MetaTransaction(vm.addr(SA_PK), bytes.concat(sel, bytes32(0)), 9,
            UAMetaTxBase(t).mtxNonce(MetaTxLib.pad(vm.addr(SA_PK)), 9), block.timestamp + 300, 0, address(0), 0, address(0));
        return _probe(t, abi.encodeCall(MetaTxBase.executeMetaTransaction, (m, _sign(MtxDigest.metaTx(t, m)))));
    }

    function _uaProbe(address t, bytes4 sel) internal returns (bytes4) {
        bytes32 from = bytes32(uint256(uint160(vm.addr(SA_PK))));
        MetaTxLib.UAMetaTransaction memory m = MetaTxLib.UAMetaTransaction(from, bytes.concat(sel, bytes32(0)), 9,
            UAMetaTxBase(t).mtxNonce(from, 9), block.timestamp + 300, 0, address(0), 0, address(0));
        return _probe(t, abi.encodeCall(UAMetaTxBase.mtxExecute, (m, UACall.auth(m.from, _sign(UAMetaTxBase(t).mtxDigest(m))))));
    }

    function _probe(address t, bytes memory cd) internal returns (bytes4 e) {
        uint256 snap = vm.snapshotState();
        (bool ok, bytes memory ret) = t.call(cd);
        vm.revertToState(snap);
        if (!ok && ret.length >= 4) e = bytes4(ret);
    }

    // ------------------------------------------------------------------ fixtures

    /// Features on for every power, owner `OWNER_ID`, the holders the test (a contract: the contract-only rate bit) and
    /// `OWNER_ID`; never the stranger.
    function _govern(IFactoryToken.TokenConfig memory c, address leg) internal view {
        c.admin = OWNER_ID;
        c.features |= (uint256(1) << GovernanceBits.PAYABLE) | (uint256(1) << GovernanceBits.MINTABLE);
        c.roles.minter = bytes32(uint256(uint160(address(this))));
        if (leg == address(0)) return;
        c.features |= (uint256(1) << GovernanceBits.RATE_ADJUSTABLE) | (uint256(1) << GovernanceBits.WRAP_DISABLEABLE);
        (c.roles.guardian, c.roles.rateAdmin) = (OWNER_ID, bytes32(uint256(uint160(address(this)))));
        c.lockedFeatures = 0;
        c.legs = new IFactoryToken.Leg[](1);
        c.legs[0] = IFactoryToken.Leg(leg, 1, 1);
        c.rate = IFactoryToken.RateConfig(2 days, 1000);
        c.maxSupply = 1e30; // a wrapped kind with MINTABLE is a hybrid (spec §5)
    }
}

/// A contract id for the regulated kinds' compliance holder (contract-only bit 10; `FORCE` and `RECORD` never one id).
contract AuditHolder {}

/// `NORMAL`, `WRAPPED`, `SCaaSDex`, its `DexPuller`, the `GovernanceRouter`, `NORMAL_REGULATED`, `WRAPPED_REGULATED`; and
/// the ABI of all fifteen against the pin (plan T32: the regulated kinds 8-13 are their base kind's rows and the eight
/// control entries, each `BIT(n)` as the existing powers, F-31).
contract SelectorAuditPlainTest is SelectorAuditRows, UALedgerBase {
    GovernanceRouter internal router;
    NormalToken internal nt;
    WrappedToken internal wt;
    SCaaSDex internal dex;
    NormalRegulatedToken internal nr;
    WrappedRegulatedToken internal wr;
    OpenFactory internal fac; // round 3r: the test its admin, configured (no router)

    /// The test is the factory of every clone and registered no token.
    function isToken(address) external pure returns (bool) { return false; }

    function setUp() public override {
        super.setUp();
        router = new GovernanceRouter(chainUidA, REG_L, address(0), false);
        IFactoryToken.ChainEnv memory e = EnvKit.env(chainUidA, REG_L, address(0), false, address(router));
        IFactoryToken.TokenConfig memory c;
        (c.name, c.symbol, c.decimals) = ("N", "N", 6);
        _govern(c, address(0));
        nt = NormalToken(EnvKit.clone(address(new NormalToken(address(this), kindArgs(0, address(this), ""))), e));
        nt.initialize(nid(address(this)), 1, abi.encode(c));
        IFactoryToken.TokenConfig memory w;
        (w.name, w.symbol, w.decimals) = ("W", "W", 6);
        _govern(w, address(new MockERC20("Leg", "LEG", 6)));
        wt = WrappedToken(payable(EnvKit.clone(address(new WrappedToken(address(this), kindArgs(1, address(this), ""))), e)));
        wt.initialize(nid(address(this)), 1, abi.encode(w));
        dex = SCaaSDex(EnvKit.clone(address(new SCaaSDex(address(this), dexArgs(address(this)))), e));
        dex.initialize(nid(address(this)), 1, abi.encode(ISCaaSDex.DexConfig(OWNER_ID, 0, address(0x7EA5), false, 0, address(0))));
        _regulate(c);
        nr = NormalRegulatedToken(EnvKit.clone(address(new NormalRegulatedToken(address(this), kindArgs(8, address(this), regArgs()))), e));
        nr.initialize(nid(address(this)), 1, abi.encode(c));
        _regulate(w);
        wr = WrappedRegulatedToken(payable(EnvKit.clone(address(new WrappedRegulatedToken(address(this), kindArgs(9, address(this), regArgs()))), e)));
        wr.initialize(nid(address(this)), 1, abi.encode(w));
        fac = new OpenFactory(nid(address(this)));
        EnvKit.genesis(chainUidA);
        fac.configureChain(chainUidA, 0, address(0), bytes32(0), 0, bytes32(0));
    }

    /// The regulated controls on (5, 6, 7, 10, 22, 23): the issuer the test, the compliance holder another contract; bit 22
    /// has no init holder, so the stranger's refusal is the role's; bit 23 (pay-meta-tax T39) is the issuer's, with a
    /// recipient.
    function _regulate(IFactoryToken.TokenConfig memory c) internal {
        c.features |= (uint256(1) << 5) | (uint256(1) << 6) | (uint256(1) << 7) | (uint256(1) << 10)
            | (uint256(1) << GovernanceBits.OPERATOR_TRANSFER) | (uint256(1) << GovernanceBits.TAX);
        c.reg.taxRecipient = bytes32(uint256(0x7A0));
        (c.roles.issuer, c.roles.compliance) = (bytes32(uint256(uint160(address(this)))),
            bytes32(uint256(uint160(address(new AuditHolder())))));
        c.reg.termsHash = keccak256("terms");
    }

    function test_everySelectorIsClassified() public {
        string[16] memory all = ["NormalToken", "WrappedToken", "NormalZetherToken", "WrappedZetherToken", "NormalPqzToken",
            "WrappedPqzToken", "SCaaSDex", "DexPuller", "GovernanceRouter", "NormalRegulatedToken", "WrappedRegulatedToken",
            "NormalZetherRegulatedToken", "WrappedZetherRegulatedToken", "NormalPqzRegulatedToken", "WrappedPqzRegulatedToken",
            "OpenFactory"];
        uint256 bad;
        for (uint256 i; i < all.length; ++i) bad += _classified(all[i]);
        assertEq(bad, 0, "every non-view external of the sixteen has exactly one pinned row");
    }

    function test_strangerRevertsOnEveryGatedRow() public {
        _stranger("NormalToken", address(nt));
        _stranger("WrappedToken", address(wt));
        _stranger("SCaaSDex", address(dex));
        _stranger("DexPuller", dex.puller());
        _stranger("GovernanceRouter", address(router));
        _stranger("NormalRegulatedToken", address(nr));
        _stranger("WrappedRegulatedToken", address(wr));
        _stranger("OpenFactory", address(fac));
    }

    function test_noGovernanceSelectorIsRelayable() public {
        _relay("NormalToken", address(nt));
        _relay("WrappedToken", address(wt));
        _relay("NormalRegulatedToken", address(nr));
        _relay("WrappedRegulatedToken", address(wr));
        // positive controls: the probes tell an allow-listed selector from a refused one
        assertTrue(_mtxProbe(address(nt), IMetaTx.cancelNonce.selector) != IMetaTx.MtxSelectorNotAllowed.selector);
        assertTrue(_uaProbe(address(nt), NormalToken.burn.selector) != IUALedger.MetaTxUnknownOp.selector);
    }

    /// The router's generic path refuses every call (`_execute`, `mtxExecute`, `mtxBatch`), `cancelNonce` included, so it
    /// publishes no allow-list row: what it lists is what is reachable, and the node's list equals it (T15).
    function test_routerPublishesNoAllowList() public view {
        (bytes4[] memory s, uint8[] memory f, uint8[] memory a) = router.mtxSelectors();
        assertEq(s.length + f.length + a.length, 0);
    }
}

/// `NORMAL_ZETHER` and `WRAPPED_ZETHER`.
contract SelectorAuditZetherTest is SelectorAuditRows, ZetherFixture {
    address internal nz;
    address internal wz;

    function setUp() public {
        _stack();
        IFactoryToken.TokenConfig memory c = _cfg(false, uint256(1) << 40);
        _govern(c, address(0));
        nz = factory.createToken(IOpenFactory.TokenKind.NORMAL_ZETHER, 1, abi.encode(c), "sa");
        Catalogue.release(factory, IOpenFactory.TokenKind.WRAPPED_ZETHER, 1, _zenv(), type(WrappedZetherToken).creationCode);
        c = _cfg(false, uint256(1) << 40);
        c.features = 0;
        _govern(c, address(new MockERC20("USD", "USD", 6)));
        wz = factory.createToken(IOpenFactory.TokenKind.WRAPPED_ZETHER, 1, abi.encode(c), "saw");
    }

    function test_strangerRevertsOnEveryGatedRow() public {
        _stranger("NormalZetherToken", nz);
        _stranger("WrappedZetherToken", wz);
    }

    function test_noGovernanceSelectorIsRelayable() public {
        _relay("NormalZetherToken", nz);
        _relay("WrappedZetherToken", wz);
    }
}

/// `NORMAL_PQZ` and `WRAPPED_PQZ`.
contract SelectorAuditPqzTest is SelectorAuditRows, PqzFixture {
    address internal np;
    address internal wp;

    function setUp() public {
        _stack();
        IFactoryToken.TokenConfig memory c = _cfg(uint256(1) << 40);
        _govern(c, address(0));
        c.features |= uint256(1) << GovernanceBits.PQZ_PROOF; // group 3h T61: bit 24 on, no holder: the stranger's MissingRole
        np = factory.createToken(IOpenFactory.TokenKind.NORMAL_PQZ, 1, abi.encode(c), "sa");
        _releaseWrapped();
        c = _cfg(uint256(1) << 40);
        c.features = 0;
        _govern(c, address(new MockERC20("USD", "USD", 6)));
        c.features |= uint256(1) << GovernanceBits.PQZ_PROOF;
        wp = factory.createToken(IOpenFactory.TokenKind.WRAPPED_PQZ, 1, abi.encode(c), "saw");
    }

    function test_strangerRevertsOnEveryGatedRow() public {
        _stranger("NormalPqzToken", np);
        _stranger("WrappedPqzToken", wp);
    }

    function test_noGovernanceSelectorIsRelayable() public {
        _relay("NormalPqzToken", np);
        _relay("WrappedPqzToken", wp);
    }
}

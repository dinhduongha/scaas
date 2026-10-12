// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {UARegistry} from "../../src/ua/UARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {NoUnderlyingToken} from "../../src/metatx/NoUnderlyingToken.sol";
import {UnderlyingToken} from "../../src/metatx/UnderlyingToken.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {MockERC20} from "../helpers/Mocks.sol";
import {ZetherKeys} from "../zether/helpers/ZetherKeys.sol";
import {noneInit, underlyingInit, Rate} from "../v2/helpers/V2Fixture.sol";
import {UARegistryBase} from "./UARegistryBase.sol";

/// The UA ledger fixture (accounts.md CTR-UA-18/19/26): a registry at `REG_L` on context A (chain 31337, `chainUidA`)
/// with the stand-in verifier for the eight classical kinds and `zether-bn254`; a `NONE` clone and a one-leg 1:1
/// `UNDERLYING` clone bound to it; two registered SIGNING UAs (`p256`, `bip340`) and a registered Zether UA.
abstract contract UALedgerBase is UARegistryBase {
    using MetaTxLib for MetaTxLib.UAMetaTransfer;
    using MetaTxLib for MetaTxLib.UAMetaTransaction;

    address internal constant REG_L = 0x5Ca0000000000000000000000000000000000003;
    uint256 internal constant ALICE_PK = 0xA11CE;
    uint256 internal constant BOB_PK = 0xB0B;
    address internal constant RELAYER = address(0xBEEF);
    address internal constant FEE_TO = address(0xFEE);
    uint32 internal constant RR = MetaTxLib.MODE_RESTRICT_RELAYER;
    uint32 internal constant RF = MetaTxLib.MODE_RESTRICT_FEE_RECIPIENT;
    uint32 internal constant PCT = MetaTxLib.MODE_FEE_PERCENT;
    uint32 internal constant FIX = MetaTxLib.MODE_FEE_FIXED;
    address internal constant POOL = MetaTxLib.UA_POOL;

    UARegistry internal lreg;
    NoUnderlyingToken internal tok;
    UnderlyingToken internal wrp;
    MockERC20 internal und;
    address internal alice;
    address internal bob;
    bytes32 internal uaP; // p256 (0x0101)
    bytes32 internal uaB; // bip340 (0x0103)
    bytes32 internal uaZ; // zether-bn254 (0x0140)

    function setUp() public virtual override {
        super.setUp();
        UARegistry.KindConfig[] memory base = _cfgs(address(mock));
        UARegistry.KindConfig[] memory c = new UARegistry.KindConfig[](base.length + 1);
        for (uint256 i; i < base.length; ++i) c[i] = base[i];
        c[base.length] = UARegistry.KindConfig(UAKinds.ZETHER_BN254, address(mock), 50_000);
        lreg = _deploy(REG_L, chainUidA, address(0), false, BUDGET, address(0), true, c);
        uaP = _register(lreg, UAKinds.P256, _key(UAKinds.P256));
        uaB = _register(lreg, UAKinds.BIP340, _key(UAKinds.BIP340));
        uaZ = _register(lreg, UAKinds.ZETHER_BN254, ZetherKeys.pub(0xA11CE5, false));
        (alice, bob) = (vm.addr(ALICE_PK), vm.addr(BOB_PK));
        vm.warp(1_800_000_000);
        tok = NoUnderlyingToken(Clones.clone(address(new NoUnderlyingToken(address(this), address(0), chainUidA, REG_L, false))));
        tok.initialize(address(this), 1, noneInit("Points", "PTS", 6, 1_000_000, alice, address(this)));
        und = new MockERC20("Und", "UND", 6);
        wrp = UnderlyingToken(Clones.clone(address(new UnderlyingToken(address(this), address(0), chainUidA, REG_L, false))));
        address[] memory us = new address[](1);
        uint256[] memory one = new uint256[](1);
        (us[0], one[0]) = (address(und), 1);
        Rate memory fixedRate;
        wrp.initialize(address(this), 1, underlyingInit(us, one, one, 6, fixedRate, address(0), address(0)));
    }

    // ----- structs -----

    function _t(bytes32 from, bytes32 to, uint256 value) internal view returns (MetaTxLib.UAMetaTransfer memory t) {
        t = MetaTxLib.UAMetaTransfer({
            from: from, to: to, value: value, entryRef: 0, batch: 1, nonce: tok.uaNonce(from, 1),
            validUntil: block.timestamp + 300, mode: RR, relayer: RELAYER, fee: 0, feeRecipient: address(0)
        });
    }

    function _m(address token, bytes32 from, bytes memory data) internal view returns (MetaTxLib.UAMetaTransaction memory m) {
        m = MetaTxLib.UAMetaTransaction({
            from: from, data: data, batch: 1, nonce: NoUnderlyingToken(token).uaNonce(from, 1),
            validUntil: block.timestamp + 300, mode: RR, relayer: RELAYER, fee: 0, feeRecipient: address(0)
        });
    }

    // ----- authorization: a native id signs the v3 digest itself; a derived UA through the registry (`metatx`) -----

    function _authFor(bytes32 from, bytes32 digest) internal view returns (bytes memory) {
        if (from == _pad(alice)) return _ecdsa(ALICE_PK, digest);
        if (from == _pad(bob)) return _ecdsa(BOB_PK, digest);
        uint16 kind = lreg.kindOf(from);
        bytes memory k = kind == UAKinds.P256 ? _key(UAKinds.P256) : _key(UAKinds.BIP340);
        return _auth(lreg, kind, k, UAKinds.PURPOSE_METATX, digest);
    }

    function _authT(address token, MetaTxLib.UAMetaTransfer memory t) internal view returns (bytes memory) {
        return _authFor(t.from, NoUnderlyingToken(token).uaTransferDigest(t));
    }

    function _authM(address token, MetaTxLib.UAMetaTransaction memory m) internal view returns (bytes memory) {
        return _authFor(m.from, NoUnderlyingToken(token).uaDigest(m));
    }

    function _xfer(MetaTxLib.UAMetaTransfer memory t) internal {
        bytes memory a = _authT(address(tok), t);
        vm.prank(RELAYER);
        tok.uaExecuteTransfer(t, a);
    }

    function _xferReverts(MetaTxLib.UAMetaTransfer memory t, bytes memory err) internal {
        bytes memory a = _authT(address(tok), t);
        vm.expectRevert(err);
        vm.prank(RELAYER);
        tok.uaExecuteTransfer(t, a);
    }

    /// `amount` of alice's native balance into `ua`.
    function _fund(bytes32 ua, uint256 amount) internal {
        vm.prank(alice);
        tok.transferToUA(ua, amount);
    }

    /// One-leg 1:1 wrapper units for `who`, by a direct wrap.
    function _wrapFor(address who, uint256 amount) internal {
        und.mint(who, amount);
        vm.startPrank(who);
        und.approve(address(wrp), amount);
        wrp.wrap(amount);
        vm.stopPrank();
    }
}

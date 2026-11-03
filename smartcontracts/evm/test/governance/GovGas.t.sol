// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {NormalToken} from "../../src/metatx/NormalToken.sol";
import {WrappedToken} from "../../src/metatx/WrappedToken.sol";
import {IERC20MetaTx} from "../../src/metatx/IERC20MetaTx.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {WrappedPqzToken} from "../../src/pqz/WrappedPqzToken.sol";
import {WrappedZetherToken} from "../../src/zether/WrappedZetherToken.sol";
import {MockERC20} from "../helpers/Mocks.sol";
import {plainEnv, Catalogue, pqzEnv} from "../helpers/Catalogue.sol";
import {PqzFixture} from "../pqz/helpers/PqzFixture.sol";
import {PQZ_UID} from "../pqz/helpers/PqzRegistryBase.sol";
import {ZetherFixture} from "../zether/helpers/ZetherFixture.sol";
import {nid} from "../helpers/Ids.sol";

/// @notice Plain `transfer` and `mtxTransfer` per kind, for the governance prototype (D1, D2; before and after,
///         `docs/research/governance/prototype/`). One row per test, so each measures from a fresh `setUp`. Written against
///         ABI strings and literal bits only: the same file compiles on the code before and after the prototype.
abstract contract GovRows is Test {
    uint256 internal constant G_PK = 0xA11CE;
    address internal constant G_TO = address(0xCAFE);
    address internal constant G_RELAYER = address(0xBEEF);
    uint256 internal constant G_LANE = 1;

    function _gSigner() internal pure returns (address) { return vm.addr(G_PK); }

    /// Both sides hold a balance and lane `G_LANE` is past nonce 0, so neither row pays a first write.
    function _prime(address t) internal {
        address s = _gSigner();
        vm.prank(s);
        (bool ok,) = t.call(abi.encodeWithSignature("transfer(address,uint256)", G_TO, 1));
        assertTrue(ok, "prime transfer");
        vm.prank(G_RELAYER);
        (ok,) = t.call(_mtxCall(t, 0));
        assertTrue(ok, "prime mtxTransfer");
    }

    function _mtxCall(address t, uint256 nonce) internal view returns (bytes memory) {
        MetaTxLib.MetaTransfer memory x = MetaTxLib.MetaTransfer({from: _gSigner(), to: G_TO, value: 1, entryRef: 0,
            batch: G_LANE, nonce: nonce, validUntil: block.timestamp + 600, mode: 0, relayer: address(0), fee: 0,
            feeRecipient: address(0)});
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(G_PK, IERC20MetaTx(t).mtxTransferDigest(x));
        return abi.encodeWithSignature(
            "mtxTransfer(address,address,uint256,uint256,uint256,uint256,uint32,address,bytes)",
            x.from, x.to, x.value, x.batch, x.nonce, x.validUntil, x.mode, x.relayer, abi.encodePacked(r, s, v));
    }

    function _row(string memory label, address t, address sender, bytes memory cd) internal {
        vm.cool(t);
        vm.cool(sender);
        vm.cool(G_TO);
        vm.prank(sender);
        uint256 g0 = gasleft();
        (bool ok,) = t.call(cd);
        uint256 used = g0 - gasleft();
        assertTrue(ok, label);
        console.log("GOVGAS", label, used);
    }

    function _plain(string memory label, address t) internal {
        _row(label, t, _gSigner(), abi.encodeWithSignature("transfer(address,uint256)", G_TO, 1));
    }

    function _mtx(string memory label, address t) internal {
        _row(label, t, G_RELAYER, _mtxCall(t, 1));
    }

    function _tokenConfig(uint256 supply) internal pure returns (IFactoryToken.TokenConfig memory c) {
        c.name = "G";
        c.symbol = "G";
        c.decimals = 18;
        c.features = 1; // PAYABLE
        c.initialSupply = supply;
        c.initialHolder = _gSigner();
    }
}

contract GovGasNormal is GovRows {
    bytes32 constant UID = 0x24e43dcbfc9624b23bf89409acd104d6e5671e2c41d8c192373d65519321c464;
    address constant G_MINTER = address(0xF00);
    address t;
    address m;
    OpenFactory f;

    function setUp() public {
        vm.warp(1_800_000_000);
        f = new OpenFactory(address(this), UID, 0);
        Catalogue.plain(f, IOpenFactory.TokenKind.NORMAL, 1, type(NormalToken).creationCode, address(0), address(0), false);
        t = f.createToken(IOpenFactory.TokenKind.NORMAL, 1, abi.encode(_tokenConfig(1_000 ether)), "n");
        _prime(t);
        m = f.createToken(IOpenFactory.TokenKind.NORMAL, 1, abi.encode(_minted()), "m");
        vm.prank(_gSigner());
        (bool ok,) = m.call(abi.encodeWithSignature("transfer(address,uint256)", G_TO, 1));
        assertTrue(ok);
    }

    function test_transfer() public { _plain("NormalToken transfer", t); }
    function test_mtxTransfer() public { _mtx("NormalToken mtxTransfer", t); }

    /// A whole-shape holder: `use` pays one feature read and one role read, no call (B-26).
    function test_mintWholeShape() public {
        _row("NormalToken mint whole-shape", m, G_MINTER, abi.encodeWithSignature("mint(address,uint256)", G_TO, 1));
    }

    function test_createToken() public {
        bytes memory cd = abi.encodeCall(OpenFactory.createToken, (IOpenFactory.TokenKind.NORMAL, 1, abi.encode(_minted()), "c"));
        _row("NormalToken createToken", address(f), address(this), cd);
    }

    function _minted() internal pure returns (IFactoryToken.TokenConfig memory c) {
        c = _tokenConfig(1_000 ether);
        c.features = 3; // PAYABLE | MINTABLE
        c.lockedFeatures = 2; // no owner: the minter survives creation on a locked bit (B-06)
        c.roles.minter = nid(G_MINTER);
    }
}

contract ColdProbe {
    uint256 private s = 1;

    function probe() external view returns (uint256 cold, uint256 warm) {
        uint256 g = gasleft();
        uint256 a = s;
        cold = g - gasleft();
        g = gasleft();
        uint256 b = s;
        warm = g - gasleft();
        require(a == b);
    }
}

/// The SLOAD prices of this EVM (`evm_version`, the D3 argument): what one `features` read on the hot path would cost.
contract GovGasSload is Test {
    function test_coldSload() public {
        ColdProbe p = new ColdProbe();
        (uint256 cold, uint256 warm) = p.probe();
        console.log("GOVGAS SLOAD cold (with gasleft overhead)", cold);
        console.log("GOVGAS SLOAD warm (with gasleft overhead)", warm);
    }
}

contract GovGasWrapped is GovRows {
    bytes32 constant UID = 0x24e43dcbfc9624b23bf89409acd104d6e5671e2c41d8c192373d65519321c464;
    address t;

    function setUp() public {
        vm.warp(1_800_000_000);
        OpenFactory f = new OpenFactory(address(this), UID, 0);
        Catalogue.plain(f, IOpenFactory.TokenKind.WRAPPED, 1, type(WrappedToken).creationCode, address(0), address(0), false);
        MockERC20 usd = new MockERC20("USD", "USD", 6);
        IFactoryToken.TokenConfig memory c = _tokenConfig(0);
        c.initialHolder = address(0);
        c.legs = new IFactoryToken.Leg[](1);
        c.legs[0] = IFactoryToken.Leg(address(usd), 1, 1);
        t = f.createToken(IOpenFactory.TokenKind.WRAPPED, 1, abi.encode(c), "w");
        _wrapTo(t, usd);
        _prime(t);
    }

    function _wrapTo(address tok, MockERC20 usd) internal {
        address s = _gSigner();
        usd.mint(s, 1_000e6);
        vm.startPrank(s);
        usd.approve(tok, type(uint256).max);
        WrappedToken(payable(tok)).wrap(500e6);
        vm.stopPrank();
    }

    function test_transfer() public { _plain("WrappedToken transfer", t); }
    function test_mtxTransfer() public { _mtx("WrappedToken mtxTransfer", t); }
}

contract GovGasPqz is GovRows, PqzFixture {
    address t;

    function setUp() public {
        _stack();
        Catalogue.release(factory, IOpenFactory.TokenKind.WRAPPED_PQZ, 1,
            pqzEnv(address(factory), PQZ_UID, address(reg), address(pqv)), type(WrappedPqzToken).creationCode);
        MockERC20 usd = new MockERC20("USD", "USD", 6);
        IFactoryToken.TokenConfig memory c = _cfg(uint256(1) << 40);
        c.features = 1; // PAYABLE
        c.lockedFeatures = 0; // the fixture locks MINTABLE for its minter (B-06); this token has neither
        c.roles.minter = 0;
        c.legs = new IFactoryToken.Leg[](1);
        c.legs[0] = IFactoryToken.Leg(address(usd), 1, 1);
        t = factory.createToken(IOpenFactory.TokenKind.WRAPPED_PQZ, 1, abi.encode(c), "w");
        address s = _gSigner();
        usd.mint(s, 1_000e6);
        vm.startPrank(s);
        usd.approve(t, type(uint256).max);
        WrappedToken(payable(t)).wrap(500e6);
        vm.stopPrank();
        _prime(t);
    }

    function test_transfer() public { _plain("WrappedPqzToken transfer", t); }
    function test_mtxTransfer() public { _mtx("WrappedPqzToken mtxTransfer", t); }
}

contract GovGasZether is GovRows, ZetherFixture {
    address t;

    function setUp() public {
        _stack();
        Catalogue.release(factory, IOpenFactory.TokenKind.WRAPPED_ZETHER, 1, _zenv(), type(WrappedZetherToken).creationCode);
        MockERC20 usd = new MockERC20("USD", "USD", 6);
        IFactoryToken.TokenConfig memory c = _cfg(false, uint256(1) << 40);
        c.features = 1; // PAYABLE
        c.lockedFeatures = 0; // the fixture locks MINTABLE for its minter (B-06); this token has neither
        c.roles.minter = 0;
        c.legs = new IFactoryToken.Leg[](1);
        c.legs[0] = IFactoryToken.Leg(address(usd), 1, 1);
        t = factory.createToken(IOpenFactory.TokenKind.WRAPPED_ZETHER, 1, abi.encode(c), "w");
        address s = _gSigner();
        usd.mint(s, 1_000e6);
        vm.startPrank(s);
        usd.approve(t, type(uint256).max);
        WrappedToken(payable(t)).wrap(500e6);
        vm.stopPrank();
        _prime(t);
    }

    function test_transfer() public { _plain("WrappedZetherToken transfer", t); }
    function test_mtxTransfer() public { _mtx("WrappedZetherToken mtxTransfer", t); }
}

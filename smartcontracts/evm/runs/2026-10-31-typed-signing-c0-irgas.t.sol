// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

// typed-signing C0 Step 2b, lever 5: the gas of the public token paths under via_ir against the legacy pipeline. Copied
// to test/metatx/IrGas.t.sol of a scratch copy. It imports only the public tokens: the whole test tree does not compile
// with via_ir under the capped memory (the verifiers), so this is the gas sample of the lever.
//   FOUNDRY_SPARSE_MODE=true [FOUNDRY_VIA_IR=true] forge test --match-path test/metatx/IrGas.t.sol -vv
import {Test, console2} from "forge-std/Test.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {NormalToken} from "../../src/metatx/NormalToken.sol";
import {WrappedToken} from "../../src/metatx/WrappedToken.sol";
import {MetaTokenBase} from "../../src/metatx/MetaTokenBase.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {AdminLib} from "../../src/metatx/AdminLib.sol";

contract Leg is ERC20("USD", "USD") {
    function mint(address to, uint256 v) external { _mint(to, v); }
}

/// Lever 3: what a read costs through the fallback of `FALLBACK` in 2026-10-31-typed-signing-c0-mock.py.
contract ViewModule {
    uint256 public x = 1;
}

contract ViewDirect {
    uint256 public x = 1;
}

contract ViewFallback {
    uint256 private x_ = 1;
    address internal immutable M = address(new ViewModule());

    fallback() external payable {
        address m = M;
        assembly ("memory-safe") {
            calldatacopy(0, 0, calldatasize())
            let ok := delegatecall(gas(), m, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            if iszero(ok) { revert(0, returndatasize()) }
            return(0, returndatasize())
        }
    }
}

contract IrGasTest is Test {
    uint256 constant PK = 0xA11CE;
    address holder = vm.addr(PK);
    address bob = address(0xB0B);
    address relayer = address(0xBEEF);
    NormalToken t;
    WrappedToken w;
    Leg u;

    function _env() internal view returns (IFactoryToken.Env memory e) {
        (e.factory, e.chainUid) = (address(this), keccak256("c0"));
    }

    function setUp() public {
        IFactoryToken.TokenConfig memory c;
        (c.name, c.symbol, c.decimals, c.features, c.initialSupply, c.initialHolder) = ("N", "N", 0, 7, 1e9, holder);
        t = NormalToken(Clones.clone(address(new NormalToken(1, _env(), ""))));
        MetaTokenBase(address(t)).initialize(address(this), 1, abi.encode(c));
        u = new Leg();
        IFactoryToken.TokenConfig memory d;
        (d.name, d.symbol, d.decimals, d.features) = ("W", "W", 0, 1 << AdminLib.PAYABLE);
        d.legs = new IFactoryToken.Leg[](1);
        d.legs[0] = IFactoryToken.Leg(address(u), 1, 1);
        w = WrappedToken(Clones.clone(address(new WrappedToken(1, _env(), ""))));
        MetaTokenBase(address(w)).initialize(address(this), 1, abi.encode(d));
        u.mint(holder, 1e9);
        vm.startPrank(holder);
        u.approve(address(w), 1e9);
        w.wrap(1e8);
        vm.stopPrank();
    }

    function _sig(bytes32 d) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PK, d);
        return abi.encodePacked(r, s, v);
    }

    function _unwrap(uint256 nonce) internal {
        MetaTxLib.MetaTransaction memory m;
        m.from = holder;
        m.data = abi.encodeWithSignature("unwrap(uint256,address,uint256)", 100, bob, 0);
        m.nonce = nonce;
        m.validUntil = block.timestamp + 300;
        bytes memory s = _sig(w.mtxDigest(m));
        vm.prank(relayer);
        w.mtxExecute(m, s);
    }

    function _transfer(uint256 nonce) internal {
        MetaTxLib.MetaTransfer memory m;
        (m.from, m.to, m.value, m.nonce, m.validUntil) = (holder, bob, 100, nonce, block.timestamp + 300);
        bytes memory s = _sig(t.mtxTransferDigest(m));
        vm.prank(relayer);
        t.mtxExecuteTransfer(m, s);
    }

    function test_viewThroughFallback() public {
        ViewDirect d = new ViewDirect();
        ViewFallback f = new ViewFallback();
        d.x();
        uint256 direct = vm.lastCallGas().gasTotalUsed;
        ViewDirect(address(f)).x();
        console2.log("a view direct / through the fallback", direct, vm.lastCallGas().gasTotalUsed);
    }

    function test_gas() public {
        _transfer(0);
        _transfer(1);
        console2.log("mtxExecuteTransfer, warm lane", vm.lastCallGas().gasTotalUsed);
        _unwrap(0);
        _unwrap(1);
        console2.log("mtxExecute(unwrap), warm lane", vm.lastCallGas().gasTotalUsed);
        MetaTxLib.Envelope memory e;
        (e.from, e.nonce, e.validUntil) = (holder, 2, block.timestamp + 300);
        bytes32 h = keccak256(bytes.concat(abi.encode(
            keccak256("Unwrap(address from,uint256 wrapped,address recipient,uint256 minOut,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"),
            holder, 100, bob, 0), abi.encode(uint256(0), uint256(2), e.validUntil, uint32(0), address(0), uint256(0), address(0))));
        (, string memory n, string memory ver, uint256 id, address vc, bytes32 salt,) = w.eip712Domain();
        bytes32 ds = keccak256(abi.encode(keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)"),
            keccak256(bytes(n)), keccak256(bytes(ver)), id, vc, salt));
        bytes memory s = _sig(keccak256(abi.encodePacked(hex"1901", ds, h)));
        vm.prank(relayer);
        w.mtxUnwrap(e, 100, bob, 0, s);
        console2.log("mtxUnwrap, warm lane", vm.lastCallGas().gasTotalUsed);
        vm.prank(holder);
        t.transfer(bob, 1);
        console2.log("transfer", vm.lastCallGas().gasTotalUsed);
    }
}

// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {stdJson} from "forge-std/StdJson.sol";
import {IERC20Errors} from "@openzeppelin/contracts/interfaces/draft-IERC6093.sol";
import {IUALedger} from "../../src/metatx/IUALedger.sol";
import {ITradeToken} from "../../src/trade/ITradeToken.sol";
import {LiquidityBase} from "./LiquidityBase.sol";

/// Answers the tokens' capability check with the row's `h` and forwards a raw call (etched at the row's DEX address).
contract KatCaller {
    bytes32 public right;

    function set(bytes32 r) external {
        right = r;
    }

    function liquidityOrderDigest(ITradeToken.LiquidityOrder calldata) external view returns (bytes32) {
        return right;
    }

    function fwd(address target, bytes calldata data) external returns (bytes memory) {
        (bool ok, bytes memory r) = target.call(data);
        if (!ok) assembly { revert(add(r, 32), mload(r)) }
        return r;
    }
}

/// The liquidity KAT (spec 2026-11-10-dex-liquidity.md §12, L37): every row of `liquidity_kat.json` against the DEX's
/// `liquidityOrderDigest` (its raw calldata, so the ABI too) at the row's address and chain, the DEX's `SaltedEIP712` domain,
/// and the token side: a token etched at the row's input address passes T7 and T8 on the row's own `h` and signature and
/// stops only at the balance (a native signer) or the absent registry (a derived one).
contract LiquidityKatTest is LiquidityBase {
    using stdJson for string;

    string internal kat;

    function setUp() public override {
        super.setUp();
        kat = vm.readFile("../vectors/ua/liquidity_kat.json");
        vm.chainId(kat.readUint(".chainId"));
        assertEq(a.chainUid(), kat.readBytes32(".chainUid"));
    }

    function _rows() internal view returns (uint256 n) {
        while (vm.keyExistsJson(kat, string.concat(".rows[", vm.toString(n), "]"))) ++n;
    }

    function _r(uint256 i, string memory k) internal pure returns (string memory) {
        return string.concat(".rows[", vm.toString(i), "].", k);
    }

    function test_kat_dexDigestAndDomain() public {
        address at = kat.readAddress(".dex");
        vm.etch(at, address(dex).code);
        (, string memory name, string memory version, uint256 cid, address vc, bytes32 salt,) =
            IERC5267Like(at).eip712Domain();
        bytes32 sep = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)"),
            keccak256(bytes(name)), keccak256(bytes(version)), cid, vc, salt));
        uint256 n = _rows();
        assertEq(n, 7);
        for (uint256 i; i < n; ++i) {
            assertEq(sep, kat.readBytes32(_r(i, "domainSeparator")), "SaltedEIP712 = the rows' separator");
            bytes32 h = kat.readBytes32(_r(i, "h"));
            assertEq(keccak256(abi.encodePacked(hex"1901", sep, kat.readBytes32(_r(i, "hashOrder")))), h);
            (bool ok, bytes memory ret) = at.staticcall(kat.readBytes(_r(i, "liquidityOrderDigestCalldata")));
            assertTrue(ok);
            assertEq(abi.decode(ret, (bytes32)), h, kat.readString(_r(i, "name")));
        }
    }

    function test_kat_tokenSide() public {
        KatCaller c = new KatCaller();
        address at = kat.readAddress(".dex");
        vm.etch(at, address(c).code);
        vm.etch(kat.readAddress(".tokenA"), address(a).code);
        vm.etch(kat.readAddress(".tokenB"), address(b).code);
        uint256 n = _rows();
        for (uint256 i; i < n; ++i) {
            bytes[] memory calls = kat.readBytesArray(_r(i, "pullCalldata"));
            if (calls.length == 0) continue;
            KatCaller(at).set(kat.readBytes32(_r(i, "h")));
            address token = kat.readAddressArray(_r(i, "pullTokens"))[0];
            uint256 amount = vm.parseUint(kat.readStringArray(_r(i, "pullAmounts"))[0]);
            bytes32 from = kat.readBytes32(_r(i, "signer"));
            if (uint256(from) >> 160 == 0) {
                vm.expectRevert(abi.encodeWithSelector(IERC20Errors.ERC20InsufficientBalance.selector,
                    address(uint160(uint256(from))), 0, amount));
            } else {
                vm.expectRevert(IUALedger.UALedgerOff.selector);
            }
            KatCaller(at).fwd(token, calls[0]);
            // a wrong answer to T7 is refused before the signature
            KatCaller(at).set(bytes32(uint256(1)));
            vm.expectRevert(abi.encodeWithSelector(ITradeToken.NotLiquidityDex.selector, at));
            KatCaller(at).fwd(token, calls[0]);
        }
    }
}

interface IERC5267Like {
    function eip712Domain() external view returns (bytes1, string memory, string memory, uint256, address, bytes32,
        uint256[] memory);
}

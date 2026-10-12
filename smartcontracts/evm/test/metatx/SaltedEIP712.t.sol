// SPDX-License-Identifier: LicenseRef-SCaaS-Community-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {ShortStrings} from "@openzeppelin/contracts/utils/ShortStrings.sol";
import {SaltedEIP712} from "../../src/common/SaltedEIP712.sol";

contract SaltedHarness is SaltedEIP712 {
    constructor(string memory n, bytes32 uid) SaltedEIP712(n, "1", uid) {}

    function separator() external view returns (bytes32) {
        return _domainSeparatorV4();
    }

    function typed(bytes32 structHash) external view returns (bytes32) {
        return _hashTypedDataV4(structHash);
    }
}

/// CTR-GEN-05: domain (name, version, chainId, verifyingContract, salt = chain_uid), fields 0x1f, clone-safe.
contract SaltedEIP712Test is Test {
    bytes32 internal constant UID = 0x24e43dcbfc9624b23bf89409acd104d6e5671e2c41d8c192373d65519321c464;
    SaltedHarness internal h;

    function setUp() public {
        vm.chainId(7622);
        h = new SaltedHarness("SCaaS TestRegistry", UID);
    }

    function _expected(address verifying) internal view returns (bytes32) {
        return keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)"),
            keccak256("SCaaS TestRegistry"), keccak256("1"), block.chainid, verifying, UID));
    }

    function test_separatorIsSalted() public view {
        assertEq(h.separator(), _expected(address(h)));
        bytes32 sh = keccak256("struct");
        assertEq(h.typed(sh), keccak256(abi.encodePacked(hex"1901", _expected(address(h)), sh)));
    }

    function test_eip712Domain_fields0x1f() public view {
        (bytes1 f, string memory n, string memory v, uint256 cid, address vc, bytes32 salt, uint256[] memory ext) =
            h.eip712Domain();
        assertEq(f, bytes1(0x1f));
        assertEq(n, "SCaaS TestRegistry");
        assertEq(v, "1");
        assertEq(cid, 7622);
        assertEq(vc, address(h));
        assertEq(salt, UID);
        assertEq(ext.length, 0);
    }

    function test_cloneUsesItsOwnAddressAndTheImplementationSalt() public {
        SaltedHarness c = SaltedHarness(Clones.clone(address(h)));
        assertEq(c.separator(), _expected(address(c)));
        (,,,, address vc, bytes32 salt,) = c.eip712Domain();
        assertEq(vc, address(c));
        assertEq(salt, UID);
        assertTrue(c.separator() != h.separator());
    }

    function test_chainIdChangeRebuilds() public {
        vm.chainId(1);
        assertEq(h.separator(), _expected(address(h)));
    }

    function test_longNameRefused() public {
        vm.expectRevert(abi.encodeWithSelector(ShortStrings.StringTooLong.selector, "SCaaS A Name Longer Than 31 Bytes"));
        new SaltedHarness("SCaaS A Name Longer Than 31 Bytes", UID);
    }

    function test_zeroChainUidRefused() public {
        vm.expectRevert(SaltedEIP712.ChainUidZero.selector);
        new SaltedHarness("SCaaS TestRegistry", bytes32(0));
    }
}

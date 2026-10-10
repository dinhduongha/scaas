// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {stdJson} from "forge-std/StdJson.sol";
import {V2Fixture} from "./helpers/V2Fixture.sol";
import {MockERC20} from "../helpers/Mocks.sol";
import {SingleUnderlyingToken} from "../../src/metatx/SingleUnderlyingToken.sol";

/// @title Ghim storage layout của từng implementation v2 (TW2 §10.1): indexer và storage proof đọc `reserve`.
/// @notice So `storageLayout` của artifact solc (`extra_output`) với `test/v2/layout/<Contract>.json` đã commit
///         (nhãn, slot, offset). Đổi layout là đổi file pin — có chủ ý, trong cùng commit.
contract LayoutTest is V2Fixture {
    using stdJson for string;

    function _pin(string memory file, string memory name) internal view {
        string memory art = vm.readFile(string.concat("./out/", file, ".sol/", name, ".json"));
        string memory pin = vm.readFile(string.concat("./test/v2/layout/", name, ".json"));
        string[] memory pl = pin.readStringArray(".labels");
        string[] memory ps = pin.readStringArray(".slots");
        uint256[] memory po = pin.readUintArray(".offsets");
        for (uint256 i; i < pl.length; ++i) {
            string memory e = string.concat(".storageLayout.storage[", vm.toString(i), "]");
            assertEq(art.readString(string.concat(e, ".label")), pl[i], name);
            assertEq(art.readString(string.concat(e, ".slot")), ps[i], name);
            assertEq(art.readUint(string.concat(e, ".offset")), po[i], name);
        }
        // no variable appended past the pin
        assertFalse(vm.keyExistsJson(art, string.concat(".storageLayout.storage[", vm.toString(pl.length), "]")), name);
    }

    function test_storageLayoutIsPinned() public view {
        _pin("NoUnderlyingToken", "NoUnderlyingToken");
        _pin("SingleUnderlyingToken", "SingleUnderlyingToken");
        _pin("MultiUnderlyingToken", "MultiUnderlyingToken");
        _pin("HederaTokensV2", "HederaSingleUnderlyingToken");
        _pin("HederaTokensV2", "HederaMultiUnderlyingToken");
    }

    /// Thứ indexer thật sự đọc: `reserve` của chân i ở `keccak256(i ‖ 6) + 2`, `num ‖ den` ở `+ 1`.
    function test_reserveSlotIsWhereIndexersReadIt() public {
        MockERC20 u = new MockERC20("U", "U", 6);
        SingleUnderlyingToken t = _single(address(u), 6, 3, 7, _fixedRate());
        u.mint(address(this), 1_000);
        u.approve(address(t), 1_000);
        t.wrap(1_000);
        bytes32 base = keccak256(abi.encode(uint256(0), uint256(6)));
        assertEq(uint256(vm.load(address(t), bytes32(uint256(base) + 2))), 1_000);
        uint256 b = uint256(vm.load(address(t), bytes32(uint256(base) + 1)));
        assertEq(b & type(uint96).max, 3);
        assertEq(b >> 96, 7);
        assertEq(address(uint160(uint256(vm.load(address(t), base)))), address(u));
        assertEq(uint256(vm.load(address(t), bytes32(uint256(5)))) & 0xff, 1); // _legCount
    }
}

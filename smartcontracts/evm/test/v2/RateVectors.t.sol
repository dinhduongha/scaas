// SPDX-License-Identifier: LicenseRef-SCaaS-Community-1.0
pragma solidity ^0.8.20;

import {V2Fixture} from "./helpers/V2Fixture.sol";
import {MockERC20} from "../helpers/Mocks.sol";
import {UnderlyingToken} from "../../src/metatx/UnderlyingToken.sol";

/// @title Vector tỉ lệ chung cho mọi họ (TW2 §10.4): `test/vectors/wrap_rate_vectors.json`.
/// @notice `(num, den, in) → (minted, used)` và `(num, den, w) → (out, burned)`, sinh từ `previewWrap` /
///         `previewUnwrap` của chính implementation. Wrapper Cosmos/Soroban/TON (R145, PLANNED) phát lại file này.
contract RateVectorsTest is V2Fixture {
    function _q(uint256 v) internal pure returns (string memory) {
        return string.concat('"', vm.toString(v), '"');
    }

    function test_writeRateVectors() public {
        MockERC20 u = new MockERC20("U", "U", 6);
        uint256 m96 = type(uint96).max;
        uint256[2][6] memory rates = [[uint256(1), 1], [uint256(1e12), 1], [uint256(1), 1e4], [m96, 1], [uint256(1), m96], [uint256(3), 7]];
        uint256[8] memory ins = [uint256(0), 1, 9_999, 10_000, 15_000, 1e6, 1e18, m96];
        uint256[7] memory ws = [uint256(0), 1, 1e12 - 1, 1e12, 1.5e12 + 7, 1e18, m96];
        string memory wj = "[";
        string memory uj = "[";
        for (uint256 r; r < rates.length; ++r) {
            UnderlyingToken t = _single(address(u), 6, rates[r][0], rates[r][1], _fixedRate());
            string memory head = string.concat('{"num":', _q(rates[r][0]), ',"den":', _q(rates[r][1]));
            for (uint256 i; i < ins.length; ++i) {
                (uint256 minted, uint256 used) = t.previewWrap(address(u), ins[i]);
                assertLe(used, ins[i]);
                wj = string.concat(wj, r + i == 0 ? "" : ",", head, ',"in":', _q(ins[i]),
                    ',"minted":', _q(minted), ',"used":', _q(used), "}");
            }
            for (uint256 i; i < ws.length; ++i) {
                (uint256 out, uint256 burned) = t.previewUnwrap(address(u), ws[i]);
                assertLe(burned, ws[i]);
                uj = string.concat(uj, r + i == 0 ? "" : ",", head, ',"w":', _q(ws[i]),
                    ',"out":', _q(out), ',"burned":', _q(burned), "}");
            }
        }
        vm.writeFile("./test/vectors/wrap_rate_vectors.json",
            string.concat('{"wrap":', wj, '],"unwrap":', uj, "]}\n"));
    }
}

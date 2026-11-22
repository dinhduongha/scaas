// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";
import {IPqChatStore} from "../../src/pqchat/IPqChatStore.sol";

/// Plan T8 (CTR-CHAT-22; spec 2026-11-21-avax-polkadot-arweave §5.2): `PqChatStore.storeMessage`'s gas at Amsterdam,
/// `isolate = true`, so each figure is one transaction's: `vm.lastCallGas()` regular gas (intrinsic and calldata floor
/// included) and the EIP-8037 state gas apart. Envelopes of 2,400 B (a 1,024-B bucket, FN-DSA-512), 5,100 B (ML-DSA-65) and
/// 24,416 B (the largest `env`), each at a new hint and at a warm one. The Cancun figures come from the gate step
/// `chatstore-cancun` (receipts' `gasUsed`), recorded in the spec, never compared with these. Regular within ±500 gas, state
/// exact; a move needs old -> new figures in its commit. GAS_MEASURE=true: the figures, no pin. Each envelope's bytes
/// are 0x5a, as the Cancun cases' (`script/deploy_pqchatstore.py cases`).
contract PqChatStoreGasTest is Test {
    uint256 internal constant SLACK = 500;

    IPqChatStore internal store;

    function setUp() public {
        store = IPqChatStore(deployCode("PqChatStore.sol:PqChatStore"));
    }

    function _row(string memory what, uint256 regular, uint256 state) internal {
        Vm.Gas memory g = vm.lastCallGas();
        uint256 s = uint256(int256(g.gasStateUsed));
        emit log_named_uint(string.concat("GAS ", what, " regular"), g.gasTotalUsed);
        emit log_named_uint(string.concat("GAS ", what, " state"), s);
        emit log_named_uint(string.concat("GAS ", what, " total"), g.gasTotalUsed + s);
        if (!vm.envOr("GAS_MEASURE", false)) {
            assertApproxEqAbs(g.gasTotalUsed, regular, SLACK, string.concat(what, " regular"));
            assertEq(s, state, string.concat(what, " state"));
        }
    }

    /// An envelope of `size` bytes 0x5a: ciphertext has almost no zero byte, so calldata is priced as non-zero bytes.
    function _env(uint256 size) internal pure returns (bytes memory e) {
        e = new bytes(size);
        for (uint256 i; i < size; ++i) {
            e[i] = 0x5a;
        }
    }

    function _store(bytes8 hint, bytes memory env) internal {
        store.storeMessage(1, hint, env);
    }

    function test_gas_storeMessage_2400() public {
        _store(bytes8(keccak256("a")), _env(2400));
        _row("storeMessage 2,400 B envelope, new hint", 177_048, 4_248_810);
        _store(bytes8(keccak256("a")), _env(2400));
        _row("storeMessage 2,400 B envelope, warm hint", 177_048, 4_150_890);
    }

    function test_gas_storeMessage_5100() public {
        _store(bytes8(keccak256("b")), _env(5100));
        _row("storeMessage 5,100 B envelope, new hint", 351_128, 8_410_410);
        _store(bytes8(keccak256("b")), _env(5100));
        _row("storeMessage 5,100 B envelope, warm hint", 351_128, 8_312_490);
    }

    function test_gas_storeMessage_24416() public {
        _store(bytes8(keccak256("c")), _env(24_416));
        _row("storeMessage 24,416 B envelope, new hint", 1_586_072, 37_933_290);
        _store(bytes8(keccak256("c")), _env(24_416));
        _row("storeMessage 24,416 B envelope, warm hint", 1_586_072, 37_835_370);
    }
}

// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IPqChat} from "./IPqChat.sol";
import {PqChatTypes} from "./PqChatTypes.sol";
import {IUARegistry} from "../ua/IUARegistry.sol";
import {UAKinds} from "../ua/UAKinds.sol";
import {ChainEnvCode} from "../factory/ChainEnvCode.sol";

/// @title `PqChatRecordLib`: the signed-record step of `PqChat`'s `createSession`, `rekey` and `postMessage` (owner 2026-11-28:
///        the release's size split is an external library, linked; CTR-CHAT-32).
/// @notice Each function takes its entry's calldata as the entry received it (`PqChat` forwards `msg.data` under this
///         function's selector by `DELEGATECALL`, nothing appended), so it decodes the same record from the same bytes. It
///         checks the signer's portable signature over the record's typed digest under `PURPOSE_PQCHAT` (P7) against the
///         registry the instance's own code names (`ChainEnvCode`; `PqChat` read and checked that env first), and returns
///         `abi.encode(record)`, the bytes `PqChat` stores. It reads and writes no storage, emits nothing, holds no state and
///         never uses `msg.sender` or `msg.value`; a registry revert bubbles unchanged. **UNAUDITED.**
library PqChatRecordLib {
    /// @notice `createSession`'s record: `s.creator`'s signature (P7), then `abi.encode(s)`.
    function sessionRecord(IPqChat.PqChatSession calldata s, IPqChat.Wrap[] calldata, IUARegistry.UASig calldata sig)
        external
        view
        returns (bytes memory)
    {
        _auth(s.creator, PqChatTypes.hashSession(s), sig);
        return abi.encode(s);
    }

    /// @notice `rekey`'s record: `e.author`'s signature (P7), then `abi.encode(e)`.
    function epochRecord(IPqChat.PqChatEpoch calldata e, IPqChat.Wrap[] calldata, IUARegistry.UASig calldata sig)
        external
        view
        returns (bytes memory)
    {
        _auth(e.author, PqChatTypes.hashEpoch(e), sig);
        return abi.encode(e);
    }

    /// @notice `postMessage`'s record: `m.sender`'s signature (P16), then the struct hash and `abi.encode(m)`.
    function messageRecord(IPqChat.PqChatMessage calldata m, IUARegistry.UASig calldata sig)
        external
        view
        returns (bytes32 hm, bytes memory)
    {
        hm = PqChatTypes.hashMessage(m);
        _auth(m.sender, hm, sig);
        return (hm, abi.encode(m));
    }

    function _auth(bytes32 ua, bytes32 structHash, IUARegistry.UASig calldata sig) private view {
        IUARegistry(ChainEnvCode.registry())
            .requirePortable(ua, UAKinds.PURPOSE_PQCHAT, PqChatTypes.typed(structHash), sig);
    }
}

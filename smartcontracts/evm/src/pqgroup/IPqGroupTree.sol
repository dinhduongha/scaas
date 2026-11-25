// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

/// @title The change records of a group's ratchet tree (`PqGroupTree`), app-agnostic (CTR-CHAT-28; review A-6): the base
///        reads them from an inheritor's commit, and an inheritor's interface takes them by inheriting this one (`IPqChat`
///        does; the ABI is the tuple, so nothing an app signs or a client encodes moves). **UNAUDITED.**
interface IPqGroupTree {
    /// @notice A key added to leaf `leaf`: the registry's KEM key `(ua, keyId)`, `kemHash = keccak256(kemPk)` of it (C18);
    ///         `via` is the inheritor's (PqChat: as in `MemberKey`), not read by the base.
    struct TreeAdd {
        uint32 leaf;
        bytes32 ua;
        uint64 keyId;
        bytes32 via;
        bytes32 kemHash;
    }

    /// @notice A live leaf a commit blanks, named by its `(ua, keyId)`.
    struct TreeRemove {
        uint32 leaf;
        bytes32 ua;
        uint64 keyId;
    }
}

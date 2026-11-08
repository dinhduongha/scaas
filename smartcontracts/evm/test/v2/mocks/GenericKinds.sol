// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IOpenFactory} from "../../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../../src/factory/IFactoryToken.sol";
import {ChainEnvCode} from "../../../src/factory/ChainEnvCode.sol";

/// The class interface of the test kinds (their ERC-165 id).
interface INoteKind {
    function initialize(bytes32 ownerUA, string calldata note) external;
    function note() external view returns (string memory);
}

interface IRosterKind {
    function initialize(bytes32 ownerUA, uint64 start, address[] calldata members) external;
    function members() external view returns (address[] memory);
}

/// The generic surface every test kind shares (factory index spec §8.8, chain-neutral spec §2.1): constructor
/// `(ReleaseId, factory_, implArgs)`, the release id as immutables, the chain values from the clone's code, `factoryInfo()`
/// (224 B), ERC-165, `validateEnv` (nothing), `chainEnv()`; `initialize` once, by the factory, on a clone with its env.
/// Test-only (no `src/` kind). **UNAUDITED.**
abstract contract GenericKindBase {
    address public immutable FACTORY;
    uint16 internal immutable CLASS;
    uint16 internal immutable KIND;
    uint64 internal immutable VERSION;
    bytes32 public owner;
    bool internal _initialized;
    /// `creating()` as `initialize` saw it.
    bytes32 public seenCreator;

    constructor(IOpenFactory.ReleaseId memory id, address factory_) {
        FACTORY = factory_;
        (CLASS, KIND, VERSION) = (id.contractClass, id.kind, id.version);
        _initialized = true; // the implementation locked
    }

    function _interfaceId() internal pure virtual returns (bytes4);

    function _begin(bytes32 ownerUA) internal {
        require(msg.sender == FACTORY, "not the factory");
        require(!_initialized, "initialized");
        ChainEnvCode.requirePresent();
        _initialized = true;
        owner = ownerUA;
        seenCreator = IOpenFactory(FACTORY).creating();
    }

    function factoryInfo() external view virtual returns (IOpenFactory.FactoryInfo memory) {
        return IOpenFactory.FactoryInfo(FACTORY, ChainEnvCode.chainUid(), CLASS, KIND, VERSION, owner, _initialized);
    }

    function supportsInterface(bytes4 id) external view virtual returns (bool) {
        return id == 0x01ffc9a7 || id == _interfaceId();
    }

    function validateEnv(IFactoryToken.ChainEnv calldata) external pure {}

    function chainEnv() external view returns (IFactoryToken.ChainEnv memory) {
        return ChainEnvCode.decode();
    }
}

/// Class 4, kind 0: an owner and a note (a string argument).
contract NoteKind is GenericKindBase, INoteKind {
    string public note;

    constructor(IOpenFactory.ReleaseId memory id, address factory_, bytes memory) GenericKindBase(id, factory_) {}

    function _interfaceId() internal pure override returns (bytes4) { return type(INoteKind).interfaceId; }

    function initialize(bytes32 ownerUA, string calldata note_) external {
        _begin(ownerUA);
        note = note_;
    }
}

/// Class 5, kind 1: an owner, a start and the members (a dynamic argument).
contract RosterKind is GenericKindBase, IRosterKind {
    uint64 public start;
    address[] internal _members;

    constructor(IOpenFactory.ReleaseId memory id, address factory_, bytes memory) GenericKindBase(id, factory_) {}

    function _interfaceId() internal pure override returns (bytes4) { return type(IRosterKind).interfaceId; }

    function initialize(bytes32 ownerUA, uint64 start_, address[] calldata members_) external {
        _begin(ownerUA);
        start = start_;
        _members = members_;
    }

    function members() external view returns (address[] memory) { return _members; }
}

/// A release that lies, by `mode` (its `implArgs`): each mode one way the factory must refuse (§8.9 negatives).
contract BadKind is GenericKindBase, INoteKind {
    uint8 internal immutable MODE;
    string public note;
    address internal immutable OTHER = address(0xF0F0);

    // modes at release deployment
    uint8 internal constant OTHER_FACTORY = 1;
    uint8 internal constant OTHER_CLASS = 2;
    uint8 internal constant OTHER_KIND = 3;
    uint8 internal constant OTHER_VERSION = 4;
    uint8 internal constant NOT_INITIALIZED = 5;
    uint8 internal constant OWNER_SET = 6;
    uint8 internal constant SHORT_192 = 7;
    uint8 internal constant LONG_256 = 8;
    uint8 internal constant NO_INFO = 9;
    uint8 internal constant NO_INTERFACE = 10;
    uint8 internal constant ALL_INTERFACES = 11;
    // modes at creation (the release itself passes)
    uint8 internal constant LEAVES_UNINITIALIZED = 12;
    uint8 internal constant OTHER_CLASS_AFTER_INIT = 13;
    uint8 internal constant INIT_REVERTS = 14;
    uint8 internal constant OTHER_CHAIN_AFTER_INIT = 15;
    uint8 internal constant NESTED = 16;
    uint8 internal constant OTHER_VERSION_AFTER_INIT = 17;
    /// `creating()` as `initialize` saw it after its nested creation (T68: the restore is visible only inside the
    /// transaction; EIP-1153 clears it at the end).
    bytes32 public seenAfter;

    constructor(IOpenFactory.ReleaseId memory id, address factory_, bytes memory implArgs) GenericKindBase(id, factory_) {
        MODE = abi.decode(implArgs, (uint8));
        if (MODE == NOT_INITIALIZED) _initialized = false;
        if (MODE == OWNER_SET) owner = bytes32(uint256(1));
    }

    function _interfaceId() internal pure override returns (bytes4) { return type(INoteKind).interfaceId; }

    function initialize(bytes32 ownerUA, string calldata note_) external {
        if (MODE == INIT_REVERTS) revert("init reverts");
        _begin(ownerUA);
        note = note_;
        if (MODE == LEAVES_UNINITIALIZED) _initialized = false;
        if (MODE == NESTED) {
            // a nested creation from `initialize`: this clone is its creator
            IOpenFactory(FACTORY).createInstance(IOpenFactory.ReleaseId(4, 0, 1), "nested",
                abi.encodeCall(INoteKind.initialize, (bytes32(uint256(0xBEEF)), "inner")));
            seenAfter = IOpenFactory(FACTORY).creating();
        }
    }

    function factoryInfo() external view override returns (IOpenFactory.FactoryInfo memory i) {
        i = IOpenFactory.FactoryInfo(MODE == OTHER_FACTORY ? OTHER : FACTORY, ChainEnvCode.chainUid(), CLASS, KIND, VERSION,
            owner, _initialized);
        bool isClone = ChainEnvCode.isClone();
        if (MODE == OTHER_CLASS || (MODE == OTHER_CLASS_AFTER_INIT && isClone)) i.contractClass = CLASS + 1;
        if (MODE == OTHER_KIND) i.kind = KIND + 1;
        if (MODE == OTHER_VERSION || (MODE == OTHER_VERSION_AFTER_INIT && isClone)) i.version = VERSION + 1;
        if (MODE == OTHER_CHAIN_AFTER_INIT && isClone) i.chainUid = keccak256("another chain");
        if (MODE == NO_INFO) revert();
        if (MODE == SHORT_192 || MODE == LONG_256) {
            bytes memory b = abi.encode(i);
            uint256 n = MODE == SHORT_192 ? 192 : 256;
            bytes memory r = new bytes(n);
            for (uint256 k; k < n && k < b.length; ++k) r[k] = b[k];
            assembly ("memory-safe") {
                return(add(r, 32), n)
            }
        }
    }

    function supportsInterface(bytes4 id) external view override returns (bool) {
        if (MODE == ALL_INTERFACES) return true;
        if (MODE == NO_INTERFACE) return id == 0x01ffc9a7;
        return id == 0x01ffc9a7 || id == type(INoteKind).interfaceId;
    }
}

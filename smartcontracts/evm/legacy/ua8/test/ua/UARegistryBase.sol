// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IUAPopVerifier} from "../../src/ua/IUAVerifier.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UARegistry} from "../../src/ua/UARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";

/// Stand-in verifier: the "signature" over (keyData, message) is `keccak256(abi.encode(keyData, message))`, so the
/// registry's message construction (kind tag, purpose, PoP digest, member digest) is what the tests exercise.
/// Modes for T-AUTH-4: 1 revert, 2 short return (31 bytes), 3 long return (64 bytes), 4 returns 2, 5 runs out of gas.
/// `burn` gas is spent before answering (gas measurements, starvation).
contract MockVerifier is IUAPopVerifier {
    uint8 public immutable mode;
    uint256 public immutable burn;

    constructor(uint8 mode_, uint256 burn_) {
        (mode, burn) = (mode_, burn_);
    }

    function verify(bytes calldata keyData, bytes32 message, bytes calldata sig) public view returns (bool) {
        uint256 start = gasleft();
        while (start - gasleft() < burn) {}
        uint8 m = mode;
        if (m == 1) revert("mock");
        if (m == 2) {
            assembly {
                mstore(0, 1)
                return(0, 31)
            }
        }
        if (m == 3) {
            assembly {
                mstore(0, 1)
                mstore(32, 0)
                return(0, 64)
            }
        }
        if (m == 4) {
            assembly {
                mstore(0, 2)
                return(0, 32)
            }
        }
        if (m == 5) {
            assembly {
                for {} 1 {} {}
            }
        }
        return sig.length == 32 && bytes32(sig) == keccak256(abi.encode(keyData, message));
    }

    function verifyPop(bytes calldata keyData, bytes32 message, bytes calldata sig) external view returns (bool) {
        return verify(keyData, message, sig);
    }
}

/// ERC-1271 wallet. Modes: 0 ECDSA by `owner` over the hash, 1 wrong magic, 2 revert, 3 out of gas, 4 ERC-7739-style:
/// rebuilds the hash from the registry's `eip712Domain()` (incl. salt) and the `UAAuth` struct carried in the
/// signature before checking the owner's ECDSA over it.
contract MockWallet {
    address public immutable owner;
    uint8 public immutable mode;
    uint256 public immutable burn;
    address public immutable registry;

    constructor(address owner_, uint8 mode_, uint256 burn_, address registry_) {
        (owner, mode, burn, registry) = (owner_, mode_, burn_, registry_);
    }

    function isValidSignature(bytes32 hash, bytes calldata sig) external view returns (bytes4) {
        uint256 start = gasleft();
        while (start - gasleft() < burn) {}
        uint8 m = mode;
        if (m == 1) return 0xdeadbeef;
        if (m == 2) revert("wallet");
        if (m == 3) {
            assembly {
                for {} 1 {} {}
            }
        }
        if (m == 4) {
            (bytes32 purpose, bytes32 digest, bytes memory ecdsa) = abi.decode(sig, (bytes32, bytes32, bytes));
            (, string memory name, string memory version, uint256 chainId, address vc, bytes32 salt,) =
                IUARegistry(registry).eip712Domain();
            bytes32 ds = keccak256(
                abi.encode(
                    UAKinds.DOMAIN_TYPEHASH, keccak256(bytes(name)), keccak256(bytes(version)), chainId, vc, salt
                )
            );
            bytes32 rebuilt = UAKinds.uaAuthDigest(ds, bytes32(uint256(uint160(address(this)))), purpose, digest);
            return rebuilt == hash && ECDSA.recover(rebuilt, ecdsa) == owner ? bytes4(0x1626ba7e) : bytes4(0xffffffff);
        }
        (address rec, ECDSA.RecoverError err,) = ECDSA.tryRecover(hash, sig);
        return err == ECDSA.RecoverError.NoError && rec == owner ? bytes4(0x1626ba7e) : bytes4(0xffffffff);
    }
}

/// gen-1 stand-in that claims one keyHash (T-REG-4 `UAKeyInUse` across generations, which a real gen 1 cannot reach
/// once the constructor's group rule holds).
contract MockPredecessor {
    bytes32 public immutable chainUid;
    bytes32 public immutable claimedKeyHash;
    bytes32 public immutable claimedOwner;

    constructor(bytes32 chainUid_, bytes32 kh, bytes32 owner_) {
        (chainUid, claimedKeyHash, claimedOwner) = (chainUid_, kh, owner_);
    }

    function generation() external pure returns (uint8) {
        return 1;
    }

    function hederaNative() external pure returns (bool) {
        return false;
    }

    function kindEnabled(uint16) external pure returns (bool) {
        return false;
    }

    function kindOf(bytes32) external pure returns (uint16) {
        return 0;
    }

    function keyOwner(bytes32 kh) external view returns (bytes32) {
        return kh == claimedKeyHash ? claimedOwner : bytes32(0);
    }
}

abstract contract UARegistryBase is Test {
    uint64 internal constant BUDGET = 12_000_000;
    address internal constant REG_A = 0x5Ca0000000000000000000000000000000000001;
    bytes32 internal constant DIGEST = keccak256("scaas.ua.test.digest");

    bytes32 internal chainUidA;
    MockVerifier internal mock;
    UARegistry internal reg;
    bytes[8] internal keys; // kinds.json valid[0..7] = kinds 0x0100..0x0107
    uint16[8] internal KINDS = [0x0100, 0x0101, 0x0102, 0x0103, 0x0104, 0x0105, 0x0106, 0x0107];

    struct Member {
        uint16 kind;
        bytes32 id;
        uint16 weight;
    }

    function setUp() public virtual {
        chainUidA = vm.parseJsonBytes32(_structures(), ".contexts.A.chainUid");
        string memory j = _kindsJson();
        for (uint256 i; i < 8; ++i) {
            keys[i] = vm.parseJsonBytes(j, string.concat(".valid[", vm.toString(i), "].keyData"));
        }
        vm.chainId(31337);
        mock = new MockVerifier(0, 0);
        reg = _deploy(REG_A, chainUidA, address(0), false, BUDGET, address(0), true, _cfgs(address(mock)));
    }

    // ----- vectors -----

    function _kindsJson() internal view returns (string memory) {
        return vm.readFile("../vectors/ua/kinds.json");
    }

    function _structures() internal view returns (string memory) {
        return vm.readFile("../vectors/ua/structures.json");
    }

    /// kinds.json `valid[i]` holds the kinds 0x0100..0x0107 in order.
    function _key(uint16 kind) internal view returns (bytes memory) {
        return keys[kind - 0x0100];
    }

    // ----- deployment -----

    /// The gen-1 default caps (controller ruling 2026-10-12; ed25519, UA-2b: the measured worst 170,286 frame gas
    /// + ~23 %, `UAGas.t.sol` `test_T_GAS_ed25519`; mock verifiers stay far below them).
    function _cap(uint16 kind) internal pure returns (uint64) {
        if (kind == 0x0100 || kind == 0x0101) return 400_000;
        if (kind == 0x0102) return 210_000;
        if (kind == 0x0105) return 70_000;
        if (kind == 0x0106) return 200_000;
        if (kind == 0x0107) return 345_000;
        return 50_000;
    }

    function _cfgs(address v) internal view returns (UARegistry.KindConfig[] memory c) {
        c = new UARegistry.KindConfig[](KINDS.length);
        for (uint256 i; i < KINDS.length; ++i) {
            c[i] = UARegistry.KindConfig(KINDS[i], v, _cap(KINDS[i]));
        }
    }

    function _deploy(
        address where,
        bytes32 uid,
        address pred,
        bool hedera,
        uint64 budget,
        address ska,
        bool msig,
        UARegistry.KindConfig[] memory cfgs
    ) internal returns (UARegistry) {
        deployCodeTo("UARegistry.sol:UARegistry", abi.encode(uid, pred, hedera, budget, ska, msig, cfgs), where);
        return UARegistry(where);
    }

    // ----- signatures -----

    function _sig(bytes memory keyData, bytes32 message) internal pure returns (bytes memory) {
        return abi.encodePacked(keccak256(abi.encode(keyData, message)));
    }

    function _pop(UARegistry r, uint16 kind, bytes memory keyData) internal view returns (bytes memory) {
        bytes32 ua = r.uaOf(kind, keyData);
        return _sig(keyData, r.uaMessage(kind, UAKinds.PURPOSE_POP, r.popDigest(ua, 0)));
    }

    function _register(UARegistry r, uint16 kind, bytes memory keyData) internal returns (bytes32) {
        return r.register(kind, keyData, _pop(r, kind, keyData), "", "");
    }

    /// The PoP is computed first: `vm.expectRevert` applies to the next external call.
    function _registerReverts(UARegistry r, uint16 kind, bytes memory keyData, bytes memory err) internal {
        bytes memory pop = _pop(r, kind, keyData);
        vm.expectRevert(err);
        r.register(kind, keyData, pop, "", "");
    }

    function _auth(UARegistry r, uint16 kind, bytes memory keyData, bytes32 purpose, bytes32 digest)
        internal
        view
        returns (bytes memory)
    {
        return abi.encode(keyData, _sig(keyData, r.uaMessage(kind, purpose, digest)));
    }

    function _pad(address a) internal pure returns (bytes32) {
        return bytes32(uint256(uint160(a)));
    }

    function _ecdsa(uint256 pk, bytes32 h) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r_, bytes32 s) = vm.sign(pk, h);
        return abi.encodePacked(r_, s, v);
    }

    function _nativeSig(UARegistry r, uint256 pk, bytes32 purpose, bytes32 digest)
        internal
        view
        returns (bytes memory)
    {
        return _ecdsa(pk, r.uaAuthDigest(_pad(vm.addr(pk)), purpose, digest));
    }

    // ----- msig -----

    /// `u16 threshold ‖ u16 count ‖ count × (u16 kind ‖ bytes32 id ‖ u16 weight)`, members sorted by id here.
    function _msigKey(uint16 threshold, Member[] memory m) internal pure returns (bytes memory d) {
        for (uint256 i = 1; i < m.length; ++i) {
            for (uint256 j = i; j > 0 && m[j - 1].id > m[j].id; --j) {
                (m[j - 1], m[j]) = (m[j], m[j - 1]);
            }
        }
        d = abi.encodePacked(threshold, uint16(m.length));
        for (uint256 i; i < m.length; ++i) {
            d = abi.encodePacked(d, m[i].kind, m[i].id, m[i].weight);
        }
    }

    /// Index of member `id` in msig key data `d`.
    function _indexOf(bytes memory d, bytes32 id) internal pure returns (uint16) {
        uint256 count = uint16(bytes2(abi.encodePacked(d[2], d[3])));
        for (uint256 i; i < count; ++i) {
            bytes32 w;
            assembly ("memory-safe") {
                w := mload(add(add(d, 34), add(4, mul(36, i))))
            }
            if (w == id) return uint16(i);
        }
        revert("member");
    }

    function _memberDigest(bytes32 ua, bytes32 purpose, bytes32 digest) internal pure returns (bytes32) {
        return UAKinds.memberDigest(ua, UAKinds.uaMessage(UAKinds.MSIG, purpose, digest));
    }

    function _msigAuth(bytes memory d, UARegistry.MemberSig[] memory sigs) internal pure returns (bytes memory) {
        return abi.encode(d, abi.encode(sigs));
    }
}

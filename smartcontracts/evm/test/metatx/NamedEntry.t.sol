// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {UACall} from "../ua/UACall.sol";
import {MtxDigest} from "../helpers/MtxDigest.sol";
import {IERC5267} from "@openzeppelin/contracts/interfaces/IERC5267.sol";
import {Vm} from "forge-std/Vm.sol";
import {console2} from "forge-std/console2.sol";
import {V2Fixture, UID_} from "../v2/helpers/V2Fixture.sol";
import {MandateFixture} from "../wallet/MandateWallet.t.sol";
import {PqzFixture} from "../pqz/helpers/PqzFixture.sol";
import {ZetherFixture} from "../zether/helpers/ZetherFixture.sol";
import {ZetherKeys} from "../zether/helpers/ZetherKeys.sol";
import {MockERC20} from "../helpers/Mocks.sol";
import {WrappedToken} from "../../src/metatx/WrappedToken.sol";
import {WrappedPqzToken} from "../../src/pqz/WrappedPqzToken.sol";
import {WrappedZetherToken} from "../../src/zether/WrappedZetherToken.sol";
import {ZetherLayer} from "../../src/zether/ZetherLayer.sol";
import {ZetherTypes} from "../../src/zether/ZetherTypes.sol";
import {MandateWallet} from "../../src/wallet/MandateWallet.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {GovernanceLib} from "../../src/governance/GovernanceLib.sol";
import {GovernanceBits} from "../../src/governance/GovernanceBits.sol";
import {TokenStore} from "../../src/metatx/TokenStore.sol";
import {Catalogue} from "../helpers/Catalogue.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";

Vm constant VM = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

// The envelope fields of a typed op, in the struct's order after the op's own (TS-D14), for the wallet JSON.
string constant E_TYPES = '{"name":"batch","type":"uint256"},{"name":"nonce","type":"uint256"},{"name":"validUntil","type":"uint256"},'
    '{"name":"mode","type":"uint32"},{"name":"relayer","type":"address"},{"name":"fee","type":"uint256"},{"name":"feeRecipient","type":"address"}';

function n(uint256 v) pure returns (string memory) {
    return string.concat('"', VM.toString(v), '"');
}

function a(address v) pure returns (string memory) {
    return string.concat('"', VM.toString(v), '"');
}

function h(bytes32 v) pure returns (string memory) {
    return string.concat('"', VM.toString(v), '"');
}

/// The message fields `E` of `eth_signTypedData_v4`: relayer / fee recipient as signed (canonical zero when unbound).
function eJson(uint256 batch, uint256 nonce, uint256 validUntil, uint32 mode, uint256 fee) pure returns (string memory) {
    return string.concat('"batch":', n(batch), ',"nonce":', n(nonce), ',"validUntil":', n(validUntil), ',"mode":', n(mode),
        ',"relayer":', a(address(0)), ',"fee":', n(fee), ',"feeRecipient":', a(address(0)));
}

/// What a wallet signs for `eth_signTypedData_v4`: the digest of the JSON it is handed, nothing from the contract's
/// struct hash (`vm.eip712HashTypedData`); the domain is the one the contract publishes (ERC-5267).
function walletDigest(address c, string memory primary, string memory fields, string memory message)
    view returns (bytes32)
{
    return VM.eip712HashTypedData(string.concat(
        '{"types":{"EIP712Domain":[{"name":"name","type":"string"},{"name":"version","type":"string"},',
        '{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"},{"name":"salt","type":"bytes32"}],"',
        primary, '":[', fields, ',', E_TYPES, ']},"primaryType":"', primary, '","domain":', domainJson(c), ',"message":{', message, '}}'
    ));
}

function domainJson(address c) view returns (string memory) {
    (, string memory name, string memory version, uint256 chainId, address vc, bytes32 salt,) = IERC5267(c).eip712Domain();
    return string.concat('{"name":"', name, '","version":"', version, '","chainId":', n(chainId), ',"verifyingContract":', a(vc),
        ',"salt":', h(salt), '}');
}

function ecdsa(uint256 pk, bytes32 digest) pure returns (bytes memory) {
    (uint8 v, bytes32 r, bytes32 s) = VM.sign(pk, digest);
    return abi.encodePacked(r, s, v);
}

// ------------------------------------------------------------------ typed-signing C1: typed_ops.json on the C0 entries

string constant TYPED_OPS = "../vectors/typed/typed_ops.json";
// ua-mtx-merge T11 (MD-7): the rows as they stood before the merged entries; a retired row is read here to show it finds no
// entry on its contract.
string constant TYPED_OPS_LEGACY = "../vectors/typed/legacy/ua-mtx-merge/typed_ops.json";
bytes32 constant SALTED_DOMAIN = keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)");

function rowKey(string memory j) pure returns (uint256) {
    return uint256(VM.parseJsonBytes32(j, ".key.private"));
}

function msgField(string memory op, string memory field) pure returns (string memory) {
    return string.concat(".ops.", op, ".message.", field);
}

function domainField(string memory op, string memory kind, string memory field) pure returns (string memory) {
    return string.concat(".ops.", op, ".domains.", kind, ".", field);
}

function rowEnvelope(string memory j, string memory op) pure returns (MetaTxLib.Envelope memory e) {
    e = rowEnvelope2(j, op);
    e.from = VM.parseJsonAddress(j, msgField(op, "from"));
}

/// The envelope without `from`, an address or a 32-byte id by the struct.
function rowEnvelope2(string memory j, string memory op) pure returns (MetaTxLib.Envelope memory e) {
    e.batch = VM.parseJsonUint(j, msgField(op, "batch"));
    e.nonce = VM.parseJsonUint(j, msgField(op, "nonce"));
    e.validUntil = VM.parseJsonUint(j, msgField(op, "validUntil"));
    e.mode = uint32(VM.parseJsonUint(j, msgField(op, "mode")));
    e.relayer = VM.parseJsonAddress(j, msgField(op, "relayer"));
    e.fee = VM.parseJsonUint(j, msgField(op, "fee"));
    e.feeRecipient = VM.parseJsonAddress(j, msgField(op, "feeRecipient"));
}

/// The row by itself: its digest under its own domain, its native signature, the hashes of its type string.
function checkRow(string memory j, string memory op, string memory kind) pure {
    require(keccak256(bytes(VM.parseJsonString(j, string.concat(".ops.", op, ".typeString"))))
        == VM.parseJsonBytes32(j, string.concat(".ops.", op, ".typehash")), "typehash");
    string memory d = string.concat(".ops.", op, ".domains.", kind, ".domain.");
    bytes32 sep = keccak256(abi.encode(SALTED_DOMAIN, keccak256(bytes(VM.parseJsonString(j, string.concat(d, "name")))),
        keccak256(bytes(VM.parseJsonString(j, string.concat(d, "version")))), VM.parseJsonUint(j, string.concat(d, "chainId")),
        VM.parseJsonAddress(j, string.concat(d, "verifyingContract")), VM.parseJsonBytes32(j, string.concat(d, "salt"))));
    bytes32 digest = VM.parseJsonBytes32(j, domainField(op, kind, "digest"));
    require(sep == VM.parseJsonBytes32(j, domainField(op, kind, "domainSeparator")), "domain separator");
    require(digest == keccak256(abi.encodePacked(hex"1901", sep, VM.parseJsonBytes32(j, string.concat(".ops.", op, ".structHash")))), "digest");
    bytes memory sig = VM.parseJsonBytes(j, domainField(op, kind, "signature"));
    bytes32 r;
    bytes32 s;
    assembly ("memory-safe") {
        r := mload(add(sig, 32))
        s := mload(add(sig, 64))
    }
    require(ecrecover(digest, uint8(sig[64]), r, s) == VM.parseJsonAddress(j, ".key.address"), "signature");
}

/// The contract's own digest of the row's struct hash: an entry accepts this signature only if it hashes what clientkeys hashed.
function onChain(string memory j, string memory op, address c) view returns (bytes memory) {
    return ecdsa(rowKey(j), keccak256(abi.encodePacked(hex"1901", domainOf(c),
        VM.parseJsonBytes32(j, string.concat(".ops.", op, ".structHash")))));
}

/// The contract's own domain separator, from its ERC-5267 fields.
function domainOf(address c) view returns (bytes32) {
    (, string memory name, string memory version, uint256 chainId, address vc, bytes32 salt,) = IERC5267(c).eip712Domain();
    return keccak256(abi.encode(SALTED_DOMAIN, keccak256(bytes(name)), keccak256(bytes(version)), chainId, vc, salt));
}

string constant UNWRAP_FIELDS = '{"name":"from","type":"bytes32"},{"name":"wrapped","type":"uint256"},{"name":"recipient","type":"address"},{"name":"minOut","type":"uint256"}';

/// C0 (TS-D14): a named entry takes the wallet's typed signature and runs the op on the kept generic pipeline; the
/// generic path stays beside it on the same `(from, batch)` lane. ua-mtx-merge T3 (R23), meaning: the named entry is the
/// merged `mtxUnwrap(UAEnvelope, …, UASig)` over `UAUnwrap` (the holder's id zero-padded, its own key); the generic
/// path beside it is the address `executeMetaTransaction` (R3). The address form is in legacy/ua-mtx-merge/.
contract NamedUnwrapTest is V2Fixture {
    uint256 constant PK = 0xA11CE;
    uint256 constant LANE = 7;
    address holder = vm.addr(PK);
    address bob = address(0xB0B);
    MockERC20 usd;
    WrappedToken w;

    function setUp() public {
        usd = new MockERC20("USD", "USD", 0);
        w = _single(address(usd), 0, 1, 1, _fixedRate());
        usd.mint(holder, 10_000);
        vm.startPrank(holder);
        usd.approve(address(w), 10_000);
        w.wrap(10_000);
        vm.stopPrank();
    }

    function _env(uint256 nonce, uint32 mode, uint256 fee) internal view returns (MetaTxLib.UAEnvelope memory e) {
        e.from = MetaTxLib.pad(holder);
        e.batch = LANE;
        e.nonce = nonce;
        e.validUntil = block.timestamp + 300;
        e.mode = mode;
        e.fee = fee;
    }

    function _walletSig(MetaTxLib.UAEnvelope memory e, uint256 wrapped, uint256 minOut)
        internal view returns (IUARegistry.UASig memory s)
    {
        string memory tail = eJson(e.batch, e.nonce, e.validUntil, e.mode, e.fee);
        string memory message = string.concat('"from":', h(e.from), ',"wrapped":', n(wrapped), ',"recipient":', a(bob),
            ',"minOut":', n(minOut), ',', tail);
        s.signature = ecdsa(PK, walletDigest(address(w), "UAUnwrap", UNWRAP_FIELDS, message));
    }

    function _native(bytes memory sig) internal pure returns (IUARegistry.UASig memory s) {
        s.signature = sig;
    }

    function _generic(uint256 nonce, uint256 wrapped, uint256 minOut)
        internal view returns (MetaTxLib.MetaTransaction memory m)
    {
        m.from = holder;
        m.data = abi.encodeWithSignature("unwrap(uint256,address,uint256)", wrapped, bob, minOut);
        m.batch = LANE;
        m.nonce = nonce;
        m.validUntil = block.timestamp + 300;
    }

    function test_c0_unwrapTyped() public {
        // the wallet's signature executes, the amount-class fee of the signed mode from the signer, after the op
        MetaTxLib.UAEnvelope memory e = _env(0, MetaTxLib.MODE_FEE_FIXED, 1);
        IUARegistry.UASig memory sig = _walletSig(e, 100, 90);
        vm.prank(relayer);
        w.mtxUnwrap(e, 100, bob, 90, sig);
        assertEq(usd.balanceOf(bob), 100);
        assertEq(w.balanceOf(holder), 10_000 - 101);
        assertEq(w.balanceOf(relayer), 1);
        assertEq(w.mtxNonce(MetaTxLib.pad(holder), LANE), 1);

        // one signature runs once
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 1, 0));
        w.mtxUnwrap(e, 100, bob, 90, sig);

        // the typed and the generic signature are not interchangeable
        e = _env(1, 0, 0);
        MetaTxLib.MetaTransaction memory m = _generic(1, 200, 0);
        IUARegistry.UASig memory typed = _walletSig(e, 200, 0);
        bytes memory generic = ecdsa(PK, MtxDigest.metaTx(address(w), m));
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        w.executeMetaTransaction(m, typed.signature);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        w.mtxUnwrap(e, 200, bob, 0, _native(generic));

        // the kept generic path runs the same op on the same lane: nonce 1 is gone for the typed form too
        vm.prank(relayer);
        w.executeMetaTransaction(m, generic);
        assertEq(usd.balanceOf(bob), 300);
        assertEq(w.mtxNonce(MetaTxLib.pad(holder), LANE), 2);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 2, 1));
        w.mtxUnwrap(e, 200, bob, 0, typed);

        // and back: the typed form takes nonce 2, the generic signature of nonce 2 is dead
        m = _generic(2, 300, 0);
        generic = ecdsa(PK, MtxDigest.metaTx(address(w), m));
        e = _env(2, 0, 0);
        w.mtxUnwrap(e, 300, bob, 0, _walletSig(e, 300, 0));
        assertEq(usd.balanceOf(bob), 600);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 3, 2));
        w.executeMetaTransaction(m, generic);
    }

    /// The same op on a warm lane through both paths, for the run log. ua-mtx-merge T3, meaning: the named entry is the
    /// merged one on `UASig`, so the generic path it is held to is the merged `mtxExecute(UAMetaTransaction, UASig)` (the
    /// same signature form); the address alias `executeMetaTransaction` is logged beside it (R3).
    function test_c0_gasNamedVsGeneric() public {
        MetaTxLib.UAEnvelope memory e = _env(0, 0, 0);
        IUARegistry.UASig memory sig = _walletSig(e, 100, 0);
        w.mtxUnwrap(e, 100, bob, 0, sig);
        e = _env(1, 0, 0);
        sig = _walletSig(e, 100, 0);
        vm.prank(relayer);
        w.mtxUnwrap(e, 100, bob, 0, sig);
        uint256 named = vm.lastCallGas().gasTotalUsed;
        MetaTxLib.MetaTransaction memory m = _generic(2, 100, 0);
        MetaTxLib.UAMetaTransaction memory u = MetaTxLib.UAMetaTransaction(e.from, m.data, LANE, 2, m.validUntil, 0,
            address(0), 0, address(0));
        sig = _native(ecdsa(PK, w.mtxDigest(u)));
        vm.prank(relayer);
        w.mtxExecute(u, sig);
        uint256 generic = vm.lastCallGas().gasTotalUsed;
        m.nonce = 3;
        bytes memory gsig = ecdsa(PK, MtxDigest.metaTx(address(w), m));
        vm.prank(relayer);
        w.executeMetaTransaction(m, gsig);
        uint256 alias_ = vm.lastCallGas().gasTotalUsed;
        console2.log("mtxUnwrap / mtxExecute(unwrap) / executeMetaTransaction(unwrap), warm lane", named, generic, alias_);
        assertLt(named, generic + 2_000);
    }

    /// C1: the `UAUnwrap` row byte for byte on the C0 entry, and run under this token's domain. ua-mtx-merge T3, meaning:
    /// the address `Unwrap` row has no entry (R23); T11 (MD-7): the `UAUnwrap` row names the merged `mtxUnwrap`, the
    /// retired `Unwrap` row is read from `TYPED_OPS_LEGACY`.
    function test_c1_unwrapRow() public {
        string memory j = VM.readFile(TYPED_OPS);
        checkRow(j, "UAUnwrap", "token");
        MetaTxLib.Envelope memory e2 = rowEnvelope2(j, "UAUnwrap");
        MetaTxLib.UAEnvelope memory e = MetaTxLib.UAEnvelope(VM.parseJsonBytes32(j, msgField("UAUnwrap", "from")), e2.batch,
            e2.nonce, e2.validUntil, e2.mode, e2.relayer, e2.fee, e2.feeRecipient);
        address from = address(uint160(uint256(e.from)));
        uint256 wrapped = VM.parseJsonUint(j, msgField("UAUnwrap", "wrapped"));
        address recipient = VM.parseJsonAddress(j, msgField("UAUnwrap", "recipient"));
        uint256 minOut = VM.parseJsonUint(j, msgField("UAUnwrap", "minOut"));
        bytes memory cd = VM.parseJsonBytes(j, domainField("UAUnwrap", "token", "calldata"));
        assertEq(abi.encodeWithSignature("mtxUnwrap((bytes32,uint256,uint256,uint256,uint32,address,uint256,address),uint256,address,uint256,(bytes,bytes,(uint16,(uint16,bytes)[],bytes)[]))", e, wrapped,
            recipient, minOut, _native(VM.parseJsonBytes(j, domainField("UAUnwrap", "token", "signature")))), cd);
        usd.mint(from, 2 * wrapped);
        vm.startPrank(from);
        usd.approve(address(w), 2 * wrapped);
        w.wrap(2 * wrapped);
        vm.stopPrank();
        IUARegistry.UASig memory sig = _native(onChain(j, "UAUnwrap", address(w))); // before the prank: an external read
        vm.prank(e.relayer);
        w.mtxUnwrap(e, wrapped, recipient, minOut, sig);
        assertEq(usd.balanceOf(recipient), wrapped);
        assertEq(w.mtxNonce(e.from, e.batch), 1);
        assertEq(w.balanceOf(e.feeRecipient), wrapped * e.fee / 1_000_000, "the row's PERCENT fee");
        // the address `Unwrap` row: its own calldata finds no function
        (bool ok, bytes memory ret) = address(w).call(VM.parseJsonBytes(VM.readFile(TYPED_OPS_LEGACY), domainField("Unwrap", "token", "calldata")));
        assertFalse(ok);
        assertEq(ret.length, 0, "no such function");
    }

    /// The named entry is no self-call target: the generic path cannot call it, nor the entry itself.
    function test_c0_namedEntryNotAllowlisted() public {
        MetaTxLib.MetaTransaction memory m = _generic(0, 1, 0);
        IUARegistry.UASig memory none;
        m.data = abi.encodeCall(w.mtxUnwrap, (_env(0, 0, 0), uint256(1), bob, uint256(0), none));
        bytes memory sig = ecdsa(PK, MtxDigest.metaTx(address(w), m));
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MtxSelectorNotAllowed.selector, w.mtxUnwrap.selector));
        w.executeMetaTransaction(m, sig);
    }
}

string constant SHIELD_FIELDS = '{"name":"from","type":"address"},{"name":"toUA","type":"bytes32"},{"name":"amount","type":"uint256"}';
string constant UA_SHIELD_FIELDS = '{"name":"from","type":"bytes32"},{"name":"toUA","type":"bytes32"},{"name":"amount","type":"uint256"}';

function shieldJson(string memory from, bytes32 toUA, uint256 amount, uint256 batch, uint256 nonce, uint256 validUntil)
    pure returns (string memory)
{
    return string.concat('"from":', from, ',"toUA":', h(toUA), ',"amount":', n(amount), ',', eJson(batch, nonce, validUntil, 0, 0));
}

contract NamedShieldPqzTest is PqzFixture {
    uint256 constant PK = 0xA11CE;
    address signer = vm.addr(PK);
    address relayer = address(0xBEEF);
    WrappedPqzToken w;
    MockERC20 usd;

    function setUp() public {
        _stack();
        _releaseWrapped();
        w = _newWrapped("wp");
        usd = MockERC20(w.underlying());
        usd.mint(signer, 100 * SCALE);
        vm.startPrank(signer);
        usd.approve(address(w), 100 * SCALE);
        w.wrap(100 * SCALE);
        vm.stopPrank();
    }

    /// ua-mtx-merge T5, meaning (R36): the EOA signs `UAShield` (its id padded) on the merged `mtxShield`, as a derived id
    /// does; the address `Shield` entry is in legacy/ua-mtx-merge/.
    function test_c0_shieldTyped() public {
        MetaTxLib.UAEnvelope memory u;
        u.from = MetaTxLib.pad(signer);
        u.validUntil = block.timestamp + 300;
        bytes memory sig = ecdsa(PK, walletDigest(address(w), "UAShield", UA_SHIELD_FIELDS,
            shieldJson(h(u.from), alice, 10, 0, 0, u.validUntil)));
        vm.prank(relayer);
        w.mtxShield(u, alice, 10, UACall.auth(u.from, sig));
        assertEq((w.pqzPending(alice, 0) >> 96) & type(uint64).max, 10, "a TRIVIAL entry");
        assertEq(w.balanceOf(signer), 90 * SCALE);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 1, 0));
        w.mtxShield(u, alice, 10, UACall.auth(u.from, sig));

        // a derived `mldsa65` UA signs `UAShield` under `metatx` (its precompile mocked), from its UA-ledger balance
        bytes32 from = _mldsaUA(9);
        vm.prank(signer);
        w.transferToUA(from, 40 * SCALE);
        MetaTxLib.UAEnvelope memory d;
        d.from = from;
        d.validUntil = u.validUntil;
        vm.roll(block.number + 1); // a new pending entry, not the block's TRIVIAL one
        vm.prank(relayer);
        w.mtxShield(d, alice, 20, UACall.auth(d.from, _mlAuth()));
        assertEq((w.pqzPending(alice, 1) >> 96) & type(uint64).max, 20);
        assertEq(w.balanceOfUA(from), 20 * SCALE);
        assertEq(w.mtxNonce(from, 0), 1);
    }

    /// C1: the row's `toUA` is `ZetherFixture`'s; here the registry answers for it as for `alice`: the signature is what is pinned.
    function _rowHolder(string memory j, string memory op, address from) internal returns (bytes32 toUA) {
        toUA = VM.parseJsonBytes32(j, msgField(op, "toUA"));
        (address ptr, bytes32 keyHash, bool proven) = reg.pqzKeyOf(alice);
        vm.mockCall(address(reg), abi.encodeCall(IUARegistry.pqzKeyOf, (toUA)), abi.encode(ptr, keyHash, proven));
        usd.mint(from, 100 * SCALE);
        vm.startPrank(from);
        usd.approve(address(w), 100 * SCALE);
        w.wrap(100 * SCALE);
        vm.stopPrank();
    }

    /// ua-mtx-merge T5, meaning (R36): the address `Shield` entry left the PQZ kinds, so the row's calldata finds no
    /// function there (MD-7: the row retired by T11, read from `TYPED_OPS_LEGACY`).
    function test_c1_shieldRowHasNoPqzEntry() public {
        string memory j = VM.readFile(TYPED_OPS_LEGACY);
        checkRow(j, "Shield", "pqz");
        MetaTxLib.Envelope memory e = rowEnvelope(j, "Shield");
        bytes32 toUA = _rowHolder(j, "Shield", e.from);
        uint256 amount = VM.parseJsonUint(j, msgField("Shield", "amount"));
        assertEq(abi.encodeWithSignature("mtxShield((address,uint256,uint256,uint256,uint32,address,uint256,address),bytes32,uint256,bytes)",
            e, toUA, amount, VM.parseJsonBytes(j, domainField("Shield", "pqz", "signature"))), VM.parseJsonBytes(j, domainField("Shield", "pqz", "calldata")));
        vm.prank(e.relayer);
        (bool ok, bytes memory ret) = address(w).call(VM.parseJsonBytes(j, domainField("Shield", "pqz", "calldata")));
        assertFalse(ok, "a retired entry runs");
        assertEq(ret.length, 0, "no function");
        assertEq(w.mtxNonce(MetaTxLib.pad(e.from), e.batch), 0);
        assertEq(w.totalShielded(), 0);
    }

    function test_c1_uaShieldRow() public {
        string memory j = VM.readFile(TYPED_OPS);
        checkRow(j, "UAShield", "pqz");
        MetaTxLib.Envelope memory env = rowEnvelope2(j, "UAShield");
        MetaTxLib.UAEnvelope memory u = MetaTxLib.UAEnvelope(VM.parseJsonBytes32(j, msgField("UAShield", "from")), env.batch, env.nonce,
            env.validUntil, env.mode, env.relayer, env.fee, env.feeRecipient);
        bytes32 toUA = _rowHolder(j, "UAShield", address(uint160(uint256(u.from))));
        uint256 amount = VM.parseJsonUint(j, msgField("UAShield", "amount"));
        // ua-mtx-merge T11, meaning (R47, MD-7): the row is the merged `mtxShield` with `UASig{signature}` (T1-T10: the
        // pre-R47 `bytes auth` form under `uaShield`, the same signature)
        IUARegistry.UASig memory rowSig;
        rowSig.signature = VM.parseJsonBytes(j, domainField("UAShield", "pqz", "signature"));
        assertEq(abi.encodeWithSignature(
            "mtxShield((bytes32,uint256,uint256,uint256,uint32,address,uint256,address),bytes32,uint256,(bytes,bytes,(uint16,(uint16,bytes)[],bytes)[]))",
            u, toUA, amount, rowSig), VM.parseJsonBytes(j, domainField("UAShield", "pqz", "calldata")), "the row: mtxShield with UASig");
        bytes memory sig = onChain(j, "UAShield", address(w));
        vm.prank(u.relayer);
        w.mtxShield(u, toUA, amount, UACall.auth(u.from, sig));
        assertEq(w.mtxNonce(u.from, u.batch), 1);
        assertEq((w.pqzPending(toUA, 0) >> 96) & type(uint64).max, amount);
    }
}

contract NamedShieldZetherTest is ZetherFixture {
    uint256 constant PK = 0x9A7E5;
    address signer = vm.addr(PK);
    WrappedZetherToken w;
    MockERC20 usd = new MockERC20("USD", "USD", 6);

    function setUp() public {
        _stack();
        Catalogue.release(factory, IOpenFactory.TokenKind.WRAPPED_ZETHER, 1, _zenv(), type(WrappedZetherToken).creationCode);
        IFactoryToken.TokenConfig memory c;
        c.name = "Zether wrapped";
        c.symbol = "zW";
        c.decimals = 6;
        c.features = 1 << GovernanceBits.PAYABLE;
        c.legs = new IFactoryToken.Leg[](1);
        c.legs[0] = IFactoryToken.Leg(address(usd), 1, 1);
        c.conf = IFactoryToken.ConfidentialConfig(bytes(""), SCALE, uint256(1) << 40, FEE, dMode, 0, 0);
        w = WrappedZetherToken(payable(factory.createToken(IOpenFactory.TokenKind.WRAPPED_ZETHER, 1, abi.encode(c), "zw")));
        tok = ZetherLayer(address(w));
        _users();
        usd.mint(signer, 100 * SCALE);
        vm.startPrank(signer);
        usd.approve(address(w), 100 * SCALE);
        w.wrap(100 * SCALE);
        vm.stopPrank();
    }

    /// ua-mtx-merge T4, meaning (R35): the EOA signs `UAShield` (its id padded) on the merged `mtxShield`, as a derived id
    /// does; the address `Shield` entry is in legacy/ua-mtx-merge/.
    function test_c0_shieldTyped() public {
        bytes32 to = ZetherTypes.UA.unwrap(bob.ua);
        MetaTxLib.UAEnvelope memory e;
        e.from = MetaTxLib.pad(signer);
        e.validUntil = block.timestamp + 300;
        bytes memory sig = ecdsa(PK, walletDigest(address(w), "UAShield", UA_SHIELD_FIELDS,
            shieldJson(h(e.from), to, 10, 0, 0, e.validUntil)));
        vm.prank(relayer);
        w.mtxShield(e, to, 10, UACall.auth(e.from, sig));
        assertEq(w.balanceOf(signer), 90 * SCALE);
        assertEq(w.totalShielded(), 10);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 1, 0));
        w.mtxShield(e, to, 10, UACall.auth(e.from, sig));

        // a derived Zether UA signs `UAShield` under `metatx`; the registry verifies over the wallet digest
        bytes32 from = ZetherTypes.UA.unwrap(alice.ua);
        vm.prank(signer);
        w.transferToUA(from, 40 * SCALE);
        MetaTxLib.UAEnvelope memory u;
        u.from = from;
        u.validUntil = e.validUntil;
        bytes32 d = walletDigest(address(w), "UAShield", UA_SHIELD_FIELDS, shieldJson(h(from), to, 15, 0, 0, u.validUntil));
        bytes memory auth = abi.encode(bytes(""), ZetherKeys.schnorr(alice.x, reg.uaMessage(_zkind(), UAKinds.PURPOSE_METATX, d), bls));
        vm.prank(relayer);
        w.mtxShield(u, to, 15, UACall.auth(u.from, auth));
        assertEq(w.balanceOfUA(from), 25 * SCALE);
        assertEq(w.totalShielded(), 25);
        assertEq(w.mtxNonce(from, 0), 1);
    }

    /// C1: the `Shield` row, its `toUA` is `bob`. ua-mtx-merge T4, meaning (R35): the address `Shield` entry left the
    /// Zether kinds, so the row's calldata finds no function there (T11: the row retired, read from `TYPED_OPS_LEGACY`).
    function test_c1_shieldRowHasNoZetherEntry() public {
        string memory j = VM.readFile(TYPED_OPS_LEGACY);
        checkRow(j, "Shield", "zether");
        MetaTxLib.Envelope memory e = rowEnvelope(j, "Shield");
        bytes32 toUA = VM.parseJsonBytes32(j, msgField("Shield", "toUA"));
        assertEq(toUA, ZetherTypes.UA.unwrap(bob.ua));
        uint256 amount = VM.parseJsonUint(j, msgField("Shield", "amount"));
        assertEq(abi.encodeWithSignature("mtxShield((address,uint256,uint256,uint256,uint32,address,uint256,address),bytes32,uint256,bytes)",
            e, toUA, amount, VM.parseJsonBytes(j, domainField("Shield", "zether", "signature"))),
            VM.parseJsonBytes(j, domainField("Shield", "zether", "calldata")));
        usd.mint(e.from, 100 * SCALE);
        vm.startPrank(e.from);
        usd.approve(address(w), 100 * SCALE);
        w.wrap(100 * SCALE);
        vm.stopPrank();
        vm.prank(e.relayer);
        (bool ok, bytes memory ret) = address(w).call(VM.parseJsonBytes(j, domainField("Shield", "zether", "calldata")));
        assertFalse(ok, "a retired entry runs");
        assertEq(ret.length, 0, "no function");
        assertEq(w.mtxNonce(MetaTxLib.pad(e.from), e.batch), 0);
        assertEq(w.totalShielded(), 0);
    }
}

/// typed-signing C0 on the mandate wallet; ua-mtx-merge T3b (Q6), meaning: `mtxSetMandate` takes `UAEnvelope` + `UASig`
/// over `UASetMandate` (ids `bytes32`), and the address `SetMandate` row has no wallet entry (T11, MD-7: the row retired,
/// read from `TYPED_OPS_LEGACY`; the `UASetMandate` row runs in `TypedOps.t.sol`).
contract NamedMandateTest is MandateFixture {
    function _walletSig(bytes32 d2, uint64 expiry, uint256 validUntil) internal view returns (IUARegistry.UASig memory a_) {
        string memory tail = eJson(3, 0, validUntil, 0, 0);
        string memory message = string.concat('"from":', h(_id(owner)), ',"token":', a(address(t)), ',"delegate":', h(d2),
            ',"maxPerPayment":', n(7), ',"maxPerPeriod":', n(9), ',"periodSeconds":', n(1 days), ',"expiry":', n(expiry), ',', tail);
        a_.signature = _sig(OWNER_PK, walletDigest(address(w), "UASetMandate",
            '{"name":"from","type":"bytes32"},{"name":"token","type":"address"},{"name":"delegate","type":"bytes32"},{"name":"maxPerPayment","type":"uint128"},'
            '{"name":"maxPerPeriod","type":"uint128"},{"name":"periodSeconds","type":"uint64"},{"name":"expiry","type":"uint64"}', message));
    }

    function test_c0_setMandateTyped() public {
        bytes32 d2 = _id(address(0xD2));
        uint64 expiry = uint64(block.timestamp + 60 days);
        MetaTxLib.UAEnvelope memory e;
        e.from = _id(owner);
        e.batch = 3;
        e.validUntil = block.timestamp + 300;
        IUARegistry.UASig memory sig = _walletSig(d2, expiry, e.validUntil);
        uint64 before = w.epoch(address(t));
        vm.prank(stranger); // a relayer: the signature is the authority
        w.mtxSetMandate(e, address(t), d2, 7, 9, 1 days, expiry, sig);
        (bytes32 delegate_,,,, uint128 perPayment, uint128 perPeriod,) = w.mandates(address(t));
        assertEq(delegate_, d2);
        assertEq(perPayment, 7);
        assertEq(perPeriod, 9);
        assertEq(w.epoch(address(t)), before + 1);
        assertEq(w.mtxNonce(_id(owner), 3), 1);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 1, 0));
        w.mtxSetMandate(e, address(t), d2, 7, 9, 1 days, expiry, sig);

        // a wallet accepts fee mode NONE only (CTR-MTX-22)
        e.nonce = 1;
        e.mode = MetaTxLib.MODE_FEE_FIXED;
        vm.expectRevert();
        w.mtxSetMandate(e, address(t), d2, 7, 9, 1 days, expiry, sig);

        // somebody else's signature: the op's `onlyOwner` reads the signer
        e.mode = 0;
        e.nonce = 0;
        e.from = _id(delegate);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        w.mtxSetMandate(e, address(t), d2, 7, 9, 1 days, expiry, sig);
    }

    /// C1: the address `SetMandate` row (`Envelope`, `bytes sig`) finds no function on a wallet of the row's key.
    function test_c1_setMandateRowHasNoWalletEntry() public {
        string memory j = VM.readFile(TYPED_OPS_LEGACY);
        checkRow(j, "SetMandate", "wallet");
        MetaTxLib.Envelope memory e = rowEnvelope(j, "SetMandate");
        bytes memory cd = VM.parseJsonBytes(j, domainField("SetMandate", "wallet", "calldata"));
        assertEq(abi.encodeWithSignature(
            "mtxSetMandate((address,uint256,uint256,uint256,uint32,address,uint256,address),address,address,uint128,uint128,uint64,uint64,bytes)",
            e, VM.parseJsonAddress(j, msgField("SetMandate", "token")), VM.parseJsonAddress(j, msgField("SetMandate", "delegate")),
            uint128(VM.parseJsonUint(j, msgField("SetMandate", "maxPerPayment"))),
            uint128(VM.parseJsonUint(j, msgField("SetMandate", "maxPerPeriod"))),
            uint64(VM.parseJsonUint(j, msgField("SetMandate", "periodSeconds"))),
            uint64(VM.parseJsonUint(j, msgField("SetMandate", "expiry"))),
            VM.parseJsonBytes(j, domainField("SetMandate", "wallet", "signature"))), cd);
        MandateWallet mine = new MandateWallet(_id(e.from), UID_, address(0), false);
        vm.prank(e.relayer);
        (bool ok, bytes memory ret) = address(mine).call(cd);
        assertFalse(ok, "a retired entry runs");
        assertEq(ret.length, 0, "no such function");
        assertEq(mine.mtxNonce(_id(e.from), e.batch), 0);
    }
}

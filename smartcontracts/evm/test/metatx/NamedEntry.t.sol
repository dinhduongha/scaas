// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

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
import {AdminLib} from "../../src/metatx/AdminLib.sol";
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
    (, string memory name, string memory version, uint256 chainId, address vc, bytes32 salt,) = IERC5267(c).eip712Domain();
    bytes32 sep = keccak256(abi.encode(SALTED_DOMAIN, keccak256(bytes(name)), keccak256(bytes(version)), chainId, vc, salt));
    return ecdsa(rowKey(j), keccak256(abi.encodePacked(hex"1901", sep,
        VM.parseJsonBytes32(j, string.concat(".ops.", op, ".structHash")))));
}

string constant UNWRAP_FIELDS = '{"name":"from","type":"address"},{"name":"wrapped","type":"uint256"},{"name":"recipient","type":"address"},{"name":"minOut","type":"uint256"}';

/// C0 (TS-D14): a named entry takes the wallet's typed signature and runs the op on the kept generic pipeline; the
/// generic `mtxExecute` stays beside it on the same `(from, batch)` lane.
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

    function _env(uint256 nonce, uint32 mode, uint256 fee) internal view returns (MetaTxLib.Envelope memory e) {
        e.from = holder;
        e.batch = LANE;
        e.nonce = nonce;
        e.validUntil = block.timestamp + 300;
        e.mode = mode;
        e.fee = fee;
    }

    function _walletSig(MetaTxLib.Envelope memory e, uint256 wrapped, uint256 minOut) internal view returns (bytes memory) {
        string memory tail = eJson(e.batch, e.nonce, e.validUntil, e.mode, e.fee);
        string memory message = string.concat('"from":', a(e.from), ',"wrapped":', n(wrapped), ',"recipient":', a(bob),
            ',"minOut":', n(minOut), ',', tail);
        return ecdsa(PK, walletDigest(address(w), "Unwrap", UNWRAP_FIELDS, message));
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
        MetaTxLib.Envelope memory e = _env(0, MetaTxLib.MODE_FEE_FIXED, 1);
        bytes memory sig = _walletSig(e, 100, 90);
        vm.prank(relayer);
        w.mtxUnwrap(e, 100, bob, 90, sig);
        assertEq(usd.balanceOf(bob), 100);
        assertEq(w.balanceOf(holder), 10_000 - 101);
        assertEq(w.balanceOf(relayer), 1);
        assertEq(w.mtxNonce(holder, LANE), 1);

        // one signature runs once
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 1, 0));
        w.mtxUnwrap(e, 100, bob, 90, sig);

        // the typed and the generic signature are not interchangeable
        e = _env(1, 0, 0);
        MetaTxLib.MetaTransaction memory m = _generic(1, 200, 0);
        bytes memory typed = _walletSig(e, 200, 0);
        bytes memory generic = ecdsa(PK, w.mtxDigest(m));
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        w.mtxExecute(m, typed);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        w.mtxUnwrap(e, 200, bob, 0, generic);

        // the kept generic path runs the same op on the same lane: nonce 1 is gone for the typed form too
        vm.prank(relayer);
        w.mtxExecute(m, generic);
        assertEq(usd.balanceOf(bob), 300);
        assertEq(w.mtxNonce(holder, LANE), 2);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 2, 1));
        w.mtxUnwrap(e, 200, bob, 0, typed);

        // and back: the typed form takes nonce 2, the generic signature of nonce 2 is dead
        m = _generic(2, 300, 0);
        generic = ecdsa(PK, w.mtxDigest(m));
        e = _env(2, 0, 0);
        w.mtxUnwrap(e, 300, bob, 0, _walletSig(e, 300, 0));
        assertEq(usd.balanceOf(bob), 600);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 3, 2));
        w.mtxExecute(m, generic);
    }

    /// The same op on a warm lane through both paths, for the run log.
    function test_c0_gasNamedVsGeneric() public {
        MetaTxLib.Envelope memory e = _env(0, 0, 0);
        bytes memory sig = _walletSig(e, 100, 0);
        w.mtxUnwrap(e, 100, bob, 0, sig);
        e = _env(1, 0, 0);
        sig = _walletSig(e, 100, 0);
        vm.prank(relayer);
        w.mtxUnwrap(e, 100, bob, 0, sig);
        uint256 named = vm.lastCallGas().gasTotalUsed;
        MetaTxLib.MetaTransaction memory m = _generic(2, 100, 0);
        sig = ecdsa(PK, w.mtxDigest(m));
        vm.prank(relayer);
        w.mtxExecute(m, sig);
        uint256 generic = vm.lastCallGas().gasTotalUsed;
        console2.log("mtxUnwrap / mtxExecute(unwrap), warm lane", named, generic);
        assertLt(named, generic + 2_000);
    }

    /// C1: the `Unwrap` row byte for byte on the C0 entry, and run under this token's domain.
    function test_c1_unwrapRow() public {
        string memory j = VM.readFile(TYPED_OPS);
        checkRow(j, "Unwrap", "token");
        MetaTxLib.Envelope memory e = rowEnvelope(j, "Unwrap");
        uint256 wrapped = VM.parseJsonUint(j, msgField("Unwrap", "wrapped"));
        address recipient = VM.parseJsonAddress(j, msgField("Unwrap", "recipient"));
        uint256 minOut = VM.parseJsonUint(j, msgField("Unwrap", "minOut"));
        assertEq(abi.encodeCall(w.mtxUnwrap, (e, wrapped, recipient, minOut, VM.parseJsonBytes(j, domainField("Unwrap", "token", "signature")))),
            VM.parseJsonBytes(j, domainField("Unwrap", "token", "calldata")));
        usd.mint(e.from, 2 * wrapped);
        vm.startPrank(e.from);
        usd.approve(address(w), 2 * wrapped);
        w.wrap(2 * wrapped);
        vm.stopPrank();
        bytes memory sig = onChain(j, "Unwrap", address(w));
        vm.prank(e.relayer);
        w.mtxUnwrap(e, wrapped, recipient, minOut, sig);
        assertEq(usd.balanceOf(recipient), wrapped);
        assertEq(w.mtxNonce(e.from, e.batch), 1);
        assertEq(w.balanceOf(e.feeRecipient), wrapped * e.fee / 1_000_000, "the row's PERCENT fee");
    }

    /// The named entry is no self-call target: the generic path cannot call it, nor the entry itself.
    function test_c0_namedEntryNotAllowlisted() public {
        MetaTxLib.MetaTransaction memory m = _generic(0, 1, 0);
        m.data = abi.encodeCall(w.mtxUnwrap, (_env(0, 0, 0), uint256(1), bob, uint256(0), bytes("")));
        bytes memory sig = ecdsa(PK, w.mtxDigest(m));
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MtxSelectorNotAllowed.selector, w.mtxUnwrap.selector));
        w.mtxExecute(m, sig);
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

    function _env(uint256 nonce) internal view returns (MetaTxLib.Envelope memory e) {
        e.from = signer;
        e.nonce = nonce;
        e.validUntil = block.timestamp + 300;
    }

    function test_c0_shieldTyped() public {
        MetaTxLib.Envelope memory e = _env(0);
        bytes memory sig = ecdsa(PK, walletDigest(address(w), "Shield", SHIELD_FIELDS,
            shieldJson(a(signer), alice, 10, 0, 0, e.validUntil)));
        vm.prank(relayer);
        w.mtxShield(e, alice, 10, sig);
        assertEq((w.pqzPending(alice, 0) >> 96) & type(uint64).max, 10, "a TRIVIAL entry");
        assertEq(w.balanceOf(signer), 90 * SCALE);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 1, 0));
        w.mtxShield(e, alice, 10, sig);

        // the UA twin: a native id signs `UAShield` itself, on the one nonce map
        MetaTxLib.UAEnvelope memory u;
        u.from = MetaTxLib.pad(signer);
        u.nonce = 1;
        u.validUntil = e.validUntil;
        sig = ecdsa(PK, walletDigest(address(w), "UAShield", UA_SHIELD_FIELDS,
            shieldJson(h(u.from), alice, 20, 0, 1, u.validUntil)));
        vm.roll(block.number + 1); // a new pending entry, not the block's TRIVIAL one
        vm.prank(relayer);
        w.uaShield(u, alice, 20, sig);
        assertEq((w.pqzPending(alice, 1) >> 96) & type(uint64).max, 20);
        assertEq(w.balanceOf(signer), 70 * SCALE);
        assertEq(w.uaNonce(u.from, 0), 2);
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

    function test_c1_shieldRow() public {
        string memory j = VM.readFile(TYPED_OPS);
        checkRow(j, "Shield", "pqz");
        MetaTxLib.Envelope memory e = rowEnvelope(j, "Shield");
        bytes32 toUA = _rowHolder(j, "Shield", e.from);
        uint256 amount = VM.parseJsonUint(j, msgField("Shield", "amount"));
        assertEq(abi.encodeWithSignature("mtxShield((address,uint256,uint256,uint256,uint32,address,uint256,address),bytes32,uint256,bytes)",
            e, toUA, amount, VM.parseJsonBytes(j, domainField("Shield", "pqz", "signature"))), VM.parseJsonBytes(j, domainField("Shield", "pqz", "calldata")));
        bytes memory sig = onChain(j, "Shield", address(w));
        vm.prank(e.relayer);
        w.mtxShield(e, toUA, amount, sig);
        assertEq(w.mtxNonce(e.from, e.batch), 1);
        assertEq((w.pqzPending(toUA, 0) >> 96) & type(uint64).max, amount);
    }

    function test_c1_uaShieldRow() public {
        string memory j = VM.readFile(TYPED_OPS);
        checkRow(j, "UAShield", "pqz");
        MetaTxLib.Envelope memory env = rowEnvelope2(j, "UAShield");
        MetaTxLib.UAEnvelope memory u = MetaTxLib.UAEnvelope(VM.parseJsonBytes32(j, msgField("UAShield", "from")), env.batch, env.nonce,
            env.validUntil, env.mode, env.relayer, env.fee, env.feeRecipient);
        bytes32 toUA = _rowHolder(j, "UAShield", address(uint160(uint256(u.from))));
        uint256 amount = VM.parseJsonUint(j, msgField("UAShield", "amount"));
        assertEq(abi.encodeCall(w.uaShield, (u, toUA, amount, VM.parseJsonBytes(j, domainField("UAShield", "pqz", "signature")))),
            VM.parseJsonBytes(j, domainField("UAShield", "pqz", "calldata")), "`uaShield` keeps `bytes auth`");
        bytes memory sig = onChain(j, "UAShield", address(w));
        vm.prank(u.relayer);
        w.uaShield(u, toUA, amount, sig);
        assertEq(w.uaNonce(u.from, u.batch), 1);
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
        c.features = 1 << AdminLib.PAYABLE;
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

    function test_c0_shieldTyped() public {
        bytes32 to = ZetherTypes.UA.unwrap(bob.ua);
        MetaTxLib.Envelope memory e;
        e.from = signer;
        e.validUntil = block.timestamp + 300;
        bytes memory sig = ecdsa(PK, walletDigest(address(w), "Shield", SHIELD_FIELDS,
            shieldJson(a(signer), to, 10, 0, 0, e.validUntil)));
        vm.prank(relayer);
        w.mtxShield(e, to, 10, sig);
        assertEq(w.balanceOf(signer), 90 * SCALE);
        assertEq(w.totalShielded(), 10);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 1, 0));
        w.mtxShield(e, to, 10, sig);

        // the UA twin: a derived Zether UA signs `UAShield` under `metatx`; the registry verifies over the wallet digest
        bytes32 from = ZetherTypes.UA.unwrap(alice.ua);
        vm.prank(signer);
        w.transferToUA(from, 40 * SCALE);
        MetaTxLib.UAEnvelope memory u;
        u.from = from;
        u.validUntil = e.validUntil;
        bytes32 d = walletDigest(address(w), "UAShield", UA_SHIELD_FIELDS, shieldJson(h(from), to, 15, 0, 0, u.validUntil));
        bytes memory auth = abi.encode(bytes(""), ZetherKeys.schnorr(alice.x, reg.uaMessage(_zkind(), UAKinds.PURPOSE_METATX, d), bls));
        vm.prank(relayer);
        w.uaShield(u, to, 15, auth);
        assertEq(w.balanceOfUA(from), 25 * SCALE);
        assertEq(w.totalShielded(), 25);
        assertEq(w.uaNonce(from, 0), 1);
    }

    /// C1: the `Shield` row, its `toUA` is `bob`.
    function test_c1_shieldRow() public {
        string memory j = VM.readFile(TYPED_OPS);
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
        bytes memory sig = onChain(j, "Shield", address(w));
        vm.prank(e.relayer);
        w.mtxShield(e, toUA, amount, sig);
        assertEq(w.mtxNonce(e.from, e.batch), 1);
        assertEq(w.totalShielded(), amount);
    }
}

contract NamedMandateTest is MandateFixture {
    function _walletSig(address d2, uint64 expiry, uint256 validUntil) internal view returns (bytes memory) {
        string memory tail = eJson(3, 0, validUntil, 0, 0);
        string memory message = string.concat('"from":', a(owner), ',"token":', a(address(t)), ',"delegate":', a(d2),
            ',"maxPerPayment":', n(7), ',"maxPerPeriod":', n(9), ',"periodSeconds":', n(1 days), ',"expiry":', n(expiry), ',', tail);
        return _sig(OWNER_PK, walletDigest(address(w), "SetMandate",
            '{"name":"from","type":"address"},{"name":"token","type":"address"},{"name":"delegate","type":"address"},{"name":"maxPerPayment","type":"uint128"},'
            '{"name":"maxPerPeriod","type":"uint128"},{"name":"periodSeconds","type":"uint64"},{"name":"expiry","type":"uint64"}', message));
    }

    function test_c0_setMandateTyped() public {
        address d2 = address(0xD2);
        uint64 expiry = uint64(block.timestamp + 60 days);
        MetaTxLib.Envelope memory e;
        e.from = owner;
        e.batch = 3;
        e.validUntil = block.timestamp + 300;
        bytes memory sig = _walletSig(d2, expiry, e.validUntil);
        uint64 before = w.epoch(address(t));
        vm.prank(stranger); // a relayer: the signature is the authority
        w.mtxSetMandate(e, address(t), d2, 7, 9, 1 days, expiry, sig);
        (address delegate_,,,, uint128 perPayment, uint128 perPeriod,) = w.mandates(address(t));
        assertEq(delegate_, d2);
        assertEq(perPayment, 7);
        assertEq(perPeriod, 9);
        assertEq(w.epoch(address(t)), before + 1);
        assertEq(w.mtxNonce(owner, 3), 1);
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
        e.from = delegate;
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        w.mtxSetMandate(e, address(t), d2, 7, 9, 1 days, expiry, sig);
    }

    function _rowCall(string memory j, MetaTxLib.Envelope memory e, bytes memory sig) internal pure returns (bytes memory) {
        return abi.encodeCall(MandateWallet.mtxSetMandate, (e, VM.parseJsonAddress(j, msgField("SetMandate", "token")),
            VM.parseJsonAddress(j, msgField("SetMandate", "delegate")), uint128(VM.parseJsonUint(j, msgField("SetMandate", "maxPerPayment"))),
            uint128(VM.parseJsonUint(j, msgField("SetMandate", "maxPerPeriod"))), uint64(VM.parseJsonUint(j, msgField("SetMandate", "periodSeconds"))),
            uint64(VM.parseJsonUint(j, msgField("SetMandate", "expiry"))), sig));
    }

    /// C1: the `SetMandate` row on a wallet of the row's key.
    function test_c1_setMandateRow() public {
        string memory j = VM.readFile(TYPED_OPS);
        checkRow(j, "SetMandate", "wallet");
        MetaTxLib.Envelope memory e = rowEnvelope(j, "SetMandate");
        assertEq(_rowCall(j, e, VM.parseJsonBytes(j, domainField("SetMandate", "wallet", "signature"))),
            VM.parseJsonBytes(j, domainField("SetMandate", "wallet", "calldata")));
        MandateWallet mine = new MandateWallet(e.from, UID_);
        bytes memory data = _rowCall(j, e, onChain(j, "SetMandate", address(mine)));
        vm.prank(e.relayer);
        (bool ok, bytes memory ret) = address(mine).call(data);
        assertTrue(ok, string(ret));
        (address d2,,,, uint128 perPayment, uint128 perPeriod,) = mine.mandates(VM.parseJsonAddress(j, msgField("SetMandate", "token")));
        assertEq(d2, VM.parseJsonAddress(j, msgField("SetMandate", "delegate")));
        assertEq(perPayment, VM.parseJsonUint(j, msgField("SetMandate", "maxPerPayment")));
        assertEq(perPeriod, VM.parseJsonUint(j, msgField("SetMandate", "maxPerPeriod")));
        assertEq(mine.mtxNonce(e.from, e.batch), 1);
    }
}

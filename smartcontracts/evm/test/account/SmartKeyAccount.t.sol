// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Base64} from "@openzeppelin/contracts/utils/Base64.sol";
import {Hashes} from "@openzeppelin/contracts/utils/cryptography/Hashes.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {P256} from "@openzeppelin/contracts/utils/cryptography/P256.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {V2Fixture, UID_, noneInit} from "../v2/helpers/V2Fixture.sol";
import {NoUnderlyingToken} from "../../src/metatx/NoUnderlyingToken.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
import {IERC20Payment} from "../../src/metatx/IERC20Payment.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {SmartKeyAccount, SubjectKey, KeyKind} from "../../src/account/SmartKeyAccount.sol";
import {SmartKeyAccountFactory} from "../../src/account/SmartKeyAccountFactory.sol";
import {plainEnv} from "../helpers/Catalogue.sol";
import {SigCheck} from "../../src/common/SigCheck.sol";

/// Software authenticator: a fixed P-256 key, authenticatorData/clientDataJSON in the WebAuthn format (L3 §5.8.1.1),
/// the signature normalised to low-s as clients do.
abstract contract WebAuthnSoft is V2Fixture {
    uint256 internal constant N = P256.N;
    string internal constant RP_ID = "pay.example.com";
    string internal constant ORIGIN = "https://pay.example.com";
    string internal constant TAIL = ',"crossOrigin":false}';

    struct Assertion {
        bytes authData;
        bytes clientData;
        bytes32 r;
        bytes32 s;
    }

    function _passkey(uint256 pk) internal pure returns (SubjectKey memory) {
        (uint256 x, uint256 y) = vm.publicKeyP256(pk);
        return SubjectKey(KeyKind.P256_WEBAUTHN, bytes32(x), bytes32(y), sha256(bytes(RP_ID)), keccak256(bytes(ORIGIN)));
    }

    function _seedKey(uint256 pk) internal pure returns (SubjectKey memory) {
        return SubjectKey(KeyKind.SECP256K1, bytes32(uint256(uint160(vm.addr(pk)))), 0, 0, 0);
    }

    function _clientData(bytes32 challenge, string memory origin, string memory tail)
        internal pure returns (bytes memory)
    {
        return abi.encodePacked('{"type":"webauthn.get","challenge":"', Base64.encodeURL(abi.encodePacked(challenge)),
                                '","origin":"', origin, '"', tail);
    }

    function _signAssertion(uint256 pk, bytes memory authData, bytes memory clientData)
        internal pure returns (Assertion memory a)
    {
        bytes32 h = sha256(abi.encodePacked(authData, sha256(clientData)));
        (bytes32 r, bytes32 s) = vm.signP256(pk, h);
        if (uint256(s) > N / 2) s = bytes32(N - uint256(s));
        a = Assertion(authData, clientData, r, s);
    }

    function _assertion(uint256 pk, bytes32 message) internal pure returns (Assertion memory) {
        return _signAssertion(pk, abi.encodePacked(sha256(bytes(RP_ID)), bytes1(0x05), uint32(0)),
                              _clientData(message, ORIGIN, TAIL));
    }

    function _enc(Assertion memory a) internal pure returns (bytes memory) {
        return abi.encode(a.authData, a.clientData, a.r, a.s);
    }

    function _sig(uint256 index, bytes memory inner) internal pure returns (bytes memory) {
        return abi.encode(index, new bytes32[](0), inner);
    }

    function _pk(uint256 index, uint256 pk, bytes32 message) internal pure returns (bytes memory) {
        return _sig(index, _enc(_assertion(pk, message)));
    }

    function _ecdsa(uint256 index, uint256 pk, bytes32 message) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, message);
        return _sig(index, abi.encodePacked(r, s, v));
    }
}

/// Calls back into the account from inside its `execute` (the guard must refuse it).
contract ReenterAccount {
    function hit(SmartKeyAccount a, MetaTxLib.MetaTransaction calldata m, bytes calldata sig) external {
        a.mtxExecute(m, sig);
    }
}

/// CTR-ACC-01…05, CTR-ACC-08…11 on `MetaTxBase` (CTR-MTX-22): WebAuthn and batch checks (ported from the built
/// `SubjectAccount` tests, `legacy/p4/`), payments through a token of the new tree, key management as a
/// `MetaTransaction` signed by the account itself, recovery, the factory, the allowlist and the pipeline.
contract SmartKeyAccountTest is WebAuthnSoft {
    uint256 internal constant PASSKEY = 0xC0FFEE1234567890;
    uint256 internal constant PASSKEY2 = 0xBADC0DE5;
    uint256 internal constant SEED = 0x5EED;
    address internal constant GUARDIAN = address(0x6A2D);
    address internal shop = address(0x5409);
    bytes4 internal constant MAGIC = IERC1271.isValidSignature.selector;

    SmartKeyAccountFactory internal fac;
    SmartKeyAccount internal acct;
    NoUnderlyingToken internal t;

    function setUp() public {
        vm.chainId(7622);
        vm.warp(1_800_000_000);
        fac = new SmartKeyAccountFactory(UID_);
        NoUnderlyingToken impl = new NoUnderlyingToken(1, plainEnv(address(this), fac.IMPLEMENTATION(), UID_, address(0), false), "");
        t = NoUnderlyingToken(_clone(address(impl), address(this), new address[](0),
            abi.encode(noneInit("Points", "PTS", 0, 0, address(this), address(this)))));
        acct = SmartKeyAccount(payable(fac.deploy(_passkey(PASSKEY), GUARDIAN)));
        t.mint(address(acct), 1000);
    }

    function _valid(SmartKeyAccount a, bytes32 digest, bytes memory sig) internal view returns (bool) {
        return a.isValidSignature(digest, sig) == MAGIC;
    }

    /// The account's own `MetaTransaction` on lane 0 (what `mtxExecuteAsOwner` builds).
    function _own(bytes memory data, uint256 nonce) internal view returns (MetaTxLib.MetaTransaction memory m) {
        m.from = address(acct);
        m.data = data;
        m.nonce = nonce;
        m.validUntil = block.timestamp + 300;
    }

    /// Signs the account's next lane-0 call with key `index` (passkey or seed) and submits it by `mtxExecuteAsOwner`.
    function _ownerCall(bytes memory data, uint256 index, uint256 pk, bool passkey) internal returns (bytes memory) {
        MetaTxLib.MetaTransaction memory m = _own(data, acct.mtxNonce(address(acct), 0));
        bytes32 d = acct.mtxDigest(m);
        bytes memory sig = passkey ? _pk(index, pk, d) : _ecdsa(index, pk, d);
        vm.prank(relayer);
        return acct.mtxExecuteAsOwner(data, m.nonce, m.validUntil, sig);
    }

    function _ownerCallFails(bytes memory data, bytes memory err) internal {
        MetaTxLib.MetaTransaction memory m = _own(data, acct.mtxNonce(address(acct), 0));
        bytes memory sig = _pk(0, PASSKEY, acct.mtxDigest(m));
        vm.expectRevert(err);
        acct.mtxExecuteAsOwner(data, m.nonce, m.validUntil, sig);
    }

    // ------------------------------------------------------------------ WebAuthn: published vectors

    /// Published vectors: base/webauthn-sol `test/WebAuthn.t.sol` (Coinbase Smart Wallet), real Chrome and Safari
    /// assertions, rpId "localhost", origin "http://localhost:3005".
    function _baseAccount() internal returns (SmartKeyAccount) {
        SubjectKey memory k = SubjectKey(
            KeyKind.P256_WEBAUTHN,
            bytes32(uint256(28573233055232466711029625910063034642429572463461595413086259353299906450061)),
            bytes32(uint256(39367742072897599771788408398752356480431855827262528811857788332151452825281)),
            sha256("localhost"), keccak256("http://localhost:3005"));
        return SmartKeyAccount(payable(fac.deploy(k, address(0))));
    }

    bytes32 internal constant BASE_CHALLENGE = 0xf631058a3ba1116acce12396fad0a125b5041c43f8e15723709f81aa8d5f4ccf;

    function test_published_chrome_vector() public {
        SmartKeyAccount a = _baseAccount();
        bytes memory inner = abi.encode(
            hex"49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d9763050000010a",
            _clientData(BASE_CHALLENGE, "http://localhost:3005", TAIL),
            bytes32(uint256(29739767516584490820047863506833955097567272713519339793744591468032609909569)),
            bytes32(uint256(45947455641742997809691064512762075989493430661170736817032030660832793108102)));
        assertTrue(_valid(a, BASE_CHALLENGE, _sig(0, inner)));
        assertFalse(_valid(a, keccak256("other"), _sig(0, inner)));
    }

    function test_published_safari_vector() public {
        SmartKeyAccount a = _baseAccount();
        bytes memory inner = abi.encode(
            hex"49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97630500000101",
            _clientData(BASE_CHALLENGE, "http://localhost:3005", "}"),
            bytes32(uint256(43684192885701841787131392247364253107519555363555461570655060745499568693242)),
            bytes32(uint256(22655632649588629308599201066602670461698485748654492451178007896016452673579)));
        assertTrue(_valid(a, BASE_CHALLENGE, _sig(0, inner)));
    }

    /// Generated by the Node software authenticator (`clientkeys/scripts/webauthn-vector.mjs`).
    function test_node_software_authenticator_vector() public {
        string memory j = vm.readFile("test/vectors/webauthn_soft.json");
        SubjectKey memory k = SubjectKey(
            KeyKind.P256_WEBAUTHN, vm.parseJsonBytes32(j, ".qx"), vm.parseJsonBytes32(j, ".qy"),
            sha256(bytes(vm.parseJsonString(j, ".rpId"))), keccak256(bytes(vm.parseJsonString(j, ".origin"))));
        SmartKeyAccount a = SmartKeyAccount(payable(fac.deploy(k, address(0))));
        bytes32 challenge = vm.parseJsonBytes32(j, ".challenge");
        assertTrue(_valid(a, challenge, vm.parseJsonBytes(j, ".signature")));
        assertFalse(_valid(a, keccak256("other"), vm.parseJsonBytes(j, ".signature")));
    }

    // ------------------------------------------------------------------ WebAuthn: refusals

    bytes32 internal constant D = keccak256("operation digest");

    function _withAuth(bytes1 flags, string memory origin, string memory tail) internal pure returns (bytes memory) {
        return _sig(0, _enc(_signAssertion(PASSKEY, abi.encodePacked(sha256(bytes(RP_ID)), flags, uint32(0)),
                                           _clientData(D, origin, tail))));
    }

    function test_soft_assertion_valid() public view {
        assertTrue(_valid(acct, D, _pk(0, PASSKEY, D)));
    }

    function test_wrong_challenge() public view {
        assertFalse(_valid(acct, D, _pk(0, PASSKEY, keccak256("another op"))));
    }

    function test_wrong_origin_and_prefix_origin() public view {
        assertFalse(_valid(acct, D, _withAuth(0x05, "https://evil.example.com", TAIL)));
        assertFalse(_valid(acct, D, _withAuth(0x05, "https://pay.example.com.evil", TAIL)));
    }

    function test_wrong_rp_id_hash() public view {
        Assertion memory a = _signAssertion(PASSKEY, abi.encodePacked(sha256("evil.example.com"), bytes1(0x05), uint32(0)),
                                            _clientData(D, ORIGIN, TAIL));
        assertFalse(_valid(acct, D, _sig(0, _enc(a))));
    }

    function test_flags() public view {
        assertFalse(_valid(acct, D, _withAuth(0x04, ORIGIN, TAIL)), "UP missing");
        assertFalse(_valid(acct, D, _withAuth(0x01, ORIGIN, TAIL)), "UV missing");
        assertTrue(_valid(acct, D, _withAuth(0x1d, ORIGIN, TAIL)), "BE|BS on top of UP|UV");
    }

    function test_high_s_is_refused() public view {
        Assertion memory a = _assertion(PASSKEY, D);
        a.s = bytes32(N - uint256(a.s));
        assertFalse(_valid(acct, D, _sig(0, _enc(a))));
    }

    function test_tampering() public view {
        Assertion memory a = _assertion(PASSKEY, D);
        a.authData[36] = 0x01;   // sign counter
        assertFalse(_valid(acct, D, _sig(0, _enc(a))));
        a = _assertion(PASSKEY, D);
        a.clientData = _clientData(D, ORIGIN, ',"crossOrigin":false,"x":1}');
        assertFalse(_valid(acct, D, _sig(0, _enc(a))));
        a = _assertion(PASSKEY, D);
        a.r = bytes32(uint256(a.r) ^ 1);
        assertFalse(_valid(acct, D, _sig(0, _enc(a))));
        a = _assertion(PASSKEY, D);
        a.authData = abi.encodePacked(sha256(bytes(RP_ID)), bytes1(0x05));   // 33 bytes
        assertFalse(_valid(acct, D, _sig(0, _enc(a))));
    }

    function test_type_create_is_refused() public view {
        bytes memory cd = abi.encodePacked('{"type":"webauthn.create","challenge":"',
            Base64.encodeURL(abi.encodePacked(D)), '","origin":"', ORIGIN, '"', TAIL);
        Assertion memory a = _signAssertion(PASSKEY, abi.encodePacked(sha256(bytes(RP_ID)), bytes1(0x05), uint32(0)), cd);
        assertFalse(_valid(acct, D, _sig(0, _enc(a))));
    }

    function test_client_data_layouts() public view {
        assertTrue(_valid(acct, D, _withAuth(0x05, ORIGIN,
            ',"crossOrigin":false,"other_keys_can_be_added_here":"do not compare clientDataJSON against a template"}')));
        assertTrue(_valid(acct, D, _withAuth(0x05, ORIGIN, "}")), "Safari: origin then }");
        assertFalse(_valid(acct, D, _withAuth(0x05, ORIGIN, ',"crossOrigin":true,"topOrigin":"https://evil.example.com"}')));
        assertFalse(_valid(acct, D, _withAuth(0x05, ORIGIN, ',"x":1,"crossOrigin":true}')));
        assertFalse(_valid(acct, D, _withAuth(0x05, ORIGIN, ',"crossOrigin": true}')));
        assertFalse(_valid(acct, D, _withAuth(0x05, ORIGIN, ',"crossOrigin":true}')));
        assertFalse(_valid(acct, D, _withAuth(0x05, ORIGIN, ',"crossOrigin":false')));
        assertFalse(_valid(acct, D, _withAuth(0x05, ORIGIN, ',"crossOrigin":falsey}')));
        assertFalse(_valid(acct, D, _withAuth(0x05, ORIGIN, "}x")));
    }

    /// C1-2: after `,"crossOrigin":false,` the clientDataJSON must still end in `}`.
    function test_C1_2_unterminatedTailRefused() public view {
        assertFalse(_valid(acct, D, _withAuth(0x05, ORIGIN, ',"crossOrigin":false,"x":1')));
        assertFalse(_valid(acct, D, _withAuth(0x05, ORIGIN, ',"crossOrigin":false,')));
    }

    function test_other_passkey_and_unknown_index_are_refused() public view {
        assertFalse(_valid(acct, D, _pk(0, PASSKEY2, D)));
        assertFalse(_valid(acct, D, _pk(5, PASSKEY, D)));
    }

    // ------------------------------------------------------------------ batch (Merkle)

    function _tree(bytes32[4] memory d) internal view returns (bytes32 root, bytes32[][4] memory proofs) {
        bytes32[4] memory l;
        for (uint256 i; i < 4; ++i) l[i] = acct.batchLeaf(d[i]);
        bytes32 n01 = Hashes.commutativeKeccak256(l[0], l[1]);
        bytes32 n23 = Hashes.commutativeKeccak256(l[2], l[3]);
        root = Hashes.commutativeKeccak256(n01, n23);
        for (uint256 i; i < 4; ++i) {
            proofs[i] = new bytes32[](2);
            proofs[i][0] = l[i ^ 1];
            proofs[i][1] = i < 2 ? n23 : n01;
        }
    }

    function _ops() internal pure returns (bytes32[4] memory d) {
        for (uint256 i; i < 4; ++i) d[i] = keccak256(abi.encode("op", i));
    }

    function test_batch_one_passkey_assertion_covers_each_op() public {
        _ownerCall(abi.encodeCall(SmartKeyAccount.addKey, (_seedKey(SEED))), 0, PASSKEY, true);
        bytes32[4] memory d = _ops();
        (bytes32 root, bytes32[][4] memory proofs) = _tree(d);
        bytes memory inner = _enc(_assertion(PASSKEY, root));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(SEED, root);
        for (uint256 i; i < 4; ++i) {
            assertTrue(_valid(acct, d[i], abi.encode(uint256(0), proofs[i], inner)), "passkey leaf");
            assertTrue(_valid(acct, d[i], abi.encode(uint256(1), proofs[i], abi.encodePacked(r, s, v))), "seed leaf");
        }
        assertFalse(_valid(acct, keccak256("not in batch"), abi.encode(uint256(0), proofs[0], inner)));
        assertFalse(_valid(acct, d[0], abi.encode(uint256(0), proofs[1], inner)));
        assertFalse(_valid(acct, d[0], _sig(0, inner)));
    }

    function test_batch_leaf_is_not_an_inner_node() public view {
        bytes32[4] memory d = _ops();
        (bytes32 root, bytes32[][4] memory proofs) = _tree(d);
        bytes32 n01 = Hashes.commutativeKeccak256(acct.batchLeaf(d[0]), acct.batchLeaf(d[1]));
        bytes32[] memory p = new bytes32[](1);
        p[0] = proofs[0][1];
        assertFalse(_valid(acct, n01, abi.encode(uint256(0), p, _enc(_assertion(PASSKEY, root)))));
    }

    // ------------------------------------------------------------------ token payments (new tree)

    function _payment(address from, bytes32 ref) internal view returns (MetaTxLib.MetaTransfer memory x, bytes32 d) {
        x = _tr(from, shop, 400, ref, uint256(ref), RR);
        d = t.mtxTransferDigest(x);
    }

    function _payWith(MetaTxLib.MetaTransfer memory x, bytes memory sig) internal {
        vm.prank(relayer);
        t.mtxExecuteTransfer(x, sig);
    }

    function test_token_pay_signed_with_passkey() public {
        (MetaTxLib.MetaTransfer memory x, bytes32 d) = _payment(address(acct), keccak256("r1"));
        bytes memory sig = _pk(0, PASSKEY, d);
        vm.expectEmit(true, true, true, true, address(t));
        emit IERC20Payment.PaymentSettled(address(acct), shop, 400, 0, relayer, keccak256("r1"));
        _payWith(x, sig);
        assertEq(t.balanceOf(shop), 400);
    }

    function test_second_key_then_pay_with_each() public {
        _ownerCall(abi.encodeCall(SmartKeyAccount.addKey, (_seedKey(SEED))), 0, PASSKEY, true);
        assertEq(acct.keyCount(), 2);
        (MetaTxLib.MetaTransfer memory x1, bytes32 d1) = _payment(address(acct), keccak256("seed"));
        _payWith(x1, _ecdsa(1, SEED, d1));
        (MetaTxLib.MetaTransfer memory x2, bytes32 d2) = _payment(address(acct), keccak256("passkey"));
        _payWith(x2, _pk(0, PASSKEY, d2));
        assertEq(t.balanceOf(shop), 800);
    }

    function test_seed_first_account_pays() public {
        SmartKeyAccount a = SmartKeyAccount(payable(fac.deploy(_seedKey(SEED), address(0))));
        t.mint(address(a), 500);
        (MetaTxLib.MetaTransfer memory x, bytes32 d) = _payment(address(a), keccak256("s1"));
        _payWith(x, _ecdsa(0, SEED, d));
        assertEq(t.balanceOf(shop), 400);
    }

    function test_signature_for_one_account_does_not_pay_from_another() public {
        SmartKeyAccount b = SmartKeyAccount(payable(fac.deploy(_passkey(PASSKEY), address(0))));
        t.mint(address(b), 1000);
        (, bytes32 dA) = _payment(address(acct), keccak256("x"));
        (MetaTxLib.MetaTransfer memory xB,) = _payment(address(b), keccak256("x"));
        bytes memory sig = _pk(0, PASSKEY, dA);
        vm.prank(relayer);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        t.mtxExecuteTransfer(xB, sig);
    }

    function test_removed_key_cannot_pay() public {
        _ownerCall(abi.encodeCall(SmartKeyAccount.addKey, (_seedKey(SEED))), 0, PASSKEY, true);
        _ownerCall(abi.encodeCall(SmartKeyAccount.removeKey, (0)), 1, SEED, false);
        (MetaTxLib.MetaTransfer memory x, bytes32 d) = _payment(address(acct), keccak256("gone"));
        bytes memory sig = _pk(0, PASSKEY, d);
        vm.prank(relayer);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        t.mtxExecuteTransfer(x, sig);
    }

    /// CTR-ACC-05: the token computes the 400k cap codehash from `SMART_KEY_ACCOUNT_IMPL` (pinned on the token side by
    /// `test_erc1271Gets400kOnlyAsSmartKeyAccountClone`); it must be the factory's implementation, whose EIP-1167
    /// clones the accounts are. With the native P256VERIFY a passkey check is about 37k; the Solidity verifier
    /// (chains without the precompile) needs the 400k.
    function test_cloneCodehashIsWhatTokensCap() public {
        assertEq(t.SMART_KEY_ACCOUNT_IMPL(), fac.IMPLEMENTATION());
        assertEq(address(acct).codehash, keccak256(abi.encodePacked(
            hex"363d3d373d3d3d363d73", fac.IMPLEMENTATION(), hex"5af43d82803e903d91602b57fd5bf3")));
        bytes memory sig = _pk(0, PASSKEY, D);
        uint256 g = gasleft();
        assertTrue(_valid(acct, D, sig));
        emit log_named_uint("isValidSignature, passkey (P256VERIFY under the repo EVM)", g - gasleft());
    }

    /// L2: on a chain without the P256VERIFY precompile the Solidity verifier needs about 280k, so the account's own
    /// signature check must stay the uncapped static self-call; `SigCheck`'s 50k cap would kill every passkey owner
    /// call there. `0x100` answers like a missing precompile (a failed call: OZ `P256` then runs `verifySolidity`).
    function test_passkeyOwnerCallWithoutPrecompile() public {
        vm.mockCallRevert(address(0x100), bytes(""), bytes(""));
        bytes memory sig = _pk(0, PASSKEY, D);
        uint256 g = gasleft();
        assertTrue(_valid(acct, D, sig));
        uint256 used = g - gasleft();
        assertGt(used, 100_000, "no precompile: the Solidity verifier ran");
        emit log_named_uint("isValidSignature, passkey, Solidity P-256 (no precompile)", used);
        _ownerCall(abi.encodeCall(SmartKeyAccount.addKey, (_seedKey(SEED))), 0, PASSKEY, true);
        assertEq(acct.keyCount(), 2);
    }

    // ------------------------------------------------------------------ key management (CTR-ACC-10)

    function test_never_zero_keys() public {
        _ownerCallFails(abi.encodeCall(SmartKeyAccount.removeKey, (0)), abi.encodeWithSelector(SmartKeyAccount.LastKey.selector));
        assertEq(acct.keyCount(), 1);
    }

    function test_rotate_passkey_to_new_passkey() public {
        _ownerCall(abi.encodeCall(SmartKeyAccount.rotateKey, (0, _passkey(PASSKEY2))), 0, PASSKEY, true);
        assertEq(acct.keyCount(), 1);
        assertTrue(_valid(acct, D, _pk(1, PASSKEY2, D)));
        assertFalse(_valid(acct, D, _pk(0, PASSKEY, D)));
        assertFalse(acct.hasKey(keccak256(abi.encode(_passkey(PASSKEY)))));
    }

    function test_remove_unknown_index() public {
        _ownerCall(abi.encodeCall(SmartKeyAccount.addKey, (_seedKey(SEED))), 0, PASSKEY, true);
        _ownerCallFails(abi.encodeCall(SmartKeyAccount.removeKey, (7)),
            abi.encodeWithSelector(SmartKeyAccount.NoSuchKey.selector, 7));
    }

    function test_owner_call_replay_expiry_and_foreign_key() public {
        bytes memory data = abi.encodeCall(SmartKeyAccount.addKey, (_seedKey(SEED)));
        MetaTxLib.MetaTransaction memory m = _own(data, 0);
        bytes32 d = acct.mtxDigest(m);
        bytes memory sig = _pk(0, PASSKEY, d);
        bytes memory foreign = _pk(0, PASSKEY2, d);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        acct.mtxExecuteAsOwner(data, 0, m.validUntil, foreign);
        acct.mtxExecuteAsOwner(data, 0, m.validUntil, sig);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 1, 0));
        acct.mtxExecuteAsOwner(data, 0, m.validUntil, sig);
        vm.warp(m.validUntil + 1);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxExpired.selector, m.validUntil, m.validUntil + 1));
        acct.mtxExecuteAsOwner(data, 1, m.validUntil, sig);
    }

    /// One signature, one digest, one lane: the named builder and `mtxExecute` consume the same nonce.
    function test_namedBuilderIsMtxExecute() public {
        bytes memory data = abi.encodeCall(SmartKeyAccount.setGuardian, (address(0xD00D)));
        MetaTxLib.MetaTransaction memory m = _own(data, 0);
        bytes memory sig = _pk(0, PASSKEY, acct.mtxDigest(m));
        vm.expectEmit(true, true, true, true, address(acct));
        emit IMetaTx.MetaTransactionExecuted(address(acct), relayer, 0, 0, acct.mtxDigest(m), relayer, 0);
        vm.prank(relayer);
        acct.mtxExecute(m, sig);
        assertEq(acct.guardian(), address(0xD00D));
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 1, 0));
        acct.mtxExecuteAsOwner(data, 0, m.validUntil, sig);
    }

    function test_duplicate_and_bad_keys() public {
        bytes4 bad = SmartKeyAccount.BadKey.selector;
        _ownerCallFails(abi.encodeCall(SmartKeyAccount.addKey, (_passkey(PASSKEY))),
            abi.encodeWithSelector(SmartKeyAccount.DuplicateKey.selector));
        SubjectKey memory k = _passkey(PASSKEY2);
        k.y = bytes32(uint256(k.y) ^ 1);                                   // off the curve
        _ownerCallFails(abi.encodeCall(SmartKeyAccount.addKey, (k)), abi.encodeWithSelector(bad));
        k = _seedKey(SEED);
        k.x = bytes32(uint256(k.x) | (1 << 200));                          // dirty bits above the address
        _ownerCallFails(abi.encodeCall(SmartKeyAccount.addKey, (k)), abi.encodeWithSelector(bad));
        k = _passkey(PASSKEY2);
        k.originHash = 0;
        _ownerCallFails(abi.encodeCall(SmartKeyAccount.addKey, (k)), abi.encodeWithSelector(bad));
        k = _passkey(PASSKEY2);
        k.rpIdHash = 0;
        _ownerCallFails(abi.encodeCall(SmartKeyAccount.addKey, (k)), abi.encodeWithSelector(bad));
        k = _seedKey(SEED);
        k.y = bytes32(uint256(1));
        _ownerCallFails(abi.encodeCall(SmartKeyAccount.addKey, (k)), abi.encodeWithSelector(bad));
        k = _seedKey(SEED);
        k.x = 0;
        _ownerCallFails(abi.encodeCall(SmartKeyAccount.addKey, (k)), abi.encodeWithSelector(bad));
        SubjectKey memory none;
        _ownerCallFails(abi.encodeCall(SmartKeyAccount.addKey, (none)), abi.encodeWithSelector(bad));
    }

    function test_self_only_functions() public {
        vm.expectRevert(SmartKeyAccount.NotSelf.selector);
        acct.addKey(_seedKey(SEED));
        vm.expectRevert(SmartKeyAccount.NotSelf.selector);
        acct.removeKey(0);
        vm.expectRevert(SmartKeyAccount.NotSelf.selector);
        acct.rotateKey(0, _seedKey(SEED));
        vm.expectRevert(SmartKeyAccount.NotSelf.selector);
        acct.setGuardian(address(this));
        vm.expectRevert(SmartKeyAccount.NotSelf.selector);
        acct.cancelRecovery();
        vm.expectRevert(SmartKeyAccount.NotSelf.selector);
        acct.execute(address(t), 0, "");
    }

    /// Another signer's `MetaTransaction` runs as that signer: the self-only functions refuse it, and its
    /// `cancelNonce` moves only its own lane.
    function test_otherSignerIsNotTheAccount() public {
        uint256 pk = 0xA11CE;
        address alice = vm.addr(pk);
        MetaTxLib.MetaTransaction memory m = _call(alice, abi.encodeCall(SmartKeyAccount.addKey, (_seedKey(SEED))), 0, RR);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, acct.mtxDigest(m));
        vm.prank(relayer);
        vm.expectRevert(SmartKeyAccount.NotSelf.selector);
        acct.mtxExecute(m, abi.encodePacked(r, s, v));
        m = _call(alice, abi.encodeCall(IMetaTx.cancelNonce, (0)), 9, RR);
        (v, r, s) = vm.sign(pk, acct.mtxDigest(m));
        vm.prank(relayer);
        acct.mtxExecute(m, abi.encodePacked(r, s, v));
        assertEq(acct.mtxNonce(alice, 0), 1);
        assertEq(acct.mtxNonce(alice, 9), 1);
        assertEq(acct.mtxNonce(address(acct), 0), 0);
        // for `from = account` only the account's keys sign: a plain EOA signature, a key the account does not hold,
        // or an ECDSA blob under the passkey's index is a `MetaTxBadSignature`
        m = _own(abi.encodeCall(IMetaTx.cancelNonce, (0)), 0);
        (v, r, s) = vm.sign(SEED, acct.mtxDigest(m));
        bytes[3] memory bad = [abi.encodePacked(r, s, v), _sig(1, abi.encodePacked(r, s, v)), _sig(0, abi.encodePacked(r, s, v))];
        for (uint256 i; i < 3; ++i) {
            vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
            acct.mtxExecute(m, bad[i]);
        }
    }

    function test_accountCancelsItsOwnLane() public {
        _ownerCall(abi.encodeCall(IMetaTx.cancelNonce, (5)), 0, PASSKEY, true);
        assertEq(acct.mtxNonce(address(acct), 5), 1);
        assertEq(acct.mtxNonce(address(acct), 0), 1);
    }

    function test_execute_moves_funds() public {
        _ownerCall(abi.encodeCall(SmartKeyAccount.execute,
                                  (address(t), 0, abi.encodeCall(t.transfer, (shop, 100)))), 0, PASSKEY, true);
        assertEq(t.balanceOf(shop), 100);
    }

    /// `execute` runs under the guard: it cannot call the account's own functions or take a second signed call.
    function test_executeCannotReenter() public {
        bytes memory inner = abi.encodeCall(SmartKeyAccount.addKey, (_seedKey(SEED)));
        _ownerCallFails(abi.encodeCall(SmartKeyAccount.execute, (address(acct), 0, inner)),
            abi.encodeWithSelector(SmartKeyAccount.CallFailed.selector,
                abi.encodeWithSelector(IMetaTx.Reentrancy.selector)));
        ReenterAccount re = new ReenterAccount();
        MetaTxLib.MetaTransaction memory m2 = _own(inner, 1);
        bytes memory sig2 = _pk(0, PASSKEY, acct.mtxDigest(m2));
        _ownerCallFails(abi.encodeCall(SmartKeyAccount.execute, (address(re), 0, abi.encodeCall(re.hit, (acct, m2, sig2)))),
            abi.encodeWithSelector(SmartKeyAccount.CallFailed.selector,
                abi.encodeWithSelector(IMetaTx.Reentrancy.selector)));
        assertEq(acct.keyCount(), 1);
        // W-Q: the guardian's entries are under the same guard (CTR-MTX-18)
        bytes[2] memory rec = [abi.encodeCall(SmartKeyAccount.initiateRecovery, (_seedKey(SEED))),
            abi.encodeCall(SmartKeyAccount.completeRecovery, (_seedKey(SEED)))];
        for (uint256 i; i < 2; ++i) {
            _ownerCallFails(abi.encodeCall(SmartKeyAccount.execute, (address(acct), 0, rec[i])),
                abi.encodeWithSelector(SmartKeyAccount.CallFailed.selector,
                    abi.encodeWithSelector(IMetaTx.Reentrancy.selector)));
        }
    }

    function test_mtxBatchIsAtomic() public {
        MetaTxLib.MetaTransaction[] memory ms = new MetaTxLib.MetaTransaction[](2);
        bytes[] memory sigs = new bytes[](2);
        ms[0] = _own(abi.encodeCall(SmartKeyAccount.addKey, (_seedKey(SEED))), 0);
        ms[1] = _own(abi.encodeCall(SmartKeyAccount.removeKey, (0)), 1);
        sigs[0] = _pk(0, PASSKEY, acct.mtxDigest(ms[0]));
        sigs[1] = _pk(0, PASSKEY, acct.mtxDigest(ms[1]));
        vm.prank(relayer);
        acct.mtxBatch(ms, sigs);
        assertEq(acct.keyCount(), 1);
        assertTrue(acct.hasKey(keccak256(abi.encode(_seedKey(SEED)))));
        // a failing item reverts the batch: the removed passkey no longer signs item 1
        ms[0] = _own(abi.encodeCall(SmartKeyAccount.setGuardian, (address(1))), 2);
        ms[1] = _own(abi.encodeCall(SmartKeyAccount.setGuardian, (address(2))), 3);
        sigs[0] = _ecdsa(1, SEED, acct.mtxDigest(ms[0]));
        sigs[1] = _pk(0, PASSKEY, acct.mtxDigest(ms[1]));
        vm.prank(relayer);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        acct.mtxBatch(ms, sigs);
        assertEq(acct.guardian(), GUARDIAN);
    }

    function test_relayerBinding() public {
        MetaTxLib.MetaTransaction memory m = _own(abi.encodeCall(IMetaTx.cancelNonce, (1)), 0);
        m.mode = RR;
        m.relayer = relayer;
        bytes memory sig = _pk(0, PASSKEY, acct.mtxDigest(m));
        vm.prank(address(0xBAD));
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxUnauthorizedRelayer.selector, relayer, address(0xBAD)));
        acct.mtxExecute(m, sig);
        vm.prank(relayer);
        acct.mtxExecute(m, sig);
    }

    // ------------------------------------------------------------------ allowlist, fee, domain (CTR-MTX-19/22)

    function test_allowlistPinned() public view {
        (bytes4[] memory s, uint8[] memory c, uint8[] memory a) = acct.mtxSelectors();
        bytes4[7] memory want = [IMetaTx.cancelNonce.selector, SmartKeyAccount.addKey.selector,
            SmartKeyAccount.removeKey.selector, SmartKeyAccount.rotateKey.selector, SmartKeyAccount.setGuardian.selector,
            SmartKeyAccount.cancelRecovery.selector, SmartKeyAccount.execute.selector];
        assertEq(s.length, 7);
        for (uint256 i; i < 7; ++i) {
            assertEq(s[i], want[i]);
            assertEq(c[i], 1, "ABSOLUTE");
            assertEq(a[i], 0);
        }
        assertEq(SmartKeyAccount.addKey.selector, bytes4(keccak256("addKey((uint8,bytes32,bytes32,bytes32,bytes32))")));
        assertEq(SmartKeyAccount.rotateKey.selector,
            bytes4(keccak256("rotateKey(uint256,(uint8,bytes32,bytes32,bytes32,bytes32))")));
        assertEq(acct.supportedModes(), 0x03);
    }

    function _signedFails(bytes memory data, bytes memory err) internal {
        MetaTxLib.MetaTransaction memory m = _own(data, 0);
        bytes memory sig = _pk(0, PASSKEY, acct.mtxDigest(m));
        vm.expectRevert(err);
        acct.mtxExecute(m, sig);
    }

    function test_unlistedSelectorsRefused() public {
        bytes4 no = IMetaTx.MtxSelectorNotAllowed.selector;
        bytes[6] memory calls = [
            abi.encodeCall(SmartKeyAccount.initiateRecovery, (_seedKey(SEED))),
            abi.encodeCall(SmartKeyAccount.completeRecovery, (_seedKey(SEED))),
            abi.encodeCall(SmartKeyAccount.initialize, (_seedKey(SEED), address(0))),
            abi.encodeCall(SmartKeyAccount.mtxExecuteAsOwner, ("", 0, 0, "")),
            abi.encodeCall(SmartKeyAccount.isValidSignature, (D, "")),
            abi.encodeCall(IMetaTx.mtxBatch, (new MetaTxLib.MetaTransaction[](0), new bytes[](0)))
        ];
        for (uint256 i; i < calls.length; ++i) _signedFails(calls[i], abi.encodeWithSelector(no, bytes4(calls[i])));
    }

    function test_staticShapes() public {
        bytes memory k = abi.encodeCall(SmartKeyAccount.addKey, (_seedKey(SEED)));
        assertEq(k.length, 164);
        _signedFails(abi.encodePacked(k, bytes32(0)),
            abi.encodeWithSelector(IMetaTx.MtxDataShape.selector, SmartKeyAccount.addKey.selector));
        _signedFails(abi.encodePacked(SmartKeyAccount.cancelRecovery.selector, bytes32(0)),
            abi.encodeWithSelector(IMetaTx.MtxDataShape.selector, SmartKeyAccount.cancelRecovery.selector));
        _signedFails(abi.encodePacked(abi.encodeCall(SmartKeyAccount.removeKey, (0)), bytes1(0)),
            abi.encodeWithSelector(IMetaTx.MtxDataShape.selector, SmartKeyAccount.removeKey.selector));
        _signedFails(abi.encodePacked(abi.encodeCall(SmartKeyAccount.setGuardian, (address(0))), bytes1(0)),
            abi.encodeWithSelector(IMetaTx.MtxDataShape.selector, SmartKeyAccount.setGuardian.selector));
        _signedFails(abi.encodePacked(abi.encodeCall(SmartKeyAccount.rotateKey, (0, _seedKey(SEED))), bytes1(0)),
            abi.encodeWithSelector(IMetaTx.MtxDataShape.selector, SmartKeyAccount.rotateKey.selector));
    }

    function test_feeModesRefused() public {
        MetaTxLib.MetaTransaction memory m = _own(abi.encodeCall(IMetaTx.cancelNonce, (1)), 0);
        m.mode = MetaTxLib.MODE_FEE_PERCENT;
        bytes memory sig = _pk(0, PASSKEY, acct.mtxDigest(m));
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MtxFeeClass.selector, IMetaTx.cancelNonce.selector, m.mode));
        acct.mtxExecute(m, sig);
        m.mode = MetaTxLib.MODE_FEE_FIXED;
        m.fee = 1;
        sig = _pk(0, PASSKEY, acct.mtxDigest(m));
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxUnknownMode.selector, m.mode));
        acct.mtxExecute(m, sig);
    }

    /// CTR-ACC-11, MT-4: `("SCaaS SmartKeyAccount", "1", chainId, account, chain_uid)`, on every clone.
    function test_domainIsSaltedSmartKeyAccount() public view {
        (bytes1 f, string memory name, string memory version, uint256 chainId, address vc, bytes32 salt_,) =
            acct.eip712Domain();
        assertEq(f, hex"1f");
        assertEq(name, "SCaaS SmartKeyAccount");
        assertEq(version, "1");
        assertEq(chainId, 7622);
        assertEq(vc, address(acct));
        assertEq(salt_, UID_);
        assertEq(acct.chainUid(), UID_);
        assertEq(fac.chainUid(), UID_);
        MetaTxLib.MetaTransaction memory m = _own(hex"12345678", 3);
        bytes32 ds = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)"),
            keccak256("SCaaS SmartKeyAccount"), keccak256("1"), uint256(7622), address(acct), UID_));
        assertEq(acct.mtxDigest(m), keccak256(abi.encodePacked(hex"1901", ds, MetaTxLib.hashStruct(m))));
    }

    // ------------------------------------------------------------------ recovery (CTR-ACC-03)

    function test_guardian_recovery_after_delay() public {
        SubjectKey memory k = _seedKey(SEED);
        vm.prank(GUARDIAN);
        acct.initiateRecovery(k);
        vm.expectRevert(abi.encodeWithSelector(SmartKeyAccount.RecoveryNotReady.selector, block.timestamp + 2 days));
        acct.completeRecovery(k);
        vm.warp(block.timestamp + 2 days - 1);
        vm.expectRevert(abi.encodeWithSelector(SmartKeyAccount.RecoveryNotReady.selector, block.timestamp + 1));
        acct.completeRecovery(k);
        vm.warp(block.timestamp + 1);
        vm.prank(address(0xA11));                  // anyone submits
        uint256 idx = acct.completeRecovery(k);
        assertEq(acct.pendingRecovery(), bytes32(0));
        assertEq(acct.keyCount(), 2, "recovery adds, removes nothing");
        assertTrue(_valid(acct, D, _ecdsa(idx, SEED, D)));
        _ownerCall(abi.encodeCall(SmartKeyAccount.removeKey, (0)), idx, SEED, false);
        assertEq(acct.keyCount(), 1);
    }

    function test_key_cancels_recovery() public {
        SubjectKey memory k = _seedKey(SEED);
        vm.prank(GUARDIAN);
        acct.initiateRecovery(k);
        _ownerCall(abi.encodeCall(SmartKeyAccount.cancelRecovery, ()), 0, PASSKEY, true);
        vm.warp(block.timestamp + 3 days);
        vm.expectRevert(SmartKeyAccount.NoRecovery.selector);
        acct.completeRecovery(k);
        _ownerCallFails(abi.encodeCall(SmartKeyAccount.cancelRecovery, ()),
            abi.encodeWithSelector(SmartKeyAccount.NoRecovery.selector));
    }

    /// Owner ruling 2026-10-30 (D2): a guardian with an EIP-7702 designator is running its delegate's code (a phished
    /// guardian's sweeper); `initiateRecovery` refuses it before anything changes.
    function test_recovery_delegatedGuardianRefused() public {
        vm.etch(GUARDIAN, abi.encodePacked(hex"ef0100", address(0x5EE9)));
        vm.prank(GUARDIAN);
        vm.expectRevert(abi.encodeWithSelector(SigCheck.CallerDelegated.selector, GUARDIAN));
        acct.initiateRecovery(_seedKey(SEED));
        assertEq(acct.pendingRecovery(), bytes32(0));
        vm.etch(GUARDIAN, "");
        vm.prank(GUARDIAN);
        acct.initiateRecovery(_seedKey(SEED));
    }

    function test_recovery_guards() public {
        SubjectKey memory k = _seedKey(SEED);
        SubjectKey memory other = _passkey(PASSKEY2);
        vm.expectRevert(SmartKeyAccount.NotGuardian.selector);
        acct.initiateRecovery(k);
        vm.prank(GUARDIAN);
        vm.expectRevert(SmartKeyAccount.BadKey.selector);
        acct.initiateRecovery(SubjectKey(KeyKind.NONE, 0, 0, 0, 0));
        vm.prank(GUARDIAN);
        acct.initiateRecovery(k);
        vm.warp(block.timestamp + 2 days);
        vm.expectRevert(SmartKeyAccount.NoRecovery.selector);
        acct.completeRecovery(other);
        _ownerCall(abi.encodeCall(SmartKeyAccount.setGuardian, (address(0xD00D))), 0, PASSKEY, true);
        vm.expectRevert(SmartKeyAccount.NoRecovery.selector);
        acct.completeRecovery(k);
        vm.prank(GUARDIAN);
        vm.expectRevert(SmartKeyAccount.NotGuardian.selector);
        acct.initiateRecovery(k);
    }

    function test_no_guardian_no_recovery() public {
        SmartKeyAccount a = SmartKeyAccount(payable(fac.deploy(_seedKey(SEED), address(0))));
        SubjectKey memory k = _passkey(PASSKEY);
        vm.prank(address(0));
        vm.expectRevert(SmartKeyAccount.NotGuardian.selector);
        a.initiateRecovery(k);
    }

    // ------------------------------------------------------------------ factory (CTR-ACC-01)

    function test_factory_predictable_permissionless_idempotent() public {
        SubjectKey memory k = _passkey(PASSKEY2);
        address predicted = fac.predict(k, GUARDIAN);
        assertEq(predicted.code.length, 0);
        vm.prank(address(0xD3AD));
        address a = fac.deploy(k, GUARDIAN);
        assertEq(a, predicted);
        assertEq(fac.deploy(k, GUARDIAN), a);
        assertTrue(fac.predict(k, address(0)) != a);
        assertEq(SmartKeyAccount(payable(a)).guardian(), GUARDIAN);
        assertEq(SmartKeyAccount(payable(a)).keyCount(), 1);
    }

    function test_initialize_is_factory_only_and_once() public {
        vm.expectRevert(SmartKeyAccount.NotFactory.selector);
        acct.initialize(_seedKey(SEED), address(0));
        SmartKeyAccount impl = SmartKeyAccount(payable(fac.IMPLEMENTATION()));
        vm.prank(address(fac));
        vm.expectRevert(SmartKeyAccount.AlreadyInitialized.selector);
        impl.initialize(_seedKey(SEED), address(0));
        vm.prank(address(fac));
        vm.expectRevert(SmartKeyAccount.AlreadyInitialized.selector);
        acct.initialize(_seedKey(SEED), address(0));
    }

    /// The implementation differs per chain (the factory passes `chain_uid`, an immutable); the account address then
    /// differs only because `Deploy.s.sol` CREATE2-deploys the factory with `chain_uid` in its initcode.
    function test_implementationDependsOnChainUid() public {
        SmartKeyAccountFactory other = new SmartKeyAccountFactory(keccak256("another chain"));
        assertTrue(other.IMPLEMENTATION().codehash != fac.IMPLEMENTATION().codehash, "chain_uid is an immutable");
        assertEq(SmartKeyAccount(payable(other.IMPLEMENTATION())).chainUid(), keccak256("another chain"));
        vm.expectRevert();
        new SmartKeyAccountFactory(bytes32(0));
    }

    /// The CREATE2 formula Odoo (`blockchain.subject.account._predict`) and clientkeys check against the same file:
    /// salt of (key, guardian) and the clone address of (implementation, salt, factory).
    function test_pinned_create2_vector() public view {
        SubjectKey memory k = _seedKey(SEED);
        string memory j = vm.readFile("test/vectors/smart_key_account_create2.json");
        bytes32 s = fac.salt(k, GUARDIAN);
        assertEq(s, vm.parseJsonBytes32(j, ".salt"));
        assertEq(Clones.predictDeterministicAddress(
            vm.parseJsonAddress(j, ".implementation"), s, vm.parseJsonAddress(j, ".factory")),
            vm.parseJsonAddress(j, ".account"));
        assertEq(fac.predict(k, GUARDIAN), Clones.predictDeterministicAddress(fac.IMPLEMENTATION(), s, address(fac)));
    }

    // ------------------------------------------------------------------ gas

    function test_gas_deploy_and_owner_call() public {
        uint256 g = gasleft();
        fac.deploy(_passkey(PASSKEY2), GUARDIAN);
        emit log_named_uint("factory.deploy (clone + initialize, passkey key)", g - gasleft());
        bytes memory data = abi.encodeCall(SmartKeyAccount.addKey, (_seedKey(SEED)));
        MetaTxLib.MetaTransaction memory m = _own(data, 0);
        bytes memory sig = _pk(0, PASSKEY, acct.mtxDigest(m));
        g = gasleft();
        acct.mtxExecuteAsOwner(data, 0, m.validUntil, sig);
        emit log_named_uint("mtxExecuteAsOwner(addKey), passkey", g - gasleft());
    }
}

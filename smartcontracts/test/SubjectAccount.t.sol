// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Base64} from "@openzeppelin/contracts/utils/Base64.sol";
import {Hashes} from "@openzeppelin/contracts/utils/cryptography/Hashes.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {P256} from "@openzeppelin/contracts/utils/cryptography/P256.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {Fixtures} from "./helpers/Fixtures.sol";
import {MetaToken} from "../src/metatx/MetaToken.sol";
import {IERC20MetaTx} from "../src/metatx/IERC20MetaTx.sol";
import {IERC20Payment} from "../src/metatx/IERC20Payment.sol";
import {MetaTxLib} from "../src/common/MetaTxLib.sol";
import {SubjectAccount, SubjectKey, KeyKind} from "../src/account/SubjectAccount.sol";
import {SubjectAccountFactory} from "../src/account/SubjectAccountFactory.sol";

/// RIP-7212 / EIP-7951 tương thích: input 160 byte `h‖r‖s‖x‖y`, ra `uint256(1)` khi hợp lệ, rỗng khi
/// không. Etch vào 0x100 để đi đường "có precompile" của `P256.verify`.
contract P256PrecompileStub {
    fallback(bytes calldata input) external returns (bytes memory) {
        if (input.length != 160) return "";
        (bytes32 h, bytes32 r, bytes32 s, bytes32 x, bytes32 y) =
            abi.decode(input, (bytes32, bytes32, bytes32, bytes32, bytes32));
        return P256.verifySolidity(h, r, s, x, y) ? abi.encode(uint256(1)) : bytes("");
    }
}

/// Authenticator phần mềm trong test: khoá P-256 cố định, authenticatorData/clientDataJSON
/// đúng định dạng WebAuthn (L3 §5.8.1.1), chữ ký chuẩn hoá low-s như client làm.
abstract contract WebAuthnSoft is Fixtures {
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
        return SubjectKey(KeyKind.P256_WEBAUTHN, bytes32(x), bytes32(y),
                          sha256(bytes(RP_ID)), keccak256(bytes(ORIGIN)));
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

contract SubjectAccountTest is WebAuthnSoft {
    uint256 internal constant PASSKEY = 0xC0FFEE1234567890;
    uint256 internal constant PASSKEY2 = 0xBADC0DE5;
    uint256 internal constant SEED = 0x5EED;
    address internal constant GUARDIAN = address(0x6A2D);
    address internal shop = address(0x5409);

    SubjectAccountFactory internal fac;
    SubjectAccount internal acct;
    MetaToken internal t;
    bytes4 internal constant MAGIC = IERC1271.isValidSignature.selector;

    function setUp() public {
        _deployFactory();
        t = _standalone(address(this), "ZVND", 0, 0, address(this));
        fac = new SubjectAccountFactory();
        acct = SubjectAccount(payable(fac.deploy(_passkey(PASSKEY), GUARDIAN)));
        t.mint(address(acct), 1000);
    }

    function _valid(SubjectAccount a, bytes32 digest, bytes memory sig) internal view returns (bool) {
        return a.isValidSignature(digest, sig) == MAGIC;
    }

    function _ownerCall(bytes memory data, uint256 index, uint256 pk, bool passkey) internal {
        uint256 nonce = acct.ownerNonce();
        uint256 until = block.timestamp + 300;
        bytes32 d = acct.ownerCallDigest(data, nonce, until);
        acct.executeAsOwner(data, nonce, until, passkey ? _pk(index, pk, d) : _ecdsa(index, pk, d));
    }

    // ------------------------------------------------------------------ WebAuthn: published vectors

    /// Vector công bố: base/webauthn-sol `test/WebAuthn.t.sol` (Coinbase Smart Wallet), lấy
    /// 2026-10-03 từ https://raw.githubusercontent.com/base/webauthn-sol/main/test/WebAuthn.t.sol —
    /// assertion thật của Chrome và Safari, rpId "localhost", origin "http://localhost:3005".
    function _baseAccount() internal returns (SubjectAccount) {
        SubjectKey memory k = SubjectKey(
            KeyKind.P256_WEBAUTHN,
            bytes32(uint256(28573233055232466711029625910063034642429572463461595413086259353299906450061)),
            bytes32(uint256(39367742072897599771788408398752356480431855827262528811857788332151452825281)),
            sha256("localhost"), keccak256("http://localhost:3005"));
        return SubjectAccount(payable(fac.deploy(k, address(0))));
    }

    bytes32 internal constant BASE_CHALLENGE = 0xf631058a3ba1116acce12396fad0a125b5041c43f8e15723709f81aa8d5f4ccf;

    function test_published_chrome_vector() public {
        SubjectAccount a = _baseAccount();
        bytes memory inner = abi.encode(
            hex"49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d9763050000010a",
            _clientData(BASE_CHALLENGE, "http://localhost:3005", TAIL),
            bytes32(uint256(29739767516584490820047863506833955097567272713519339793744591468032609909569)),
            bytes32(uint256(45947455641742997809691064512762075989493430661170736817032030660832793108102)));
        assertTrue(_valid(a, BASE_CHALLENGE, _sig(0, inner)));
        assertFalse(_valid(a, keccak256("other"), _sig(0, inner)));
    }

    function test_published_safari_vector() public {
        SubjectAccount a = _baseAccount();
        bytes memory inner = abi.encode(
            hex"49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97630500000101",
            _clientData(BASE_CHALLENGE, "http://localhost:3005", "}"),
            bytes32(uint256(43684192885701841787131392247364253107519555363555461570655060745499568693242)),
            bytes32(uint256(22655632649588629308599201066602670461698485748654492451178007896016452673579)));
        assertTrue(_valid(a, BASE_CHALLENGE, _sig(0, inner)));
    }

    /// Vector do authenticator phần mềm Node (WebCrypto P-256, chữ ký DER → low-s) sinh:
    /// `clientkeys/scripts/webauthn-vector.mjs` ⇒ `test/vectors/webauthn_soft.json`.
    function test_node_software_authenticator_vector() public {
        string memory j = vm.readFile("test/vectors/webauthn_soft.json");
        SubjectKey memory k = SubjectKey(
            KeyKind.P256_WEBAUTHN, vm.parseJsonBytes32(j, ".qx"), vm.parseJsonBytes32(j, ".qy"),
            sha256(bytes(vm.parseJsonString(j, ".rpId"))), keccak256(bytes(vm.parseJsonString(j, ".origin"))));
        SubjectAccount a = SubjectAccount(payable(fac.deploy(k, address(0))));
        bytes32 challenge = vm.parseJsonBytes32(j, ".challenge");
        assertTrue(_valid(a, challenge, vm.parseJsonBytes(j, ".signature")));
        assertFalse(_valid(a, keccak256("other"), vm.parseJsonBytes(j, ".signature")));
    }

    // ------------------------------------------------------------------ WebAuthn: refusals

    bytes32 internal constant D = keccak256("operation digest");

    function test_soft_assertion_valid() public view {
        assertTrue(_valid(acct, D, _pk(0, PASSKEY, D)));
    }

    function test_wrong_challenge() public view {
        assertFalse(_valid(acct, D, _pk(0, PASSKEY, keccak256("another op"))));
    }

    function test_wrong_origin() public view {
        Assertion memory a = _signAssertion(PASSKEY, abi.encodePacked(sha256(bytes(RP_ID)), bytes1(0x05), uint32(0)),
                                            _clientData(D, "https://evil.example.com", TAIL));
        assertFalse(_valid(acct, D, _sig(0, _enc(a))));
    }

    function test_origin_prefix_of_registered_is_refused() public view {
        Assertion memory a = _signAssertion(PASSKEY, abi.encodePacked(sha256(bytes(RP_ID)), bytes1(0x05), uint32(0)),
                                            _clientData(D, "https://pay.example.com.evil", TAIL));
        assertFalse(_valid(acct, D, _sig(0, _enc(a))));
    }

    function test_wrong_rp_id_hash() public view {
        Assertion memory a = _signAssertion(PASSKEY, abi.encodePacked(sha256("evil.example.com"), bytes1(0x05), uint32(0)),
                                            _clientData(D, ORIGIN, TAIL));
        assertFalse(_valid(acct, D, _sig(0, _enc(a))));
    }

    function test_up_missing() public view {
        Assertion memory a = _signAssertion(PASSKEY, abi.encodePacked(sha256(bytes(RP_ID)), bytes1(0x04), uint32(0)),
                                            _clientData(D, ORIGIN, TAIL));
        assertFalse(_valid(acct, D, _sig(0, _enc(a))));
    }

    function test_uv_missing() public view {
        Assertion memory a = _signAssertion(PASSKEY, abi.encodePacked(sha256(bytes(RP_ID)), bytes1(0x01), uint32(0)),
                                            _clientData(D, ORIGIN, TAIL));
        assertFalse(_valid(acct, D, _sig(0, _enc(a))));
    }

    function test_extra_flags_are_accepted() public view {
        // BE|BS (passkey đồng bộ) + UP|UV.
        Assertion memory a = _signAssertion(PASSKEY, abi.encodePacked(sha256(bytes(RP_ID)), bytes1(0x1d), uint32(7)),
                                            _clientData(D, ORIGIN, TAIL));
        assertTrue(_valid(acct, D, _sig(0, _enc(a))));
    }

    function test_high_s_is_refused() public view {
        Assertion memory a = _assertion(PASSKEY, D);
        a.s = bytes32(N - uint256(a.s));
        assertFalse(_valid(acct, D, _sig(0, _enc(a))));
    }

    function test_tampered_auth_data() public view {
        Assertion memory a = _assertion(PASSKEY, D);
        a.authData[36] = 0x01;   // sign counter
        assertFalse(_valid(acct, D, _sig(0, _enc(a))));
    }

    function test_tampered_client_data_after_signing() public view {
        Assertion memory a = _assertion(PASSKEY, D);
        a.clientData = _clientData(D, ORIGIN, ',"crossOrigin":false,"x":1}');
        assertFalse(_valid(acct, D, _sig(0, _enc(a))));
    }

    function test_tampered_r() public view {
        Assertion memory a = _assertion(PASSKEY, D);
        a.r = bytes32(uint256(a.r) ^ 1);
        assertFalse(_valid(acct, D, _sig(0, _enc(a))));
    }

    function test_type_create_is_refused() public view {
        bytes memory cd = abi.encodePacked('{"type":"webauthn.create","challenge":"',
            Base64.encodeURL(abi.encodePacked(D)), '","origin":"', ORIGIN, '"', TAIL);
        Assertion memory a = _signAssertion(PASSKEY, abi.encodePacked(sha256(bytes(RP_ID)), bytes1(0x05), uint32(0)), cd);
        assertFalse(_valid(acct, D, _sig(0, _enc(a))));
    }

    function test_cross_origin_true_is_refused() public view {
        Assertion memory a = _signAssertion(PASSKEY, abi.encodePacked(sha256(bytes(RP_ID)), bytes1(0x05), uint32(0)),
            _clientData(D, ORIGIN, ',"crossOrigin":true,"topOrigin":"https://evil.example.com"}'));
        assertFalse(_valid(acct, D, _sig(0, _enc(a))));
    }

    function _withTail(string memory tail) internal pure returns (bytes memory) {
        return _sig(0, _enc(_signAssertion(PASSKEY, abi.encodePacked(sha256(bytes(RP_ID)), bytes1(0x05), uint32(0)),
                                           _clientData(D, ORIGIN, tail))));
    }

    function test_client_data_layouts() public view {
        // Chrome thêm khoá ngẫu nhiên sau crossOrigin: nhận.
        assertTrue(_valid(acct, D, _withTail(
            ',"crossOrigin":false,"other_keys_can_be_added_here":"do not compare clientDataJSON against a template"}')));
        // Khoá lạ chen trước crossOrigin, khoảng trắng, crossOrigin true: đều từ chối (SEC-01).
        assertFalse(_valid(acct, D, _withTail(',"x":1,"crossOrigin":true}')));
        assertFalse(_valid(acct, D, _withTail(',"crossOrigin": true}')));
        assertFalse(_valid(acct, D, _withTail(',"crossOrigin":true}')));
        assertFalse(_valid(acct, D, _withTail(',"crossOrigin":false')));
        assertFalse(_valid(acct, D, _withTail(',"crossOrigin":falsey}')));
    }

    function test_trailing_garbage_after_close_is_refused() public view {
        Assertion memory a = _signAssertion(PASSKEY, abi.encodePacked(sha256(bytes(RP_ID)), bytes1(0x05), uint32(0)),
            _clientData(D, ORIGIN, "}x"));
        assertFalse(_valid(acct, D, _sig(0, _enc(a))));
    }

    function test_short_auth_data_is_refused() public view {
        Assertion memory a = _assertion(PASSKEY, D);
        a.authData = abi.encodePacked(sha256(bytes(RP_ID)), bytes1(0x05));
        assertFalse(_valid(acct, D, _sig(0, _enc(a))));
    }

    function test_other_passkey_is_refused() public view {
        assertFalse(_valid(acct, D, _pk(0, PASSKEY2, D)));
    }

    function test_unknown_key_index_is_refused() public view {
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
        _ownerCall(abi.encodeCall(SubjectAccount.addKey, (_seedKey(SEED))), 0, PASSKEY, true);
        bytes32[4] memory d = _ops();
        (bytes32 root, bytes32[][4] memory proofs) = _tree(d);
        bytes memory inner = _enc(_assertion(PASSKEY, root));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(SEED, root);
        for (uint256 i; i < 4; ++i) {
            assertTrue(_valid(acct, d[i], abi.encode(uint256(0), proofs[i], inner)), "passkey leaf");
            assertTrue(_valid(acct, d[i], abi.encode(uint256(1), proofs[i], abi.encodePacked(r, s, v))), "seed leaf");
        }
        // digest ngoài lô, proof của dòng khác, hoặc dùng gốc như một digest đơn: đều từ chối.
        assertFalse(_valid(acct, keccak256("not in batch"), abi.encode(uint256(0), proofs[0], inner)));
        assertFalse(_valid(acct, d[0], abi.encode(uint256(0), proofs[1], inner)));
        assertFalse(_valid(acct, d[0], _sig(0, inner)));
    }

    function test_batch_leaf_is_not_an_inner_node() public view {
        bytes32[4] memory d = _ops();
        (, bytes32[][4] memory proofs) = _tree(d);
        // Một nút trong (n01) dùng như "digest" với proof còn lại không tái tạo được gốc: lá băm kép.
        bytes32 n01 = Hashes.commutativeKeccak256(acct.batchLeaf(d[0]), acct.batchLeaf(d[1]));
        bytes32[] memory p = new bytes32[](1);
        p[0] = proofs[0][1];
        (bytes32 root,) = _tree(d);
        bytes memory inner = _enc(_assertion(PASSKEY, root));
        assertFalse(_valid(acct, n01, abi.encode(uint256(0), p, inner)));
    }

    // ------------------------------------------------------------------ MetaToken pay

    function _payment(address from, bytes32 ref) internal view returns (MetaTxLib.MetaTransaction memory m, bytes32 d) {
        m = _mt(from, shop, 400, _payData(ref), uint256(ref), MetaTxLib.MODE_RESTRICT_RELAYER);
        d = t.metaTxDigest(m);
    }

    function test_metatoken_pay_signed_with_passkey() public {
        (MetaTxLib.MetaTransaction memory m, bytes32 d) = _payment(address(acct), keccak256("r1"));
        bytes memory sig = _pk(0, PASSKEY, d);
        vm.expectEmit(true, true, true, true, address(t));
        emit IERC20Payment.PaymentSettled(address(acct), shop, 400, 0, relayer, keccak256("r1"));
        vm.prank(relayer);
        t.executeMetaTransaction(m, sig);
        assertEq(t.balanceOf(shop), 400);
    }

    function test_second_key_then_pay_with_each() public {
        _ownerCall(abi.encodeCall(SubjectAccount.addKey, (_seedKey(SEED))), 0, PASSKEY, true);
        assertEq(acct.keyCount(), 2);
        (MetaTxLib.MetaTransaction memory m1, bytes32 d1) = _payment(address(acct), keccak256("seed"));
        bytes memory s1 = _ecdsa(1, SEED, d1);
        vm.prank(relayer);
        t.executeMetaTransaction(m1, s1);
        (MetaTxLib.MetaTransaction memory m2, bytes32 d2) = _payment(address(acct), keccak256("passkey"));
        bytes memory s2 = _pk(0, PASSKEY, d2);
        vm.prank(relayer);
        t.executeMetaTransaction(m2, s2);
        assertEq(t.balanceOf(shop), 800);
    }

    function test_seed_first_account_pays() public {
        SubjectAccount a = SubjectAccount(payable(fac.deploy(_seedKey(SEED), address(0))));
        t.mint(address(a), 500);
        (MetaTxLib.MetaTransaction memory m, bytes32 d) = _payment(address(a), keccak256("s1"));
        bytes memory sig = _ecdsa(0, SEED, d);
        vm.prank(relayer);
        t.executeMetaTransaction(m, sig);
        assertEq(t.balanceOf(shop), 400);
    }

    function test_signature_for_one_account_does_not_pay_from_another() public {
        // Cùng passkey, guardian khác ⇒ account khác. Digest mang `from`, nên chữ ký không chuyển được.
        SubjectAccount b = SubjectAccount(payable(fac.deploy(_passkey(PASSKEY), address(0))));
        t.mint(address(b), 1000);
        (, bytes32 dA) = _payment(address(acct), keccak256("x"));
        (MetaTxLib.MetaTransaction memory mB,) = _payment(address(b), keccak256("x"));
        bytes memory sig = _pk(0, PASSKEY, dA);
        vm.prank(relayer);
        vm.expectRevert(IERC20MetaTx.MetaTxBadSignature.selector);
        t.executeMetaTransaction(mB, sig);
    }

    function test_removed_key_cannot_pay() public {
        _ownerCall(abi.encodeCall(SubjectAccount.addKey, (_seedKey(SEED))), 0, PASSKEY, true);
        _ownerCall(abi.encodeCall(SubjectAccount.removeKey, (0)), 1, SEED, false);
        (MetaTxLib.MetaTransaction memory m, bytes32 d) = _payment(address(acct), keccak256("gone"));
        bytes memory sig = _pk(0, PASSKEY, d);
        vm.prank(relayer);
        vm.expectRevert(IERC20MetaTx.MetaTxBadSignature.selector);
        t.executeMetaTransaction(m, sig);
    }

    // ------------------------------------------------------------------ key lifecycle

    function test_never_zero_keys() public {
        _ownerCallFails(abi.encodeCall(SubjectAccount.removeKey, (0)), SubjectAccount.LastKey.selector);
        assertEq(acct.keyCount(), 1);
    }

    function test_rotate_passkey_to_new_passkey() public {
        _ownerCall(abi.encodeCall(SubjectAccount.rotateKey, (0, _passkey(PASSKEY2))), 0, PASSKEY, true);
        assertEq(acct.keyCount(), 1);
        assertTrue(_valid(acct, D, _pk(1, PASSKEY2, D)));
        assertFalse(_valid(acct, D, _pk(0, PASSKEY, D)));
        assertFalse(acct.hasKey(keccak256(abi.encode(_passkey(PASSKEY)))));
    }

    function test_owner_call_replay_expiry_and_foreign_key() public {
        bytes memory data = abi.encodeCall(SubjectAccount.addKey, (_seedKey(SEED)));
        uint256 until = block.timestamp + 300;
        bytes memory sig = _pk(0, PASSKEY, acct.ownerCallDigest(data, 0, until));
        bytes memory foreign = _pk(0, PASSKEY2, acct.ownerCallDigest(data, 0, until));
        vm.expectRevert(SubjectAccount.BadSignature.selector);
        acct.executeAsOwner(data, 0, until, foreign);
        acct.executeAsOwner(data, 0, until, sig);
        vm.expectRevert(SubjectAccount.BadNonce.selector);
        acct.executeAsOwner(data, 0, until, sig);
        vm.warp(until + 1);
        vm.expectRevert(SubjectAccount.SignatureExpired.selector);
        acct.executeAsOwner(data, 1, until, sig);
    }

    function _ownerCallFails(bytes memory data, bytes4 err) internal {
        uint256 until = block.timestamp + 300;
        bytes memory sig = _pk(0, PASSKEY, acct.ownerCallDigest(data, 0, until));
        vm.expectRevert(abi.encodeWithSelector(SubjectAccount.CallFailed.selector, abi.encodeWithSelector(err)));
        acct.executeAsOwner(data, 0, until, sig);
    }

    function test_duplicate_and_bad_keys() public {
        _ownerCallFails(abi.encodeCall(SubjectAccount.addKey, (_passkey(PASSKEY))), SubjectAccount.DuplicateKey.selector);
        SubjectKey memory k = _passkey(PASSKEY2);
        k.y = bytes32(uint256(k.y) ^ 1);                                   // ngoài đường cong
        _ownerCallFails(abi.encodeCall(SubjectAccount.addKey, (k)), SubjectAccount.BadKey.selector);
        k = _seedKey(SEED);
        k.x = bytes32(uint256(k.x) | (1 << 200));                          // bit bẩn trên địa chỉ
        _ownerCallFails(abi.encodeCall(SubjectAccount.addKey, (k)), SubjectAccount.BadKey.selector);
        k = _passkey(PASSKEY2);
        k.originHash = 0;
        _ownerCallFails(abi.encodeCall(SubjectAccount.addKey, (k)), SubjectAccount.BadKey.selector);
        SubjectKey memory none;
        _ownerCallFails(abi.encodeCall(SubjectAccount.addKey, (none)), SubjectAccount.BadKey.selector);
    }

    function test_self_only_functions() public {
        vm.expectRevert(SubjectAccount.NotSelf.selector);
        acct.addKey(_seedKey(SEED));
        vm.expectRevert(SubjectAccount.NotSelf.selector);
        acct.removeKey(0);
        vm.expectRevert(SubjectAccount.NotSelf.selector);
        acct.setGuardian(address(this));
        vm.expectRevert(SubjectAccount.NotSelf.selector);
        acct.execute(address(t), 0, "");
    }

    function test_execute_moves_funds() public {
        _ownerCall(abi.encodeCall(SubjectAccount.execute,
                                  (address(t), 0, abi.encodeCall(t.transfer, (shop, 100)))), 0, PASSKEY, true);
        assertEq(t.balanceOf(shop), 100);
    }

    // ------------------------------------------------------------------ recovery

    function test_guardian_recovery_after_delay() public {
        SubjectKey memory k = _seedKey(SEED);
        vm.prank(GUARDIAN);
        acct.initiateRecovery(k);
        vm.expectRevert(abi.encodeWithSelector(SubjectAccount.RecoveryNotReady.selector, block.timestamp + 2 days));
        acct.completeRecovery(k);
        vm.warp(block.timestamp + 2 days);
        vm.prank(address(0xA11));                  // ai cũng nộp được
        uint256 idx = acct.completeRecovery(k);
        assertTrue(_valid(acct, D, _ecdsa(idx, SEED, D)));
        // Khoá mới xoá passkey đã mất.
        _ownerCall(abi.encodeCall(SubjectAccount.removeKey, (0)), idx, SEED, false);
        assertEq(acct.keyCount(), 1);
    }

    function test_key_cancels_recovery() public {
        SubjectKey memory k = _seedKey(SEED);
        vm.prank(GUARDIAN);
        acct.initiateRecovery(k);
        _ownerCall(abi.encodeCall(SubjectAccount.cancelRecovery, ()), 0, PASSKEY, true);
        vm.warp(block.timestamp + 3 days);
        vm.expectRevert(SubjectAccount.NoRecovery.selector);
        acct.completeRecovery(k);
    }

    function test_recovery_guards() public {
        SubjectKey memory k = _seedKey(SEED);
        SubjectKey memory other = _passkey(PASSKEY2);
        vm.expectRevert(SubjectAccount.NotGuardian.selector);
        acct.initiateRecovery(k);
        vm.prank(GUARDIAN);
        acct.initiateRecovery(k);
        vm.warp(block.timestamp + 2 days);
        vm.expectRevert(SubjectAccount.NoRecovery.selector);
        acct.completeRecovery(other);   // không phải khoá đang chờ
        // Đổi guardian huỷ recovery của guardian cũ.
        _ownerCall(abi.encodeCall(SubjectAccount.setGuardian, (address(0xD00D))), 0, PASSKEY, true);
        vm.expectRevert(SubjectAccount.NoRecovery.selector);
        acct.completeRecovery(k);
        vm.prank(GUARDIAN);
        vm.expectRevert(SubjectAccount.NotGuardian.selector);
        acct.initiateRecovery(k);
    }

    function test_no_guardian_no_recovery() public {
        SubjectAccount a = SubjectAccount(payable(fac.deploy(_seedKey(SEED), address(0))));
        SubjectKey memory k = _passkey(PASSKEY);
        vm.prank(address(0));
        vm.expectRevert(SubjectAccount.NotGuardian.selector);
        a.initiateRecovery(k);
    }

    // ------------------------------------------------------------------ factory

    function test_factory_predictable_permissionless_idempotent() public {
        SubjectKey memory k = _passkey(PASSKEY2);
        address predicted = fac.predict(k, GUARDIAN);
        assertEq(predicted.code.length, 0);
        vm.prank(address(0xD3AD));
        address a = fac.deploy(k, GUARDIAN);
        assertEq(a, predicted);
        assertEq(fac.deploy(k, GUARDIAN), a);                 // lần hai: cùng địa chỉ, không revert
        assertTrue(fac.predict(k, address(0)) != a);          // guardian nằm trong salt (RS4-1)
        assertEq(SubjectAccount(payable(a)).guardian(), GUARDIAN);
        assertEq(SubjectAccount(payable(a)).keyCount(), 1);
    }

    function test_initialize_is_factory_only_and_once() public {
        vm.expectRevert(SubjectAccount.NotFactory.selector);
        acct.initialize(_seedKey(SEED), address(0));
        SubjectAccount impl = SubjectAccount(payable(fac.IMPLEMENTATION()));
        vm.prank(address(fac));
        vm.expectRevert(SubjectAccount.AlreadyInitialized.selector);
        impl.initialize(_seedKey(SEED), address(0));
        vm.prank(address(fac));
        vm.expectRevert(SubjectAccount.AlreadyInitialized.selector);
        acct.initialize(_seedKey(SEED), address(0));
    }

    /// Ghim địa chỉ CREATE2 cho Odoo (`blockchain.subject.account._predict`) và clientkeys.
    /// Ghim CÔNG THỨC (không ghim bytecode): salt của (khoá, guardian), và địa chỉ clone của
    /// (implementation, salt, factory) cố định trong JSON. Odoo và clientkeys kiểm cùng file.
    function test_pinned_create2_vector() public view {
        SubjectKey memory k = _seedKey(SEED);
        string memory j = vm.readFile("test/vectors/subject_account_create2.json");
        bytes32 s = fac.salt(k, GUARDIAN);
        assertEq(s, vm.parseJsonBytes32(j, ".salt"));
        assertEq(Clones.predictDeterministicAddress(
            vm.parseJsonAddress(j, ".implementation"), s, vm.parseJsonAddress(j, ".factory")),
            vm.parseJsonAddress(j, ".account"));
        assertEq(fac.predict(k, GUARDIAN), Clones.predictDeterministicAddress(fac.IMPLEMENTATION(), s, address(fac)));
    }

    /// Ghim digest `OwnerCall` mà Odoo (`_owner_call_digest`) và clientkeys (`hashTypedData` của typed
    /// data Odoo phát) cũng phải ra: account ở 0x…ACC0, chain 31337, data 0x1234, nonce 3, hạn 1.8e9.
    function test_pinned_owner_call_digest() public {
        address at = address(0xACC0);
        vm.etch(at, address(acct).code);
        bytes32 d = SubjectAccount(payable(at)).ownerCallDigest(hex"1234", 3, 1_800_000_000);
        emit log_named_bytes32("ownerCallDigest", d);
        assertEq(block.chainid, 31337);
        assertEq(d, OWNER_CALL_PIN);
    }

    bytes32 internal constant OWNER_CALL_PIN = 0x24bb1dae4c38217e81cff2a57e2c7b461830c462e83cf6184e0d4714cf625610;

    // ------------------------------------------------------------------ gas

    function _gasPay(bytes32 ref) internal returns (uint256 used) {
        (MetaTxLib.MetaTransaction memory m, bytes32 d) = _payment(address(acct), ref);
        bytes memory sig = _pk(0, PASSKEY, d);
        vm.prank(relayer);
        uint256 g = gasleft();
        t.executeMetaTransaction(m, sig);
        used = g - gasleft();
    }

    function test_gas_pay_passkey_solidity_fallback() public {
        assertEq(address(0x100).code.length, 0);
        uint256 used = _gasPay(keccak256("g1"));
        emit log_named_uint("executeMetaTransaction pay, passkey, Solidity P-256", used);
    }

    function test_gas_pay_passkey_precompile_stub() public {
        vm.etch(address(0x100), type(P256PrecompileStub).runtimeCode);
        uint256 used = _gasPay(keccak256("g2"));
        emit log_named_uint("executeMetaTransaction pay, passkey, etched RIP-7212 verifier (Solidity body)", used);
        // Hỏng vẫn hỏng khi có precompile.
        (MetaTxLib.MetaTransaction memory m, bytes32 d) = _payment(address(acct), keccak256("g3"));
        bytes memory sig = _pk(0, PASSKEY2, d);
        vm.prank(relayer);
        vm.expectRevert(IERC20MetaTx.MetaTxBadSignature.selector);
        t.executeMetaTransaction(m, sig);
    }

    /// forge 1.3.5 có `--evm-version osaka` nhưng không có P256VERIFY native (đo ra y hệt đường
    /// Solidity). Ước lượng precompile thật: etch một stub luôn trả 1 (PUSH1 1 PUSH1 0 MSTORE
    /// PUSH1 32 PUSH1 0 RETURN, ~18 gas) rồi cộng giá precompile: EIP-7951 = 6900, RIP-7212 = 3450;
    /// trừ 2500 (địa chỉ etch là cold 2600, precompile luôn warm 100).
    function test_gas_pay_passkey_precompile_estimate() public {
        vm.etch(address(0x100), hex"600160005260206000f3");
        uint256 used = _gasPay(keccak256("g5"));
        emit log_named_uint("executeMetaTransaction pay, passkey, constant stub at 0x100 (raw)", used);
        emit log_named_uint("  => estimate with EIP-7951 P256VERIFY (6900)", used - 2500 - 18 + 6900);
        emit log_named_uint("  => estimate with RIP-7212 (3450)", used - 2500 - 18 + 3450);
    }

    function test_gas_pay_seed_key() public {
        _ownerCall(abi.encodeCall(SubjectAccount.addKey, (_seedKey(SEED))), 0, PASSKEY, true);
        (MetaTxLib.MetaTransaction memory m, bytes32 d) = _payment(address(acct), keccak256("g4"));
        bytes memory sig = _ecdsa(1, SEED, d);
        vm.prank(relayer);
        uint256 g = gasleft();
        t.executeMetaTransaction(m, sig);
        emit log_named_uint("executeMetaTransaction pay, seed secp256k1 key", g - gasleft());
    }

    function test_gas_deploy() public {
        uint256 g = gasleft();
        fac.deploy(_passkey(PASSKEY2), GUARDIAN);
        emit log_named_uint("factory.deploy (clone + initialize, passkey key)", g - gasleft());
    }
}

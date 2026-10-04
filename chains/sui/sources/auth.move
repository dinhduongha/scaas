/// Chữ ký của chủ thể trên một digest 32 byte (R30/R31). Cờ lược đồ = cờ Sui, nên địa chỉ của
/// chủ thể = `blake2b256(flag ‖ pk)` giống hệt địa chỉ ví Sui của cùng khoá.
module bamboo::auth;

use std::bcs;
use std::hash::sha2_256;
use sui::ecdsa_k1;
use sui::ecdsa_r1;
use sui::ed25519;
use sui::hash::blake2b256;

const ED25519: u8 = 0;
const SECP256K1: u8 = 1;
const SECP256R1: u8 = 2;
const PASSKEY: u8 = 6;
const SHA256: u8 = 1;

/// n/2 của secp256k1 và secp256r1: chữ ký `s > n/2` bị từ chối (một chữ ký, một dạng).
const K1_HALF_N: u256 = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;
const R1_HALF_N: u256 = 0x7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8;

#[error]
const EBadKey: vector<u8> = b"Unknown signature scheme or wrong public key length.";

/// `sig` = 64 byte r‖s (ed25519: 64 byte). Passkey thêm `authenticator_data` và `client_data_json`
/// của assertion WebAuthn; lược đồ khác để rỗng.
public struct Auth has copy, drop, store {
    sig: vector<u8>,
    authenticator_data: vector<u8>,
    client_data_json: vector<u8>,
}

public fun new(sig: vector<u8>, authenticator_data: vector<u8>, client_data_json: vector<u8>): Auth {
    Auth { sig, authenticator_data, client_data_json }
}

public fun passkey(): u8 { PASSKEY }

public fun key_ok(scheme: u8, pk: &vector<u8>): bool {
    let n = pk.length();
    (scheme == ED25519 && n == 32) || ((scheme == SECP256K1 || scheme == SECP256R1 || scheme == PASSKEY) && n == 33)
}

public fun address_of(scheme: u8, pk: &vector<u8>): address {
    assert!(key_ok(scheme, pk), EBadKey);
    let mut b = vector[scheme];
    b.append(*pk);
    sui::address::from_bytes(blake2b256(&b))
}

/// Digest mà ví Sui ký trong `signPersonalMessage(msg)`: intent (PersonalMessage, V0, Sui) ‖ BCS(vector<u8>).
public fun personal_digest(msg: vector<u8>): vector<u8> {
    let mut b = vector[3u8, 0, 0];
    b.append(bcs::to_bytes(&msg));
    blake2b256(&b)
}

/// `rp_id_hash`/`origins` chỉ dùng cho passkey: origin của assertion phải nằm trong `origins` (danh sách của
/// account, sửa được bằng chữ ký một khoá hiện có — review M1).
public fun verify(
    scheme: u8,
    pk: &vector<u8>,
    rp_id_hash: &vector<u8>,
    origins: &vector<vector<u8>>,
    digest: &vector<u8>,
    a: &Auth,
): bool {
    if (!key_ok(scheme, pk) || a.sig.length() != 64) return false;
    if (scheme == ED25519) return ed25519::ed25519_verify(&a.sig, pk, digest);
    if (scheme == SECP256K1) {
        return low_s(&a.sig, K1_HALF_N) && ecdsa_k1::secp256k1_verify(&a.sig, pk, digest, SHA256)
    };
    if (scheme == SECP256R1) {
        return low_s(&a.sig, R1_HALF_N) && ecdsa_r1::secp256r1_verify(&a.sig, pk, digest, SHA256)
    };
    webauthn_ok(pk, rp_id_hash, origins, digest, a)
}

/// Assertion WebAuthn (round-3 §C): type, challenge = base64url(digest), origin ∈ `origins`, rpIdHash, UP+UV,
/// low-s, P-256 trên `sha256(authenticatorData ‖ sha256(clientDataJSON))`.
fun webauthn_ok(pk: &vector<u8>, rp_id_hash: &vector<u8>, origins: &vector<vector<u8>>, digest: &vector<u8>, a: &Auth): bool {
    let ad = &a.authenticator_data;
    let cd = &a.client_data_json;
    if (ad.length() < 37 || rp_id_hash.length() != 32) return false;
    let mut i = 0;
    while (i < 32) {
        if (ad[i] != rp_id_hash[i]) return false;
        i = i + 1;
    };
    if (ad[32] & 5 != 5) return false;
    if (!contains(cd, &b"\"type\":\"webauthn.get\"")) return false;
    let mut ch = b"\"challenge\":\"";
    ch.append(base64url(digest));
    ch.push_back(34);
    if (!contains(cd, &ch)) return false;
    let origin = origin_of(a);
    if (origin.is_empty() || !origins.contains(&origin)) return false;
    if (!low_s(&a.sig, R1_HALF_N)) return false;
    let mut msg = *ad;
    msg.append(sha2_256(*cd));
    ecdsa_r1::secp256r1_verify(&a.sig, pk, &msg, SHA256)
}

/// Lá chữ ký có phần WebAuthn (passkey) hay không — chọn khoá cần thử.
public fun is_webauthn(a: &Auth): bool { !a.authenticator_data.is_empty() }

/// Origin trong `clientDataJSON` của một assertion (dùng lúc đăng ký passkey). Rỗng nếu không có.
public fun origin_of(a: &Auth): vector<u8> {
    let cd = &a.client_data_json;
    let key = b"\"origin\":\"";
    let start = find(cd, &key);
    if (start == cd.length()) return vector[];
    let mut i = start + key.length();
    let mut out = vector[];
    while (i < cd.length() && cd[i] != 34) {
        out.push_back(cd[i]);
        i = i + 1;
    };
    if (i == cd.length()) vector[] else out
}

public fun rp_id_hash_of(a: &Auth): vector<u8> {
    let ad = &a.authenticator_data;
    let mut out = vector[];
    let mut i = 0;
    while (i < 32 && i < ad.length()) {
        out.push_back(ad[i]);
        i = i + 1;
    };
    out
}

fun low_s(sig: &vector<u8>, half_n: u256): bool {
    let mut s: u256 = 0;
    let mut i = 32;
    while (i < 64) {
        s = (s << 8) | (sig[i] as u256);
        i = i + 1;
    };
    s <= half_n
}

fun contains(hay: &vector<u8>, needle: &vector<u8>): bool { find(hay, needle) < hay.length() }

/// Vị trí đầu tiên của `needle` trong `hay`, hoặc `hay.length()`.
fun find(hay: &vector<u8>, needle: &vector<u8>): u64 {
    let (h, n) = (hay.length(), needle.length());
    if (n == 0 || n > h) return h;
    let mut i = 0;
    while (i + n <= h) {
        let mut j = 0;
        while (j < n && hay[i + j] == needle[j]) j = j + 1;
        if (j == n) return i;
        i = i + 1;
    };
    h
}

/// RFC 4648 §5, không padding (đúng cách WebAuthn mã hoá challenge).
public fun base64url(data: &vector<u8>): vector<u8> {
    let table = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = vector[];
    let (mut acc, mut bits, mut i) = (0u32, 0u8, 0);
    while (i < data.length()) {
        acc = (acc << 8) | (data[i] as u32);
        bits = bits + 8;
        while (bits >= 6) {
            bits = bits - 6;
            out.push_back(table[((acc >> bits) & 63) as u64]);
        };
        acc = acc & ((1u32 << bits) - 1);
        i = i + 1;
    };
    if (bits > 0) out.push_back(table[((acc << (6 - bits)) & 63) as u64]);
    out
}

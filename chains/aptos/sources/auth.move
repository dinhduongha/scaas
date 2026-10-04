/// Chữ ký của chủ thể trên một digest 32 byte (R30/R31, spec §4.2). Hai lược đồ, chọn theo độ dài khoá:
/// - ed25519 (32 byte): ví ký `fullMessage` của Wallet Standard `aptos:signMessage`; `envelope` = `fullMessage`.
///   Phong bì parse chặt: dòng đầu `APTOS`; mỗi dòng sau `<khoá>: <giá trị>`, khoá ∈ {address, application, chainId,
///   message, nonce}, mỗi khoá tối đa một lần; `message` đúng một lần và bằng `<nhãn>:0x<hex digest>`; `chainId` nếu
///   có thì bằng chain id on-chain; Account có origin ⇒ `application` bắt buộc và ∈ origins (review M1: trang lừa
///   xin ký rồi tự nộp thẳng, không qua Odoo).
/// - WebAuthn P-256 (65 byte `0x04‖x‖y`, AnyPublicKey biến thể 2 của AIP-66): `envelope` = `u16be(len ad) ‖ ad ‖
///   clientDataJSON`; challenge = base64url(digest), type `webauthn.get`, origin ∈ origins của Account, không
///   `crossOrigin: true`/`topOrigin` (iframe khác origin — review L1), rpIdHash của khoá, UP+UV, P-256 low-s (`bamboo::p256`, UNAUDITED) trên `sha256(ad ‖ sha256(clientDataJSON))`.
module bamboo::auth {
    use std::hash::{sha2_256, sha3_256};
    use bamboo::p256;
    use aptos_std::ed25519;

    const ED25519: u8 = 0;
    const WEBAUTHN: u8 = 2;
    const NONE: u8 = 255;

    public fun ed25519(): u8 { ED25519 }

    public fun webauthn(): u8 { WEBAUTHN }

    /// Lược đồ theo độ dài khoá; `NONE` nếu không nhận.
    public fun scheme_of(pk: &vector<u8>): u8 {
        let n = pk.length();
        if (n == 32) ED25519 else if (n == 65 && pk[0] == 4) WEBAUTHN else NONE
    }

    /// Khoá `pk` dẫn ra đúng `auth_key` (= `account::get_authentication_key(owner)`, bằng `bcs(owner)` với tài
    /// khoản stateless — AIP-115): ed25519 legacy `sha3(pk‖0x00)`, SingleKey ed25519 `sha3(0x00‖0x20‖pk‖0x02)`,
    /// SingleKey WebAuthn `sha3(0x02‖0x41‖pk‖0x02)` (AIP-55/AIP-66).
    public fun proves(auth_key: &vector<u8>, pk: &vector<u8>): bool {
        let s = scheme_of(pk);
        if (s == ED25519) {
            let legacy = *pk;
            legacy.push_back(0);
            if (sha3_256(legacy) == *auth_key) return true;
            let single = vector[0u8, 32];
            single.append(*pk);
            single.push_back(2);
            sha3_256(single) == *auth_key
        } else if (s == WEBAUTHN) {
            let single = vector[2u8, 65];
            single.append(*pk);
            single.push_back(2);
            sha3_256(single) == *auth_key
        } else false
    }

    /// `<nhãn>:0x<64 hex chữ thường>` — đúng chuỗi `message` mà ví ký.
    public fun expected_message(label: vector<u8>, digest: &vector<u8>): vector<u8> {
        let out = label;
        out.append(b":0x");
        let hexd = b"0123456789abcdef";
        let i = 0;
        while (i < digest.length()) {
            let b = digest[i];
            out.push_back(hexd[((b >> 4) as u64)]);
            out.push_back(hexd[((b & 15) as u64)]);
            i += 1;
        };
        out
    }

    /// Một chữ ký của khoá `pk` trên `digest`. `rp_id_hash`/`origins`/`table` chỉ dùng cho WebAuthn; `table` =
    /// `p256::table(pk)` lưu lúc đăng ký khoá (rỗng ⇒ tính tại chỗ).
    public fun verify(
        pk: &vector<u8>,
        label: vector<u8>,
        digest: &vector<u8>,
        sig: &vector<u8>,
        envelope: &vector<u8>,
        rp_id_hash: &vector<u8>,
        origins: &vector<vector<u8>>,
        table: &vector<u256>,
        chain_id: u8,
    ): bool {
        if (sig.length() != 64 || digest.length() != 32) return false;
        let s = scheme_of(pk);
        if (s == ED25519) {
            if (!check_envelope(envelope, &expected_message(label, digest), chain_id, origins)) return false;
            return ed25519::signature_verify_strict(
                &ed25519::new_signature_from_bytes(*sig),
                &ed25519::new_unvalidated_public_key_from_bytes(*pk),
                *envelope,
            )
        };
        if (s != WEBAUTHN) return false;
        let (ok, ad, cd) = webauthn_parts(envelope);
        if (!ok || ad.length() < 37 || rp_id_hash.length() != 32) return false;
        let i = 0;
        while (i < 32) {
            if (ad[i] != rp_id_hash[i]) return false;
            i += 1;
        };
        if (ad[32] & 5 != 5) return false;
        // So chuỗi con an toàn: trình duyệt escape `"` trong mọi giá trị chuỗi nên needle không lọt vào giá trị.
        if (!contains(&cd, &b"\"type\":\"webauthn.get\"")) return false;
        if (contains(&cd, &b"\"crossOrigin\":true") || contains(&cd, &b"\"topOrigin\"")) return false;
        let ch = b"\"challenge\":\"";
        ch.append(base64url(digest));
        ch.push_back(34);
        if (!contains(&cd, &ch)) return false;
        let origin = origin_of(&cd);
        if (origin.is_empty() || !origins.contains(&origin)) return false;
        let msg = ad;
        msg.append(sha2_256(cd));
        if (table.is_empty()) p256::verify(pk, &sha2_256(msg), sig) else p256::verify_with(table, &sha2_256(msg), sig)
    }

    /// Phong bì `aptos:signMessage` (spec §4.2). Không phụ thuộc thứ tự dòng. `origins` khác rỗng ⇒ dòng
    /// `application` bắt buộc và giá trị ∈ `origins`.
    public fun check_envelope(full: &vector<u8>, message: &vector<u8>, chain_id: u8, origins: &vector<vector<u8>>): bool {
        let lines = split(full, 10);
        if (lines.length() < 2 || lines[0] != b"APTOS") return false;
        let seen = vector[false, false, false, false, false];
        let keys = vector[b"address", b"application", b"chainId", b"message", b"nonce"];
        let i = 1;
        while (i < lines.length()) {
            let line = &lines[i];
            let (k, found) = (0, false);
            while (k < 5 && !found) {
                let prefix = keys[k];
                prefix.append(b": ");
                if (starts_with(line, &prefix)) {
                    found = true;
                    if (seen[k]) return false;
                    *seen.borrow_mut(k) = true;
                    let value = slice(line, prefix.length(), line.length());
                    if (k == 3 && value != *message) return false;
                    if (k == 2 && value != decimal(chain_id)) return false;
                    if (k == 1 && !origins.is_empty() && !origins.contains(&value)) return false;
                } else k += 1;
            };
            if (!found) return false;
            i += 1;
        };
        seen[3] && (origins.is_empty() || seen[1])
    }

    /// `(ok, authenticatorData, clientDataJSON)` từ `u16be(len ad) ‖ ad ‖ cd`.
    public fun webauthn_parts(envelope: &vector<u8>): (bool, vector<u8>, vector<u8>) {
        let n = envelope.length();
        if (n < 2) return (false, vector[], vector[]);
        let len = ((envelope[0] as u64) << 8) | (envelope[1] as u64);
        if (2 + len > n) return (false, vector[], vector[]);
        (true, slice(envelope, 2, 2 + len), slice(envelope, 2 + len, n))
    }

    /// rpIdHash và origin của một assertion (mở Account lười bằng passkey: lấy từ chính assertion đã ký).
    public fun webauthn_origin(envelope: &vector<u8>): (vector<u8>, vector<u8>) {
        let (ok, ad, cd) = webauthn_parts(envelope);
        if (!ok || ad.length() < 32) return (vector[], vector[]);
        (slice(&ad, 0, 32), origin_of(&cd))
    }

    /// `"origin":"…"` trong clientDataJSON, rỗng nếu không có.
    public fun origin_of(cd: &vector<u8>): vector<u8> {
        let key = b"\"origin\":\"";
        let start = find(cd, &key);
        if (start == cd.length()) return vector[];
        let i = start + key.length();
        let out = vector[];
        while (i < cd.length() && cd[i] != 34) {
            out.push_back(cd[i]);
            i += 1;
        };
        if (i == cd.length()) vector[] else out
    }

    /// RFC 4648 §5, không padding (cách WebAuthn mã hoá challenge).
    public fun base64url(data: &vector<u8>): vector<u8> {
        let table = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let out = vector[];
        let (acc, bits, i) = (0u32, 0u8, 0);
        while (i < data.length()) {
            acc = (acc << 8) | (data[i] as u32);
            bits += 8;
            while (bits >= 6) {
                bits -= 6;
                out.push_back(table[(((acc >> bits) & 63) as u64)]);
            };
            acc &= (1u32 << bits) - 1;
            i += 1;
        };
        if (bits > 0) out.push_back(table[(((acc << (6 - bits)) & 63) as u64)]);
        out
    }

    fun decimal(v: u8): vector<u8> {
        if (v == 0) return b"0";
        let out = vector[];
        while (v > 0) {
            out.insert(0, 48 + v % 10);
            v /= 10;
        };
        out
    }

    fun split(b: &vector<u8>, sep: u8): vector<vector<u8>> {
        let (out, cur, i) = (vector[], vector[], 0);
        while (i < b.length()) {
            if (b[i] == sep) {
                out.push_back(cur);
                cur = vector[];
            } else cur.push_back(b[i]);
            i += 1;
        };
        out.push_back(cur);
        out
    }

    fun starts_with(b: &vector<u8>, p: &vector<u8>): bool {
        if (p.length() > b.length()) return false;
        let i = 0;
        while (i < p.length()) {
            if (b[i] != p[i]) return false;
            i += 1;
        };
        true
    }

    fun slice(b: &vector<u8>, from: u64, to: u64): vector<u8> {
        let (out, i) = (vector[], from);
        while (i < to) {
            out.push_back(b[i]);
            i += 1;
        };
        out
    }

    fun contains(hay: &vector<u8>, needle: &vector<u8>): bool { find(hay, needle) < hay.length() }

    /// Vị trí đầu tiên của `needle` trong `hay`, hoặc `hay.length()`.
    fun find(hay: &vector<u8>, needle: &vector<u8>): u64 {
        let (h, n) = (hay.length(), needle.length());
        if (n == 0 || n > h) return h;
        let i = 0;
        while (i + n <= h) {
            let j = 0;
            while (j < n && hay[i + j] == needle[j]) j += 1;
            if (j == n) return i;
            i += 1;
        };
        h
    }

    #[test]
    fun envelope_rules() {
        let m = b"bamboo.metaop.v1:0xab";
        assert!(check_envelope(&b"APTOS\nmessage: bamboo.metaop.v1:0xab\nnonce: 01", &m, 4, &vector[]), 0);
        // order does not matter; every known key once
        assert!(check_envelope(&b"APTOS\nnonce: 01\nchainId: 4\napplication: https://pay.test\nmessage: bamboo.metaop.v1:0xab\naddress: 0x1", &m, 4, &vector[]), 1);
        // a second message line (phishing page asked to sign "...\nmessage: <ours>")
        assert!(!check_envelope(&b"APTOS\nmessage: hello\nmessage: bamboo.metaop.v1:0xab", &m, 4, &vector[]), 2);
        assert!(!check_envelope(&b"APTOS\nmessage: bamboo.metaop.v1:0xab\nmessage: bamboo.metaop.v1:0xab", &m, 4, &vector[]), 3);
        // unknown key, wrong chain, missing message, wrong prefix, trailing newline
        assert!(!check_envelope(&b"APTOS\nmessage: bamboo.metaop.v1:0xab\nfoo: 1", &m, 4, &vector[]), 4);
        assert!(!check_envelope(&b"APTOS\nmessage: bamboo.metaop.v1:0xab\nchainId: 1", &m, 4, &vector[]), 5);
        assert!(!check_envelope(&b"APTOS\nnonce: 1", &m, 4, &vector[]), 6);
        assert!(!check_envelope(&b"APTOSX\nmessage: bamboo.metaop.v1:0xab", &m, 4, &vector[]), 7);
        assert!(!check_envelope(&b"APTOS\nmessage: bamboo.metaop.v1:0xab\n", &m, 4, &vector[]), 8);
        assert!(!check_envelope(&b"APTOS\nmessage: bamboo.metaop.v1:0xabc", &m, 4, &vector[]), 9);
        assert!(check_envelope(&b"APTOS\nchainId: 132\nmessage: bamboo.metaop.v1:0xab", &m, 132, &vector[]), 10);
        // origins set: `application` is required and must be one of them
        let o = vector[b"https://pay.test"];
        assert!(check_envelope(&b"APTOS\napplication: https://pay.test\nmessage: bamboo.metaop.v1:0xab", &m, 4, &o), 13);
        assert!(!check_envelope(&b"APTOS\napplication: https://evil.test\nmessage: bamboo.metaop.v1:0xab", &m, 4, &o), 14);
        assert!(!check_envelope(&b"APTOS\nmessage: bamboo.metaop.v1:0xab", &m, 4, &o), 15);
        assert!(expected_message(b"x", &x"00ff") == b"x:0x00ff", 11);
        assert!(base64url(&x"fbff") == b"-_8", 12);
    }
}

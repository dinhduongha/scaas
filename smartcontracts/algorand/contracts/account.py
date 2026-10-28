"""SCaaS `account` app on Algorand (near-algorand T12; spec §4.1, §4.3, §4.6; NET-ALL-04, CTR-ACC-03; R7).

One app per deployment holds every subject's record; tokens, mandate and DEX check signers by an inner call to `verify`
(synchronous), so keys are shared by every token. Subject = `Holder` (kind 0 a native address, 1 a UA id); a UA opens
lazily on its first signed op (the key must derive the id, kinds.json), the relayer paying the record's MBR; a native
address signs with its current authority (64-byte wallet signature, `common.verify_native`), or — rekeyed to a LogicSig
or a multisig, which has no ed25519 key — with keys it registered (`add_key_native`, sender = the address).

Record box `"s" ‖ kind ‖ id` (34 B name), rewritten at its new size (the relayer pays exactly the growth, §2 row 15; a
shrink refunds nothing):

    0 key_nonce u64 ‖ 8 policy u8 ‖ 9 n_pk u8 ‖ 10 guardian (kind u8 ‖ id 32; zero = none) ‖ 43 recovery ready_at u64
    (0 = none) ‖ 51 recovery key id 32 ‖ 83 recovery key needs an origin u8 ‖ 84 recovery origin sha256 32 (zero = none)
    ‖ 116 n_keys u8 ‖ 117 n_origins u8 ‖ 118 keys n_keys × 32 ‖ origins n_origins × 32

A key is held as its UA id `UA(kind, keyData)` (the auth carries the key; the id binds kind, key data and a passkey's
rpIdHash), an origin as its sha256; `n_pk` counts the keys that sign only from a listed origin (passkeys, msigs with a
passkey member).

`auth: byte[]` = a native holder's 64-byte wallet signature, else `tag ‖ body`:
    1 ed25519    pk 32 ‖ sig 64 over "MX" ‖ text (the wallet sign-bytes form, §4.6)
    2 secp256k1  x ‖ y 64 ‖ r ‖ s 64: ecdsa_verify Secp256k1 over the digest, low s
    3 passkey    x ‖ y 64 ‖ r ‖ s 64 ‖ u16 n ‖ authenticatorData (n) ‖ clientDataJSON (the rest): NET-ALL-04 over
                 challenge = b64url(digest), ecdsa_verify Secp256r1 over sha256(authData ‖ sha256(clientDataJSON)), low s
    4 msig       u16 n ‖ keyData (n) ‖ (u8 member index ‖ u16 len ‖ member auth)*, indexes strictly increasing; a
                 member auth is a 64-byte signature by an algorand-address member's current authority, else tag 1–3

Key ops (op codes 6–12, the shared table): amount 0, pay_ref / lane zero, nonce = the signer's key nonce (consumed),
`contract` = this app's address, to = from (start / finish recovery: from = the guardian, to = the subject),
`extra = sha256(ARC-4(entry parameters after (op, auth)))`; set_policy and finish_recovery are actions under op codes 10
and 11 with signed parameters `[6, policy]` / `[7]` (as NEAR). No local state (OptIn refused); Update / Delete refused.
"""
from algopy import (Account, BigUInt, Bytes, Global, OpUpFeeSource, String, Txn, UInt64, arc4, ensure_budget, op,
                    subroutine, urange)

from common import (COST_ENTRY, COST_NATIVE, TAIL, KIND_ADDRESS, KIND_UA, OP_ADD_KEY, OP_ADD_ORIGIN, OP_CANCEL_RECOVERY, OP_REMOVE_KEY,
                    OP_REMOVE_ORIGIN, OP_SET_GUARDIAN, OP_START_RECOVERY, Bytes32, Holder, MetaOp, check_envelope,
                    authority, digest, mbr_paid, sign_bytes, verify_native, zero)

MAX_KEYS = 8
MAX_ORIGINS = 8
MAX_ORIGIN_LEN = 128
RECOVERY_DELAY_S = 172_800
POLICY_PASSKEY_FOR_VALUE = 1
KEYOP_SET_POLICY = 6
KEYOP_FINISH_RECOVERY = 7
# Members per msig (T12 fixes 1-2, Ruling T12-budget): min(the 2,048 B app-call argument bound, the budget bound of
# every group shape), so that a registered msig always signs at its full threshold with real browser assertions. With
# inner budget calls (pooled 256 per group) the budget never binds; the arguments do: the lazily opening all-passkey
# n-of-n mtx_add_key with Chrome-shaped assertions (its extra member, a 64 B origin: 286 B clientDataJSON) takes
# 1,823 B at 3 members, 2,316 B at 4 (runs/2026-10-28-algorand-limits.txt).
MSIG_MAX_MEMBERS = 3
PASSKEY_FIELD_MAX = 1024
# signature costs ensured before each check (common.TAIL added); a passkey's also grows with its clientDataJSON
COST_SECP256K1 = 2000
COST_PASSKEY = 3300
COST_PASSKEY_PER_BYTE = 3  # clientDataJSON / authenticatorData (budget bound, as NEAR's PASSKEY_FIELD_MAX)

KIND_ALGORAND_ADDRESS = 0x0018
KIND_WEBAUTHN_P256 = 0x0100
KIND_ED25519 = 0x0102
KIND_SECP256K1 = 0x0108
KIND_MSIG = 0x0120
# kinds.json TAG = keccak256(tag string)
TAG_P256 = b"\x28\x60\x27\xcc\xb5\xbc\xb7\xd6\xcb\x87\x72\xd1\x46\xe6\xdb\x32\x49\xce\x90\x7b\x77\xce\x28\xdd\xc3\x55\x76\x16\x9b\xd4\x9d\xa0"
TAG_ED25519 = b"\x65\xca\x73\xd2\xd2\x90\x50\x3a\x47\x85\x18\x87\x12\xdd\x0b\x97\x1b\x5f\xbf\x31\x13\xc1\xdc\x87\x18\x5a\x46\x02\x1b\x51\x31\xbc"
TAG_SECP256K1 = b"\x98\x52\x18\x57\xbc\xe4\xe5\x83\x0d\x7d\x08\x4b\x5d\x6b\xae\x9b\x6b\x59\x53\x7e\xf7\xe8\xdb\x7a\x57\xc3\x27\xbf\x52\x4a\x6d\xe9"
TAG_MSIG = b"\x0c\x74\xd8\x92\x36\xd9\x33\x51\xf7\x2b\xa0\x9e\x86\x36\x3f\x0c\xe9\x77\xca\x1f\x49\x2e\xa2\x4e\xbf\x63\x14\x23\x11\x57\xfd\xd4"
HALF_N_P256 = 0x7FFFFFFF800000007FFFFFFFFFFFFFFFDE737D56D38BCF4279DCE5617E3192A8

AUTH_ED25519 = 1
AUTH_SECP256K1 = 2
AUTH_PASSKEY = 3
AUTH_MSIG = 4

O_POLICY = 8
O_NPK = 9
O_GUARDIAN = 10
O_READY = 43
O_RKEY = 51
O_RPK = 83
O_RORIGIN = 84
O_NKEYS = 116
O_NORIGINS = 117
HEADER = 118
RECOVERY_LEN = 73  # ready_at ‖ key id ‖ needs origin ‖ origin hash

CD_TYPE = b'{"type":"webauthn.get","challenge":"'
CD_ORIGIN = b'","origin":"'
CD_CROSS = b',"crossOrigin":false'


class KeyRecord(arc4.Struct, frozen=True):
    kind: arc4.UInt16
    key_data: arc4.DynamicBytes


class AccountApp(arc4.ARC4Contract, name="Account"):
    @arc4.abimethod(create="require")
    def create(self) -> None:
        pass

    @arc4.baremethod(allow_actions=["NoOp"])
    def budget(self) -> None:
        """Opcode budget for the group (700 per app call, pooled); the relayer adds these as simulate reports."""

    # ------------------------------------------------------------ for tokens, mandate, DEX
    @arc4.abimethod
    def verify(self, holder_kind: arc4.UInt8, holder: Bytes32, digest: Bytes32, auth: Bytes) -> bool:
        """`auth` signs `digest` for the holder, for a value op: a record-key signature obeys POLICY_PASSKEY_FOR_VALUE
        (a native wallet signature is the address's own authority, like a direct ARC-200 transfer). An unknown UA's
        record is opened (exact-MBR payment just before this call, forwarded by the calling token). Fails otherwise."""
        before = Global.current_application_address.min_balance
        ensure_budget(COST_ENTRY, OpUpFeeSource.GroupCredit)
        h = Holder(holder_kind, holder)
        rec, opened = value_signed(h, digest, auth)
        if opened:
            put(h, rec)
        mbr_paid(before, UInt64(0))
        return True

    @arc4.abimethod(readonly=True)
    def verify_mbr(self, holder_kind: arc4.UInt8, holder: Bytes32, digest: Bytes32, auth: Bytes) -> UInt64:
        """`verify`'s checks, no write: the MBR its lazy open needs (0 when the record exists)."""
        _rec, opened = value_signed(Holder(holder_kind, holder), digest, auth)
        return box_mbr(_rec.length) if opened else UInt64(0)

    @arc4.abimethod(readonly=True)
    def key_nonce(self, holder_kind: arc4.UInt8, holder: Bytes32) -> UInt64:
        rec, exists = op.Box.get(rec_name(Holder(holder_kind, holder)))
        return op.extract_uint64(rec, 0) if exists else UInt64(0)

    # ------------------------------------------------------------ key ops (op codes 6–12)
    @arc4.abimethod
    def mtx_add_key(self, op_: MetaOp, auth: Bytes, key: KeyRecord, origin: arc4.DynamicBytes) -> None:
        before = Global.current_application_address.min_balance
        rec = own(op_, auth, UInt64(OP_ADD_KEY), arc4.Tuple((key, origin)).bytes)
        kid, needs = key_info(key.kind.as_uint64(), key.key_data.native)
        rec = with_key(rec, kid, needs)
        if origin.native.length:
            rec = with_origin(rec, origin_hash(origin.native))
        save(op_.from_, rec, String("add_key"))
        mbr_paid(before, UInt64(0))

    @arc4.abimethod
    def mtx_remove_key(self, op_: MetaOp, auth: Bytes, key: KeyRecord) -> None:
        before = Global.current_application_address.min_balance
        rec = own(op_, auth, UInt64(OP_REMOVE_KEY), arc4.Tuple((key,)).bytes)
        kid, needs = key_info(key.kind.as_uint64(), key.key_data.native)
        save(op_.from_, without(rec, kid, needs), String("remove_key"))
        mbr_paid(before, UInt64(0))

    @arc4.abimethod
    def mtx_add_origin(self, op_: MetaOp, auth: Bytes, origin: arc4.DynamicBytes) -> None:
        before = Global.current_application_address.min_balance
        rec = own(op_, auth, UInt64(OP_ADD_ORIGIN), arc4.Tuple((origin,)).bytes)
        save(op_.from_, with_origin(rec, origin_hash(origin.native)), String("add_origin"))
        mbr_paid(before, UInt64(0))

    @arc4.abimethod
    def mtx_remove_origin(self, op_: MetaOp, auth: Bytes, origin: arc4.DynamicBytes) -> None:
        before = Global.current_application_address.min_balance
        rec = own(op_, auth, UInt64(OP_REMOVE_ORIGIN), arc4.Tuple((origin,)).bytes)
        save(op_.from_, without_origin(rec, origin_hash(origin.native)), String("remove_origin"))
        mbr_paid(before, UInt64(0))

    @arc4.abimethod
    def mtx_set_guardian(self, op_: MetaOp, auth: Bytes, guardian: Holder) -> None:
        """`guardian` zero (kind 0, zero id) = none; any change cancels a pending recovery (CTR-ACC-03)."""
        before = Global.current_application_address.min_balance
        rec = own(op_, auth, UInt64(OP_SET_GUARDIAN), guardian.bytes)
        assert guardian.kind.as_uint64() <= KIND_UA, "unknown holder kind"
        assert guardian.bytes != op_.from_.bytes, "a subject is not its own guardian"
        rec = op.replace(op.replace(rec, O_GUARDIAN, guardian.bytes), O_READY, op.bzero(RECOVERY_LEN))
        save(op_.from_, rec, String("set_guardian"))
        mbr_paid(before, UInt64(0))

    @arc4.abimethod
    def mtx_set_policy(self, op_: MetaOp, auth: Bytes, policy: arc4.UInt8) -> None:
        """The set_policy action (op code 10, signed parameters `[6, policy]`); any current key may sign it."""
        before = Global.current_application_address.min_balance
        rec = own(op_, auth, UInt64(OP_SET_GUARDIAN), Bytes(b"\x06") + policy.bytes)
        assert policy.as_uint64() & ~UInt64(POLICY_PASSKEY_FOR_VALUE) == 0, "unknown policy bit"
        save(op_.from_, op.setbyte(rec, O_POLICY, policy.as_uint64()), String("set_policy"))
        mbr_paid(before, UInt64(0))

    @arc4.abimethod
    def mtx_start_recovery(self, op_: MetaOp, auth: Bytes, key: KeyRecord, origin: arc4.DynamicBytes) -> None:
        """Signed by the guardian (`op.from`), `op.to` = the subject: `key` (and `origin`) are added by the guardian's
        `mtx_finish_recovery` after RECOVERY_DELAY_S unless a current key cancels or the guardian changes first. A key
        already present or a full key set is refused now (fail fast: keep a slot free)."""
        before = Global.current_application_address.min_balance
        t = guarded(op_)
        signer = signed_key_op(op_, auth, UInt64(OP_START_RECOVERY), arc4.Tuple((key, origin)).bytes)
        kid, needs = key_info(key.kind.as_uint64(), key.key_data.native)
        oh = zero()
        after = with_key(t, kid, needs)
        if origin.native.length:
            oh = origin_hash(origin.native)
            after = with_origin(after, oh)
        usable(after, op_.to)
        t = op.replace(t, O_READY, op.itob(Global.latest_timestamp + RECOVERY_DELAY_S) + kid.bytes
                       + op.extract(op.itob(UInt64(1) if needs else UInt64(0)), 7, 1) + oh.bytes)
        put(op_.from_, signer)
        save(op_.to, t, String("start_recovery"))
        mbr_paid(before, UInt64(0))

    @arc4.abimethod
    def mtx_finish_recovery(self, op_: MetaOp, auth: Bytes) -> None:
        """Signed by the guardian once the delay is over (op code 11, signed parameters `[7]`): the recovery key is
        added and none removed (CTR-ACC-03); the subject's key nonce moves on (ops signed before are void)."""
        before = Global.current_application_address.min_balance
        t = guarded(op_)
        signer = signed_key_op(op_, auth, UInt64(OP_START_RECOVERY), Bytes(b"\x07"))
        ready = op.extract_uint64(t, O_READY)
        assert ready != 0, "no recovery pending"
        assert Global.latest_timestamp >= ready, "recovery delay (172,800 s) not over"
        t = with_key(t, Bytes32.from_bytes(op.extract(t, O_RKEY, 32)), op.getbyte(t, O_RPK) != 0)
        oh = op.extract(t, O_RORIGIN, 32)
        if oh != zero().bytes:
            t = with_origin(t, Bytes32.from_bytes(oh))
        t = op.replace(op.replace(t, O_READY, op.bzero(RECOVERY_LEN)), 0, op.itob(op.extract_uint64(t, 0) + 1))
        put(op_.from_, signer)
        save(op_.to, t, String("finish_recovery"))
        mbr_paid(before, UInt64(0))

    @arc4.abimethod
    def mtx_cancel_recovery(self, op_: MetaOp, auth: Bytes) -> None:
        before = Global.current_application_address.min_balance
        rec = own(op_, auth, UInt64(OP_CANCEL_RECOVERY), Bytes())
        assert op.extract_uint64(rec, O_READY) != 0, "no recovery pending"
        save(op_.from_, op.replace(rec, O_READY, op.bzero(RECOVERY_LEN)), String("cancel_recovery"))
        mbr_paid(before, UInt64(0))

    @arc4.abimethod
    def add_key_native(self, key: KeyRecord, origin: arc4.DynamicBytes) -> None:
        """The sender (a native address, whatever its authority: key, LogicSig or multisig) adds a key directly."""
        before = Global.current_application_address.min_balance
        h = Holder(arc4.UInt8(KIND_ADDRESS), Bytes32.from_bytes(Txn.sender.bytes))
        rec, exists = op.Box.get(rec_name(h))
        if not exists:
            rec = op.bzero(HEADER)
        kid, needs = key_info(key.kind.as_uint64(), key.key_data.native)
        rec = with_key(rec, kid, needs)
        if origin.native.length:
            rec = with_origin(rec, origin_hash(origin.native))
        save(h, rec, String("add_key_native"))
        mbr_paid(before, UInt64(0))


# ---------------------------------------------------------------- signed ops
@subroutine
def signed_key_op(o: MetaOp, auth: Bytes, code: UInt64, params: Bytes) -> Bytes:
    """A key op's shape, envelope and signature; the signer's record with its key nonce consumed."""
    ensure_budget(COST_ENTRY, OpUpFeeSource.GroupCredit)
    assert o.op.as_uint64() == code and o.amount.as_biguint() == 0 and o.pay_ref == zero() and o.lane == zero(), \
        "key op shape (op code, amount 0, pay_ref and lane zero)"
    assert o.extra.bytes == op.sha256(params), "extra is not sha256 of the parameters"
    check_envelope(o)
    rec, _opened, _mode = signed(o.from_, digest(o), auth)
    nonce = op.extract_uint64(rec, 0)
    assert nonce == o.nonce.as_uint64(), "wrong key nonce"
    return op.replace(rec, 0, op.itob(nonce + 1))


@subroutine
def own(o: MetaOp, auth: Bytes, code: UInt64, params: Bytes) -> Bytes:
    rec = signed_key_op(o, auth, code, params)
    assert o.to.bytes == o.from_.bytes, "to must be the subject"
    return rec


@subroutine
def guarded(o: MetaOp) -> Bytes:
    """Recovery: `op.to`'s record, whose guardian (set: the zero holder means none) is the signer `op.from`."""
    assert o.to.bytes != o.from_.bytes, "a subject is not its own guardian"
    t, exists = op.Box.get(rec_name(o.to))
    assert exists, "no such subject"
    g = op.extract(t, O_GUARDIAN, 33)
    assert g != op.bzero(33), "no guardian"
    assert g == o.from_.bytes, "not the subject's guardian"
    return t


@subroutine
def value_signed(h: Holder, d: Bytes32, auth: Bytes) -> tuple[Bytes, bool]:
    """`signed` for a value op: POLICY_PASSKEY_FOR_VALUE binds every record-key signature (NET-ALL-23 item 3)."""
    rec, opened, mode = signed(h, d, auth)
    if op.getbyte(rec, O_POLICY) & POLICY_PASSKEY_FOR_VALUE:
        assert mode != 1, "POLICY_PASSKEY_FOR_VALUE: value ops need a passkey signature"
    return rec, opened


@subroutine
def signed(h: Holder, d: Bytes32, auth: Bytes) -> tuple[Bytes, bool, UInt64]:
    """`auth` signs `d` for `h`: (the record — stored, or new for a lazy UA open or a native address's first key op;
    opened = a new UA record; mode 0 native wallet signature, 1 a record key, 2 a passkey or an all-passkey msig)."""
    rec, exists = op.Box.get(rec_name(h))
    if h.kind.as_uint64() == KIND_ADDRESS and auth.length == 64:
        assert verify_native(Account(h.id.bytes), d, auth), "bad signature"
        if not exists:
            rec = op.bzero(HEADER)
        return rec, False, UInt64(0)
    lazy = not exists
    if lazy:
        assert h.kind.as_uint64() == KIND_UA, "no SCaaS key: an address signs with its wallet key or keys it added"
        rec = op.bzero(HEADER)
    assert auth.length > 0, "empty auth"
    mode = UInt64(1)
    if op.getbyte(auth, 0) == AUTH_MSIG:
        kd = op.extract(auth, 3, op.extract_uint16(auth, 1))
        kid, needs = key_info(UInt64(KIND_MSIG), kd)
        rec, all_pk = msig_ok(kd, auth, d, rec, lazy)
        if all_pk:
            mode = UInt64(2)
    else:
        rec, kind, kid, needs = leaf_ok(auth, d, rec, lazy)
        if kind == KIND_WEBAUTHN_P256:
            mode = UInt64(2)
    if lazy:
        assert kid == h.id, "the key does not derive the UA id"
        assert derived(kid.bytes), "UA id in the native space (CTR-UA-03)"
        rec = with_key(rec, kid, needs)
        usable(rec, h)
    else:
        assert has(rec, UInt64(HEADER), n_keys(rec), kid.bytes), "not a key of the subject"
    return rec, lazy, mode


@subroutine
def leaf_ok(auth: Bytes, d: Bytes32, rec: Bytes, lazy: bool) -> tuple[Bytes, UInt64, Bytes32, bool]:
    """One single-key signature (tags 1–3) over `d` → (`rec`, the key's kind, its UA id, it needs an origin). A
    passkey's origin must be one `rec` lists — or, `lazy` (a record being opened), is added to it."""
    tag = op.getbyte(auth, 0)
    if tag == AUTH_ED25519:
        assert auth.length == 97, "ed25519 auth length"
        pk = op.extract(auth, 1, 32)
        ensure_budget(COST_NATIVE + TAIL, OpUpFeeSource.GroupCredit)
        assert op.ed25519verify_bare(sign_bytes(d), op.extract(auth, 33, 64), pk), "ed25519 signature"
        return rec, UInt64(KIND_ED25519), ua_of(UInt64(KIND_ED25519), pk), False
    if tag == AUTH_SECP256K1:
        assert auth.length == 129, "secp256k1 auth length"
        # ecdsa_verify Secp256k1 accepts lower-S signatures only (libsecp256k1; test_high_s_refused)
        ensure_budget(COST_SECP256K1 + TAIL, OpUpFeeSource.GroupCredit)
        assert op.ecdsa_verify(op.ECDSA.Secp256k1, d.bytes, op.extract(auth, 65, 32), op.extract(auth, 97, 32),
                               op.extract(auth, 1, 32), op.extract(auth, 33, 32)), "secp256k1 signature (low s)"
        return rec, UInt64(KIND_SECP256K1), ua_of(UInt64(KIND_SECP256K1), op.extract(auth, 1, 64)), False
    assert tag == AUTH_PASSKEY, "unknown auth tag"
    assert auth.length >= 131, "passkey auth length"
    n = op.extract_uint16(auth, 129)
    ad = op.extract(auth, 131, n)
    cd = op.substring(auth, 131 + n, auth.length)
    assert ad.length <= PASSKEY_FIELD_MAX and cd.length <= PASSKEY_FIELD_MAX, \
        "passkey clientDataJSON / authenticatorData over 1024 bytes"
    ensure_budget(COST_PASSKEY + COST_PASSKEY_PER_BYTE * cd.length + TAIL, OpUpFeeSource.GroupCredit)
    # NET-ALL-04 order: authenticatorData ≥ 37 B, rpIdHash (bound by the key id below), UP and UV, the grammar, the
    # origin listed, low s, the signature
    assert ad.length >= 37 and op.getbyte(ad, 32) & 5 == 5, "passkey authenticatorData (rpIdHash or UP / UV flags)"
    oh = Bytes32.from_bytes(op.sha256(client_origin(cd, d)))
    if lazy:
        rec = with_origin(rec, oh)
    else:
        assert has(rec, origins_at(rec), n_origins(rec), oh.bytes), "passkey origin not listed"
    s = op.extract(auth, 97, 32)
    assert BigUInt.from_bytes(s) <= HALF_N_P256, "passkey signature high s"
    assert op.ecdsa_verify(op.ECDSA.Secp256r1, op.sha256(ad + op.sha256(cd)), op.extract(auth, 65, 32), s,
                           op.extract(auth, 1, 32), op.extract(auth, 33, 32)), "passkey signature"
    return rec, UInt64(KIND_WEBAUTHN_P256), ua_of(UInt64(KIND_WEBAUTHN_P256), op.extract(auth, 1, 64)
                                                  + op.extract(ad, 0, 32)), True


@subroutine
def client_origin(cd: Bytes, d: Bytes32) -> Bytes:
    """NET-ALL-04 item 4, the bounded parse (as NEAR `webauthn::origin_of`): `{"type":"webauthn.get","challenge":"`
    b64url(d) `","origin":"` origin `"` then `}` (end), or `,"crossOrigin":false` then `}` (end) or `,` … `}` (end)
    with no `"topOrigin"` / `"crossOrigin"` after; no whitespace, no member before crossOrigin, no `\\` in the origin.
    Returns the origin."""
    assert cd.length > 91 and op.extract(cd, 0, 36) == CD_TYPE and op.extract(cd, 79, 12) == CD_ORIGIN, \
        "passkey clientDataJSON (type, challenge or origin)"
    assert op.base64_decode(op.Base64.URLEncoding, op.extract(cd, 36, 43) + b"=") == d.bytes, \
        "passkey clientDataJSON (type, challenge or origin)"
    # the origin ends at the first `"`; no `\\` before it. 8 bytes per step (SWAR: a word holds byte b iff
    # word ^ b…b has a zero byte), then byte-wise in the word that holds one
    padded = cd + op.bzero(8)
    i = UInt64(91)
    while True:
        assert i < cd.length and i <= 91 + MAX_ORIGIN_LEN, "passkey clientDataJSON (type, challenge or origin)"
        w = op.extract_uint64(padded, i)
        if zero_byte(w ^ 0x2222222222222222) or zero_byte(w ^ 0x5C5C5C5C5C5C5C5C):
            break
        i += 8
    while True:  # ends within this word (the padding holds neither byte)
        c = op.getbyte(padded, i)
        if c == 0x22:
            break
        assert c != 0x5C, "passkey clientDataJSON (type, challenge or origin)"
        i += 1
    assert i > 91 and i <= 91 + MAX_ORIGIN_LEN, "passkey clientDataJSON (type, challenge or origin)"
    t = op.substring(cd, i + 1, cd.length)
    if t != b"}" and t != CD_CROSS + b"}":
        n = t.length
        assert n > 22 and op.extract(t, 0, 21) == CD_CROSS + b"," and op.getbyte(t, n - 1) == 0x7D, \
            "passkey clientDataJSON (members after origin)"
        # every `"` after crossOrigin:false starts neither member name (8 bytes per step, as above)
        tp = t + op.bzero(8)
        for j in urange(20, n, 8):
            if zero_byte(op.extract_uint64(tp, j) ^ 0x2222222222222222):
                for k in urange(j, j + 8 if j + 8 < n else n):
                    if op.getbyte(t, k) == 0x22:
                        if k + 11 <= n:
                            assert op.extract(t, k, 11) != b'"topOrigin"', "passkey clientDataJSON (topOrigin)"
                        if k + 13 <= n:
                            assert op.extract(t, k, 13) != b'"crossOrigin"', "passkey clientDataJSON (crossOrigin)"
    return op.extract(cd, 91, i - 91)


@subroutine
def zero_byte(x: UInt64) -> bool:
    """`x` has a zero byte: (x − 0x01…01) & ~x & 0x80…80 ≠ 0 (the subtraction mod 2^64)."""
    _carry, low = op.addw(x, 0xFEFEFEFEFEFEFEFF)
    return (low & ~x & 0x8080808080808080) != 0


@subroutine
def msig_ok(kd: Bytes, auth: Bytes, d: Bytes32, rec: Bytes, lazy: bool) -> tuple[Bytes, bool]:
    """Msig member signatures (key data valid: `key_info`): an algorand-address member by its current authority, a
    key member by its own kind; weights summed against the threshold. A key counts for one member only (an address
    member's authority and an ed25519 member's key are the same kind of key). Returns (`rec`, every member a
    passkey)."""
    count = op.extract_uint16(kd, 2)
    seen = Bytes()
    weight = UInt64(0)
    first = UInt64(0)
    pos = 3 + kd.length
    while pos < auth.length:
        i = op.getbyte(auth, pos)
        a = op.extract(auth, pos + 3, op.extract_uint16(auth, pos + 1))
        pos += 3 + a.length
        assert i >= first, "msig signatures not in member order"
        first = i + 1
        assert i < count, "msig member index"
        o = 4 + 36 * i
        mkind = op.extract_uint16(kd, o)
        mid = op.extract(kd, o + 2, 32)
        if mkind == KIND_ALGORAND_ADDRESS:
            assert verify_native(Account(mid), d, a), "msig member signature"
            key = authority(Account(mid)).bytes
        else:
            assert a.length > 0 and op.getbyte(a, 0) != AUTH_MSIG, "msig inside msig"
            rec, lk, lid, _needs = leaf_ok(a, d, rec, lazy)
            assert lk == mkind and lid.bytes == mid, "msig member key mismatch"
            key = op.extract(a, 1, 32) if lk == KIND_ED25519 else lid.bytes
        assert not has(seen, UInt64(0), seen.length // 32, key), "msig member key repeated"
        seen += key
        weight += op.extract_uint16(kd, o + 34)
    assert weight >= op.extract_uint16(kd, 0), "msig threshold not met"
    all_pk = True
    for i in urange(count):
        if op.extract_uint16(kd, 4 + 36 * i) != KIND_WEBAUTHN_P256:
            all_pk = False
    return rec, all_pk


# ---------------------------------------------------------------- keys
@subroutine
def ua_of(kind: UInt64, kd: Bytes) -> Bytes32:
    """`UA(kind, keyData) = keccak256(TAG(kind) ‖ keyData)` (kinds.json)."""
    tag = Bytes(TAG_MSIG)
    if kind == KIND_ED25519:
        tag = Bytes(TAG_ED25519)
    elif kind == KIND_SECP256K1:
        tag = Bytes(TAG_SECP256K1)
    elif kind == KIND_WEBAUTHN_P256:
        tag = Bytes(TAG_P256)
    return Bytes32.from_bytes(op.keccak256(tag + kd))


@subroutine
def derived(x: Bytes) -> bool:
    """CTR-UA-03: a derived id has non-zero top 96 bits."""
    return op.extract(x, 0, 12) != op.bzero(12)


@subroutine
def key_info(kind: UInt64, kd: Bytes) -> tuple[Bytes32, bool]:
    """A key a subject may hold, validated (as NEAR `KeyRecord::validate`): (its UA id, it signs only from a listed
    origin)."""
    needs = False
    if kind == KIND_ED25519:
        assert kd.length == 32, "key data"
    elif kind == KIND_SECP256K1:
        assert kd.length == 64, "key data"
    elif kind == KIND_WEBAUTHN_P256:
        assert kd.length == 96, "key data"
        needs = True
    else:
        assert kind == KIND_MSIG, "key kind not accepted on Algorand"
        needs = msig_valid(kd)
    kid = ua_of(kind, kd)
    assert derived(kid.bytes), "UA id in the native space (CTR-UA-03)"
    return kid, needs


@subroutine
def msig_valid(kd: Bytes) -> bool:
    """`u16 threshold ‖ u16 count ‖ count × (u16 kind ‖ bytes32 id ‖ u16 weight)`, big-endian, ids strictly increasing;
    members algorand-address (0x0018) or a single-key kind verified here. Returns: a member is a passkey."""
    assert kd.length >= 4, "msig key data too short"
    count = op.extract_uint16(kd, 2)
    assert count >= 1 and count <= MSIG_MAX_MEMBERS, "msig member count out of range"
    assert kd.length == 4 + 36 * count, "msig key data length"
    total = UInt64(0)
    pk = False
    prev = BigUInt(0)
    for i in urange(count):
        o = 4 + 36 * i
        k = op.extract_uint16(kd, o)
        mid = op.extract(kd, o + 2, 32)
        if k == KIND_WEBAUTHN_P256:
            pk = True
        if k != KIND_ALGORAND_ADDRESS:
            assert (k == KIND_WEBAUTHN_P256 or k == KIND_ED25519 or k == KIND_SECP256K1) and derived(mid), \
                "msig member kind not accepted"
        w = op.extract_uint16(kd, o + 34)
        assert w > 0, "msig member weight 0"
        assert i == 0 or BigUInt.from_bytes(mid) > prev, "msig members not strictly increasing"
        prev = BigUInt.from_bytes(mid)
        total += w
    threshold = op.extract_uint16(kd, 0)
    assert threshold >= 1 and threshold <= total, "msig threshold out of range"
    return pk


# ---------------------------------------------------------------- records
@subroutine
def rec_name(h: Holder) -> Bytes:
    return b"s" + h.bytes


@subroutine
def box_mbr(n: UInt64) -> UInt64:
    """Protocol box MBR of a record of `n` bytes (name 34 B): 2,500 + 400 per name + value byte (µALGO)."""
    return 2500 + 400 * (34 + n)


@subroutine
def n_keys(rec: Bytes) -> UInt64:
    return op.getbyte(rec, O_NKEYS)


@subroutine
def n_origins(rec: Bytes) -> UInt64:
    return op.getbyte(rec, O_NORIGINS)


@subroutine
def origins_at(rec: Bytes) -> UInt64:
    return HEADER + 32 * n_keys(rec)


@subroutine
def find(rec: Bytes, at: UInt64, n: UInt64, x: Bytes) -> UInt64:
    """The index of `x` among the `n` 32-byte entries at `at`, or `n`."""
    for i in urange(n):
        if op.extract(rec, at + 32 * i, 32) == x:
            return i
    return n


@subroutine
def has(rec: Bytes, at: UInt64, n: UInt64, x: Bytes) -> bool:
    return find(rec, at, n, x) < n


@subroutine
def with_key(rec: Bytes, kid: Bytes32, needs: bool) -> Bytes:
    n = n_keys(rec)
    assert not has(rec, UInt64(HEADER), n, kid.bytes), "key already present"
    assert n < MAX_KEYS, "MAX_KEYS (8) reached"
    at = HEADER + 32 * n
    rec = op.extract(rec, 0, at) + kid.bytes + op.substring(rec, at, rec.length)
    rec = op.setbyte(rec, O_NKEYS, n + 1)
    if needs:
        rec = op.setbyte(rec, O_NPK, op.getbyte(rec, O_NPK) + 1)
    return rec


@subroutine
def without(rec: Bytes, kid: Bytes32, needs: bool) -> Bytes:
    n = n_keys(rec)
    i = find(rec, UInt64(HEADER), n, kid.bytes)
    assert i < n, "unknown key"
    at = HEADER + 32 * i
    rec = op.extract(rec, 0, at) + op.substring(rec, at + 32, rec.length)
    rec = op.setbyte(rec, O_NKEYS, n - 1)
    if needs:
        rec = op.setbyte(rec, O_NPK, op.getbyte(rec, O_NPK) - 1)
    return rec


@subroutine
def origin_hash(origin: Bytes) -> Bytes32:
    assert origin.length > 0 and origin.length <= MAX_ORIGIN_LEN, "origin length"
    return Bytes32.from_bytes(op.sha256(origin))


@subroutine
def with_origin(rec: Bytes, oh: Bytes32) -> Bytes:
    """Adds an origin (idempotent, as NEAR); the cap is `usable`'s."""
    if has(rec, origins_at(rec), n_origins(rec), oh.bytes):
        return rec
    return op.setbyte(rec + oh.bytes, O_NORIGINS, n_origins(rec) + 1)


@subroutine
def without_origin(rec: Bytes, oh: Bytes32) -> Bytes:
    at, n = origins_at(rec), n_origins(rec)
    i = find(rec, at, n, oh.bytes)
    assert i < n, "unknown origin"
    p = at + 32 * i
    return op.setbyte(op.extract(rec, 0, p) + op.substring(rec, p + 32, rec.length), O_NORIGINS, n - 1)


@subroutine
def usable(rec: Bytes, h: Holder) -> None:
    """Never a UA without a key, over the origin cap, or with a passkey and no origin to sign from (a native address
    keeps its wallet authority)."""
    if h.kind.as_uint64() == KIND_UA:
        assert n_keys(rec) > 0, "the last key cannot be removed"
    assert n_origins(rec) <= MAX_ORIGINS, "MAX_ORIGINS (8) reached"
    assert n_origins(rec) > 0 or op.getbyte(rec, O_NPK) == 0, "a passkey needs an origin"


@subroutine
def put(h: Holder, rec: Bytes) -> None:
    """Writes `rec`; a record box created here is announced by `KeyOp(h, "open")` (every first write goes through
    here: a lazy open by `verify`, a key op, a recovery's guardian, `add_key_native`)."""
    name = rec_name(h)
    if not op.Box.delete(name):
        arc4.emit("KeyOp", h, arc4.String("open"))
    op.Box.put(name, rec)


@subroutine
def save(h: Holder, rec: Bytes, action: String) -> None:
    usable(rec, h)
    put(h, rec)
    arc4.emit("KeyOp", h, arc4.String(action))

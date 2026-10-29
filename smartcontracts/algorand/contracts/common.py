"""Shared by every SCaaS Algorand app (near-algorand T11; spec §2 rows 1, 3, 4, 8, §4.6).

`MetaOp` v1 as an ARC-4 static tuple (big-endian), `digest = sha256("scaas.metaop.v1" ‖ ARC-4(op))` — the layout of
`scripts/gen_vectors.py` (306 bytes with the label). Native signature: `ed25519verify_bare` over the wallet sign-bytes
form `SIGN_PREFIX ‖ text` by the address's current authority. `payId` / `payLane` / `ref`: the EVM derivation.
"""
import typing

from algopy import (Account, Application, BigUInt, Bytes, FixedBytes, Global, OpUpFeeSource, TransactionType, Txn, UInt64, arc4,
                    ensure_budget, gtxn, itxn, op, subroutine, urange)

Bytes32 = FixedBytes[typing.Literal[32]]

LABEL = b"scaas.metaop.v1"
SIGN_PREFIX = b"MX"  # the wallet sign-bytes prefix (ARC-60 style), the one place it is spelled

# Ruling T12-budget: a signature check first raises the call's opcode budget to its cost plus TAIL (the rest of the
# caller's work) by inner budget calls when the group's top-level calls do not give it; their fees come from the
# group's fee credit (the relayer's fee pooling), never from an app's balance. Costs measured (limits log).
TAIL = 1000
COST_NATIVE = 2300  # "MX" ‖ text(d) and ed25519verify_bare (1,900)
COST_ENTRY = 1500   # an account entry's work before its first signature check (op digest, record, key data)

KIND_ADDRESS = 0  # holder kinds (vectors: 0 = a native address, its 32-byte key; 1 = a UA id)
KIND_UA = 1

OP_PAY = 0
OP_TRADE = 1
OP_MANDATE_PAY = 2
OP_REVOKE = 3
OP_TRANSFER = 4
OP_EXECUTE_TRANSFER = 5
OP_ADD_KEY = 6
OP_REMOVE_KEY = 7
OP_ADD_ORIGIN = 8
OP_REMOVE_ORIGIN = 9
OP_SET_GUARDIAN = 10
OP_START_RECOVERY = 11
OP_CANCEL_RECOVERY = 12
OP_CANCEL = 14
OP_INVALIDATE_NONCES = 15
ARC4_TRUE = b"\x15\x1f\x7c\x75\x80"  # an ABI `bool` return log: the return prefix ‖ true
VERIFY = "verify(uint8,byte[32],byte[32],byte[])bool"          # a value op (POLICY_PASSKEY_FOR_VALUE)
VERIFY_KEY = "verify_key(uint8,byte[32],byte[32],byte[])bool"  # an op that moves no value (revoke, cancel, invalidate)
METAOP_ABI = ("(byte[32],byte[32],uint8,(uint8,byte[32]),(uint8,byte[32]),byte[32],uint128,byte[32],byte[32],uint64,"
              "uint64,byte[32])")
MTX_PAY = "mtx_pay(" + METAOP_ABI + ",byte[],address)void"
RELAY = "relay(uint64," + METAOP_ABI + ",byte[])void"  # the router's entry (T15): the executor's next transaction


class Holder(arc4.Struct, frozen=True):
    kind: arc4.UInt8
    id: Bytes32


class MetaOp(arc4.Struct, frozen=True):
    network: Bytes32
    contract: Bytes32  # the token app address
    op: arc4.UInt8
    from_: Holder
    to: Holder
    relayer: Bytes32  # zero = any relayer
    amount: arc4.UInt128
    pay_ref: Bytes32
    lane: Bytes32
    nonce: arc4.UInt64
    valid_until: arc4.UInt64  # seconds, against Global.latest_timestamp
    extra: Bytes32


class Order(arc4.Struct, frozen=True):
    """A DEX order (T14, NEAR's `Order` of Task 8 in ARC-4, 88 B): signed through its trade leg, op 1 with `to = relayer
    =` the DEX app address, `amount = sell_amount`, `extra = sha256(ARC-4(order))`. Fill-or-kill: a fill moves the
    whole `sell_amount` and pays at least `min_buy` of `buy_token`. `relayer`: the settle submitter (CTR-DEX-09), zero
    = any. `expiry` in seconds; no leg moves after it."""
    sell_token: arc4.UInt64  # token app ids
    buy_token: arc4.UInt64
    sell_amount: arc4.UInt128
    min_buy: arc4.UInt128
    relayer: Bytes32
    expiry: arc4.UInt64


@subroutine
def digest(o: MetaOp) -> Bytes32:
    return Bytes32.from_bytes(op.sha256(LABEL + o.bytes))


@subroutine
def text(d: Bytes32) -> Bytes:
    """NET-ALL-23 first build: `"scaas.metaop.v1:" ‖ hex(digest)` (lower-case)."""
    out = Bytes(LABEL + b":")
    for i in urange(0, 32, 4):  # 4 digest bytes → 8 nibbles, one per byte → ASCII, in uint64 (no lookup table)
        x = op.extract_uint32(d.bytes, i)
        x = (x | (x << 16)) & 0x0000FFFF0000FFFF
        x = (x | (x << 8)) & 0x00FF00FF00FF00FF
        x = (x | (x << 4)) & 0x0F0F0F0F0F0F0F0F
        x += 0x3030303030303030 + (((x + 0x0606060606060606) >> 4) & 0x0101010101010101) * 39  # 'a' - '0' - 10
        out += op.itob(x)
    return out


@subroutine
def sign_bytes(d: Bytes32) -> Bytes:
    return SIGN_PREFIX + text(d)


@subroutine
def authority(addr: Account) -> Account:
    """The key that signs for `addr` now: `AcctAuthAddr` when rekeyed, else the address itself."""
    auth, _exists = op.AcctParamsGet.acct_auth_addr(addr)
    return addr if auth == Global.zero_address else auth


@subroutine
def verify_native(addr: Account, d: Bytes32, sig: Bytes) -> bool:
    """Kind 0x0018: the wallet signature of the current authority. A LogicSig or multisig authority has no ed25519
    key, so nothing verifies (such an address signs through an account record, spec §4.3)."""
    assert sig.length == 64, "ed25519 signature is 64 bytes"
    ensure_budget(COST_NATIVE + TAIL, OpUpFeeSource.GroupCredit)
    return op.ed25519verify_bare(sign_bytes(d), sig, authority(addr).bytes)


@subroutine
def meta_pay_id(salt: Bytes32, meta: Bytes) -> Bytes32:
    return Bytes32.from_bytes(op.keccak256(b"scaas.pay.meta" + salt.bytes + op.keccak256(meta)))


@subroutine
def pay_lane(pay_ref: Bytes32) -> Bytes32:
    return Bytes32.from_bytes(op.keccak256(b"scaas.pay.lane" + pay_ref.bytes))


@subroutine
def relay_ref(network: Bytes32, target: Bytes32, call: Bytes, salt: Bytes32) -> Bytes32:
    """`keccak256("scaas.relayfee" ‖ network ‖ target ‖ keccak256(call) ‖ salt)`, salt = the payment op's `extra`."""
    return Bytes32.from_bytes(
        op.keccak256(b"scaas.relayfee" + network.bytes + target.bytes + op.keccak256(call) + salt.bytes)
    )


@subroutine
def lane_key(h: Holder, lane: Bytes32) -> Bytes32:
    """Lane box name body (after the `l` prefix): `sha256(kind ‖ holder ‖ lane)` (the raw 65 B exceeds 64 B)."""
    return Bytes32.from_bytes(op.sha256(h.bytes + lane.bytes))


@subroutine
def zero() -> Bytes32:
    return Bytes32.from_bytes(op.bzero(32))


@subroutine
def check_envelope(o: MetaOp) -> None:
    """Rules 1, 2, 7 for every signed entry: this network, this app, not expired, relayer zero or the sender."""
    assert o.network.bytes == Global.genesis_hash, "wrong network"
    assert o.contract.bytes == Global.current_application_address.bytes, "wrong contract"
    assert Global.latest_timestamp <= o.valid_until.as_uint64(), "expired"
    assert o.relayer == zero() or o.relayer.bytes == Txn.sender.bytes, "relayer is not the sender"


@subroutine
def mbr_payment() -> UInt64:
    """The MBR payment of this call: the group transaction just before it when that is a payment to the app address
    (it neither closes nor rekeys: a close-out would over-fund the app), else 0."""
    if Txn.group_index > 0:
        p = gtxn.Transaction(Txn.group_index - 1)
        if p.type == TransactionType.Payment and p.receiver == Global.current_application_address:
            assert p.close_remainder_to == Global.zero_address and p.rekey_to == Global.zero_address, \
                "MBR payment must not close or rekey"
            assert p.amount > 0, "MBR payment must equal the new boxes' MBR exactly"
            return p.amount
    return UInt64(0)


@subroutine
def mbr_paid(before: UInt64, forwarded: UInt64) -> None:
    """§2 row 15: the MBR payment equals exactly what this call added to the app's AcctMinBalance (after minus
    `before`; a shrink adds nothing and refunds nothing) plus what it `forwarded` by inner payment to another app's
    exact-MBR call; no payment when that is 0."""
    after = Global.current_application_address.min_balance
    grown = after - before if after > before else UInt64(0)
    assert mbr_payment() == grown + forwarded, "MBR payment must equal the new boxes' MBR exactly"


@subroutine
def account_verify(account_app: UInt64, h: Holder, d: Bytes32, auth: Bytes, forwarded: UInt64) -> None:
    """Inner `account.verify(h, d, auth)` (a value op: POLICY_PASSKEY_FOR_VALUE binds), preceded by the forwarded MBR
    payment when there is one (inner fees 0: the relayer's group pays them by fee pooling)."""
    account_call(account_app, arc4.arc4_signature("verify(uint8,byte[32],byte[32],byte[])bool"), h, d, auth, forwarded)


@subroutine
def account_call(account_app: UInt64, method: Bytes, h: Holder, d: Bytes32, auth: Bytes, forwarded: UInt64) -> None:
    """Inner `account.<method>(h, d, auth)` (`verify`, or `verify_key` for an op that moves no value), after the
    forwarded MBR payment when there is one; the call must answer true."""
    app = Application(account_app)
    call = itxn.ApplicationCall(
        app_id=app, fee=0,
        app_args=(method, h.kind.bytes, h.id.bytes, d.bytes, arc4.DynamicBytes(auth).bytes))
    if forwarded:
        _pay, res = itxn.submit_txns(itxn.Payment(receiver=app.address, amount=forwarded, fee=0), call)
        assert res.last_log == ARC4_TRUE, "bad signature"
    else:
        assert call.submit().last_log == ARC4_TRUE, "bad signature"


@subroutine
def rest(need: UInt64) -> UInt64:
    """The MBR payment beyond `need` (this app's new boxes): forwarded to another app's exact-MBR call."""
    paid = mbr_payment()
    assert paid >= need, "MBR payment must equal the new boxes' MBR exactly"
    return paid - need


@subroutine
def signed_by(account_app: UInt64, method: Bytes, h: Holder, d: Bytes32, auth: Bytes, forward: UInt64) -> UInt64:
    """`auth` signs `d` for `h`: a native address's 64-byte wallet signature here, else the account app's `method`
    selector (`verify` or `verify_key`) after `forward` µALGO (a lazy record open). Returns what was forwarded."""
    if h.kind.as_uint64() == KIND_ADDRESS and auth.length == 64:
        assert verify_native(Account(h.id.bytes), d, auth), "bad signature"
        return UInt64(0)
    account_call(account_app, method, h, d, auth, forward)
    return forward


@subroutine
def send(token: UInt64, to: Holder, amount: BigUInt, forwarded: UInt64) -> None:
    """This app's token balance → `to` by an inner token call (arc200_transfer to an address, transfer_to_ua to a UA
    id), after the MBR of the receiver's new box when `forwarded` (inner fees 0: the relayer pools them)."""
    app = Application(token)
    sel = arc4.arc4_signature("arc200_transfer(address,uint256)bool")
    if to.kind.as_uint64() == KIND_UA:
        sel = arc4.arc4_signature("transfer_to_ua(byte[32],uint256)void")
    call = itxn.ApplicationCall(app_id=app, fee=0, app_args=(sel, to.id.bytes, arc4.UInt256(amount).bytes))
    if forwarded:
        itxn.submit_txns(itxn.Payment(receiver=app.address, amount=forwarded, fee=0), call)
    else:
        call.submit()

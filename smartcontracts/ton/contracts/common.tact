// Shared messages and helpers: TEP-74 jetton messages, the signed MetaOp v1 (R30, §2 of
// docs/history/specs/2026-10-03-net-ton.md; current rules docs/networks/ton.md), the TON Connect signData envelope, passkey (R31).

// ------------------------------------------------------------------ TEP-74 / TEP-89

message(0x0f8a7ea5) JettonTransfer {
    queryId: Int as uint64;
    amount: Int as coins;
    destination: Address;
    responseDestination: Address?;
    customPayload: Cell?;
    forwardTonAmount: Int as coins;
    forwardPayload: Slice as remaining;
}

message(0x178d4519) JettonTransferInternal {
    queryId: Int as uint64;
    amount: Int as coins;
    sender: Address;
    responseDestination: Address?;
    forwardTonAmount: Int as coins;
    forwardPayload: Slice as remaining;
}

message(0x7362d09c) JettonNotification {
    queryId: Int as uint64;
    amount: Int as coins;
    sender: Address;
    forwardPayload: Slice as remaining;
}

message(0xd53276db) JettonExcesses {
    queryId: Int as uint64;
}

message(0x595f07bc) JettonBurn {
    queryId: Int as uint64;
    amount: Int as coins;
    responseDestination: Address?;
    customPayload: Cell?;
}

message(0x7bdd97de) JettonBurnNotification {
    queryId: Int as uint64;
    amount: Int as coins;
    sender: Address;
    responseDestination: Address?;
}

message(0x2c76b973) ProvideWalletAddress {
    queryId: Int as uint64;
    ownerAddress: Address;
    includeAddress: Bool;
}

message(0xd1735400) TakeWalletAddress {
    queryId: Int as uint64;
    walletAddress: Address;
    ownerAddress: Cell?;
}

// ------------------------------------------------------------------ SCaaS messages

/// Relayer -> payer's jetton wallet (or Mandate owner ops). `op` = MetaOp v1 cell tree,
/// `auth` = signature envelope. `responseDestination` and `matchWith` are the relayer's own choices (its TON,
/// a DEX matching hint). `forwardTon` is the relayer's TON too, but it decides whether a contract recipient
/// (DEX, Mandate) learns of the tokens, so the payer signs a floor for it and the wallet refuses less
/// (review H2): `pay` -> `MetaOp.extra`, `trade` -> `TradeParams.forwardTon`.
message(0x5b0a1d01) SignedOp {
    op: Cell;
    auth: Cell;
    params: Cell?;
    stateInit: Cell?;
    responseDestination: Address;
    forwardTon: Int as coins;
    matchWith: Int as uint256;
}

message(0x5b0a1d03) Mint {
    queryId: Int as uint64;
    to: Address;
    amount: Int as coins;
    responseDestination: Address?;
}

// Events (external-out). Only the indexer reads them; layout is part of the adapter contract.
message(0x9b1c0d01) MetaTransactionExecuted {
    master: Address;
    from: Address;
    digest: Int as uint256;
}

message(0x9b1c0d02) PaymentSettled {
    from: Address;
    to: Address;
    amount: Int as coins;
    payRef: Int as uint256;
}

message(0x9b1c0d03) TradeSettled {
    a: Int as uint256;
    b: Int as uint256;
}

/// CTR-MTX-26: emitted by the payer's wallet before its transfer, so it precedes the payee wallet's
/// `PaymentSettled` in logical time. `meta` is the snake chain exactly as the relayer sent it (never parsed).
message(0x9b1c0d04) PaymentMeta {
    master: Address;
    payId: Int as uint256;
    meta: Cell;
}

// ------------------------------------------------------------------ constants

const METAOP_DOMAIN: Int = 0x73636161732e6d6574616f702e7631; // "scaas.metaop.v1" (120 bits)
const OP_PAY: Int = 1;
const OP_TRADE: Int = 2;
const OP_MANDATE_PAY: Int = 3;
const OP_REVOKE: Int = 4;
const OP_SET_KEY: Int = 5;

const SIGN_DATA_PREFIX: Int = 0x75569022;
// crc32 of METAOP_SCHEMA (smartcontracts/ton/tests/vectors.ts checks it against the TL-B string).
const METAOP_SCHEMA_CRC: Int = 0x45ba8d70;

const PAY_TAG: Int = 0x626d7074;   // "bmpt": forward payload `pay_tag pay_ref:uint256`
const TRADE_TAG: Int = 0x626d7472; // "bmtr": forward payload `trade_tag ^MetaOp ^TradeParams match_with:uint256`
// "bmcl": forward payload `cancel_tag order:uint256` of a zero-amount transfer. It rides the same jetton path as
// the order's leg, so TON's per-pair message order delivers it after the leg (review L11: no cancel map).
const CANCEL_TAG: Int = 0x626d636c;

// Replay entries live at most two LANE_TTL windows: a MetaOp may not be valid further ahead (review M4).
const LANE_TTL: Int = 2592000; // 30 days — keep equal to fam_ton.LANE_TTL_S and ≤ Odoo LANE_HORIZON_S

const AUTH_TONCONNECT: Int = 0;
const AUTH_PASSKEY: Int = 1;

// Standard wallet code hashes (from @ton/ton; tests/vectors.ts re-derives them).
const W5R1_CODE_HASH: Int = 0x20834b7b72b112147e1b2fb457b84e74d1a30f04f737d4f62a668e9552d2b72f;
// W5R1 deployed as a library cell (exotic, type 2) referencing the code above.
const W5R1_LIB_HASH: Int = 0x44b96c52eaa2e18b272629e6e496004d08e0c364c1835a7418b92fb7585a2ed1;
const V4R2_CODE_HASH: Int = 0xfeb5ff6820e2ff0d9483e7e0d62c817d846789fb4ae580c878866d959dabd5c0;
const V3R2_CODE_HASH: Int = 0x84dafa449f98a6987789ba232358072bc0f76dc4524002a5d0918b9a75d2d599;

const P256_HALF_N: Int = 0x7FFFFFFF800000007FFFFFFFFFFFFFFFDE737D56D38BCF4279DCE5617E3192A8;

// Error codes (stable: the relayer maps them to reasons).
const E_DOMAIN: Int = 701;
const E_NETWORK: Int = 702;
const E_CONTRACT: Int = 703;
const E_FROM: Int = 704;
const E_EXPIRED: Int = 705;
const E_NONCE: Int = 706;
const E_RELAYER: Int = 707;
const E_SIG: Int = 708;
const E_NO_KEY: Int = 709;
const E_STATE_INIT: Int = 710;
const E_BALANCE: Int = 711;
const E_OP: Int = 712;
const E_PARAMS: Int = 713;
const E_VALUE: Int = 714;
const E_AUTH: Int = 715;
const E_SENDER: Int = 716;
const E_TTL: Int = 717;

// ------------------------------------------------------------------ MetaOp

struct MetaOp {
    network: Int;
    op: Int;
    amount: Int;
    nonce: Int;
    validUntil: Int;
    contract: Address;
    from: Address;
    to: Address;
    relayer: Address?;
    payRef: Int;
    lane: Int;
    extra: Int;
    digest: Int;
}

struct TradeParams {
    tokenIn: Address;
    tokenOut: Address;
    minOut: Int;
    counterparty: Address?;
    maxFeePpm: Int;
    forwardTon: Int; // signed floor for SignedOp.forwardTon (review H2)
}

fun parseMetaOp(c: Cell): MetaOp {
    let s = c.beginParse();
    throwUnless(E_DOMAIN, s.loadUint(120) == METAOP_DOMAIN);
    let network = s.loadInt(32);
    let op = s.loadUint(8);
    let amount = s.loadUint(128);
    let nonce = s.loadUint(64);
    let validUntil = s.loadUint(64);
    let contract = s.loadAddress();
    let p = s.loadRef().beginParse();
    let r = s.loadRef().beginParse();
    s.endParse();
    let from = p.loadAddress();
    let to = p.loadAddress();
    let relayer: Address? = null;
    if (p.preloadUint(2) == 0) {
        p.skipBits(2);
    } else {
        relayer = p.loadAddress();
    }
    p.endParse();
    let payRef = r.loadUint(256);
    let lane = r.loadUint(256);
    let extra = r.loadUint(256);
    r.endParse();
    return MetaOp {
        network, op, amount, nonce, validUntil, contract, from, to, relayer, payRef, lane, extra,
        digest: c.hash(),
    };
}

fun parseTradeParams(c: Cell): TradeParams {
    let s = c.beginParse();
    let tokenIn = s.loadAddress();
    let tokenOut = s.loadAddress();
    let minOut = s.loadUint(128);
    let counterparty: Address? = null;
    if (s.preloadUint(2) == 0) {
        s.skipBits(2);
    } else {
        counterparty = s.loadAddress();
    }
    let maxFeePpm = s.loadUint(32);
    let forwardTon = s.loadCoins();
    s.endParse();
    return TradeParams { tokenIn, tokenOut, minOut, counterparty, maxFeePpm, forwardTon };
}

/// Global id of the network (config param 19), the network half of the signing domain (R10-4).
fun globalId(): Int {
    return getConfigParam(19)!!.beginParse().loadInt(32);
}

/// Common MetaOp checks: domain separation (network + contract), expiry, relayer binding.
fun checkMetaOpEnvelope(m: MetaOp, relayer: Address) {
    throwUnless(E_NETWORK, m.network == globalId());
    throwUnless(E_CONTRACT, m.contract == myAddress());
    throwUnless(E_EXPIRED, m.validUntil > now());
    if (m.relayer != null) {
        throwUnless(E_RELAYER, m.relayer!! == relayer);
    }
}

// ------------------------------------------------------------------ signatures

/// TON Connect signData (cell): Ed25519 over the hash of
/// `0x75569022 crc32(schema):u32 timestamp:u64 owner:MsgAddress ^domain ^payload`.
fun signDataHash(owner: Address, timestamp: Int, domain: Cell, payload: Cell): Int {
    return beginCell()
        .storeUint(SIGN_DATA_PREFIX, 32)
        .storeUint(METAOP_SCHEMA_CRC, 32)
        .storeUint(timestamp, 64)
        .storeAddress(owner)
        .storeRef(domain)
        .storeRef(payload)
        .endCell()
        .hash();
}

/// auth kind 0: `kind:uint8 signature:bits512 timestamp:uint64 ^domain`.
fun checkTonConnect(a: Slice, owner: Address, op: Cell, pubkey: Int) {
    let auth = a;
    let sig = auth.loadBits(512);
    let ts = auth.loadUint(64);
    let domain = auth.loadRef();
    auth.endParse();
    throwUnless(E_SIG, checkSignature(signDataHash(owner, ts, domain, op), sig, pubkey));
}

/// Owner pubkey from the owner's wallet StateInit: the StateInit must hash to the owner address
/// (review S18), and its code must be a standard wallet whose data layout we know.
fun pubkeyFromStateInit(owner: Address, si: Cell): Int {
    let addr = parseStdAddress(owner.asSlice());
    throwUnless(E_STATE_INIT, addr.workchain == 0 && si.hash() == addr.address);
    let s = si.beginParse();
    throwUnless(E_STATE_INIT, !s.loadBool()); // split_depth
    throwUnless(E_STATE_INIT, !s.loadBool()); // special
    throwUnless(E_STATE_INIT, s.loadBool());
    let code = s.loadRef();
    throwUnless(E_STATE_INIT, s.loadBool());
    let data = s.loadRef().beginParse();
    let ch = code.hash();
    if (ch == W5R1_CODE_HASH || ch == W5R1_LIB_HASH) {
        data.skipBits(1 + 32 + 32); // is_signature_allowed seqno wallet_id
        return data.loadUint(256);
    }
    throwUnless(E_STATE_INIT, ch == V4R2_CODE_HASH || ch == V3R2_CODE_HASH);
    data.skipBits(32 + 32); // seqno subwallet
    return data.loadUint(256);
}

// ------------------------------------------------------------------ passkey (WebAuthn, P-256)

asm fun p256CheckDataSignature(data: Slice, signature: Slice, publicKey: Slice): Bool { P256_CHKSIGNS }

asm fun sha256Of4(a: Slice, b: Slice, c: Slice, d: Slice): Int { 4 PUSHINT HASHEXT_SHA256 }

fun b64urlChar(v: Int): Int {
    if (v < 26) { return 65 + v; }
    if (v < 52) { return 97 + v - 26; }
    if (v < 62) { return 48 + v - 52; }
    return v == 62 ? 45 : 95;
}

/// base64url (no padding) of a 32-byte value: 43 characters.
fun b64url32(x: Int): Slice {
    // 256 bits padded to 258 = 43 sextets; never shift left (Int is 257-bit signed).
    let b = beginCell();
    let i = 42;
    while (i > 0) {
        b = b.storeUint(b64urlChar((x >> (i * 6 - 2)) & 63), 8);
        i -= 1;
    }
    b = b.storeUint(b64urlChar((x & 15) << 2), 8);
    return b.asSlice();
}

/// Passkey record: `pubkey:bits264 rp_id_hash:uint256 ^origin_prefix`.
/// auth kind 1: `kind:uint8 r:uint256 s:uint256 ^authenticatorData ^cdj_suffix` where the suffix cell may
/// carry one more ref (client data longer than one cell).
fun checkPasskey(a: Slice, record: Cell, digest: Int) {
    let auth = a;
    let r = auth.loadUint(256);
    let sv = auth.loadUint(256);
    let authData = auth.loadRef().beginParse();
    let suffixCell = auth.loadRef();
    auth.endParse();
    throwUnless(E_SIG, sv <= P256_HALF_N);
    let rec = record.beginParse();
    let pub = rec.loadBits(264);
    let rpIdHash = rec.loadUint(256);
    let origin = rec.loadRef().beginParse();
    throwUnless(E_SIG, authData.bits() >= 296 && authData.refs() == 0);
    throwUnless(E_SIG, authData.preloadUint(256) == rpIdHash);
    let fl = authData;
    fl.skipBits(256);
    let flags = fl.preloadUint(8);
    throwUnless(E_SIG, (flags & 0x05) == 0x05); // UP and UV
    let s1 = suffixCell.beginParse();
    let s2 = emptySlice();
    if (s1.refs() == 1) {
        s2 = s1.preloadRef().beginParse();
        throwUnless(E_SIG, s2.refs() == 0);
    }
    throwUnless(E_SIG, s1.bits() >= origin.bits() && s1.preloadBits(origin.bits()) == origin);
    let prefix = "{\"type\":\"webauthn.get\",\"challenge\":\"".asSlice();
    let s1data = beginCell().storeSlice(s1.preloadBits(s1.bits())).asSlice();
    let cdjHash = sha256Of4(prefix, b64url32(digest), s1data, s2);
    let signed = beginCell().storeSlice(authData).storeUint(cdjHash, 256).asSlice();
    let sig = beginCell().storeUint(r, 256).storeUint(sv, 256).asSlice();
    throwUnless(E_SIG, p256CheckDataSignature(signed, sig, pub));
}

// ------------------------------------------------------------------ CTR-MTX-26 (payment metadata)

/// `keccak256("scaas.pay.meta" ‖ salt ‖ keccak256(meta))`, `meta` = the bytes of the snake chain (each cell's
/// data along its first ref; Tact's `keccak256(Slice)`), byte for byte the EVM `metaPayId`.
fun metaPayId(salt: Int, meta: Cell): Int {
    return keccak256(beginCell().storeSlice("scaas.pay.meta".asSlice()).storeUint(salt, 256)
        .storeUint(keccak256(meta.beginParse()), 256).asSlice());
}

/// `keccak256("scaas.pay.lane" ‖ p)`: the lane of a payment id (CTR-MTX-23).
fun payLane(p: Int): Int {
    return keccak256(beginCell().storeSlice("scaas.pay.lane".asSlice()).storeUint(p, 256).asSlice());
}

// ------------------------------------------------------------------ jetton helpers

fun payTag(payRef: Int): Slice {
    return beginCell().storeBit(true).storeRef(beginCell().storeUint(PAY_TAG, 32).storeUint(payRef, 256).endCell()).asSlice();
}

fun emptyForwardPayload(): Slice {
    return beginCell().storeBit(false).asSlice();
}

/// Body of a TEP-74 forward payload (`Either Cell ^Cell`).
fun forwardBody(payload: Slice): Slice {
    let fp = payload;
    if (fp.bits() == 0) {
        return emptySlice();
    }
    if (fp.loadBool()) {
        return fp.loadRef().beginParse();
    }
    return fp;
}

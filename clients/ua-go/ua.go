// Package ua is the SCaaS Universal Account identity layer (accounts.md §1.3–§1.6) for Go client systems: the kind table,
// ids, keyHash, purpose tags, ua_msg, the portable PoP / KEM record / PQZ key record digests, the registry's UAAuth digest, member digests, canonical ids and key-data
// validation. The same rules live in Solidity (UAKinds.sol), JS (clientkeys ua.js), Rust (scaas-ua), Python and C#;
// smartcontracts/vectors/ua pins all six. UNAUDITED.
package ua

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/sha3"
)

// Error carries the code every implementation and the vector files share (UAKeyData, UAKindUnknown, …).
type Error struct{ Code, Reason string }

func (e *Error) Error() string {
	if e.Reason == "" {
		return e.Code
	}
	return e.Code + ": " + e.Reason
}

func fail(code, reason string) error { return &Error{Code: code, Reason: reason} }

func keyDataErr(reason string) error { return &Error{Code: "UAKeyData", Reason: reason} }

// Kind is one row of the kind table; Lengths empty = variable-length key data; Group "" = none.
type Kind struct {
	Number  uint16
	Name    string
	Native  bool
	Lengths []int
	Group   string
}

var Kinds = []Kind{
	{0x0001, "evm-eoa", true, []int{20}, ""},
	{0x0002, "evm-contract", true, []int{20}, ""},
	{0x0003, "hedera-native", true, []int{20}, ""},
	{0x0010, "solana-ed25519", true, []int{32}, ""},
	{0x0011, "stellar-account", true, []int{32}, ""},
	{0x0012, "soroban-contract", true, []int{32}, ""},
	{0x0013, "aptos-account", true, []int{32}, ""},
	{0x0014, "sui-address", true, []int{32}, ""},
	{0x0015, "cosmos-account", true, []int{20, 32}, ""},
	{0x0016, "ton-wallet", true, []int{32}, ""},
	{0x0017, "near-account", true, []int{32}, ""},
	{0x0018, "algorand-address", true, []int{32}, ""},
	{0x0100, "webauthn-p256", false, []int{96}, "p256"},
	{0x0101, "p256", false, []int{64}, "p256"},
	{0x0102, "ed25519", false, []int{32}, "ed25519"},
	{0x0103, "bip340", false, []int{32}, "secp256k1"},
	{0x0104, "schnorr-bn254", false, []int{64}, "bn254-g1"},
	{0x0105, "schnorr-bls12381", false, []int{128}, "bls12381-g1"},
	{0x0106, "bls12381-minsig", false, []int{256}, "bls12381-g2"},
	{0x0107, "bls-bn254-minsig", false, []int{128}, "bn254-g2"},
	{0x0110, "musig2-secp256k1", false, nil, "secp256k1"},
	{0x0111, "frost-secp256k1", false, nil, "secp256k1"},
	{0x0112, "musig2-bn254", false, nil, "bn254-g1"},
	{0x0113, "frost-bn254", false, nil, "bn254-g1"},
	{0x0120, "msig", false, nil, ""},
	{0x0130, "mldsa44", false, []int{1312}, "mldsa44"},
	{0x0131, "mldsa65", false, []int{1952}, "mldsa65"},
	{0x0132, "fndsa512", false, []int{897}, "fndsa512"},
	{0x0133, "slhdsa128s", false, []int{32}, "slhdsa128s"},
	{0x0141, "zether-bls12381", false, []int{128}, "bls12381-g1"},
	{0x0108, "secp256k1", false, []int{64}, "secp256k1"}, // 2026-10-17, appended as in kinds.json
}

// Schemes are not kinds (UA-6 U14): 0x0142 is the PQZ key attribute of a PQ holder; it keeps its tag and keyHash group.
var Schemes = []Kind{{0x0142, "pqz-mlwe", false, PqzKeyLengths, "pqz-mlwe"}}

// PqzKeyLengths are the public key lengths of the PQZ parameter sets (PqzSet.PK).
var PqzKeyLengths = []int{16384, 18432, 20480, 22528}

var Groups = []string{"p256", "ed25519", "secp256k1", "bn254-g1", "bls12381-g1", "bls12381-g2", "bn254-g2", "mldsa44",
	"mldsa65", "fndsa512", "slhdsa128s", "pqz-mlwe"}

var Purposes = []string{"pop", "metatx", "metatx-cancel", "member", "zether-auth", "zether-owner", "keyop",
	"receiver-fee", "vp", "vc-anchor", "trade", "kem", "pqz-key"}

const (
	DomainType   = "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)"
	UAAuthType   = "UAAuth(bytes32 ua,bytes32 purpose,bytes32 digest)"
	RegistryName = "SCaaS UARegistry"
)

func Keccak256(parts ...[]byte) (out [32]byte) {
	h := sha3.NewLegacyKeccak256()
	for _, p := range parts {
		h.Write(p)
	}
	copy(out[:], h.Sum(nil))
	return
}

var MsgTag = Keccak256([]byte("scaas.ua.msg.v1"))

func KindInfo(kind uint16) (*Kind, error) {
	for i := range Kinds {
		if Kinds[i].Number == kind {
			return &Kinds[i], nil
		}
	}
	return nil, fail("UAKindUnknown", fmt.Sprintf("0x%04x", kind))
}

func derived(kind uint16) (*Kind, error) {
	for i := range Schemes {
		if Schemes[i].Number == kind {
			return nil, fail("UAKindNotDerived", Schemes[i].Name)
		}
	}
	k, err := KindInfo(kind)
	if err != nil {
		return nil, err
	}
	if k.Native {
		return nil, fail("UAKindNotDerived", k.Name)
	}
	return k, nil
}

// tagged accepts a kind or a scheme (tag, keyHash, message); ids and key data take kinds only.
func tagged(kind uint16) (*Kind, error) {
	for i := range Schemes {
		if Schemes[i].Number == kind {
			return &Schemes[i], nil
		}
	}
	return derived(kind)
}

func singleSigning(k uint16) bool {
	return (k >= 0x0100 && k <= 0x0108) || (k >= 0x0110 && k <= 0x0113) || (k >= 0x0130 && k <= 0x0133)
}

func IsNative(kind uint16) bool  { k, err := KindInfo(kind); return err == nil && k.Native }
func IsZether(kind uint16) bool  { return kind == 0x0141 }
func IsSigning(kind uint16) bool { return kind == 0x0120 || kind == 0x0141 || singleSigning(kind) }

// IsPqzHolder: kinds that may hold a PQZ key attribute, mldsa44, mldsa65, fndsa512 (an msig per MsigPqzEligible).
func IsPqzHolder(kind uint16) bool { return kind >= 0x0130 && kind <= 0x0132 }
func IsMember(kind uint16, hederaNative bool) bool {
	return singleSigning(kind) || kind == 0x0001 || kind == 0x0002 || (hederaNative && kind == 0x0003)
}

func KindTagString(kind uint16) (string, error) {
	k, err := tagged(kind)
	if err != nil {
		return "", err
	}
	return "scaas.ua." + k.Name + ".v1", nil
}

func Tag(kind uint16) ([32]byte, error) {
	s, err := KindTagString(kind)
	if err != nil {
		return [32]byte{}, err
	}
	return Keccak256([]byte(s)), nil
}

func GroupTagString(group string) (string, bool) {
	for _, g := range Groups {
		if g == group {
			return "scaas.ua.group." + g + ".v1", true
		}
	}
	return "", false
}

func GroupTag(group string) ([32]byte, bool) {
	s, ok := GroupTagString(group)
	if !ok {
		return [32]byte{}, false
	}
	return Keccak256([]byte(s)), true
}

func PurposeTag(purpose string) ([32]byte, error) { return PurposeTagV(purpose, 1) }

// PurposeTagV is the tag of a purpose version: every purpose is v1, "pop" is also v2 (UA-8: the portable PoP).
func PurposeTagV(purpose string, version uint32) ([32]byte, error) {
	for _, p := range Purposes {
		if p == purpose && (version == 1 || (p == "pop" && version == 2)) {
			return Keccak256([]byte("scaas.ua.purpose." + p + ".v" + strconv.FormatUint(uint64(version), 10))), nil
		}
	}
	return [32]byte{}, fail("UAPurposeUnknown", purpose)
}

// UAOf is keccak256(TAG(kind) ‖ keyData), without validation (see DeriveUA).
func UAOf(kind uint16, keyData []byte) ([32]byte, error) {
	if _, err := derived(kind); err != nil {
		return [32]byte{}, err
	}
	t, err := Tag(kind)
	if err != nil {
		return t, err
	}
	return Keccak256(t[:], keyData), nil
}

func InNativeSpace(id [32]byte) bool {
	for _, b := range id[:12] {
		if b != 0 {
			return false
		}
	}
	return true
}

// DeriveUA validates, derives, and refuses an id whose top 96 bits are zero (CTR-UA-03).
func DeriveUA(kind uint16, keyData []byte, hederaNative bool) ([32]byte, error) {
	if err := ValidateKeyData(kind, keyData, hederaNative); err != nil {
		return [32]byte{}, err
	}
	u, err := UAOf(kind, keyData)
	if err != nil {
		return u, err
	}
	if InNativeSpace(u) {
		return [32]byte{}, fail("UAIdInNativeSpace", hex.EncodeToString(u[:]))
	}
	return u, nil
}

// NativeID left-pads a native id to 32 bytes.
func NativeID(kind uint16, raw []byte) (id [32]byte, err error) {
	k, err := KindInfo(kind)
	if err != nil {
		return id, err
	}
	if !k.Native {
		return id, fail("UAKindNotNative", k.Name)
	}
	for _, n := range k.Lengths {
		if n == len(raw) {
			copy(id[32-n:], raw)
			return id, nil
		}
	}
	return id, keyDataErr("length")
}

// KeyHashOf is keccak256(GROUP(g) ‖ canonical pubkey), nil for structures. Call on validated key data.
func KeyHashOf(kind uint16, keyData []byte) (*[32]byte, error) {
	k, err := tagged(kind)
	if err != nil {
		return nil, err
	}
	if k.Group == "" {
		return nil, nil
	}
	lo, hi := 0, len(keyData)
	switch kind {
	case 0x0100, 0x0101, 0x0108:
		hi = 32
	case 0x0110, 0x0111:
		lo, hi = 1, 33
	case 0x0112, 0x0113:
		hi = 64
	}
	if hi > len(keyData) {
		return nil, keyDataErr("length")
	}
	g, _ := GroupTag(k.Group)
	h := Keccak256(g[:], keyData[lo:hi])
	return &h, nil
}

func UAMessage(kind uint16, purpose, digest [32]byte) ([32]byte, error) {
	t, err := Tag(kind)
	if err != nil {
		return t, err
	}
	return Keccak256(MsgTag[:], t[:], purpose[:], digest[:]), nil
}

func word(v uint64) []byte {
	w := make([]byte, 32)
	for i := 0; i < 8; i++ {
		w[31-i] = byte(v >> (8 * i))
	}
	return w
}

func addressWord(a [20]byte) []byte { return append(make([]byte, 12), a[:]...) }

var (
	// PopV2Tag is PURPOSE_POP_V2 = keccak256("scaas.ua.purpose.pop.v2").
	PopV2Tag, _ = PurposeTagV("pop", 2)
	// KemRecordTag and PqzKeyRecordTag tag the KEM record and the PQZ key record digests.
	KemRecordTag     = Keccak256([]byte("scaas.ua.kem-record.v1"))
	PqzKeyRecordTag  = Keccak256([]byte("scaas.ua.pqz-key-record.v1"))
	kemPurpose, _    = PurposeTag("kem")
	pqzKeyPurpose, _ = PurposeTag("pqz-key")
)

// KemPkLength is the one KEM key the registry stores: ML-KEM-1024 ek ‖ X25519 pk (X-Wing order).
const KemPkLength = 1600

// PortablePopDigest is keccak256(PURPOSE_POP_V2 ‖ ua ‖ pqzKeyHash ‖ kemRecordHash), each hash zero when absent (UA-8 P1: no chain).
func PortablePopDigest(ua, pqzKeyHash, kemRecordHash [32]byte) [32]byte {
	return Keccak256(PopV2Tag[:], ua[:], pqzKeyHash[:], kemRecordHash[:])
}

// RegistrationDigest is keccak256(portablePopDigest ‖ pqzPopHash): what the signer's pop signs under UAMessage(kind, POP_V2, ·).
func RegistrationDigest(portable, pqzPopHash [32]byte) [32]byte {
	return Keccak256(portable[:], pqzPopHash[:])
}

// KemRecordDigest is keccak256(KEM_RECORD_TAG ‖ ua ‖ uint256(version) ‖ keccak256(kemPk)): version 1 … 2^64 − 1, a 1,600-byte key.
func KemRecordDigest(ua [32]byte, version uint64, kemPk []byte) ([32]byte, error) {
	if version == 0 {
		return [32]byte{}, fail("UAKemVersion", "0")
	}
	if len(kemPk) != KemPkLength {
		return [32]byte{}, fail("UAKemKeyLength", strconv.Itoa(len(kemPk)))
	}
	pk := Keccak256(kemPk)
	return Keccak256(KemRecordTag[:], ua[:], word(version), pk[:]), nil
}

// KemRecordMessage is what the UA signs for a KEM record: UAMessage(kind, PURPOSE_KEM, KemRecordDigest).
func KemRecordMessage(kind uint16, ua [32]byte, version uint64, kemPk []byte) ([32]byte, error) {
	d, err := KemRecordDigest(ua, version, kemPk)
	if err != nil {
		return d, err
	}
	return UAMessage(kind, kemPurpose, d)
}

// Kem is a KEM record attribute; nil or {0, empty} = absent.
type Kem struct {
	Version uint64
	Pk      []byte
}

func (k *Kem) hash(ua [32]byte) ([32]byte, error) {
	if k == nil || (k.Version == 0 && len(k.Pk) == 0) {
		return [32]byte{}, nil
	}
	return KemRecordDigest(ua, k.Version, k.Pk)
}

// holds: a PQZ / KEM holder is a single-key PQ kind, or an msig whose key data is PQ-eligible (malformed key data is UAKeyData).
func holds(kind uint16, keyData []byte) (bool, error) {
	if IsPqzHolder(kind) {
		return true, nil
	}
	if kind == 0x0120 && len(keyData) > 0 {
		return MsigPqzEligible(keyData)
	}
	return false, nil
}

// pqzKeyHashOf is KeyHashOf(0x0142, key); a key of no parameter set's length is UAKeyData.
func pqzKeyHashOf(pqzKey []byte) ([32]byte, error) {
	for _, n := range PqzKeyLengths {
		if n == len(pqzKey) {
			h, err := KeyHashOf(0x0142, pqzKey)
			if err != nil {
				return [32]byte{}, err
			}
			return *h, nil
		}
	}
	return [32]byte{}, keyDataErr("PQZ key length")
}

// proofHashOf is the proof hash from the proof bytes and / or the hash (absent = zero; an empty or all-zero hash is absent);
// both given and different is UAPqzPopHash, and so is keccak256("") (an empty proof is no proof).
func proofHashOf(pqzPop, pqzPopHash []byte) ([32]byte, error) {
	var proof, given *[32]byte
	if len(pqzPop) > 0 {
		h := Keccak256(pqzPop)
		proof = &h
	}
	if len(pqzPopHash) > 0 {
		if len(pqzPopHash) != 32 {
			return [32]byte{}, fail("UAPqzPopHash", "hash must be 32 bytes")
		}
		var g [32]byte
		copy(g[:], pqzPopHash)
		if g != ([32]byte{}) {
			given = &g
		}
	}
	if proof != nil && given != nil && *proof != *given {
		return [32]byte{}, fail("UAPqzPopHash", "proof and hash differ")
	}
	var h [32]byte
	if proof != nil {
		h = *proof
	} else if given != nil {
		h = *given
	}
	if h == Keccak256(nil) {
		return h, fail("UAPqzPopHash", "empty proof")
	}
	return h, nil
}

// HolderPop is the portable PoP of a registration (UA-8 P1, P2), as HolderPopMessage returns it. Message is
// UAMessage(kind, POP_V2, RegistrationDigest): what the signer's pop signs (every kind). MemberDigest (msig only, else nil)
// is MemberDigest(ua, Message): what each member signs under `member`; a code-less native member signs
// PersonalSignDigest(MemberDigest) (ruling C7).
type HolderPop struct {
	PqzKeyHash, PqzPopHash, KemRecordHash, PortablePopDigest, RegistrationDigest, Message [32]byte
	MemberDigest                                                                          *[32]byte
}

// HolderPopMessage is the portable PoP message of a registration. Attributes: pqzKey with its proof pqzPop (or only its hash
// pqzPopHash; a relayer may hold only that) and the initial KEM record; nil / empty = absent. Only holders may carry them
// (UAPqzHolder, UAKemHolder; an msig needs keyData to show it is PQ-eligible); a PQZ key always comes with its proof hash and
// only with it (UAPqzPopHash).
func HolderPopMessage(kind uint16, ua [32]byte, keyData, pqzKey, pqzPop, pqzPopHash []byte, kem *Kem) (*HolderPop, error) {
	hasKem := kem != nil && (kem.Version != 0 || len(kem.Pk) != 0)
	if len(pqzKey) > 0 || hasKem {
		ok, err := holds(kind, keyData)
		if err != nil {
			return nil, err
		}
		if !ok && len(pqzKey) > 0 {
			return nil, fail("UAPqzHolder", fmt.Sprintf("0x%04x may not hold a PQZ key", kind))
		}
		if !ok {
			return nil, fail("UAKemHolder", fmt.Sprintf("0x%04x may not hold a KEM key", kind))
		}
	}
	popHash, err := proofHashOf(pqzPop, pqzPopHash)
	if err != nil {
		return nil, err
	}
	if (len(pqzKey) > 0) != (popHash != [32]byte{}) {
		return nil, fail("UAPqzPopHash", "a PQZ key comes with its proof hash and only with it")
	}
	r := &HolderPop{PqzPopHash: popHash}
	if len(pqzKey) > 0 {
		if r.PqzKeyHash, err = pqzKeyHashOf(pqzKey); err != nil {
			return nil, err
		}
	}
	if r.KemRecordHash, err = kem.hash(ua); err != nil {
		return nil, err
	}
	r.PortablePopDigest = PortablePopDigest(ua, r.PqzKeyHash, r.KemRecordHash)
	r.RegistrationDigest = RegistrationDigest(r.PortablePopDigest, popHash)
	if r.Message, err = UAMessage(kind, PopV2Tag, r.RegistrationDigest); err != nil {
		return nil, err
	}
	if kind == 0x0120 {
		m := MemberDigest(ua, r.Message)
		r.MemberDigest = &m
	}
	return r, nil
}

// PqzRegMessage is the message R_REG proves over: UAMessage(0x0142, POP_V2, PortablePopDigest(ua, keyHash(0x0142, pqzKey), kemRecordHash)).
func PqzRegMessage(ua [32]byte, pqzKey []byte, kem *Kem) ([32]byte, error) {
	h, err := pqzKeyHashOf(pqzKey)
	if err != nil {
		return h, err
	}
	kr, err := kem.hash(ua)
	if err != nil {
		return kr, err
	}
	return UAMessage(0x0142, PopV2Tag, PortablePopDigest(ua, h, kr))
}

// PqzKeyDigest is keccak256(PQZ_KEY_RECORD_TAG ‖ ua ‖ pqzKeyHash): what a later PQZ key's R_REG proves over (no proof hash: no cycle).
func PqzKeyDigest(ua, pqzKeyHash [32]byte) [32]byte {
	return Keccak256(PqzKeyRecordTag[:], ua[:], pqzKeyHash[:])
}

// PqzKeyRecordDigest is keccak256(pqzKeyDigest ‖ pqzPopHash): what setPqzKey's signature signs under UAMessage(kind, PURPOSE_PQZ_KEY, ·).
func PqzKeyRecordDigest(keyDigest, pqzPopHash [32]byte) [32]byte {
	return Keccak256(keyDigest[:], pqzPopHash[:])
}

// PqzKeyRecord is the PQZ key record of setPqzKey (ruling A1-I1), see PqzKeyRecordMessage. Message is what the UA signs,
// PqzRegMessage what the key's R_REG proves over.
type PqzKeyRecord struct {
	PqzKeyHash, PqzPopHash, PqzKeyDigest, RecordDigest, Message, PqzRegMessage [32]byte
	MemberDigest                                                               *[32]byte
}

// PqzKeyRecordMessage is the signed, portable, write-once PQZ key record: accepted only by a registration without a PQZ key
// (alreadySet = it has one: UAPqzKeySet). The holder rules of HolderPopMessage; the key and its proof hash are both required.
func PqzKeyRecordMessage(kind uint16, ua [32]byte, keyData, pqzKey, pqzPop, pqzPopHash []byte, alreadySet bool) (*PqzKeyRecord, error) {
	ok, err := holds(kind, keyData)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fail("UAPqzHolder", fmt.Sprintf("0x%04x may not hold a PQZ key", kind))
	}
	if alreadySet {
		return nil, fail("UAPqzKeySet", "write-once")
	}
	r := &PqzKeyRecord{}
	if r.PqzKeyHash, err = pqzKeyHashOf(pqzKey); err != nil {
		return nil, err
	}
	if r.PqzPopHash, err = proofHashOf(pqzPop, pqzPopHash); err != nil {
		return nil, err
	}
	if r.PqzPopHash == ([32]byte{}) {
		return nil, fail("UAPqzPopHash", "a PQZ key record needs its proof hash")
	}
	r.PqzKeyDigest = PqzKeyDigest(ua, r.PqzKeyHash)
	r.RecordDigest = PqzKeyRecordDigest(r.PqzKeyDigest, r.PqzPopHash)
	if r.Message, err = UAMessage(kind, pqzKeyPurpose, r.RecordDigest); err != nil {
		return nil, err
	}
	if r.PqzRegMessage, err = UAMessage(0x0142, pqzKeyPurpose, r.PqzKeyDigest); err != nil {
		return nil, err
	}
	if kind == 0x0120 {
		m := MemberDigest(ua, r.Message)
		r.MemberDigest = &m
	}
	return r, nil
}

// PersonalSignDigest is the EIP-191 personal_sign of a 32-byte digest: keccak256(0x19 ‖ "Ethereum Signed Message:\n32" ‖ digest).
// A code-less native (EOA) msig member signs it over the MemberDigest of a portable record only (POP_V2, KEM, PQZ_KEY; ruling
// C7); every other purpose stays UAAuth (CTR-MTX-14).
func PersonalSignDigest(digest [32]byte) [32]byte {
	return Keccak256([]byte("\x19Ethereum Signed Message:\n32"), digest[:])
}

// IsPortablePurpose: POP_V2, KEM, PQZ_KEY are the only purposes a code-less native msig member signs by personal_sign.
func IsPortablePurpose(tag [32]byte) bool {
	return tag == PopV2Tag || tag == kemPurpose || tag == pqzKeyPurpose
}

// Domain is the registry's EIP-712 domain ("SCaaS UARegistry", "<generation>", chainId, registry, salt = chainUid).
type Domain struct {
	Generation uint32
	ChainID    uint64
	Registry   [20]byte
	ChainUID   [32]byte
}

func UAAuthDomainSeparator(d Domain) [32]byte {
	t, n, v := Keccak256([]byte(DomainType)), Keccak256([]byte(RegistryName)), Keccak256([]byte(strconv.FormatUint(uint64(d.Generation), 10)))
	return Keccak256(t[:], n[:], v[:], word(d.ChainID), addressWord(d.Registry), d.ChainUID[:])
}

// UAAuthDigest is the EIP-712 digest of UAAuth(ua, purpose, digest): what native signers behind the registry sign.
func UAAuthDigest(d Domain, ua, purpose, digest [32]byte) [32]byte {
	t := Keccak256([]byte(UAAuthType))
	s := Keccak256(t[:], ua[:], purpose[:], digest[:])
	sep := UAAuthDomainSeparator(d)
	return Keccak256([]byte{0x19, 0x01}, sep[:], s[:])
}

func MemberDigest(structureUA, uaMsg [32]byte) [32]byte { return Keccak256(structureUA[:], uaMsg[:]) }

// CanonicalID returns lower-case hex; a 32-byte id with the top 96 bits zero is written as its 20-byte native id.
func CanonicalID(text string) (string, error) {
	h, ok := strings.CutPrefix(text, "0x")
	if !ok || (len(h) != 40 && len(h) != 64) {
		return "", fail("UAIdFormat", text)
	}
	if _, err := hex.DecodeString(h); err != nil {
		return "", fail("UAIdFormat", text)
	}
	h = strings.ToLower(h)
	if len(h) == 64 && strings.HasPrefix(h, strings.Repeat("0", 24)) {
		h = h[24:]
	}
	return "0x" + h, nil
}

// MsigPqzEligible: the weight of msig members outside kinds 0x0130-0x0133 is below the threshold (CTR-PQZ-12).
func MsigPqzEligible(keyData []byte) (bool, error) {
	d := keyData
	if len(d) < 4 || len(d) != 4+36*(int(d[2])<<8|int(d[3])) {
		return false, keyDataErr("length")
	}
	classical := 0
	for o := 4; o < len(d); o += 36 {
		if k := int(d[o])<<8 | int(d[o+1]); k < 0x0130 || k > 0x0133 {
			classical += int(d[o+34])<<8 | int(d[o+35])
		}
	}
	return classical < int(d[0])<<8|int(d[1]), nil
}

// Member is one msig member.
type Member struct {
	Kind   uint16
	ID     [32]byte
	Weight uint16
}

// EncodeMsig is u16 threshold ‖ u16 count ‖ count × (u16 kind ‖ bytes32 id ‖ u16 weight).
func EncodeMsig(threshold uint16, members []Member) []byte {
	out := []byte{byte(threshold >> 8), byte(threshold), byte(len(members) >> 8), byte(len(members))}
	for _, m := range members {
		out = append(out, byte(m.Kind>>8), byte(m.Kind))
		out = append(out, m.ID[:]...)
		out = append(out, byte(m.Weight>>8), byte(m.Weight))
	}
	return out
}

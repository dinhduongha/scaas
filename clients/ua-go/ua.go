// Package ua is the SCaaS Universal Account identity layer (accounts.md §1.3–§1.6) for Go client systems: the kind table,
// ids, keyHash, purpose tags, ua_msg, popDigest, the registry's UAAuth digest, member digests, canonical ids and key-data
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
	{0x0140, "zether-bn254", false, []int{64}, "bn254-g1"},
	{0x0141, "zether-bls12381", false, []int{128}, "bls12381-g1"},
	{0x0142, "pqz-mlwe", false, []int{16384}, "pqz-mlwe"},
	{0x0108, "secp256k1", false, []int{64}, "secp256k1"}, // 2026-10-17, appended as in kinds.json
}

var Groups = []string{"p256", "ed25519", "secp256k1", "bn254-g1", "bls12381-g1", "bls12381-g2", "bn254-g2", "mldsa44",
	"mldsa65", "fndsa512", "slhdsa128s", "pqz-mlwe"}

var Purposes = []string{"pop", "authref", "metatx", "metatx-cancel", "member", "zether-auth", "zether-owner", "keyop",
	"receiver-fee", "vp", "vc-anchor", "trade"}

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
	k, err := KindInfo(kind)
	if err != nil {
		return nil, err
	}
	if k.Native {
		return nil, fail("UAKindNotDerived", k.Name)
	}
	return k, nil
}

func singleSigning(k uint16) bool {
	return (k >= 0x0100 && k <= 0x0108) || (k >= 0x0110 && k <= 0x0113) || (k >= 0x0130 && k <= 0x0133)
}

func IsNative(kind uint16) bool  { k, err := KindInfo(kind); return err == nil && k.Native }
func IsZether(kind uint16) bool  { return kind >= 0x0140 && kind <= 0x0142 }
func IsSigning(kind uint16) bool { return kind == 0x0120 || singleSigning(kind) }
func IsMember(kind uint16, hederaNative bool) bool {
	return singleSigning(kind) || kind == 0x0001 || kind == 0x0002 || (hederaNative && kind == 0x0003)
}

func KindTagString(kind uint16) (string, error) {
	k, err := derived(kind)
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

func PurposeTag(purpose string) ([32]byte, error) {
	for _, p := range Purposes {
		if p == purpose {
			return Keccak256([]byte("scaas.ua.purpose." + p + ".v1")), nil
		}
	}
	return [32]byte{}, fail("UAPurposeUnknown", purpose)
}

// UAOf is keccak256(TAG(kind) ‖ keyData), without validation (see DeriveUA).
func UAOf(kind uint16, keyData []byte) ([32]byte, error) {
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
	k, err := derived(kind)
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

func ChainKeyHash(chainID uint64) [32]byte {
	return Keccak256([]byte("evm:" + strconv.FormatUint(chainID, 10)))
}

func word(v uint64) []byte {
	w := make([]byte, 32)
	for i := 0; i < 8; i++ {
		w[31-i] = byte(v >> (8 * i))
	}
	return w
}

func addressWord(a [20]byte) []byte { return append(make([]byte, 12), a[:]...) }

// PopDigest is pop_digest (CTR-UA-07).
func PopDigest(chainID uint64, chainUID [32]byte, registry [20]byte, ua, authRef [32]byte) [32]byte {
	pop, _ := PurposeTag("pop")
	ckh := ChainKeyHash(chainID)
	return Keccak256(pop[:], ckh[:], chainUID[:], addressWord(registry), ua[:], authRef[:])
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

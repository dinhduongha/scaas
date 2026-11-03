package ua

import (
	"encoding/hex"
)

// The registry's explicit arguments (typed-signing R1 / R1b: TS-D10 … TS-D13; owner KEM rulings 2026-10-31), as clientkeys
// registrationArgs and ua-rs registration_args. Every struct marshals to the named JSON of clientkeys and the node job API.

// Hex is bytes that marshal as 0x-hex JSON.
type Hex []byte

func (h Hex) MarshalJSON() ([]byte, error) { return []byte(`"0x` + hex.EncodeToString(h) + `"`), nil }

// RegisterCalldataLimit is the largest calldata whose EIP-7976 floor (15,000 + 64 per byte) fits the EIP-7825 cap 2^24: 261,909 B.
const RegisterCalldataLimit = ((1 << 24) - 15_000) / 64

// KemKey is the registry's KEM key (TS-D11): kemPk = Scheme ‖ MlkemEk ‖ X25519; the empty key is scheme 0, no ek, x25519 0.
type KemKey struct {
	Scheme  uint8 `json:"scheme"`
	MlkemEk Hex   `json:"mlkemEk"`
	X25519  Hex   `json:"x25519"`
}

// KemKeyOf splits an assembled kemPk; empty = the empty key; a malformed key is refused as the registry does (KemRecordHash:
// UAKemScheme, UAKemKeyLength).
func KemKeyOf(kemPk []byte) (KemKey, error) {
	if len(kemPk) == 0 {
		return KemKey{X25519: make(Hex, 32)}, nil
	}
	if _, err := KemRecordHash([32]byte{}, 0, kemPk); err != nil {
		return KemKey{}, err
	}
	return KemKey{kemPk[0], kemPk[1 : len(kemPk)-32], kemPk[len(kemPk)-32:]}, nil
}

// UAAttrs is the registration's attributes: KemPkHash non-zero is the KEM hash commit (Kem = the scheme only).
type UAAttrs struct {
	PqzKey     Hex    `json:"pqzKey"`
	PqzPopHash Hex    `json:"pqzPopHash"`
	Kem        KemKey `json:"kem"`
	KemPkHash  Hex    `json:"kemPkHash"`
}

// MsigMember is one member of a typed MsigStructure.
type MsigMember struct {
	Kind   uint16 `json:"kind"`
	ID     Hex    `json:"id"`
	Weight uint16 `json:"weight"`
}

// MsigStructure is CTR-UA-09 key data, typed (TS-D10).
type MsigStructure struct {
	Threshold uint16       `json:"threshold"`
	Members   []MsigMember `json:"members"`
}

// MsigStructureOf parses msig key data.
func MsigStructureOf(keyData []byte) (*MsigStructure, error) {
	d := keyData
	if len(d) < 4 || len(d) != 4+36*(int(d[2])<<8|int(d[3])) {
		return nil, keyDataErr("length")
	}
	s := &MsigStructure{Threshold: uint16(d[0])<<8 | uint16(d[1]), Members: []MsigMember{}}
	for o := 4; o < len(d); o += 36 {
		s.Members = append(s.Members, MsigMember{uint16(d[o])<<8 | uint16(d[o+1]), d[o+2 : o+34], uint16(d[o+34])<<8 | uint16(d[o+35])})
	}
	return s, nil
}

// WebAuthnKey is the typed key of 0x0100.
type WebAuthnKey struct {
	X        Hex `json:"x"`
	Y        Hex `json:"y"`
	RpIdHash Hex `json:"rpIdHash"`
}

// MuSig2Key is the typed key of 0x0110 / 0x0112.
type MuSig2Key struct {
	AggKey     Hex   `json:"aggKey"`
	MemberKeys []Hex `json:"memberKeys"`
}

// FrostMember is one signer of a FrostKey.
type FrostMember struct {
	Commitments []Hex `json:"commitments"`
	R           Hex   `json:"r"`
	Z           Hex   `json:"z"`
}

// FrostKey is the typed key of 0x0111 / 0x0113.
type FrostKey struct {
	GroupKey  Hex           `json:"groupKey"`
	Threshold uint16        `json:"threshold"`
	Members   []FrostMember `json:"members"`
}

// TypedKey is the typed key of packed key data (R1b, TS-D13): *WebAuthnKey, *MuSig2Key or *FrostKey (points of 33 B on secp256k1,
// 64 B on bn254); nil for any other kind. The registry assembles the same bytes (same id).
func TypedKey(kind uint16, keyData []byte) (any, error) {
	d := keyData
	if kind == 0x0100 {
		if len(d) != 96 {
			return nil, keyDataErr("length")
		}
		return &WebAuthnKey{d[:32], d[32:64], d[64:]}, nil
	}
	s := map[uint16]int{0x0110: 33, 0x0111: 33, 0x0112: 64, 0x0113: 64}[kind]
	if s == 0 {
		return nil, nil
	}
	if kind == 0x0110 || kind == 0x0112 {
		n, err := u16At(d, s)
		if err != nil {
			return nil, err
		}
		if len(d) != s+2+n*s {
			return nil, keyDataErr("length")
		}
		k := &MuSig2Key{AggKey: d[:s], MemberKeys: []Hex{}}
		for i := 0; i < n; i++ {
			k.MemberKeys = append(k.MemberKeys, d[s+2+i*s:s+2+(i+1)*s])
		}
		return k, nil
	}
	t, err := u16At(d, s)
	if err != nil {
		return nil, err
	}
	n, err := u16At(d, s+2)
	if err != nil {
		return nil, err
	}
	per := (t+1)*s + 32
	if len(d) != s+4+n*per {
		return nil, keyDataErr("length")
	}
	k := &FrostKey{GroupKey: d[:s], Threshold: uint16(t), Members: []FrostMember{}}
	for i := 0; i < n; i++ {
		o := s + 4 + i*per
		m := FrostMember{Commitments: []Hex{}, R: d[o+t*s : o+(t+1)*s], Z: d[o+(t+1)*s : o+per]}
		for j := 0; j < t; j++ {
			m.Commitments = append(m.Commitments, d[o+j*s:o+(j+1)*s])
		}
		k.Members = append(k.Members, m)
	}
	return k, nil
}

// InnerSig is one signature of a member of an inner msig: its slot there. No list of its own: a third level has no form.
type InnerSig struct {
	Index uint16 `json:"index"`
	Sig   Hex    `json:"sig"`
}

// MemberSig is one msig slot's signature: a signing member Sig, Members empty; an msig member Members, Sig empty.
type MemberSig struct {
	Index   uint16     `json:"index"`
	Members []InnerSig `json:"members"`
	Sig     Hex        `json:"sig"`
}

// UASig is the signature of requireAuthorized / setKemKey / setPqzKey (TS-D12): native — Signature; a derived single key —
// KeyData (empty for the stored kinds) + Signature; an msig — Members. A portable record's signature never has KeyData.
type UASig struct {
	KeyData   Hex         `json:"keyData"`
	Signature Hex         `json:"signature"`
	Members   []MemberSig `json:"members"`
}

// NewUASig fills a UASig (nil members = none).
func NewUASig(keyData, signature []byte, members []MemberSig) UASig {
	if members == nil {
		members = []MemberSig{}
	}
	return UASig{keyData, signature, members}
}

// SetKemKeyArgs is setKemKey(ua, version, kem, sig).
type SetKemKeyArgs struct {
	UA      Hex    `json:"ua"`
	Version uint64 `json:"version"`
	Kem     KemKey `json:"kem"`
	Sig     UASig  `json:"sig"`
}

// NewSetKemKeyArgs builds setKemKey's arguments; sig empty for the version-0 hash-commit fill; no key is no call.
func NewSetKemKeyArgs(ua [32]byte, version uint64, kemPk []byte, sig UASig) (*SetKemKeyArgs, error) {
	if len(kemPk) == 0 {
		return nil, fail("UAKemKeyLength", "0")
	}
	kem, err := KemKeyOf(kemPk)
	if err != nil {
		return nil, err
	}
	return &SetKemKeyArgs{ua[:], version, kem, sig}, nil
}

// SetPqzKeyArgs is setPqzKey(ua, pqzKey, pqzPopHash, sig).
type SetPqzKeyArgs struct {
	UA         Hex   `json:"ua"`
	PqzKey     Hex   `json:"pqzKey"`
	PqzPopHash Hex   `json:"pqzPopHash"`
	Sig        UASig `json:"sig"`
}

// NewSetPqzKeyArgs builds setPqzKey's arguments.
func NewSetPqzKeyArgs(ua [32]byte, pqzKey []byte, pqzPopHash [32]byte, sig UASig) *SetPqzKeyArgs {
	return &SetPqzKeyArgs{ua[:], pqzKey, pqzPopHash[:], sig}
}

// RegisterArgs is one registry call: register (Kind, KeyData), registerMsig (Structure), registerWebAuthn (Key) or
// registerMuSig2 / registerFrost (Kind, Key). Pop is a Hex, or []MemberSig for registerMsig.
type RegisterArgs struct {
	Entry     string         `json:"entry"`
	Kind      uint16         `json:"kind,omitempty"`
	KeyData   Hex            `json:"keyData,omitempty"`
	Structure *MsigStructure `json:"structure,omitempty"`
	Key       any            `json:"key,omitempty"`
	Attrs     UAAttrs        `json:"attrs"`
	PqzPop    Hex            `json:"pqzPop"`
	Pop       any            `json:"pop"`
}

func tailLen(b []byte) int { return 32 + (len(b)+31)/32*32 } // a `bytes` tail: length word + padded data
func bytesArrLen(xs []Hex) int {
	n := 32
	for _, x := range xs {
		n += 32 + tailLen(x)
	}
	return n
}
func kemLen(k KemKey) int    { return 96 + tailLen(k.MlkemEk) }
func attrsLen(a UAAttrs) int { return 128 + tailLen(a.PqzKey) + kemLen(a.Kem) }
func memberSigsLen(ms []MemberSig) int {
	n := 32
	for _, m := range ms {
		n += 32 + 96 + 32 + tailLen(m.Sig)
		for _, x := range m.Members {
			n += 32 + 64 + tailLen(x.Sig)
		}
	}
	return n
}

// CalldataLength is the ABI calldata length of the call (selector included), as clientkeys registryCalldataLength.
func (a *RegisterArgs) CalldataLength() int {
	rest := attrsLen(a.Attrs) + tailLen(a.PqzPop)
	if ms, ok := a.Pop.([]MemberSig); ok {
		return 4 + 128 + 96 + 96*len(a.Structure.Members) + rest + memberSigsLen(ms)
	}
	rest += tailLen(a.Pop.(Hex))
	switch k := a.Key.(type) {
	case *WebAuthnKey:
		return 4 + 192 + rest
	case *MuSig2Key:
		return 4 + 160 + 64 + tailLen(k.AggKey) + bytesArrLen(k.MemberKeys) + rest
	case *FrostKey:
		n := 4 + 160 + 96 + tailLen(k.GroupKey) + 32 + rest
		for _, m := range k.Members {
			n += 32 + 96 + bytesArrLen(m.Commitments) + tailLen(m.R)
		}
		return n
	}
	return 4 + 160 + tailLen(a.KeyData) + rest
}

// CalldataLength is the ABI calldata length of setKemKey (selector included).
func (a *SetKemKeyArgs) CalldataLength() int {
	return 4 + 128 + kemLen(a.Kem) + 96 + tailLen(a.Sig.KeyData) + tailLen(a.Sig.Signature) + memberSigsLen(a.Sig.Members)
}

// RegistrationInput is the registration of RegistrationArgs. Pop: the signer's signature; Members: an msig's member signatures.
// KemCommit: nil chooses by size, true forces the hash commit, false the full key.
type RegistrationInput struct {
	Kind                                       uint16
	KeyData, PqzKey, PqzPopHash, PqzPop, KemPk []byte
	Pop                                        []byte
	Members                                    []MemberSig
	KemCommit                                  *bool
}

// RegistrationArgs is the registry call of a registration (TS-D10 … TS-D13), as clientkeys registrationArgs. The KEM key is
// version 0 (owner 2026-10-31): in full, or, only when the full call is over RegisterCalldataLimit (X0: PQZH n2560-kmax16384 with
// a PQZ key) or KemCommit, the hash commit (Kem = {scheme, empty, 0}, KemPkHash = keccak256(kemPk)) plus the returned fill
// setKemKey(ua, 0, kem, UASig{}), open to anyone (the pop signed the same record).
func RegistrationArgs(in RegistrationInput) (*RegisterArgs, *SetKemKeyArgs, error) {
	var popHash [32]byte
	if len(in.PqzKey) > 0 || len(in.PqzPopHash) > 0 {
		h, err := proofHashOf(in.PqzPop, in.PqzPopHash)
		if err != nil {
			return nil, nil, err
		}
		popHash = h
	}
	kem, err := KemKeyOf(in.KemPk)
	if err != nil {
		return nil, nil, err
	}
	a := &RegisterArgs{Entry: "register", Attrs: UAAttrs{in.PqzKey, popHash[:], kem, make(Hex, 32)}, PqzPop: in.PqzPop, Pop: Hex(in.Pop)}
	switch in.Kind {
	case 0x0120:
		if a.Structure, err = MsigStructureOf(in.KeyData); err != nil {
			return nil, nil, err
		}
		a.Entry, a.Pop = "registerMsig", NewUASig(nil, nil, in.Members).Members
	case 0x0100:
		a.Entry = "registerWebAuthn"
	case 0x0110, 0x0112:
		a.Entry, a.Kind = "registerMuSig2", in.Kind
	case 0x0111, 0x0113:
		a.Entry, a.Kind = "registerFrost", in.Kind
	default:
		a.Kind, a.KeyData = in.Kind, in.KeyData
	}
	if a.Key, err = TypedKey(in.Kind, in.KeyData); err != nil {
		return nil, nil, err
	}
	commit := a.CalldataLength() > RegisterCalldataLimit
	if in.KemCommit != nil {
		commit = *in.KemCommit
	}
	if len(in.KemPk) == 0 || !commit {
		return a, nil, nil
	}
	ua, err := UAOf(in.Kind, in.KeyData)
	if err != nil {
		return nil, nil, err
	}
	h := Keccak256(in.KemPk)
	a.Attrs.Kem, a.Attrs.KemPkHash = KemKey{Scheme: kem.Scheme, X25519: make(Hex, 32)}, h[:]
	fill, err := NewSetKemKeyArgs(ua, 0, in.KemPk, NewUASig(nil, nil, nil))
	return a, fill, err
}

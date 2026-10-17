package ua

import (
	"bytes"
	"math/big"

	"filippo.io/edwards25519"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	blsfp "github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	"github.com/consensys/gnark-crypto/ecc/bn254"
)

func mustHex(s string) *big.Int {
	v, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic(s)
	}
	return v
}

var (
	secpP = mustHex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f")
	secpN = mustHex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")
	p256P = mustHex("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff")
	p256B = mustHex("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b")
	bnR   = mustHex("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001")
	three = big.NewInt(3)
	seven = big.NewInt(7)
)

func need(ok bool, reason string) error {
	if ok {
		return nil
	}
	return keyDataErr(reason)
}

func isZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

func secpX(x []byte) error {
	X := new(big.Int).SetBytes(x)
	if X.Cmp(secpP) >= 0 {
		return keyDataErr("range")
	}
	rhs := new(big.Int).Exp(X, three, secpP)
	rhs.Add(rhs, seven).Mod(rhs, secpP)
	return need(new(big.Int).ModSqrt(rhs, secpP) != nil, "curve")
}

func secpCompressed(b []byte) error {
	if b[0] != 2 && b[0] != 3 {
		return keyDataErr("prefix")
	}
	return secpX(b[1:33])
}

func secpXY(d []byte) error {
	X, Y := new(big.Int).SetBytes(d[:32]), new(big.Int).SetBytes(d[32:64])
	if X.Cmp(secpP) >= 0 || Y.Cmp(secpP) >= 0 {
		return keyDataErr("range")
	}
	rhs := new(big.Int).Exp(X, three, secpP)
	rhs.Add(rhs, seven).Mod(rhs, secpP)
	lhs := new(big.Int).Mul(Y, Y)
	return need(lhs.Mod(lhs, secpP).Cmp(rhs) == 0, "curve")
}

func p256Point(xy []byte) error {
	x, y := new(big.Int).SetBytes(xy[:32]), new(big.Int).SetBytes(xy[32:64])
	if x.Cmp(p256P) >= 0 || y.Cmp(p256P) >= 0 {
		return keyDataErr("range")
	}
	rhs := new(big.Int).Exp(x, three, p256P)
	rhs.Sub(rhs, new(big.Int).Mul(three, x)).Add(rhs, p256B).Mod(rhs, p256P)
	return need(new(big.Int).Exp(y, big.NewInt(2), p256P).Cmp(rhs) == 0, "curve")
}

func ed25519Key(b []byte) error {
	p, err := new(edwards25519.Point).SetBytes(b)
	if err != nil {
		return keyDataErr("curve")
	}
	// SetBytes accepts y ≥ p and a negative zero x; the re-encoding is canonical, so compare
	if !bytes.Equal(p.Bytes(), b) {
		return keyDataErr("canonical")
	}
	return need(new(edwards25519.Point).MultByCofactor(p).Equal(edwards25519.NewIdentityPoint()) != 1, "small-order")
}

func bnG1(b []byte) error {
	if isZero(b) {
		return keyDataErr("identity")
	}
	var p bn254.G1Affine
	if p.X.SetBytesCanonical(b[:32]) != nil || p.Y.SetBytesCanonical(b[32:64]) != nil {
		return keyDataErr("range")
	}
	return need(p.IsOnCurve(), "curve")
}

func bnG2(b []byte) error {
	if isZero(b) {
		return keyDataErr("identity")
	}
	var p bn254.G2Affine // EIP-197 order: imaginary part (A1) first
	if p.X.A1.SetBytesCanonical(b[:32]) != nil || p.X.A0.SetBytesCanonical(b[32:64]) != nil ||
		p.Y.A1.SetBytesCanonical(b[64:96]) != nil || p.Y.A0.SetBytesCanonical(b[96:128]) != nil {
		return keyDataErr("range")
	}
	if !p.IsOnCurve() {
		return keyDataErr("curve")
	}
	return need(p.IsInSubGroup(), "subgroup")
}

func blsFp(e *blsfp.Element, b []byte) error {
	if !isZero(b[:16]) {
		return keyDataErr("padding")
	}
	return need(e.SetBytesCanonical(b[16:64]) == nil, "range")
}

func blsG1(b []byte) error {
	if isZero(b) {
		return keyDataErr("identity")
	}
	var p bls12381.G1Affine
	for i, e := range []*blsfp.Element{&p.X, &p.Y} {
		if err := blsFp(e, b[64*i:64*i+64]); err != nil {
			return err
		}
	}
	if !p.IsOnCurve() {
		return keyDataErr("curve")
	}
	return need(p.IsInSubGroup(), "subgroup")
}

func blsG2(b []byte) error {
	if isZero(b) {
		return keyDataErr("identity")
	}
	var p bls12381.G2Affine // EIP-2537 order: c0 (A0) first
	for i, e := range []*blsfp.Element{&p.X.A0, &p.X.A1, &p.Y.A0, &p.Y.A1} {
		if err := blsFp(e, b[64*i:64*i+64]); err != nil {
			return err
		}
	}
	if !p.IsOnCurve() {
		return keyDataErr("curve")
	}
	return need(p.IsInSubGroup(), "subgroup")
}

func u16At(d []byte, o int) (int, error) {
	if len(d) < o+2 {
		return 0, keyDataErr("length")
	}
	return int(d[o])<<8 | int(d[o+1]), nil
}

// musig2: Q ‖ u16 n ‖ n × P_i, 2 ≤ n ≤ 16, P_i strictly increasing.
func musig2(d []byte, point func([]byte) error, size int) error {
	n, err := u16At(d, size)
	if err != nil {
		return err
	}
	if n < 2 || n > 16 {
		return keyDataErr("n")
	}
	if len(d) != size+2+n*size {
		return keyDataErr("length")
	}
	if err := point(d[:size]); err != nil {
		return err
	}
	for i := 0; i < n; i++ {
		o := size + 2 + i*size
		if err := point(d[o : o+size]); err != nil {
			return err
		}
		if i > 0 && bytes.Compare(d[o-size:o], d[o:o+size]) >= 0 {
			return keyDataErr("order")
		}
	}
	return nil
}

// frost: Y ‖ u16 t ‖ u16 n ‖ n × (t × C_ik ‖ R_i ‖ μ_i), 2 ≤ t ≤ n ≤ 16, μ_i < order.
func frost(d []byte, point func([]byte) error, size int, order *big.Int) error {
	t, err := u16At(d, size)
	if err != nil {
		return err
	}
	n, err := u16At(d, size+2)
	if err != nil {
		return err
	}
	if t < 2 || t > n || n > 16 {
		return keyDataErr("threshold")
	}
	per := (t+1)*size + 32
	if len(d) != size+4+n*per {
		return keyDataErr("length")
	}
	if err := point(d[:size]); err != nil {
		return err
	}
	for i := 0; i < n; i++ {
		o := size + 4 + i*per
		for j := 0; j <= t; j++ { // t commitments, then R_i
			if err := point(d[o+j*size : o+(j+1)*size]); err != nil {
				return err
			}
		}
		if new(big.Int).SetBytes(d[o+(t+1)*size:o+per]).Cmp(order) >= 0 {
			return keyDataErr("scalar")
		}
	}
	return nil
}

// msig: u16 threshold ‖ u16 count ‖ count × (u16 kind ‖ bytes32 id ‖ u16 weight) (CTR-UA-09).
func msig(d []byte, hederaNative bool) error {
	threshold, err := u16At(d, 0)
	if err != nil {
		return err
	}
	count, err := u16At(d, 2)
	if err != nil {
		return err
	}
	if count < 1 || count > 16 {
		return keyDataErr("count")
	}
	if len(d) != 4+36*count {
		return keyDataErr("length")
	}
	total := 0
	for i := 0; i < count; i++ {
		o := 4 + 36*i
		kind := uint16(d[o])<<8 | uint16(d[o+1])
		var id [32]byte
		copy(id[:], d[o+2:o+34])
		weight := int(d[o+34])<<8 | int(d[o+35])
		if !IsMember(kind, hederaNative) {
			return keyDataErr("member-kind")
		}
		if weight < 1 {
			return keyDataErr("weight")
		}
		if IsNative(kind) != InNativeSpace(id) {
			return keyDataErr("member-id")
		}
		if i > 0 && bytes.Compare(d[o-34:o-2], id[:]) >= 0 {
			return keyDataErr("order")
		}
		total += weight
	}
	return need(threshold >= 1 && threshold <= total, "threshold")
}

// fndsa: 0x09 ‖ 512 × 14-bit h_i (big-endian bit packing), each < 12289.
func fndsa(d []byte) error {
	if d[0] != 0x09 {
		return keyDataErr("header")
	}
	for i := 0; i < 512; i++ {
		v := 0
		for j := 0; j < 14; j++ {
			k := i*14 + j
			v = v<<1 | int(d[1+k/8]>>(7-uint(k%8))&1)
		}
		if v >= 12289 {
			return keyDataErr("coefficient")
		}
	}
	return nil
}

// ValidateKeyData returns a UAKeyData error unless keyData is the unique canonical encoding of a valid key or structure.
func ValidateKeyData(kind uint16, d []byte, hederaNative bool) error {
	k, err := derived(kind)
	if err != nil {
		return err
	}
	if len(k.Lengths) > 0 {
		ok := false
		for _, n := range k.Lengths {
			ok = ok || n == len(d)
		}
		if !ok {
			return keyDataErr("length")
		}
	}
	switch kind {
	case 0x0100:
		return p256Point(d[:64])
	case 0x0101:
		return p256Point(d)
	case 0x0102:
		return ed25519Key(d)
	case 0x0103:
		return secpX(d)
	case 0x0104, 0x0140:
		return bnG1(d)
	case 0x0105, 0x0141:
		return blsG1(d)
	case 0x0106:
		return blsG2(d)
	case 0x0107:
		return bnG2(d)
	case 0x0108:
		return secpXY(d)
	case 0x0110:
		return musig2(d, secpCompressed, 33)
	case 0x0111:
		return frost(d, secpCompressed, 33, secpN)
	case 0x0112:
		return musig2(d, bnG1, 64)
	case 0x0113:
		return frost(d, bnG1, 64, bnR)
	case 0x0120:
		return msig(d, hederaNative)
	case 0x0132:
		return fndsa(d)
	}
	return nil // mldsa44/65, slhdsa128s, pqz-mlwe: the length is the whole check
}

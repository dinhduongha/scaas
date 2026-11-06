// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0

// Tests of the cgo binding against smartcontracts/vectors/ua/{keys,sign,kem,seal,vault,zether}.json, clients/zether-prover/vectors/
// and the PQZ facade; the load check, handle freeing and secret wiping of the binding itself. Needs libscaas_ua_c
// (cargo build --release in clients/ua-c). From clients/ua-go: go vet ./... && go test ./...
package wallet

import (
	"bytes"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	ua "github.com/dinhduongha/scaas/clients/ua-go"
)

type obj = map[string]any

func vec(t *testing.T, path string) obj {
	raw, err := os.ReadFile("../../../" + path)
	if err != nil {
		t.Fatal(err)
	}
	var v obj
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func uaVec(t *testing.T, name string) obj { return vec(t, "smartcontracts/vectors/ua/"+name) }

func rows(v any) []obj {
	out := []obj{}
	for _, r := range v.([]any) {
		out = append(out, r.(obj))
	}
	return out
}

func b(v any) []byte {
	x, err := hex.DecodeString(strings.TrimPrefix(v.(string), "0x"))
	if err != nil {
		panic(err)
	}
	return x
}

func b32(v any) (o [32]byte) { copy(o[:], b(v)); return }
func hx(x []byte) string     { return "0x" + hex.EncodeToString(x) }

// u64 is a version: a JSON number, or a decimal string past 2^53.
func u64(v any) uint64 {
	if s, ok := v.(string); ok {
		return must(strconv.ParseUint(s, 10, 64))
	}
	return uint64(v.(float64))
}

func n32(v any) uint32 {
	if i, ok := v.(int); ok {
		return uint32(i)
	}
	return uint32(v.(float64))
}
func js(v any) string {
	if v == nil {
		return ""
	}
	o, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(o)
}

// code is the status name of an error ("" for nil).
func code(err error) string {
	var e *Error
	if err == nil {
		return ""
	}
	if errors.As(err, &e) {
		return e.Code
	}
	return "go: " + err.Error()
}

type fix struct {
	t  *testing.T
	mn map[string]obj
	ws map[string]*Wallet
}

func newFix(t *testing.T) *fix {
	f := &fix{t: t, mn: map[string]obj{}, ws: map[string]*Wallet{}}
	for _, m := range rows(uaVec(t, "keys.json")["mnemonics"]) {
		f.mn[m["id"].(string)] = m
	}
	return f
}

// must, must0, must2 fail the test (a panic) on an error.
func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func must0(err error) {
	if err != nil {
		panic(err)
	}
}

func must2[A, B any](a A, b B, err error) (A, B) {
	if err != nil {
		panic(err)
	}
	return a, b
}

func (f *fix) fresh(mid string) *Wallet {
	m := f.mn[mid]
	w := must(FromMnemonic([]byte(m["words"].(string)), []byte(m["passphrase"].(string))))
	f.t.Cleanup(w.Close)
	return w
}

func (f *fix) w(mid string) *Wallet {
	if f.ws[mid] == nil {
		f.ws[mid] = f.fresh(mid)
	}
	return f.ws[mid]
}

func (f *fix) key(w *Wallet, kind, account, index any) *Key {
	k := must(w.UAKey(uint16(n32(kind)), n32(account), n32(index)))
	f.t.Cleanup(k.Close)
	return k
}

func (f *fix) native(mid, net string, index uint32, coin any) *Key {
	c := uint32(CoinDefault)
	if coin != nil {
		c = n32(coin)
	}
	k := must(f.w(mid).NativeKey(network(net), index, c))
	f.t.Cleanup(k.Close)
	return k
}

func (f *fix) kem(r obj, w *Wallet) *KemKey {
	if w == nil {
		mid := "pq_kat"
		if m, ok := r["mnemonic"].(string); ok {
			mid = m
		}
		w = f.w(mid)
	}
	kk := must(f.key(w, r["kind"], r["account"], r["index"]).KemKey(u64(r["version"])))
	f.t.Cleanup(kk.Close)
	return kk
}

func network(name string) uint32 {
	for i, n := range Networks {
		if n == name {
			return uint32(i)
		}
	}
	panic(name)
}

// --- the binding's own checks ---

func TestLoadRefusesWrongAbiOrFeatures(t *testing.T) {
	if err := Load(); err != nil {
		t.Fatal(err)
	}
	abiVersionHook = func(uint32) uint32 { return 5 }
	loadMu.Lock()
	loaded = false
	loadMu.Unlock()
	err := Load()
	_, _, gerr := Generate()
	_, merr := FromMnemonic([]byte("abandon"), nil)
	abiVersionHook = func(v uint32) uint32 { return v }
	if !errors.Is(err, ErrLibraryMismatch) || !errors.Is(gerr, ErrLibraryMismatch) || !errors.Is(merr, ErrLibraryMismatch) {
		t.Fatalf("ABI 5 accepted: %v / %v / %v", err, gerr, merr)
	}
	if err := Load(); err != nil {
		t.Fatal(err)
	}
	good := FeatureWallet | FeaturePq | FeaturePqz | FeaturePqzSetN2304Kmax4096
	if CheckBuild(6, good) != nil || CheckBuild(6, FeatureWallet|FeaturePq) != nil {
		t.Fatal("a good build refused")
	}
	for label, c := range map[string]struct {
		abi uint32
		f   uint64
	}{"abi 5": {5, good}, "abi 7": {7, good}, "no wallet": {6, good &^ FeatureWallet}, "no pq": {6, good &^ FeaturePq},
		"an unknown bit": {6, good | 1<<12}, "a vectors build (C1)": {6, good | FeatureVectors}, "two sets": {6, good | FeaturePqzSetN2048Kmax1024},
		"pqz without a set": {6, FeatureWallet | FeaturePq | FeaturePqz}, "a set without pqz": {6, FeatureWallet | FeaturePq | FeaturePqzSetN2304Kmax4096}} {
		if !errors.Is(CheckBuild(c.abi, c.f), ErrLibraryMismatch) {
			t.Error(label)
		}
	}
}

func TestAbiVersionIs6AndFeatures(t *testing.T) {
	if ABI() != 6 {
		t.Fatal(ABI())
	}
	f := Features()
	if f&FeatureWallet == 0 || f&FeaturePq == 0 || f&FeatureExternal != 0 || f&FeatureVectors != 0 {
		t.Fatalf("%#x", f)
	}
	if _, err := ExternalKeyNew(`{"kind":257,"keyData":"0x"}`); code(err) != "UAKindUnavailable" {
		t.Fatal(err)
	}
	if StatusName(40) != "UAPqzSetMismatch" {
		t.Fatal(StatusName(40))
	}
}

type fake struct{ h handle }

func (f *fake) hd() *handle { return &f.h }

func TestHandleFreedExactlyOnce(t *testing.T) {
	var n atomic.Int32
	f := &fake{h: handle{p: unsafe.Pointer(new(byte)), free: func(unsafe.Pointer) { n.Add(1) }}}
	f.h.Close()
	f.h.Close()
	if n.Load() != 1 {
		t.Fatalf("freed %d times", n.Load())
	}
	// the finalizer frees what Close did not
	func() { track(&fake{h: handle{p: unsafe.Pointer(new(byte)), free: func(unsafe.Pointer) { n.Add(1) }}}) }()
	for i := 0; i < 100 && n.Load() < 2; i++ {
		runtime.GC()
		time.Sleep(10 * time.Millisecond)
	}
	if n.Load() != 2 {
		t.Fatalf("the finalizer did not free: %d", n.Load())
	}
	g := track(&fake{h: handle{p: unsafe.Pointer(new(byte)), free: func(unsafe.Pointer) { n.Add(1) }}})
	g.h.Close()
	g = nil
	for i := 0; i < 20; i++ {
		runtime.GC()
		time.Sleep(5 * time.Millisecond)
	}
	if n.Load() != 3 {
		t.Fatalf("closed, then finalized: freed %d times", n.Load()-2)
	}
}

func TestCloseWaitsForACallInFlight(t *testing.T) {
	var freed atomic.Bool
	h := &handle{p: unsafe.Pointer(new(byte)), free: func(unsafe.Pointer) { freed.Store(true) }}
	in, out := make(chan struct{}), make(chan struct{})
	go func() {
		_ = h.use(func(unsafe.Pointer) error { close(in); <-out; return nil })
	}()
	<-in
	done := make(chan struct{})
	go func() { h.Close(); close(done) }()
	select {
	case <-done:
		t.Fatal("Close did not wait")
	case <-time.After(200 * time.Millisecond):
	}
	if freed.Load() {
		t.Fatal("freed under a call")
	}
	close(out)
	<-done
	if !freed.Load() {
		t.Fatal("not freed")
	}
}

func TestUseAfterCloseNeverReachesTheLibrary(t *testing.T) {
	f := newFix(t)
	w := f.fresh("pq_kat")
	k := must(w.UAKey(0x0102, 0, 0))
	k.Close()
	w.Close()
	if _, err := k.KeyData(); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
	if _, err := w.UAKey(0x0102, 0, 0); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
}

func TestSecretBufferWipedAfterCall(t *testing.T) {
	f := newFix(t)
	var seen [][]byte
	real := secretBuf
	secretBuf = func(n int) []byte { x := real(n); seen = append(seen, x); return x }
	defer func() { secretBuf = real }()
	through := func(label string, call func()) {
		n := len(seen)
		call()
		if len(seen) == n {
			t.Errorf("%s: no secret buffer", label)
		}
		for _, x := range seen[n:] {
			if !bytes.Equal(x, make([]byte, len(x))) {
				t.Errorf("%s: not wiped", label)
			}
		}
	}
	m := f.mn["pq_kat"]
	var w *Wallet
	through("FromMnemonic", func() { w = must(FromMnemonic([]byte(m["words"].(string)), []byte(m["passphrase"].(string)))) })
	defer w.Close()
	var v string
	through("SealVault", func() { v = must(w.SealVault([]byte("correct horse 9"))) })
	through("OpenVault", func() { must(OpenVault(v, []byte("correct horse 9"), nil, nil)).Close() })
	through("Unlock", func() {
		w2 := f.fresh("pq_kat")
		must0(w2.Lock())
		must0(w2.Unlock(v, []byte("correct horse 9"), nil, nil))
	})
	var v2 string
	through("VaultRewrapPin", func() { v2 = must(VaultRewrapPin(v, []byte("correct horse 9"), []byte("battery staple 7"))) })
	through("VaultEnablePrf", func() {
		must(VaultEnablePrf(v2, []byte("battery staple 7"), bytes.Repeat([]byte{7}, 32), "c", []byte("s")))
	})
	through("SealLabelVault", func() {
		must(w.ImportNativeKey(0, bytes.Repeat([]byte{1}, 32))).Close()
		must(w.SealLabelVault("native-import:evm:0", []byte("correct horse 9")))
	})
	through("Verify", func() {
		g, sb := must2(Generate())
		defer g.Close()
		defer sb.Close()
		words := must(sb.Reveal())
		pos := must(sb.Challenge())
		ws := bytes.Fields(words)
		if !must(sb.Verify([][]byte{ws[pos[0]-1], ws[pos[1]-1], ws[pos[2]-1]})) {
			t.Error("verify")
		}
		e := must(sb.Take())
		if len(e) != 32 {
			t.Error("take")
		}
		Wipe(words)
		Wipe(e)
		if !bytes.Equal(e, make([]byte, 32)) {
			t.Error("Wipe")
		}
	})
	leaf := must(w.ExportPqzLeafRaw(0, 0))
	Wipe(leaf)
	if !bytes.Equal(leaf, make([]byte, 32)) {
		t.Error("Wipe(leaf)")
	}
}

func TestFixedSizeAndShortSecretsAreRefused(t *testing.T) {
	f := newFix(t)
	if err := f.w("pq_kat").Unlock("{}", nil, make([]byte, 31), nil); code(err) != "UAKeyData" {
		t.Fatal(err)
	}
	if _, err := AeadSeal(1, make([]byte, 31), make([]byte, 12), nil, []byte("x")); code(err) != "UAKeyData" {
		t.Fatal(err)
	}
	if _, err := AeadOpen(1, make([]byte, 32), make([]byte, 11), nil, make([]byte, 20)); code(err) != "UAKeyData" {
		t.Fatal(err)
	}
}

// --- keys.json ---

func TestKeysJSON(t *testing.T) {
	f := newFix(t)
	v := uaVec(t, "keys.json")
	falcon := Features()&FeatureFalcon != 0
	n := 0
	for _, r := range rows(v["ua"]) {
		kind := uint16(n32(r["kind"]))
		if (kind == 0x0132 || kind == 0x0135) && !falcon {
			continue
		}
		kd := must(f.key(f.w(r["mnemonic"].(string)), r["kind"], r["account"], r["index"]).KeyData())
		if hx(kd) != r["keyData"] {
			t.Errorf("%s: key data", r["name"])
		}
		if r["ua"] != nil {
			if id, err := ua.DeriveUA(kind, kd, false); err != nil || hx(id[:]) != r["ua"] {
				t.Errorf("%s: the own port's UA", r["name"])
			}
		}
		n++
	}
	if n < 184 {
		t.Fatal(n)
	}
	for _, r := range rows(v["native"]) {
		kd := must(f.native(r["mnemonic"].(string), r["network"].(string), n32(r["index"]), r["coinType"]).KeyData())
		if hex.EncodeToString(kd) != strings.TrimPrefix(r["publicKey"].(string), "0x") {
			t.Errorf("%s %v", r["network"], r["index"])
		}
	}
	for _, r := range rows(v["refusals"]) {
		w := f.w(r["mnemonic"].(string))
		var err error
		if r["what"] == "ua" {
			_, err = w.UAKey(uint16(n32(r["kind"])), n32(r["account"]), n32(r["index"]))
		} else {
			c := uint32(CoinDefault)
			if r["coinType"] != nil {
				c = n32(r["coinType"])
			}
			_, err = w.NativeKey(network(r["network"].(string)), n32(r["index"]), c)
		}
		if code(err) != "UA"+r["error"].(string) {
			t.Errorf("%s: %v", r["reason"], err)
		}
	}
}

// --- sign.json ---

var deterministic = map[uint16]bool{0x0101: true, 0x0102: true, 0x0106: true, 0x0107: true, 0x0108: true}

func TestSignJSONUAAndMember(t *testing.T) {
	f := newFix(t)
	v := uaVec(t, "sign.json")
	falcon := Features()&FeatureFalcon != 0
	exact := 0
	for _, r := range rows(v["ua"]) {
		kind := uint16(n32(r["kind"]))
		if (kind == 0x0132 || kind == 0x0135) && !falcon {
			continue
		}
		sig := must(f.key(f.w(r["mnemonic"].(string)), r["kind"], r["account"], r["index"]).SignUA(b32(r["purposeTag"]), b32(r["digest"])))
		if deterministic[kind] {
			if hx(sig) != r["signature"] {
				t.Errorf("%s %s", r["name"], r["purpose"])
			}
			exact++
		} else if kind != 0x0132 && kind != 0x0135 && len(sig) != len(b(r["signature"])) {
			t.Errorf("%s: length", r["name"])
		}
	}
	if exact < 10 {
		t.Fatal(exact)
	}
	for _, r := range rows(v["member"]) {
		kind := uint16(n32(r["kind"]))
		sig := must(f.key(f.w(r["mnemonic"].(string)), r["kind"], r["account"], r["index"]).SignMember(b32(r["structureUa"]), b32(r["structureUaMsg"])))
		if (deterministic[kind] && hx(sig) != r["signature"]) || len(sig) != len(b(r["signature"])) {
			t.Errorf("%s", r["name"])
		}
	}
}

func TestSignJSONPolicyTypedTx(t *testing.T) {
	f := newFix(t)
	v := uaVec(t, "sign.json")
	k := f.native("pq_kat", "evm", 0, nil)
	signed, refused := 0, 0
	for _, r := range rows(v["policy"]) {
		sig, err := k.SignTyped(js(r["td"]), js(r["expect"]))
		if _, ok := r["refused"]; ok {
			if code(err) != "UAPolicyRefused" {
				t.Errorf("%s: %v", r["id"], err)
			}
			refused++
			continue
		}
		if raw := must(k.SignDigestRaw(b32(r["digest"]))); err != nil || !bytes.Equal(sig, raw) {
			t.Errorf("%s: %v", r["id"], err)
		}
		signed++
	}
	if signed != 10 || refused != 14 {
		t.Fatal(signed, refused)
	}
	typed := v["typed"].(obj)
	for _, r := range rows(typed["generic"]) {
		if sig := must(k.SignTypedAny(js(r["td"]))); !bytes.Equal(sig, must(k.SignDigestRaw(b32(r["digest"])))) {
			t.Errorf("%s", r["id"])
		}
	}
	for _, r := range rows(typed["refusals"]) {
		if _, err := k.SignTypedAny(js(r["td"])); code(err) != "UAArgument" {
			t.Errorf("%s: %v", r["id"], err)
		}
	}
	tx := v["tx"].(obj)
	for _, r := range rows(tx["rows"]) {
		s := r["signer"].(obj)
		raw := must(f.native(s["mnemonic"].(string), s["network"].(string), n32(s["index"]), nil).SignTransaction(js(r["tx"])))
		if hx(raw) != r["raw"] {
			t.Errorf("type %v", r["tx"].(obj)["type"])
		}
	}
	for _, r := range rows(tx["refusals"]) {
		if _, err := k.SignTransaction(js(r["tx"])); code(err) != "UAArgument" {
			t.Errorf("%s: %v", r["id"], err)
		}
	}
	if _, err := f.key(f.w("pq_kat"), 0x0108, 0, 0).SignDigestRaw([32]byte{}); code(err) != "UARawDigestRefused" {
		t.Fatal(err)
	}
	if p := must(k.SignKeyProof([]byte("challenge"))); len(p) != 65 {
		t.Fatal(len(p))
	}
	if _, err := f.key(f.w("pq_kat"), 0x0101, 0, 0).SignKeyProof([]byte("challenge")); code(err) != "UAArgument" {
		t.Fatal(err)
	}
}

func TestSignJSONWebAuthn(t *testing.T) {
	v := uaVec(t, "sign.json")["webauthn"].(obj)
	for _, r := range rows(v["accepted"]) {
		ch := must(WebAuthnChallenge(b32(r["purposeTag"]), b32(r["digest"])))
		own := must(ua.UAMessage(0x0100, b32(r["purposeTag"]), b32(r["digest"])))
		if hx(ch[:]) != r["expectedChallenge"] || ch != own {
			t.Error("challenge")
		}
	}
	all := append(rows(v["accepted"]), rows(v["refusals"])...)
	for _, r := range all {
		got, err := WebAuthnAssertion(b(r["keyData"]), b32(r["expectedChallenge"]), b(r["authData"]), b(r["clientDataJSON"]), b32(r["r"]), b32(r["s"]))
		if e, ok := r["error"].(string); ok {
			if code(err) != "UA"+e {
				t.Errorf("%v: %v", r["case"], err)
			}
		} else if err != nil || hx(got) != r["assertion"] {
			t.Errorf("accepted: %v", err)
		}
	}
}

func abiWord(x int) []byte { return new(big.Int).SetInt64(int64(x)).FillBytes(make([]byte, 32)) }
func abiBytes(x []byte) []byte {
	return append(append(abiWord(len(x)), x...), make([]byte, (32-len(x)%32)%32)...)
}
func abiList(items [][]byte) []byte {
	out, offs, o := abiWord(len(items)), []byte{}, 32*len(items)
	for _, it := range items {
		offs = append(offs, abiWord(o)...)
		o += len(it)
	}
	return append(append(out, offs...), bytes.Join(items, nil)...)
}

// memberSigs is abi.encode(MemberSig[]) of a UASig JSON's members (ua8.rs encode_member_sigs).
func memberSigs(ms []any) []byte {
	if len(ms) == 0 {
		return nil
	}
	slots := [][]byte{}
	for _, m := range ms {
		m := m.(obj)
		inner := [][]byte{}
		for _, x := range m["members"].([]any) {
			x := x.(obj)
			inner = append(inner, append(append(abiWord(int(x["index"].(float64))), abiWord(64)...), abiBytes(b(x["sig"]))...))
		}
		lst := abiList(inner)
		s := append(append(append(abiWord(int(m["index"].(float64))), abiWord(96)...), abiWord(96+len(lst))...), lst...)
		slots = append(slots, append(s, abiBytes(b(m["sig"]))...))
	}
	return append(abiWord(32), abiList(slots)...)
}

func TestSignJSONMsigThroughUASig(t *testing.T) {
	f := newFix(t)
	built, refused := 0, 0
	for _, r := range rows(uaVec(t, "sign.json")["msig"]) {
		keys := []*Key{}
		pos := func(x obj) int {
			k := x["key"].(obj)
			keys = append(keys, f.key(f.w(k["mnemonic"].(string)), k["kind"], k["account"], k["index"]))
			return len(keys) - 1
		}
		slots := []obj{}
		for _, s := range rows(r["slots"]) {
			if ms, ok := s["members"]; ok {
				inner := []obj{}
				for _, x := range rows(ms) {
					inner = append(inner, obj{"index": x["index"], "key": pos(x)})
				}
				slots = append(slots, obj{"index": s["index"], "members": inner})
			} else {
				slots = append(slots, obj{"index": s["index"], "key": pos(s)})
			}
		}
		m := obj{"keyData": r["keyData"], "slots": slots}
		if in, ok := r["inner"]; ok {
			m["inner"] = in
		}
		got, err := UASig(js(obj{"purpose": r["purposeTag"], "digest": r["digest"], "msig": m}), keys)
		if ref, ok := r["refused"].(string); ok {
			if code(err) != ref {
				t.Errorf("%s: %v", r["case"], err)
			}
			refused++
			continue
		}
		var sig obj
		if err != nil || json.Unmarshal([]byte(got), &sig) != nil || hx(memberSigs(sig["members"].([]any))) != r["memberSigs"] {
			t.Errorf("%s: %v", r["case"], err)
		}
		built++
	}
	if built != 3 || refused != 4 {
		t.Fatal(built, refused)
	}
}

// --- kem.json ---

func TestKemJSON(t *testing.T) {
	f := newFix(t)
	v := uaVec(t, "kem.json")
	for _, r := range rows(v["keys"]) {
		if pk := must(f.kem(r, nil).KemPk()); hx(pk) != r["kemPk"] {
			t.Errorf("kind %v version %v", r["kind"], r["version"])
		}
	}
	for _, r := range rows(v["refusals"]) {
		ver, ok := r["version"].(float64)
		if _, has := r["mnemonic"]; !has || !ok || ver >= 1<<63 {
			continue // the msig row; 2^64 is not a uint64
		}
		_, err := f.key(f.w(r["mnemonic"].(string)), r["kind"], r["account"], r["index"]).KemKey(uint64(ver))
		if code(err) != "UA"+r["error"].(string) {
			t.Errorf("kind %v: %v", r["kind"], err)
		}
	}
	for _, r := range rows(v["encapsRefusals"]) {
		if _, _, _, err := KemEncaps(b(r["kemPk"])); code(err) != "UA"+r["error"].(string) {
			t.Errorf("%s: %v", r["id"], err)
		}
	}
	k0 := rows(v["keys"])[0]
	ct, e, ss, err := KemEncaps(b(k0["kemPk"]))
	if err != nil || !bytes.Equal(must(f.kem(k0, nil).Decaps(ct, e)), ss) {
		t.Fatal("round trip", err)
	}
	for _, r := range rows(v["decaps"]) {
		if len(b(r["x25519Eph"])) != 32 {
			continue // a 31-byte E is not a [32]byte
		}
		got, err := f.kem(r["key"].(obj), nil).Decaps(b(r["mlkemCt"]), b32(r["x25519Eph"]))
		if e, ok := r["error"].(string); ok && e != "" {
			if code(err) != "UA"+e {
				t.Errorf("%s: %v", r["id"], err)
			}
		} else if err != nil || hx(got) != r["ss"] {
			t.Errorf("%s: %v", r["id"], err)
		}
	}
	eph := must(KemEphemeral())
	defer eph.Close()
	if pk := must(eph.KemPk()); pk[0] != 1 {
		t.Fatal(pk[0])
	}
}

// --- seal.json ---

func TestSealJSONRowsAndRefusals(t *testing.T) {
	f := newFix(t)
	v := uaVec(t, "seal.json")
	for _, r := range rows(v["seal"]) {
		rc := r["recipient"].(obj)
		if _, ok := rc["kind"]; !ok {
			continue // an ephemeral recipient from a fixed seed: under `vectors` only
		}
		kk := f.kem(rc, nil)
		pt := must(kk.Open(r["purpose"].(string), b(r["aad"]), b(r["mlkemCt"]), b32(r["x25519Eph"]), b(r["ciphertext"])))
		if hx(pt) != r["pt"] {
			t.Errorf("%s", r["id"])
		}
		mct, e, ct, err := Seal(b(r["kemPk"]), r["purpose"].(string), b(r["aad"]), pt)
		if err != nil || len(mct) != KemCtLen || len(ct) != len(pt)+16 || !bytes.Equal(must(kk.Open(r["purpose"].(string), b(r["aad"]), mct, e, ct)), pt) {
			t.Errorf("%s: fresh seal %v", r["id"], err)
		}
	}
	ref := v["refusals"].(obj)
	var base obj
	for _, r := range rows(v["seal"]) {
		if r["id"] == ref["base"] {
			base = r
		}
	}
	n := KemCtLen
	for _, r := range rows(ref["rows"]) {
		wire := b(base["wire"])
		if w, ok := r["wire"]; ok {
			wire = b(w)
		}
		if wire[0] != 1 || wire[1] != 1 {
			continue // version or scheme 2: the named fields carry neither
		}
		key := ref["key"].(obj)
		if k, ok := r["key"]; ok {
			key = k.(obj)
		}
		aad, purpose := b(base["aad"]), base["purpose"].(string)
		if a, ok := r["aad"]; ok {
			aad = b(a)
		}
		if p, ok := r["purpose"]; ok {
			purpose = p.(string)
		}
		var eph [32]byte
		copy(eph[:], wire[2+n:2+n+32])
		if _, err := f.kem(key, nil).Open(purpose, aad, wire[2:2+n], eph, wire[2+n+32:]); code(err) != "UA"+r["error"].(string) {
			t.Errorf("%s: %v", r["id"], err)
		}
	}
	pk := b(rows(v["seal"])[0]["kemPk"])
	for _, r := range rows(v["argumentRefusals"]) {
		if _, _, _, err := Seal(pk, r["purpose"].(string), nil, make([]byte, int(r["ptLength"].(float64)))); code(err) != "UA"+r["error"].(string) {
			t.Errorf("%s: %v", r["id"], err)
		}
	}
}

func (f *fix) opener(r obj) *KemKey { return f.kem(r["opener"].(obj)["kem"].(obj), nil) }

func TestSealJSONContainersAndAcceptance(t *testing.T) {
	f := newFix(t)
	v := uaVec(t, "seal.json")
	n := 0
	for _, r := range rows(v["containers"]) {
		if _, ok := r["opener"].(obj)["session"]; ok {
			continue // a link container opens only through its session
		}
		pt, err := f.opener(r).OpenContainer(js(r["container"]), js(r["expect"]), js(r["members"]), js(r["accepted"]))
		if err != nil || hx(pt) != r["pt"] {
			t.Errorf("%s: %v", r["id"], err)
		}
		if r["accepted"] != nil {
			if _, err := f.opener(r).OpenContainer(js(r["container"]), js(r["expect"]), js(r["members"]), ""); code(err) != "UAContainerSender" {
				t.Errorf("%s without accepted: %v", r["id"], err)
			}
		}
		n++
	}
	if n != 3 {
		t.Fatal(n)
	}
	n = 0
	for _, r := range rows(v["acceptance"]) {
		if _, ok := r["link"]; ok {
			continue // a fixed session exists under `vectors` only
		}
		var err error
		kk := f.opener(r)
		if rs, _ := r["restore"].(bool); rs {
			var w *Wallet
			if w, err = RestoreBackup(kk, js(r["container"]), js(r["expect"]), js(r["members"]), js(r["accepted"]), nil, nil); w != nil {
				w.Close()
			}
		} else {
			_, err = kk.OpenContainer(js(r["container"]), js(r["expect"]), js(r["members"]), js(r["accepted"]))
		}
		want := ""
		if e, ok := r["error"].(string); ok && e != "" {
			want = "UA" + e
		}
		if code(err) != want {
			t.Errorf("%s: %v", r["id"], err)
		}
		n++
	}
	if n != 28 {
		t.Fatal(n)
	}
}

func uaOf(t *testing.T, kind uint16, k *Key) string {
	id := must(ua.DeriveUA(kind, must(k.KeyData()), false))
	return hx(id[:])
}

func TestSealJSONReplayBackupRows(t *testing.T) {
	f := newFix(t)
	v := uaVec(t, "seal.json")
	pk := b(rows(uaVec(t, "kem.json")["keys"])[0]["kemPk"])
	n := 0
	for _, r := range rows(v["replay"]) {
		if r["kind"] != "backup" {
			continue // link windows: a session starts now in a release build
		}
		var cur *Wallet
		if c, ok := r["current"].(obj); ok {
			mid := "pq_kat"
			if uaOf(t, 0x0102, f.key(f.w("twelve_words"), 0x0102, 0, 0)) == c["ua"] {
				mid = "twelve_words"
			}
			cur = f.fresh(mid)
			k := f.key(cur, 0x0102, 0, 0)
			rk := must(f.key(f.w("pq_kat"), 0x0130, 0, 0).KeyData())
			for i := 0; i < int(c["generation"].(float64)); i++ {
				must(cur.BackupSeal(k, []Recipient{{Kind: 0x0130, KeyData: rk, KemPk: pk}}))
			}
		}
		fn := RestoreBackup
		if ar, _ := r["allowRollback"].(bool); ar {
			fn = RestoreBackupRollback
		}
		w, err := fn(f.opener(r), js(r["container"]), js(r["expect"]), "", "", cur, nil)
		if e, ok := r["error"].(string); ok && e != "" {
			if code(err) != "UA"+e {
				t.Errorf("%s: %v", r["id"], err)
			}
		} else if err != nil || (w != nil) != r["install"].(bool) {
			t.Errorf("%s: %v installed %v", r["id"], err, w != nil)
		}
		if w != nil {
			w.Close()
		}
		n++
	}
	if n != 6 {
		t.Fatal(n)
	}
}

func TestBackupSealRestoresAWallet(t *testing.T) {
	f := newFix(t)
	w := f.fresh("twelve_words")
	sender := f.key(w, 0x0102, 0, 0)
	f.key(w, 0x0101, 0, 1)
	k0 := rows(uaVec(t, "kem.json")["keys"])[0]
	rkey := f.key(f.w("pq_kat"), 0x0130, 0, 0)
	rk, pk := must(rkey.KeyData()), b(k0["kemPk"])
	var cs []obj
	if err := json.Unmarshal([]byte(must(w.BackupSeal(sender, []Recipient{{Kind: 0x0130, KeyData: rk, KemPk: pk}, {KemPk: pk, Ephemeral: true}}))), &cs); err != nil || len(cs) != 2 {
		t.Fatal(err, len(cs))
	}
	expect := obj{"purpose": "scaas/backup/v1", "sender": obj{"ua": uaOf(t, 0x0102, sender)}, "recipient": obj{"ua": uaOf(t, 0x0130, rkey), "version": 0}}
	out := must(RestoreBackup(f.kem(k0, nil), js(cs[0]), js(expect), "", "", nil, nil))
	defer out.Close()
	if !bytes.Equal(must(f.key(out, 0x0102, 0, 0).KeyData()), must(sender.KeyData())) {
		t.Fatal("restored key")
	}
	var m obj
	_ = json.Unmarshal([]byte(must(out.ManifestJSON())), &m)
	if m["backupGeneration"].(float64) != 1 || len(m["entries"].([]any)) != 2 {
		t.Fatal(m)
	}
	if _, err := w.BackupSeal(sender, nil); code(err) != "UAArgument" {
		t.Fatal(err)
	}
}

func TestLinkSessionAndLinkSeal(t *testing.T) {
	f := newFix(t)
	v := uaVec(t, "seal.json")
	s := must(NewLinkSession())
	defer s.Close()
	pk := must(s.KemPk())
	if !regexp.MustCompile(`^[0-9]{8}$`).MatchString(must(s.ShortCode())) {
		t.Fatal("short code")
	}
	var r obj
	for _, x := range rows(v["containers"]) {
		if _, ok := x["opener"].(obj)["session"]; ok {
			r = x
		}
	}
	h := ua.Keccak256(pk)
	expect := r["expect"].(obj)
	expect["recipient"] = obj{"kemPkHash": hx(h[:])}
	if _, err := FromLink(s, js(r["container"]), js(expect), "", "", nil); code(err) != "UAContainerReplay" {
		t.Fatal(err)
	}
	if _, err := FromLink(s, js(r["container"]), js(expect), "", "", nil); code(err) != "UAKeyRevoked" {
		t.Fatal(err)
	}
	w := f.fresh("twelve_words")
	key := f.key(w, 0x0102, 0, 0)
	must(w.ImportNativeKey(0, bytes.Repeat([]byte{3}, 32))).Close()
	for _, wrong := range []bool{false, true} {
		s := must(NewLinkSession())
		defer s.Close()
		pk, sc := must(s.KemPk()), must(s.ShortCode())
		if wrong {
			sc = map[bool]string{true: "00000001", false: "00000000"}[sc == "00000000"]
		}
		c := must(w.LinkSeal(key, pk, sc))
		h := ua.Keccak256(pk)
		ex := js(obj{"purpose": "scaas/link/v1", "sender": obj{"ua": uaOf(t, 0x0102, key)}, "recipient": obj{"kemPkHash": hx(h[:])}})
		out, err := FromLink(s, c, ex, "", "", nil)
		if wrong {
			if code(err) != "UASealOpen" {
				t.Fatal(err)
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		defer out.Close()
		if !bytes.Equal(must(f.key(out, 0x0102, 0, 0).KeyData()), must(key.KeyData())) {
			t.Fatal("linked key")
		}
		if a, b := must(out.ManifestJSON()), must(w.ManifestJSON()); !strings.Contains(a, `"imports":[{"network":"evm","n":0}]`) || !strings.Contains(b, `"imports":[{"network":"evm","n":0}]`) {
			t.Fatal(a)
		}
	}
	if _, err := w.LinkSeal(key, pk[:len(pk)-1], "12345678"); code(err) != "UAKemCheck" {
		t.Fatal(err)
	}
}

// --- vault.json ---

func unlockOf(u obj) (pin, prf []byte) {
	if p, ok := u["pin"].(string); ok {
		pin = []byte(p)
	}
	if p, ok := u["prfOutput"]; ok {
		prf = b(p)
	}
	return
}

func TestVaultJSON(t *testing.T) {
	f := newFix(t)
	v := uaVec(t, "vault.json")
	byEntropy := map[string]string{}
	for id, m := range f.mn {
		if m["passphrase"] == "" {
			byEntropy[m["entropy"].(string)] = id
		}
	}
	for _, r := range rows(v["vaults"]) {
		pin, prf := unlockOf(r["unlock"].(obj))
		w := must(OpenVault(js(r["vault"]), pin, prf, nil))
		defer w.Close()
		want := must(f.key(f.w(byEntropy[r["plaintext"].(string)]), 0x0102, 0, 0).KeyData())
		if !bytes.Equal(must(f.key(w, 0x0102, 0, 0).KeyData()), want) {
			t.Errorf("%s", r["id"])
		}
	}
	for _, r := range rows(v["refusals"]) {
		pin, prf := unlockOf(r["unlock"].(obj))
		w, err := OpenVault(js(r["vault"]), pin, prf, nil)
		if code(err) != "UA"+r["error"].(string) {
			t.Errorf("%s: %v", r["id"], err)
		}
		if w != nil {
			w.Close()
		}
	}
	if _, err := OpenVault(js(rows(v["vaults"])[0]["vault"]), nil, nil, nil); code(err) != "UAArgument" {
		t.Fatal("neither secret:", err)
	}
	tw := f.w("twelve_words")
	v1 := must(tw.SealVault([]byte("correct horse 9")))
	if _, err := tw.SealVault([]byte("12345678")); code(err) != "UAArgument" {
		t.Fatal("the new-passphrase policy:", err)
	}
	if must(VaultNeedsRewrap(v1)) {
		t.Fatal("rewrap")
	}
	v2 := must(VaultRewrapPin(v1, []byte("correct horse 9"), []byte("battery staple 7")))
	prf := make([]byte, 32)
	for i := range prf {
		prf[i] = byte(i)
	}
	v3 := must(VaultEnablePrf(v2, []byte("battery staple 7"), prf, "cred-1", []byte("salt")))
	want := must(f.key(tw, 0x0102, 0, 0).KeyData())
	for _, c := range []struct {
		v        string
		pin, prf []byte
	}{{v1, []byte("correct horse 9"), nil}, {v2, []byte("battery staple 7"), nil}, {v3, nil, prf}} {
		w := must(OpenVault(c.v, c.pin, c.prf, nil))
		defer w.Close()
		if !bytes.Equal(must(f.key(w, 0x0102, 0, 0).KeyData()), want) {
			t.Fatal("reopened")
		}
	}
	if _, err := OpenVault(v2, []byte("correct horse 9"), nil, nil); code(err) != "UAVaultOpen" {
		t.Fatal(err)
	}
}

// --- custody ---

func TestCustody(t *testing.T) {
	f := newFix(t)
	w := f.fresh("twelve_words")
	v := must(w.SealVault([]byte("correct horse 9")))
	k := f.key(w, 0x0101, 0, 0)
	tag := must(ua.PurposeTag("metatx"))
	before := must(k.SignUA(tag, [32]byte{}))
	imp := must(w.ImportNativeKey(0, bytes.Repeat([]byte{1}, 32)))
	defer imp.Close()
	rawBefore := must(imp.SignDigestRaw([32]byte{9}))
	label := must(w.SealLabelVault("native-import:evm:0", []byte("correct horse 9")))
	must0(w.Lock())
	if _, err := k.SignUA(tag, [32]byte{}); code(err) != "UAKeyRevoked" {
		t.Fatal(err)
	}
	if _, err := w.UAKey(0x0101, 0, 0); code(err) != "UAWalletLocked" {
		t.Fatal(err)
	}
	if mp := must(w.MemoryProtection()); mp != (MemoryProtection{}) {
		t.Fatal(mp)
	}
	must0(w.Unlock(v, []byte("correct horse 9"), nil, nil))
	if _, err := k.SignUA(tag, [32]byte{}); code(err) != "UAKeyRevoked" {
		t.Fatal("unlock revived:", err)
	}
	if !bytes.Equal(must(f.key(w, 0x0101, 0, 0).SignUA(tag, [32]byte{})), before) {
		t.Fatal("after unlock")
	}
	if _, err := w.ImportedKey(0, 0); code(err) != "UAArgument" {
		t.Fatal("held before its vault opens:", err)
	}
	if err := w.OpenLabelVault(label, []byte("wrong horse 9"), nil); code(err) != "UAVaultOpen" {
		t.Fatal(err)
	}
	must0(w.OpenLabelVault(label, []byte("correct horse 9"), nil))
	k2 := must(w.ImportedKey(0, 0))
	defer k2.Close()
	if !bytes.Equal(must(k2.SignDigestRaw([32]byte{9})), rawBefore) {
		t.Fatal("imported key")
	}
	if _, err := w.ImportedKey(1, 0); code(err) != "UAArgument" {
		t.Fatal("CLI-SGN-11:", err)
	}
	other := must(f.w("pq_kat").SealVault([]byte("correct horse 9")))
	must0(w.Lock())
	if err := w.Unlock(other, []byte("correct horse 9"), nil, nil); code(err) != "UAWalletMismatch" {
		t.Fatal(err)
	}
	var m []obj
	_ = json.Unmarshal([]byte(must(f.w("pq_kat").DiscoverCandidates(0x0102, 0, 3))), &m)
	if len(m) != 3 || m[2]["index"].(float64) != 2 {
		t.Fatal(m)
	}
	mp := must(f.w("pq_kat").MemoryProtection())
	if mp.Chunks < 1 || (Features()&FeatureMlock != 0 && mp.NoDump != mp.Chunks) {
		t.Fatal(mp)
	}
}

func TestChildHandleAfterWalletFreeIsKeyRevoked(t *testing.T) {
	f := newFix(t)
	m := f.mn["pq_kat"]
	w := must(FromMnemonic([]byte(m["words"].(string)), nil))
	k := must(w.UAKey(0x0130, 0, 0))
	defer k.Close()
	kk := must(k.KemKey(0))
	defer kk.Close()
	n := must(w.NativeKey(0, 0, CoinDefault))
	defer n.Close()
	w.Close()
	if _, err := k.SignUA(must(ua.PurposeTag("metatx")), [32]byte{}); code(err) != "UAKeyRevoked" {
		t.Fatal(err)
	}
	if _, err := n.SignDigestRaw([32]byte{}); code(err) != "UAKeyRevoked" {
		t.Fatal(err)
	}
	if _, err := kk.Decaps(make([]byte, KemCtLen), [32]byte{1}); code(err) != "UAKeyRevoked" {
		t.Fatal(err)
	}
	if kd := must(k.KeyData()); len(kd) != 1312 {
		t.Fatal("public data", len(kd))
	}
}

func TestSeedBackupSequence(t *testing.T) {
	f := newFix(t)
	w, sb := must2(Generate())
	defer w.Close()
	defer sb.Close()
	words := must(sb.Reveal())
	ws := bytes.Fields(words)
	if len(ws) != 24 {
		t.Fatal(len(ws))
	}
	if _, err := sb.Reveal(); code(err) != "UAArgument" {
		t.Fatal("shown once:", err)
	}
	pos := must(sb.Challenge())
	if e := must(sb.Take()); e != nil {
		t.Fatal("taken before the words are confirmed")
	}
	if must(sb.Verify([][]byte{[]byte("x"), []byte("y"), []byte("z")})) {
		t.Fatal("wrong words accepted")
	}
	pos = must(sb.Challenge())
	if !must(sb.Verify([][]byte{ws[pos[0]-1], ws[pos[1]-1], ws[pos[2]-1]})) {
		t.Fatal("verify")
	}
	if e := must(sb.Take()); len(e) != 32 {
		t.Fatal(len(e))
	}
	if e := must(sb.Take()); e != nil {
		t.Fatal("taken twice")
	}
	w2 := must(FromMnemonic(words, nil))
	defer w2.Close()
	if !bytes.Equal(must(f.key(w2, 0x0102, 0, 0).KeyData()), must(f.key(w, 0x0102, 0, 0).KeyData())) {
		t.Fatal("same wallet")
	}
}

// --- errors carry no input ---

func TestErrorStringsNeverContainAnInput(t *testing.T) {
	f := newFix(t)
	secrets := []string{"zebrasecretword", "Pa55-word-Secret", "SECRETvalue0xdead", "deadbeefcafe1234"}
	w := f.w("pq_kat")
	evm, kk := f.native("pq_kat", "evm", 0, nil), f.kem(rows(uaVec(t, "kem.json")["keys"])[0], nil)
	qk := must(w.PqzKey(0, 0))
	defer qk.Close()
	zk := must(w.ZetherKey(60, 0, 7))
	defer zk.Close()
	words := strings.Join(append(strings.Fields(f.mn["pq_kat"]["words"].(string))[:23], "zebrasecretword"), " ")
	td := js(obj{"types": obj{"EIP712Domain": []any{}}, "primaryType": "SECRETvalue0xdead", "domain": obj{}, "message": obj{"v": "SECRETvalue0xdead"}})
	vault := js(rows(uaVec(t, "vault.json")["vaults"])[0]["vault"])
	calls := []func() error{
		func() error { _, err := FromMnemonic([]byte(words), []byte("Pa55-word-Secret")); return err },
		func() error {
			_, err := OpenVault(vault, []byte("Pa55-word-Secret"), nil, []byte("zebrasecretword"))
			return err
		},
		func() error {
			_, err := evm.SignTyped(td, js(obj{"check": "Payment", "account": "0xdeadbeefcafe1234", "payee": "Pa55-word-Secret"}))
			return err
		},
		func() error { _, err := evm.SignTransaction(`{"type":2,"chainId":"SECRETvalue0xdead"}`); return err },
		func() error {
			_, err := kk.OpenContainer(`{"v":"Pa55-word-Secret"}`, `{"purpose":"zebrasecretword"}`, "", "")
			return err
		},
		func() error { _, err := qk.Call("zebrasecretword", "{}"); return err },
		func() error {
			_, err := qk.Call("dec", `{"ct":"0xdeadbeefcafe1234","window":"SECRETvalue0xdead"}`)
			return err
		},
		func() error {
			_, err := zk.Call("proveTransfer", `{"key":{"mnemonic":"zebrasecretword Pa55-word-Secret"}}`)
			return err
		},
		func() error {
			_, err := VaultRewrapPin(vault, []byte("Pa55-word-Secret"), []byte("zebrasecretword"))
			return err
		},
	}
	for i, c := range calls {
		err := c()
		if err == nil {
			t.Fatalf("%d: no error", i)
		}
		for _, s := range secrets {
			for j := 0; j+6 <= len(s); j++ {
				if strings.Contains(err.Error(), s[j:j+6]) {
					t.Errorf("%d: %q echoes %q", i, err, s)
				}
			}
		}
	}
}

func TestAeadHkdfHmac(t *testing.T) {
	mac := must(HmacSha256(bytes.Repeat([]byte{0x0b}, 20), []byte("Hi There")))
	if hex.EncodeToString(mac[:]) != "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7" {
		t.Fatal("RFC 4231 case 1")
	}
	salt, info := make([]byte, 13), make([]byte, 10)
	for i := range salt {
		salt[i] = byte(i)
	}
	for i := range info {
		info[i] = byte(0xf0 + i)
	}
	if okm := must(HkdfSha256(bytes.Repeat([]byte{0x0b}, 22), salt, info, 42)); hex.EncodeToString(okm) != "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865" {
		t.Fatal("RFC 5869 A.1")
	}
	key, nonce := bytes.Repeat([]byte{5}, 32), make([]byte, 12)
	for _, alg := range []uint32{AeadAes256Gcm, AeadAes256GcmSiv} {
		ct := must(AeadSeal(alg, key, nonce, []byte("aad"), []byte("plaintext")))
		if pt := must(AeadOpen(alg, key, nonce, []byte("aad"), ct)); string(pt) != "plaintext" {
			t.Fatal(alg)
		}
		ct[len(ct)-1] ^= 1
		if _, err := AeadOpen(alg, key, nonce, []byte("aad"), ct); code(err) != "UAAead" {
			t.Fatal(err)
		}
	}
	if _, err := AeadSeal(3, key, nonce, nil, []byte("x")); code(err) != "UAArgument" {
		t.Fatal(err)
	}
}

// --- the Zether facade ---

func TestZether(t *testing.T) {
	f := newFix(t)
	r33 := vec(t, "clients/zether-prover/vectors/r33_keys.json")
	w := must(FromMnemonic([]byte(r33["mnemonic"].(string)), nil))
	defer w.Close()
	bls := r33["bls12381"].(obj)
	for _, r := range rows(bls["keys"]) {
		p := strings.Split(r["path"].(string), "/")
		var c, a, u uint32
		fmt.Sscan(p[2], &c)
		fmt.Sscan(p[3], &a)
		fmt.Sscan(p[4], &u)
		k := must(w.ZetherKey(c, a, u))
		defer k.Close()
		y, id := must2(k.Public())
		if hx(y) != r["Y"] || hx(id[:]) != r["UA"] {
			t.Errorf("%s", r["path"])
		}
	}
	if _, err := w.ZetherKey(60, 0, 9); code(err) != "UAArgument" {
		t.Fatal(err)
	}
	k := must(w.ZetherKey(60, 0, 7))
	defer k.Close()
	var pop obj
	_ = json.Unmarshal([]byte(must(k.Call("pop", `{"curve":"bls12381"}`))), &pop)
	want := rows(bls["keys"])[0]["pop"].(obj)
	for _, fld := range []string{"popDigest", "registrationDigest", "uaMsg"} {
		if pop[fld] != want[fld] {
			t.Error(fld)
		}
	}
	tv := vec(t, "clients/zether-prover/vectors/transfer_bls12381.json")
	req := tv["request"].(obj)
	delete(req, "key")
	delete(req, "includeWitness")
	// ARCH-POS-13 (T15c, T14b): no command of a release build decrypts a caller's ciphertext (the words commands: below)
	for cmd, r := range map[string]obj{"checkBalance": {"acc": req["acc"], "balance": req["balance"]}, "proveTransfer": req} {
		if _, err := k.Call(cmd, js(r)); code(err) != "UAArgument" {
			t.Fatal(cmd, err)
		}
	}
	if _, err := k.Call("pop", `{"key":{"seed":"0x11"}}`); code(err) != "UAArgument" {
		t.Fatal(err)
	}
	zj := uaVec(t, "zether.json")
	for _, r := range rows(zj["cacheBox"]) {
		zk := must(f.fresh(r["mnemonic"].(string)).ZetherKey(n32(r["coin"]), n32(r["account"]), n32(r["use"])))
		defer zk.Close()
		pt := must(zk.OpenBalanceCache(js(r["box"])))
		if hx(pt) != r["plaintext"] || !bytes.Equal(must(zk.OpenBalanceCache(must(zk.SealBalanceCache(pt)))), pt) {
			t.Errorf("%s", r["id"])
		}
	}
	for _, r := range rows(zj["cacheRefusals"]) {
		zk := must(f.fresh(r["mnemonic"].(string)).ZetherKey(n32(r["coin"]), n32(r["account"]), n32(r["use"])))
		defer zk.Close()
		if _, err := zk.OpenBalanceCache(js(r["box"])); code(err) != "UAAead" {
			t.Errorf("%s: %v", r["id"], err)
		}
	}
	y, _ := must2(k.Public())
	must0(w.Lock())
	if _, err := k.Call("pop", "{}"); code(err) != "UAKeyRevoked" {
		t.Fatal(err)
	}
	if y2, _ := must2(k.Public()); !bytes.Equal(y, y2) {
		t.Fatal("public data stays readable")
	}
}

// commands is scaas-ua `facade::<name>::COMMANDS` read from its source (T15g): the release commands and the `vectors`-only raw
// forms. A test asserts that a command is in it, never that it equals a list (spec no-decryption-oracle §4.13).
func commands(t *testing.T, name string) (release, raw []string) {
	src, err := os.ReadFile("../../ua-rs/src/facade/" + name + ".rs")
	if err != nil {
		t.Fatal(err)
	}
	body := string(src)[strings.Index(string(src), "pub const COMMANDS: &[&str] = &["):]
	gated := false
	for _, ln := range strings.Split(body[:strings.Index(body, "];")], "\n")[1:] {
		ln = strings.TrimSpace(ln)
		if ln == `#[cfg(feature = "vectors")]` {
			gated = true
		} else if strings.HasPrefix(ln, `"`) {
			if gated {
				raw = append(raw, strings.Trim(ln, `",`))
			} else {
				release = append(release, strings.Trim(ln, `",`))
			}
			gated = false
		}
	}
	return
}

func in(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// T15g (ARCH-POS-13): the words commands on the forge rows (smartcontracts/vectors/zether/state.json; the holders are
// r33_keys.json's): each in COMMANDS, the balances the contract's; another holder's words refused before the key (ua-rs
// tests/facade_zether_state.rs counts the key's uses); every `vectors`-only raw form refused by the release library.
func TestZetherWordsOnTheForgeRows(t *testing.T) {
	release, raw := commands(t, "zether")
	if !in(release, "balance") || !in(release, "pendingBalance") || !in(raw, "decrypt") || !in(raw, "decryptPending") {
		t.Fatal(release, raw)
	}
	st := vec(t, "smartcontracts/vectors/zether/state.json")
	row := map[string]obj{}
	for _, r := range rows(st["accounts"]) {
		row[strings.Split(r["name"].(string), ":")[0]] = r
	}
	words := func(name string) string {
		r := obj{"ua": row[name]["ua"], "account": row[name]["account"], "accountData": row[name]["accountData"], "tableBits": 18, "boundBits": 20}
		for _, f := range []string{"family", "chainId", "chainUid", "token", "block", "psid"} {
			r[f] = st[f]
		}
		return js(r)
	}
	r33 := vec(t, "clients/zether-prover/vectors/r33_keys.json")
	w := must(FromMnemonic([]byte(r33["mnemonic"].(string)), nil))
	defer w.Close()
	alice, bob := must(w.ZetherKey(60, 0, 7)), must(w.ZetherKey(60, 1, 7))
	defer alice.Close()
	defer bob.Close()
	amount := func(k *ZetherKey, cmd, name string) any {
		var out obj
		must0(json.Unmarshal([]byte(must(k.Call(cmd, words(name)))), &out))
		return out["amount"]
	}
	if got, want := amount(alice, "balance", "alice"), fmt.Sprint(row["alice"]["balance"]); got != want {
		t.Fatal(got, want)
	}
	if got, want := amount(bob, "pendingBalance", "bob"), fmt.Sprint(row["bob"]["pending"]); got != want {
		t.Fatal(got, want)
	}
	if _, err := bob.Call("balance", words("alice")); code(err) != "UAArgument" {
		t.Fatal("another holder's words:", err)
	}
	for _, c := range raw {
		if _, err := alice.Call(c, "{}"); code(err) != "UAArgument" {
			t.Fatal(c, err)
		}
	}
}

// T15g (ARCH-POS-13): `balance` on a forge row (smartcontracts/vectors/pqz/n2304-kmax4096/state.json): in COMMANDS; the forge
// keys are mocked, so the words bind to no wallet key and are refused (UAArgument), with the other set's psid UAPqzSetMismatch,
// both before the key (ua-rs tests/facade_pqz_state.rs counts the key's uses); every `vectors`-only raw form refused.
func TestPqzWordsOnTheForgeRows(t *testing.T) {
	release, raw := commands(t, "pqz")
	if !in(release, "balance") || !in(raw, "dec") {
		t.Fatal(release, raw)
	}
	st := vec(t, "smartcontracts/vectors/pqz/n2304-kmax4096/state.json")
	a := rows(st["accounts"])[0]
	words := obj{"chainUid": st["chainUid"], "token": st["token"], "psid": st["psid"]}
	for _, f := range []string{"ua", "block", "account", "pending", "accWords", "blobs", "keyRecord"} {
		words[f] = a[f]
	}
	f := newFix(t)
	k := must(f.fresh("pq_kat").PqzKey(0, 0))
	defer k.Close()
	if _, err := k.Call("balance", js(words)); code(err) != "UAArgument" {
		t.Fatal(err)
	}
	words["psid"] = pqzl2048
	if _, err := k.Call("balance", js(words)); code(err) != "UAPqzSetMismatch" {
		t.Fatal(err)
	}
	for _, c := range raw {
		if _, err := k.Call(c, "{}"); code(err) != "UAArgument" {
			t.Fatal(c, err)
		}
	}
	// T15i: words rows for wallet keys (smartcontracts/vectors/pqz/n2304-kmax4096/wallet_state.json, written by ua-rs under
	// `vectors`, gen_wallet_state.sh): each row's own handle decrypts its balance
	w := f.fresh("pq_kat")
	for _, r := range rows(vec(t, "smartcontracts/vectors/pqz/n2304-kmax4096/wallet_state.json")["rows"]) {
		q := must(w.PqzKey(uint32(r["account"].(float64)), uint32(r["index"].(float64))))
		out := must(q.Call("balance", js(r["request"])))
		q.Close()
		var got obj
		if err := json.Unmarshal([]byte(out), &got); err != nil || got["value"] != r["value"] {
			t.Fatal(r["name"], out, err)
		}
	}
}

// --- the PQZ facade ---

const pqzl2304 = "0xef1ffbcbd05394f8276e50a6c254022edf53bbd08a56e22aadddac2b9b90336e"
const pqzl2048 = "0xc752e7f57778114dbfaac5d43843577b54e13e3ed162517145a37b5a3ec6cdfe"

func TestPqz(t *testing.T) {
	f := newFix(t)
	if Features()&FeaturePqz == 0 || Features()&FeaturePqzSetN2304Kmax4096 == 0 {
		t.Fatal("pqz n2304-kmax4096 in the default build")
	}
	var s obj
	_ = json.Unmarshal([]byte(must(PqzSet())), &s)
	if s["set"] != "n2304-kmax4096" || s["pqzlId"] != pqzl2304 {
		t.Fatal(s)
	}
	must0(PqzCheckSet(js(s)))
	s["set"] = "n2048-kmax1024"
	if err := PqzCheckSet(js(s)); code(err) != "UAPqzSetMismatch" {
		t.Fatal(err)
	}
	m := f.mn["pq_kat"]
	seed := must(pbkdf2.Key(sha512.New, m["words"].(string), []byte("mnemonic"+m["passphrase"].(string)), 2048, 64))
	prk := hmac.New(sha256.New, []byte("scaas.ua.pq.v1"))
	prk.Write(seed)
	w := f.fresh("pq_kat")
	for _, ai := range [][2]uint32{{0, 0}, {1, 2}} {
		h := hmac.New(sha256.New, prk.Sum(nil))
		h.Write([]byte("scaas.ua.pqz-mlwe.v1"))
		_ = binary.Write(h, binary.BigEndian, ai)
		h.Write([]byte{1})
		leaf := must(w.ExportPqzLeafRaw(ai[0], ai[1]))
		if !bytes.Equal(leaf, h.Sum(nil)) {
			t.Fatal("leaf", ai)
		}
		Wipe(leaf)
	}
	if _, err := w.ExportPqzLeafRaw(1<<31, 0); code(err) != "UAArgument" {
		t.Fatal(err)
	}
	k := must(w.PqzKey(0, 0))
	defer k.Close()
	pk := must(k.PublicKey())
	if len(pk) != 18432 {
		t.Fatal(len(pk))
	}
	req := obj{"proofSystemId": pqzl2304, "kind": 0x0131, "ua": "0x" + strings.Repeat("11", 32)}
	var out obj
	_ = json.Unmarshal([]byte(must(k.Call("proveRegister", js(req)))), &out)
	if !bytes.Equal(b(out["stmt"])[96:], pk) {
		t.Fatal("stmt")
	}
	req["proofSystemId"] = pqzl2048
	if _, err := k.Call("proveRegister", js(req)); code(err) != "UAPqzSetMismatch" {
		t.Fatal(err)
	}
	req["proofSystemId"] = pqzl2304
	req["seed32"] = "0x" + strings.Repeat("11", 32)
	if _, err := k.Call("proveRegister", js(req)); code(err) != "UAArgument" {
		t.Fatal(err)
	}
	delete(req, "seed32")
	var e obj
	_ = json.Unmarshal([]byte(must(k.Call("enc", js(obj{"pks": []string{hx(pk)}, "values": []int{123456}})))), &e)
	// ARCH-POS-13 (T15c): a release build has no raw decrypt; a well-formed `dec` is an unknown command
	if _, err := k.Call("dec", js(obj{"ct": e["u"].(string) + e["vs"].([]any)[0].(string)[2:]})); code(err) != "UAArgument" {
		t.Fatal(err)
	}
	box := must(k.SealBalanceCache([]byte(`{"v":1}`)))
	if pt := must(k.OpenBalanceCache(box)); string(pt) != `{"v":1}` {
		t.Fatal(string(pt))
	}
	k1 := must(w.PqzKey(0, 1))
	defer k1.Close()
	if _, err := k1.OpenBalanceCache(box); code(err) != "UAAead" {
		t.Fatal(err)
	}
	must0(w.Lock())
	if _, err := k.Call("proveRegister", js(req)); code(err) != "UAKeyRevoked" {
		t.Fatal(err)
	}
	if pk2 := must(k.PublicKey()); !bytes.Equal(pk, pk2) {
		t.Fatal("public data stays readable")
	}
	if _, err := w.ExportPqzLeafRaw(0, 0); code(err) != "UAWalletLocked" {
		t.Fatal(err)
	}
}

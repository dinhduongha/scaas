package ua

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
)

type obj = map[string]any

func load(t *testing.T, name string) obj {
	raw, err := os.ReadFile("../../smartcontracts/vectors/ua/" + name)
	if err != nil {
		t.Fatal(err)
	}
	var v obj
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func rows(v obj, k string) []obj {
	out := []obj{}
	for _, r := range v[k].([]any) {
		out = append(out, r.(obj))
	}
	return out
}

func bs(v any) []byte {
	b, err := hex.DecodeString(strings.TrimPrefix(v.(string), "0x"))
	if err != nil {
		panic(err)
	}
	return b
}
func b32(v any) (o [32]byte) { copy(o[:], bs(v)); return }
func b20(v any) (o [20]byte) { copy(o[:], bs(v)); return }
func hx(b []byte) string     { return "0x" + hex.EncodeToString(b) }
func kind(v any) uint16      { return uint16(v.(float64)) }

func code(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return "no UAError: " + err.Error()
}

func TestTableGroupsPurposesConstants(t *testing.T) {
	k := load(t, "kinds.json")
	if len(rows(k, "kinds")) != len(Kinds) {
		t.Fatal("kind count")
	}
	for _, r := range rows(k, "kinds") {
		n := kind(r["kind"])
		info, err := KindInfo(n)
		if err != nil || info.Name != r["name"] || info.Native != r["native"] {
			t.Fatalf("kind %#x", n)
		}
		want := []int{}
		for _, l := range r["lengths"].([]any) {
			want = append(want, int(l.(float64)))
		}
		if len(want) != len(info.Lengths) {
			t.Fatalf("%s lengths", info.Name)
		}
		for i := range want {
			if want[i] != info.Lengths[i] {
				t.Fatalf("%s lengths", info.Name)
			}
		}
		group, _ := r["group"].(string)
		if info.Group != group || IsSigning(n) != r["signing"] || IsZether(n) != r["zether"] ||
			IsMember(n, false) != r["member"] || IsMember(n, true) != r["memberHedera"] || IsPqzHolder(n) != r["pqzHolder"] {
			t.Fatalf("%s sets or group", info.Name)
		}
		if info.Native {
			if _, err := Tag(n); code(err) != "UAKindNotDerived" {
				t.Fatalf("%s tag", info.Name)
			}
			continue
		}
		s, _ := KindTagString(n)
		tg, _ := Tag(n)
		if s != r["tag"] || hx(tg[:]) != r["TAG"] {
			t.Fatalf("%s tag", info.Name)
		}
	}
	if len(rows(k, "schemes")) != len(Schemes) {
		t.Fatal("scheme count")
	}
	for i, r := range rows(k, "schemes") {
		s, _ := KindTagString(kind(r["kind"]))
		tg, _ := Tag(kind(r["kind"]))
		if Schemes[i].Number != kind(r["kind"]) || Schemes[i].Name != r["name"] || Schemes[i].Group != r["group"] ||
			s != r["tag"] || hx(tg[:]) != r["TAG"] {
			t.Fatalf("scheme %v", r["name"])
		}
		if _, err := UAOf(Schemes[i].Number, make([]byte, 16384)); code(err) != "UAKindNotDerived" {
			t.Fatal("scheme UAOf")
		}
		if code(ValidateKeyData(Schemes[i].Number, make([]byte, 16384), false)) != "UAKindNotDerived" {
			t.Fatal("scheme validate")
		}
	}
	pqzKey := bs(k["pqzKey"])
	if kh, err := KeyHashOf(0x0142, pqzKey); err != nil || hx(kh[:]) != k["pqzKeyHash"] {
		t.Fatal("pqzKeyHash")
	}
	for _, r := range rows(k, "groups") {
		s, _ := GroupTagString(r["group"].(string))
		g, _ := GroupTag(r["group"].(string))
		if s != r["tag"] || hx(g[:]) != r["GROUP"] {
			t.Fatalf("group %s", r["group"])
		}
	}
	if len(rows(k, "purposes")) != len(Purposes)+1 { // `pop` has v1 and v2
		t.Fatal("purpose count")
	}
	for _, r := range rows(k, "purposes") {
		p, err := PurposeTagV(r["purpose"].(string), uint32(r["version"].(float64)))
		if err != nil || hx(p[:]) != r["purposeTag"] {
			t.Fatalf("purpose %s", r["purpose"])
		}
	}
	for _, bad := range []struct {
		p string
		v uint32
	}{{"metatx", 2}, {"pop", 3}, {"pop", 0}, {"nope", 1}} {
		if _, err := PurposeTagV(bad.p, bad.v); code(err) != "UAPurposeUnknown" {
			t.Fatalf("purpose %v", bad)
		}
	}
	c := k["constants"].(obj)
	pop, _ := PurposeTag("pop")
	dt, at, nh := Keccak256([]byte(DomainType)), Keccak256([]byte(UAAuthType)), Keccak256([]byte(RegistryName))
	if hx(MsgTag[:]) != c["MSG_TAG"] || hx(pop[:]) != c["POP_TAG"] || hx(dt[:]) != c["DOMAIN_TYPEHASH"] ||
		hx(at[:]) != c["UAAUTH_TYPEHASH"] || hx(nh[:]) != c["NAME_HASH"] {
		t.Fatal("constants")
	}
}

func TestValidRows(t *testing.T) {
	for _, r := range rows(load(t, "kinds.json"), "valid") {
		n, d := kind(r["kind"]), bs(r["keyData"])
		u, err := DeriveUA(n, d, r["hederaNative"].(bool))
		if err != nil || hx(u[:]) != r["ua"] {
			t.Fatalf("%s: %v", r["name"], err)
		}
		h, err := KeyHashOf(n, d)
		if err != nil {
			t.Fatal(err)
		}
		if (h == nil) != (r["keyHash"] == nil) || (h != nil && hx(h[:]) != r["keyHash"]) {
			t.Fatalf("%s keyHash", r["name"])
		}
	}
}

func TestInvalidRows(t *testing.T) {
	for _, r := range rows(load(t, "kinds.json"), "invalid") {
		err := ValidateKeyData(kind(r["kind"]), bs(r["keyData"]), r["hederaNative"].(bool))
		if err == nil || code(err) != r["error"] {
			t.Errorf("%v %s: got %v", r["kind"], r["reason"], err)
		}
	}
}

func TestNativesNativeSpaceCanonicalIDs(t *testing.T) {
	k := load(t, "kinds.json")
	for _, r := range rows(k, "natives") {
		id, err := NativeID(kind(r["kind"]), bs(r["raw"]))
		c, _ := CanonicalID(hx(id[:]))
		if err != nil || hx(id[:]) != r["id"] || c != r["canonical"] {
			t.Fatalf("native %v", r["kind"])
		}
	}
	for _, r := range rows(k, "nativeInvalid") {
		if _, err := NativeID(kind(r["kind"]), bs(r["raw"])); err == nil || code(err) != r["error"] {
			t.Fatalf("nativeInvalid %v", r["kind"])
		}
	}
	for _, r := range rows(k, "nativeSpace") {
		if InNativeSpace(b32(r["id"])) != r["inNativeSpace"] {
			t.Fatalf("nativeSpace %s", r["id"])
		}
	}
	for _, r := range rows(k, "canonicalIds") {
		got, err := CanonicalID(r["input"].(string))
		if want, ok := r["canonical"]; ok {
			if err != nil || got != want {
				t.Fatalf("canonical %q", r["input"])
			}
		} else if err == nil || code(err) != r["error"] {
			t.Fatalf("canonical %q accepted", r["input"])
		}
	}
}

func TestMessages(t *testing.T) {
	for _, r := range rows(load(t, "kinds.json"), "messages") {
		p, _ := PurposeTagV(r["purpose"].(string), uint32(r["version"].(float64))) // each row carries its purpose `version` (A4-c1)
		if hx(p[:]) != r["purposeTag"] {
			t.Fatalf("message purposeTag %v", r["purpose"])
		}
		m, err := UAMessage(kind(r["kind"]), p, b32(r["digest"]))
		if err != nil || hx(m[:]) != r["uaMsg"] {
			t.Fatalf("message %v %s", r["kind"], r["purpose"])
		}
	}
}

func TestStructures(t *testing.T) {
	s := load(t, "structures.json")
	k := load(t, "kinds.json")
	ctx := s["contexts"].(obj)
	for _, p := range rows(s, "pop") {
		portable := PortablePopDigest(b32(p["ua"]), b32(p["pqzKeyHash"]), b32(p["kemRecordHash"]))
		reg := RegistrationDigest(portable, b32(p["pqzPopHash"]))
		if hx(portable[:]) != p["portablePopDigest"] || hx(reg[:]) != p["registrationDigest"] {
			t.Fatalf("pop %v", p["ua"])
		}
	}
	pqzKey := bs(k["pqzKey"])
	proof := bytes.Repeat([]byte{7}, 32)
	for _, r := range rows(s, "pqzReg") {
		ua, kem := b32(r["ua"]), b32(r["kemRecordHash"])
		h, err := KeyHashOf(0x0142, pqzKey)
		portable := PortablePopDigest(ua, *h, kem)
		msg, _ := UAMessage(0x0142, PopV2Tag, portable)
		if err != nil || hx(h[:]) != r["pqzKeyHash"] || hx(portable[:]) != r["portablePopDigest"] || hx(msg[:]) != r["pqzRegMessage"] {
			t.Fatalf("pqzReg %v", r["ua"])
		}
		if kem != ([32]byte{}) {
			continue // the row's KEM record hash is opaque; the real records are in portable.json
		}
		m, err := PqzRegMessage(ua, pqzKey, nil)
		got, err2 := HolderPopMessage(kind(r["kind"]), ua, nil, pqzKey, nil, proof, nil)
		if err != nil || err2 != nil || hx(m[:]) != r["pqzRegMessage"] || hx(got.PqzKeyHash[:]) != r["pqzKeyHash"] ||
			hx(got.PortablePopDigest[:]) != r["portablePopDigest"] {
			t.Fatalf("pqzReg holder %v", r["ua"])
		}
		for _, bad := range []uint16{0x0101, 0x0133} {
			if _, err := HolderPopMessage(bad, ua, nil, pqzKey, nil, proof, nil); code(err) != "UAPqzHolder" {
				t.Fatalf("holder kind %#x", bad)
			}
		}
	}
	for _, r := range rows(s, "pqzMsig") {
		d := bs(r["keyData"])
		got, err := MsigPqzEligible(d)
		u, err2 := DeriveUA(0x0120, d, false)
		h := [32]byte{}
		if got {
			h = b32(k["pqzKeyHash"])
		}
		pd := PortablePopDigest(b32(r["ua"]), h, [32]byte{})
		if err != nil || err2 != nil || got != r["eligible"] || hx(u[:]) != r["ua"] || hx(pd[:]) != r["portablePopDigest"] {
			t.Fatalf("pqzMsig %v", r["reason"])
		}
	}
	for _, a := range rows(s, "uaAuth") {
		c := ctx[a["context"].(string)].(obj)
		d := Domain{uint32(a["generation"].(float64)), uint64(c["chainId"].(float64)), b20(c["registry"]), b32(c["chainUid"])}
		sep := UAAuthDomainSeparator(d)
		got := UAAuthDigest(d, b32(a["ua"]), b32(a["purposeTag"]), b32(a["digest"]))
		if hx(sep[:]) != a["domainSeparator"] || hx(got[:]) != a["uaAuthDigest"] {
			t.Fatalf("uaAuth %s %v", a["context"], a["generation"])
		}
	}
	for _, m := range rows(s, "member") {
		got := MemberDigest(b32(m["structureUa"]), b32(m["uaMsg"]))
		if hx(got[:]) != m["memberDigest"] {
			t.Fatal("member")
		}
	}
}

func opt(r obj, k string) string { s, _ := r[k].(string); return s }
func hxp(p *[32]byte) string {
	if p == nil {
		return ""
	}
	return hx(p[:])
}
func u64(v any) uint64 { return uint64(v.(float64)) }

// register is the holder call over a registration row's attrs (and the proof bytes, or only their hash).
func register(row obj, hashOnly bool) (*HolderPop, error) {
	a := row["attrs"].(obj)
	pop, hash, pk, ver := bs(row["pqzPop"]), bs(a["pqzPopHash"]), bs(a["kemPk"]), u64(a["kemVersion"])
	if hashOnly {
		pop = nil
	}
	return HolderPopMessage(kind(row["kind"]), b32(row["ua"]), bs(row["keyData"]), bs(a["pqzKey"]), pop, hash, &Kem{ver, pk})
}

func find(rs []obj, k string, v any) obj {
	for _, r := range rs {
		if r[k] == v {
			return r
		}
	}
	panic(fmt.Sprintf("no row with %s = %v", k, v))
}

func TestPortable(t *testing.T) {
	p := load(t, "portable.json")
	tags := p["tags"].(obj)
	tg := func(n string) string { return tags[n].(obj)["hash"].(string) }
	kem, pqk := kemPurpose, pqzKeyPurpose
	if hx(PopV2Tag[:]) != tg("PURPOSE_POP_V2") || hx(kem[:]) != tg("PURPOSE_KEM") || hx(pqk[:]) != tg("PURPOSE_PQZ_KEY") ||
		hx(KemRecordTag[:]) != tg("KEM_RECORD_TAG") || hx(PqzKeyRecordTag[:]) != tg("PQZ_KEY_RECORD_TAG") {
		t.Fatal("tags")
	}
	n, withPqz, msigs := 0, 0, 0
	for _, r := range rows(p, "registrations") {
		name := r["name"]
		ua := b32(r["ua"])
		if got, err := UAOf(kind(r["kind"]), bs(r["keyData"])); err != nil || hx(got[:]) != r["ua"] {
			t.Fatalf("%v ua", name)
		}
		for _, hashOnly := range []bool{false, true} {
			h, err := register(r, hashOnly)
			if err != nil {
				t.Fatalf("%v: %v", name, err)
			}
			portable := PortablePopDigest(ua, h.PqzKeyHash, h.KemRecordHash)
			reg := RegistrationDigest(portable, h.PqzPopHash)
			msg, _ := UAMessage(kind(r["kind"]), PopV2Tag, reg)
			if hx(h.PqzKeyHash[:]) != r["pqzKeyHash"] || hx(h.PqzPopHash[:]) != r["attrs"].(obj)["pqzPopHash"] ||
				hx(h.KemRecordHash[:]) != r["kemRecordHash"] || hx(h.PortablePopDigest[:]) != r["portablePopDigest"] ||
				hx(h.RegistrationDigest[:]) != r["registrationDigest"] || hx(h.Message[:]) != r["popMessage"] ||
				portable != h.PortablePopDigest || reg != h.RegistrationDigest || msg != h.Message ||
				hxp(h.MemberDigest) != opt(r, "memberDigest") {
				t.Fatalf("%v (hashOnly %v)", name, hashOnly)
			}
		}
		a := r["attrs"].(obj)
		if pk := bs(a["pqzKey"]); len(pk) > 0 {
			withPqz++
			var kem *Kem
			if v := u64(a["kemVersion"]); v != 0 {
				kem = &Kem{v, bs(a["kemPk"])}
			}
			if m, err := PqzRegMessage(ua, pk, kem); err != nil || hx(m[:]) != r["pqzRegMessage"] {
				t.Fatalf("%v pqzRegMessage", name)
			}
		} else if b32(r["pqzRegMessage"]) != ([32]byte{}) {
			t.Fatalf("%v pqzRegMessage not zero", name)
		}
		if kind(r["kind"]) == 0x0120 {
			msigs++
		}
		n++
	}
	if n != 25 || withPqz != 8 || msigs != 6 {
		t.Fatalf("counts %d %d %d", n, withPqz, msigs)
	}
}

func TestKemRecord(t *testing.T) {
	p := load(t, "portable.json")
	for _, r := range rows(p, "kemRecords") {
		ua, pk := b32(r["ua"]), bs(r["kemPk"])
		d, err := KemRecordDigest(ua, u64(r["version"]), pk)
		m, err2 := KemRecordMessage(kind(r["kind"]), ua, u64(r["version"]), pk)
		want, _ := UAMessage(kind(r["kind"]), kemPurpose, d)
		if err != nil || err2 != nil || hx(d[:]) != r["digest"] || hx(m[:]) != r["message"] || m != want {
			t.Fatalf("kem %v", r["id"])
		}
		if kind(r["kind"]) == 0x0120 {
			if md := MemberDigest(ua, m); hx(md[:]) != r["memberDigest"] {
				t.Fatalf("kem member %v", r["id"])
			}
		}
	}
	if len(rows(p, "kemRecords")) != 9 {
		t.Fatal("kem count")
	}
	u := bytes.Repeat([]byte{1}, 32)
	var ua [32]byte
	copy(ua[:], u)
	for _, c := range []struct {
		v    uint64
		pk   []byte
		code string
	}{{0, make([]byte, 1600), "UAKemVersion"}, {1, make([]byte, 1599), "UAKemKeyLength"}, {1, make([]byte, 1601), "UAKemKeyLength"}, {1, nil, "UAKemKeyLength"}} {
		if _, err := KemRecordDigest(ua, c.v, c.pk); code(err) != c.code {
			t.Fatalf("kem %v: %v", c.code, err)
		}
	}
	if d, err := KemRecordDigest(ua, ^uint64(0), make([]byte, 1600)); err != nil || hx(d[:]) != "0xdea39530ca31145e34cb14a02a34952227ee39703d12cbeb2428539002c7dd31" {
		t.Fatal("max version") // pins the 8-byte version word
	}
	if c := ChainKeyHash(1<<40 + 7); hx(c[:]) != "0x6e45d591a544f53396f6e86d49f5809196c5725f9d99dbd2ca97f9925c7ce950" { // keccak256("evm:1099511627783")
		t.Fatal("chain key hash")
	}
}

func TestPqzKeyRecord(t *testing.T) {
	p := load(t, "portable.json")
	regs := rows(p, "registrations")
	n, msigRows := 0, 0
	for _, r := range rows(p, "pqzKeyRecords") {
		ua, key, hash := b32(r["ua"]), bs(r["pqzKey"]), bs(r["pqzPopHash"])
		k := kind(r["kind"])
		kd := bs(find(regs, "ua", r["ua"])["keyData"])
		pop := bs(find(regs, "set", r["set"])["pqzPop"])
		for _, hashOnly := range []bool{false, true} {
			var g *PqzKeyRecord
			var err error
			if hashOnly {
				g, err = PqzKeyRecordMessage(k, ua, kd, key, nil, hash, false)
			} else {
				g, err = PqzKeyRecordMessage(k, ua, kd, key, pop, nil, false)
			}
			if err != nil {
				t.Fatalf("%v: %v", r["name"], err)
			}
			if hx(g.PqzKeyHash[:]) != r["pqzKeyHash"] || hx(g.PqzPopHash[:]) != r["pqzPopHash"] || hx(g.PqzKeyDigest[:]) != r["pqzKeyDigest"] ||
				hx(g.RecordDigest[:]) != r["recordDigest"] || hx(g.Message[:]) != r["message"] || hx(g.PqzRegMessage[:]) != r["pqzRegMessage"] ||
				g.PqzKeyDigest != PqzKeyDigest(ua, g.PqzKeyHash) || g.RecordDigest != PqzKeyRecordDigest(g.PqzKeyDigest, g.PqzPopHash) ||
				(g.MemberDigest != nil) != (k == 0x0120) || hxp(g.MemberDigest) != opt(r, "memberDigest") {
				t.Fatalf("%v (hashOnly %v)", r["name"], hashOnly)
			}
			if k == 0x0120 {
				msigRows++
				if *g.MemberDigest != MemberDigest(ua, g.Message) {
					t.Fatal("member digest")
				}
			}
		}
		if _, err := PqzKeyRecordMessage(k, ua, kd, key, nil, hash, true); code(err) != "UAPqzKeySet" { // write-once
			t.Fatalf("%v write-once", r["name"])
		}
		n++
	}
	if n != 8 || msigRows != 8 { // 4 msig rows, each with the proof bytes and hash-only
		t.Fatalf("counts %d %d", n, msigRows)
	}
}

func TestPersonalSignPortablePurposes(t *testing.T) {
	p := load(t, "portable.json")
	metatx, pop := mustTag(t, "metatx"), mustTag(t, "pop")
	if !IsPortablePurpose(PopV2Tag) || !IsPortablePurpose(kemPurpose) || !IsPortablePurpose(pqzKeyPurpose) || IsPortablePurpose(metatx) || IsPortablePurpose(pop) {
		t.Fatal("IsPortablePurpose")
	}
	md := b32(find(rows(p, "registrations"), "name", "msig-pq-native")["memberDigest"])
	// known answer from the JS reference (clientkeys ua.js); prefix = 0x19 + "Ethereum Signed Message:\n32" (28 bytes)
	if hx(md[:]) != "0x606d9a70c70d39e5d8d079c3ae31eefa6db574219dab56d6c776cb6731e61a7c" {
		t.Fatal("memberDigest")
	}
	if ps := PersonalSignDigest(md); hx(ps[:]) != "0xe5d24987e9b4e710063a5432d6215eaead64d8dc073f7561726d21644d54c3d8" {
		t.Fatalf("personalSignDigest %x", ps)
	}
	if len("\x19Ethereum Signed Message:\n32") != 28 {
		t.Fatal("prefix length")
	}
	n := find(rows(p, "negatives"), "name", "native-personal-sign-under-metatx")
	if IsPortablePurpose(b32(n["mutation"].(obj)["set"].(obj)["purposeTag"])) {
		t.Fatal("metatx is not portable")
	}
}

func mustTag(t *testing.T, p string) [32]byte {
	tg, err := PurposeTag(p)
	if err != nil {
		t.Fatal(err)
	}
	return tg
}

func TestHolderRefusals(t *testing.T) {
	p := load(t, "portable.json")
	regs := rows(p, "registrations")
	run, sigLevel := 0, 0
	for _, n := range rows(p, "negatives") {
		name, entry, want := n["name"], n["entry"], n["error"]
		m := n["mutation"].(obj)
		set, _ := m["set"].(obj)
		plain := true
		for k := range set {
			plain = plain && (strings.HasPrefix(k, "attrs.") || k == "pqzPop")
		}
		switch {
		case (entry == "register" || entry == "storePqzPop") && plain:
			row := find(regs, "name", m["row"])
			mut := obj{}
			for k, v := range row {
				mut[k] = v
			}
			attrs := obj{}
			for k, v := range row["attrs"].(obj) {
				attrs[k] = v
			}
			mut["attrs"] = attrs
			for _, o := range []obj{func() obj { w, _ := m["registerWith"].(obj); return w }(), set} { // registerWith first, then the mutation
				for k, v := range o {
					if f, ok := strings.CutPrefix(k, "attrs."); ok {
						attrs[f] = v
					} else {
						mut[k] = v
					}
				}
			}
			got, err := register(mut, false)
			if want == "UAPoP" { // the digest layer accepts it; the PoP of the unmutated row does not cover it
				if err != nil || hx(got.Message[:]) == row["popMessage"] {
					t.Fatalf("%v: %v", name, err)
				}
			} else if err == nil || code(err) != want {
				t.Fatalf("%v: want %v got %v", name, want, err)
			}
			run++
		case entry == "setPqzKey" && (want == "UAPqzKeySet" || want == "UAPqzHolder" || want == "UAPqzPopHash"):
			rec := find(rows(p, "pqzKeyRecords"), "name", m["row"])
			uaHex, hashV := rec["ua"], rec["pqzPopHash"]
			if v, ok := set["ua"]; ok {
				uaHex = v
			}
			if v, ok := set["pqzPopHash"]; ok {
				hashV = v
			}
			holder := find(regs, "ua", uaHex)
			_, err := PqzKeyRecordMessage(kind(holder["kind"]), b32(uaHex), bs(holder["keyData"]), bs(rec["pqzKey"]), nil, bs(hashV), holder["attrs"].(obj)["pqzKey"] != "0x")
			if err == nil || code(err) != want {
				t.Fatalf("%v: want %v got %v", name, want, err)
			}
			run++
		case entry == "setKemKey" && name == "kem-record-of-other-ua":
			// the record of one UA offered for another: the signed message differs, so the signature cannot verify
			k := find(rows(p, "kemRecords"), "id", m["row"])
			target := find(regs, "ua", set["ua"])
			msg, err := KemRecordMessage(kind(target["kind"]), b32(set["ua"]), u64(k["version"]), bs(k["kemPk"]))
			if err != nil || hx(msg[:]) == k["message"] {
				t.Fatalf("%v", name)
			}
			run++
		default:
			sigLevel++ // signatures / native personal_sign: verified by the signature vectors
		}
	}
	if run != 56 || sigLevel != 7 {
		t.Fatalf("negatives %d digest-layer, %d signature-level", run, sigLevel)
	}
	u, key, proof := b32(hx(bytes.Repeat([]byte{1}, 32))), make([]byte, 16384), bytes.Repeat([]byte{7}, 32)
	// malformed msig key data is UAKeyData, not "not a holder"; an msig without key data is not a holder
	for _, kd := range [][]byte{{0, 2, 0}, {0, 2, 0, 2, 9, 9}} {
		if _, err := HolderPopMessage(0x0120, u, kd, key, nil, proof, nil); code(err) != "UAKeyData" {
			t.Fatalf("msig key data %x", kd)
		}
	}
	for _, c := range []struct {
		kind               uint16
		kd, key, pop, hash []byte
		kem                *Kem
		code               string
	}{
		{0x0120, nil, key, nil, proof, nil, "UAPqzHolder"},
		{0x0130, nil, key, nil, make([]byte, 31), nil, "UAPqzPopHash"},
		{0x0130, nil, key, []byte{}, nil, nil, "UAPqzPopHash"},
		{0x0130, nil, make([]byte, 100), nil, proof, nil, "UAKeyData"},
		{0x0130, nil, nil, nil, nil, &Kem{1, nil}, "UAKemKeyLength"},
		{0x0101, nil, nil, nil, nil, &Kem{1, make([]byte, 1600)}, "UAKemHolder"},
	} {
		if _, err := HolderPopMessage(c.kind, u, c.kd, c.key, c.pop, c.hash, c.kem); code(err) != c.code {
			t.Fatalf("refusal %+v: %v", c, err)
		}
	}
	// a zero-length proof hash is absent (same as no hash)
	a, _ := HolderPopMessage(0x0130, u, nil, nil, nil, nil, nil)
	b, _ := HolderPopMessage(0x0130, u, nil, nil, nil, []byte{}, nil)
	if a.Message != b.Message {
		t.Fatal("empty proof hash is absent")
	}
}

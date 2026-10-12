package ua

import (
	"encoding/hex"
	"encoding/json"
	"errors"
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
			IsMember(n, false) != r["member"] || IsMember(n, true) != r["memberHedera"] {
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
	for _, r := range rows(k, "groups") {
		s, _ := GroupTagString(r["group"].(string))
		g, _ := GroupTag(r["group"].(string))
		if s != r["tag"] || hx(g[:]) != r["GROUP"] {
			t.Fatalf("group %s", r["group"])
		}
	}
	for _, r := range rows(k, "purposes") {
		p, err := PurposeTag(r["purpose"].(string))
		if err != nil || hx(p[:]) != r["purposeTag"] {
			t.Fatalf("purpose %s", r["purpose"])
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
		p, _ := PurposeTag(r["purpose"].(string))
		m, err := UAMessage(kind(r["kind"]), p, b32(r["digest"]))
		if err != nil || hx(m[:]) != r["uaMsg"] {
			t.Fatalf("message %v %s", r["kind"], r["purpose"])
		}
	}
}

func TestStructures(t *testing.T) {
	s := load(t, "structures.json")
	ctx := s["contexts"].(obj)
	for _, p := range rows(s, "pop") {
		c := ctx[p["context"].(string)].(obj)
		id := uint64(c["chainId"].(float64))
		ckh := ChainKeyHash(id)
		got := PopDigest(id, b32(c["chainUid"]), b20(c["registry"]), b32(p["ua"]), b32(p["authRef"]))
		if hx(ckh[:]) != p["chainKeyHash"] || hx(got[:]) != p["popDigest"] {
			t.Fatalf("pop %s", p["context"])
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

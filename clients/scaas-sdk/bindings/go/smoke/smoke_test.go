// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0

// Package smoke is the Go binding's smoke test (plan T20h; spec §16.1) over the async API through uniffi-bindgen-go's output
// (../generated): each SDK call blocks its goroutine while the SDK's runtime runs it. Rows:
// smartcontracts/vectors/keystore/keystore.json, each container the Go store's `keystore`: valid rows list their seeds and
// every seed opens with the rows' passphrase (its accounts listed); refused rows fail with their named error. Then: a Go
// authenticator's PRF through the copy call (passkey unlock), `Next` on the subscription, a panic as Internal, a Go error in
// the store and in the authenticator (the SDK's error, no panic), the load check. Run by ../run.sh (gate `bind-go`).
package smoke

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"

	"scaas/copycall"
	sdk "scaas/generated/scaas_sdk"
	"scaas/generated/scaas_sdk_ffi"
)

const repo = "bench hurt jump file august wise shallow faculty impulse spring exact slush thunder author capable act festival slice deposit sauce coconut afford frown better"
const pass = "river-otter-7 ünï"

func secret(t *testing.T, v string) *sdk.SecretBytes {
	b := []byte(v)
	s, err := sdk.SecretNew(uint32(len(b)))
	if err != nil {
		t.Fatal(err)
	}
	if copycall.Write(sdk.SecretId(s), b) != 0 {
		t.Fatal("copy call")
	}
	return s
}

// memStore is the SDK's store contract over a map: PutIf refuses another revision with Conflict.
type memStore struct {
	mu     sync.Mutex
	items  map[string][]byte
	throws bool
}

func newStore() *memStore { return &memStore{items: map[string][]byte{}} }

func (s *memStore) Get(name string, reason string) (*sdk.StoredItem, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.throws {
		return nil, errors.New("the app's store failed")
	}
	b, ok := s.items[name]
	if !ok {
		return nil, nil
	}
	return &sdk.StoredItem{Bytes: b, Rev: sdk.RevOf(b)}, nil
}

func (s *memStore) PutIf(name string, prevRev *uint64, bytes []byte, policy sdk.StorePolicy) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.items[name]
	if ok != (prevRev != nil) || (ok && sdk.RevOf(b) != *prevRev) {
		return sdk.NewStoreErrorConflict()
	}
	s.items[name] = append([]byte(nil), bytes...)
	return nil
}

func (s *memStore) Delete(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.items, name)
	return nil
}

// one caller at a time here: no lock to hold
func (s *memStore) Lock(name string) (uint64, error) { return 1, nil }
func (s *memStore) Unlock(token uint64)              {}

// fakeAuth: a PRF of 32 bytes from the salt (deterministic, a test stand-in), written by the copy call into prfOut's secret.
type fakeAuth struct {
	mu     sync.Mutex
	throws bool
}

func (a *fakeAuth) CreatePasskey(rpId string, userName string, exclude [][]byte) (sdk.PasskeyCreated, error) {
	return sdk.PasskeyCreated{}, sdk.NewAuthErrorUnavailable()
}

func (a *fakeAuth) GetAssertion(req sdk.AssertionRequest, prfOut uint64) (sdk.Assertion, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.throws {
		return sdk.Assertion{}, errors.New("the app's authenticator failed")
	}
	if req.PrfSalt == nil {
		return sdk.Assertion{}, sdk.NewAuthErrorRefused()
	}
	salt := *req.PrfSalt
	out := make([]byte, 32)
	for i := range out {
		out[i] = salt[i%len(salt)] ^ 0x5a ^ byte(i)
	}
	if copycall.Write(prfOut, out) != 0 {
		return sdk.Assertion{}, sdk.NewAuthErrorRefused()
	}
	return sdk.Assertion{CredentialId: []byte{0xc1, 0xed}, AuthenticatorData: make([]byte, 37), ClientDataJson: []byte{}, Signature: make([]byte, 64), Prf: true}, nil
}

func (a *fakeAuth) PlatformSecret(keyHandle string, salt []byte, reason string, policy *sdk.KeyPolicy, out uint64) error {
	return sdk.NewAuthErrorUnavailable()
}

func (a *fakeAuth) P256Generate(policy sdk.KeyPolicy) (sdk.SePublic, error) {
	return sdk.SePublic{}, sdk.NewAuthErrorUnavailable()
}

func (a *fakeAuth) P256Sign(keyHandle string, uaMsg []byte, reason string) ([]byte, error) {
	return nil, sdk.NewAuthErrorUnavailable()
}

func open(t *testing.T, st *memStore, auth *fakeAuth) *sdk.Sdk {
	rp := "wallet.example"
	var a sdk.ForeignAuthenticator = auth
	s, err := sdk.Open(sdk.BindingConfig{RpId: &rp, Limits: sdk.LimitsDefault()}, st, &a)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func over(t *testing.T, text string) *sdk.Sdk {
	st := newStore()
	st.items["keystore"] = []byte(text)
	return open(t, st, &fakeAuth{})
}

// code is an error's code: its message (`Display` is the code), or "Ok".
func code(err error) string {
	if err == nil {
		return "Ok"
	}
	var e *sdk.SdkError
	if !errors.As(err, &e) {
		return "not an SdkError: " + err.Error()
	}
	s := errors.Unwrap(e).Error()
	if i := strings.Index(s, ": "); i >= 0 {
		return s[i+2:]
	}
	return s
}

type row struct {
	ID    string `json:"id"`
	Text  string `json:"text"`
	Error string `json:"error"`
}

type seed struct {
	ID       string `json:"id"`
	Label    string `json:"label"`
	Words    uint32 `json:"words"`
	Backup   string `json:"backup"`
	Accounts []struct {
		ID string `json:"id"`
	} `json:"accounts"`
}

func TestLoadCheck(t *testing.T) {
	if v := sdk.ApiVersion(); v != 1 {
		t.Fatalf("api_version %d", v)
	}
}

func TestKeystoreRows(t *testing.T) {
	raw, err := os.ReadFile("../../../../../smartcontracts/vectors/keystore/keystore.json")
	if err != nil {
		t.Fatal(err)
	}
	var d struct {
		Passphrase string `json:"passphrase"`
		Valid      []row  `json:"valid"`
		Refused    []row  `json:"refused"`
	}
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatal(err)
	}
	opened := 0
	for _, r := range d.Valid {
		var c struct {
			Seeds []seed `json:"seeds"`
		}
		if err := json.Unmarshal([]byte(r.Text), &c); err != nil {
			t.Fatal(err)
		}
		s := over(t, r.Text)
		got, err := s.Vault().Seeds()
		if err != nil || len(got) != len(c.Seeds) {
			t.Fatalf("%s: %v, %d seeds", r.ID, err, len(got))
		}
		for i, w := range c.Seeds {
			g := got[i]
			if g.Id != w.ID || g.Label != w.Label || g.Words != w.Words || g.Backup != w.Backup || g.Unlocked {
				t.Errorf("%s: seed %s", r.ID, w.ID)
			}
		}
		for _, w := range c.Seeds {
			if err := s.Vault().Unlock(w.ID, sdk.UnlockPassphrase{Field0: secret(t, d.Passphrase)}); err != nil {
				t.Fatalf("%s %s: %v", r.ID, w.ID, err)
			}
			info, err := s.Vault().Seed(w.ID)
			if err != nil || !info.Unlocked {
				t.Errorf("%s %s unlocked", r.ID, w.ID)
			}
			accounts, err := s.Account().Accounts(w.ID)
			if err != nil || len(accounts) != len(w.Accounts) {
				t.Fatalf("%s %s accounts: %v", r.ID, w.ID, err)
			}
			for i, a := range accounts {
				if a.Id != w.Accounts[i].ID {
					t.Errorf("%s %s account %d", r.ID, w.ID, i)
				}
			}
			opened++
		}
		if len(c.Seeds) > 0 {
			first := c.Seeds[0].ID
			s.Vault().Lock(first)
			if e := code(s.Vault().Unlock(first, sdk.UnlockPassphrase{Field0: secret(t, "not the one 9")})); e != "VaultOpen" {
				t.Errorf("%s: a wrong passphrase is %s", r.ID, e)
			}
		}
	}
	for _, r := range d.Refused {
		// the refusal comes from the opening's read or from the first call's
		st := newStore()
		st.items["keystore"] = []byte(r.Text)
		var a sdk.ForeignAuthenticator = &fakeAuth{}
		rp := "wallet.example"
		s, err := sdk.Open(sdk.BindingConfig{RpId: &rp, Limits: sdk.LimitsDefault()}, st, &a)
		if err == nil {
			_, err = s.Vault().Seeds()
		}
		if e := code(err); e != r.Error {
			t.Errorf("%s: %s, want %s", r.ID, e, r.Error)
		}
	}
	// control: the rows were read and the seeds opened
	if len(d.Valid) < 5 || opened < 5 || len(d.Refused) < 19 {
		t.Fatalf("control: %d valid, %d opened, %d refused", len(d.Valid), opened, len(d.Refused))
	}
}

func TestStoreAuthenticatorPanicAndErrors(t *testing.T) {
	st, auth := newStore(), &fakeAuth{}
	s := open(t, st, auth)
	sub := s.Subscribe()
	if ev := sub.Next(50); ev != nil {
		t.Fatalf("next: %v", *ev)
	}
	info, err := s.Vault().ImportWords(sdk.ImportWords{Label: "Main", Words: secret(t, repo), VaultPassphrase: secret(t, pass)})
	if err != nil {
		t.Fatal(err)
	}
	changed := false
	for ev := sub.Next(200); ev != nil; ev = sub.Next(200) {
		if _, ok := (*ev).(sdk.EventKeystoreChanged); ok {
			changed = true
		}
	}
	if !changed {
		t.Error("next: KeystoreChanged")
	}

	// the PRF return: a Go authenticator writes it by the copy call; the passkey unlock opens the seed with it
	if err := s.Vault().EnablePasskeyUnlock(info.Id, secret(t, pass)); err != nil {
		t.Fatal(err)
	}
	s.Vault().Lock(info.Id)
	if err := s.Vault().Unlock(info.Id, sdk.UnlockPasskey{}); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Vault().Seed(info.Id); !got.Unlocked {
		t.Error("passkey unlock by the PRF")
	}

	// a Go error in the authenticator: Unexpected on the Rust side, the SDK's refusal here, no panic
	s.Vault().Lock(info.Id)
	auth.mu.Lock()
	auth.throws = true
	auth.mu.Unlock()
	if e := code(s.Vault().Unlock(info.Id, sdk.UnlockPasskey{})); e == "Ok" || e == "Internal" {
		t.Errorf("authenticator error: %s", e)
	}
	auth.mu.Lock()
	auth.throws = false
	auth.mu.Unlock()
	// a Go error in the store: Unexpected, the store's failure (VaultIo)
	st.mu.Lock()
	st.throws = true
	st.mu.Unlock()
	_, err = s.Vault().Seeds()
	if e := code(err); e != "VaultIo" {
		t.Errorf("store error: %s", e)
	}
	st.mu.Lock()
	st.throws = false
	st.mu.Unlock()

	// a panic inside a call (the reference library's hook): Internal, the SDK goes on
	if e := code(scaas_sdk_ffi.PanicInCall(s)); e != "Internal" {
		t.Errorf("panic: %s", e)
	}
	if got, err := s.Vault().Seeds(); err != nil || len(got) != 1 {
		t.Errorf("control: after the panic: %v", err)
	}
}

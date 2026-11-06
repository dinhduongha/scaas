// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0

// Package wallet is the ua-rs wallet through libscaas_ua_c (clients/ua-c, C ABI v6) by cgo (spec 2026-11-05-ua-rs-sign §9.2,
// plan T13e). The identity port (the parent package ua) stays this module's own code and the independent cross-check; signing,
// KEM, seal, vault, backup, link and the Zether and PQZ facades are the library's.
//
// Load: every constructor checks once that scaas_ua_abi_version() is 6 and scaas_ua_features() a build this package knows
// (ErrLibraryMismatch otherwise). Secrets: secret inputs are []byte (a string cannot be wiped); a NUL-terminated copy this
// package makes of one is wiped after the call; secret outputs are []byte the caller wipes with Wipe. Handles: each type owns
// one library handle, freed once by Close or by its finalizer; Close waits for calls in flight on it. The library is linked from
// clients/ua-c/target/release (CGO_LDFLAGS may name another). UNAUDITED.
package wallet

/*
#cgo CFLAGS: -I${SRCDIR}/../../ua-c/include
#cgo LDFLAGS: -L${SRCDIR}/../../ua-c/target/release -lscaas_ua_c -Wl,-rpath,${SRCDIR}/../../ua-c/target/release
#include "scaas_ua.h"
*/
import "C"

import (
	"errors"
	"fmt"
	"runtime"
	"sync"
	"unsafe"
)

// ABIVersion is the C ABI this package speaks.
const ABIVersion = 6

// The scaas_ua_features() bits.
const (
	FeatureWallet uint64 = 1 << iota
	FeaturePq
	FeatureFalcon
	FeatureZether
	FeaturePqz
	FeaturePqzSetN2048Kmax1024
	FeaturePqzSetN2304Kmax4096
	FeaturePqzSetN2560Kmax16384
	FeaturePqzSetN2816Kmax65536
	FeatureExternal
	FeatureMlock
	// FeatureVectors: a test build (scaas-ua feature `vectors`); CheckBuild refuses it (spec no-decryption-oracle §4.8, Codex C1).
	FeatureVectors
	featureEnd
)

const featureSets = FeaturePqzSetN2048Kmax1024 | FeaturePqzSetN2304Kmax4096 | FeaturePqzSetN2560Kmax16384 | FeaturePqzSetN2816Kmax65536

// Networks of NativeKey, in SCAAS_UA_NETWORK_* order.
var Networks = []string{"evm", "cosmos", "hedera_ecdsa", "hedera_ed25519", "sui", "stellar", "ton", "aptos", "solana"}

const (
	CoinDefault            = 0xFFFFFFFF // a network's own SLIP-44 coin type
	AeadAes256Gcm          = 1
	AeadAes256GcmSiv       = 2
	KemPkLen               = 1601
	KemCtLen               = 1568
	MnemonicMax            = 256
	EntropyMax             = 32
	ZetherYLen             = 128
	ZetherUseConf          = 7
	ZetherUseViewing       = 8
	PqzOutMax              = 1052672 // SCAAS_UA_PQZ_OUT_MAX: a PQZ answer's buffer (never sized by a size query)
	errKeyData       int32 = 1
	errBuffer        int32 = 9
)

var (
	// ErrLibraryMismatch: the library is not ABI 6, or its feature bits are not a build this package knows.
	ErrLibraryMismatch = errors.New("scaas_ua: libscaas_ua_c is not a build this binding knows")
	// ErrClosed: a call on a handle after its Close (it never reaches the library).
	ErrClosed = errors.New("scaas_ua: handle closed")
)

// Error is a status of the library: Code is its name ("UASealOpen" ...), Detail the library's detail (never an input).
type Error struct {
	Status       int32
	Code, Detail string
}

func (e *Error) Error() string { return e.Code + ": " + e.Detail }

func refuse(what string) error { return &Error{Status: errKeyData, Code: "UAKeyData", Detail: what} }

// CheckBuild refuses a library of another ABI or an unknown feature set (the load check), and any test build (FeatureVectors).
func CheckBuild(abi uint32, features uint64) error {
	if abi != ABIVersion {
		return fmt.Errorf("%w: ABI %d, this binding needs %d", ErrLibraryMismatch, abi, ABIVersion)
	}
	if features&FeatureVectors != 0 {
		return fmt.Errorf("%w: a test build (feature vectors)", ErrLibraryMismatch)
	}
	need, sets := FeatureWallet|FeaturePq, features&featureSets
	if features&need != need || features >= featureEnd || sets&(sets-1) != 0 || (sets != 0) != (features&FeaturePqz != 0) {
		return fmt.Errorf("%w: features %#x", ErrLibraryMismatch, features)
	}
	return nil
}

var (
	loadMu         sync.Mutex
	loaded         bool
	abiVersionHook = func(v uint32) uint32 { return v } // test hook: maps the library's ABI version before the check
)

// Load checks the library once (every constructor calls it); a refused library stays refused.
func Load() error {
	loadMu.Lock()
	defer loadMu.Unlock()
	if loaded {
		return nil
	}
	if err := CheckBuild(abiVersionHook(uint32(C.scaas_ua_abi_version())), uint64(C.scaas_ua_features())); err != nil {
		return err
	}
	loaded = true
	return nil
}

// ABI is the library's scaas_ua_abi_version().
func ABI() uint32 { return uint32(C.scaas_ua_abi_version()) }

// Features is the library's scaas_ua_features().
func Features() uint64 { return uint64(C.scaas_ua_features()) }

// StatusName is the static name of a status ("UAOk", "UAKeyData" ...).
func StatusName(s int32) string { return C.GoString(C.scaas_ua_status_name(C.ScaasUaStatus(s))) }

// call runs one status-returning call on a locked OS thread, so that its last-error detail (per thread) is this call's.
func call(f func() C.ScaasUaStatus) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	s := f()
	if s == 0 {
		return nil
	}
	return &Error{Status: int32(s), Code: C.GoString(C.scaas_ua_status_name(s)), Detail: C.GoString(C.scaas_ua_last_error())}
}

func isBuffer(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.Status == errBuffer
}

// --- secrets ---

// secretBuf is a test hook (secret_buffer_wiped_after_call): every copy this package makes of a secret comes from here.
var secretBuf = func(n int) []byte { return make([]byte, n) }

// Wipe zeroizes b (a secret this package returned, or the caller's own).
func Wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}

// args holds one call's C strings (freed) and secret copies (wiped) and pins them.
type args struct {
	frees []unsafe.Pointer
	wipes [][]byte
	pin   runtime.Pinner
}

func (a *args) str(s string) *C.char {
	c := C.CString(s)
	a.frees = append(a.frees, unsafe.Pointer(c))
	return c
}

// opt is a public optional string: "" is NULL.
func (a *args) opt(s string) *C.char {
	if s == "" {
		return nil
	}
	return a.str(s)
}

// secret is a NUL-terminated copy of a secret, wiped by done; nil is NULL.
func (a *args) secret(b []byte) *C.char {
	if b == nil {
		return nil
	}
	x := secretBuf(len(b) + 1)
	copy(x, b)
	a.wipes = append(a.wipes, x)
	a.pin.Pin(&x[0])
	return (*C.char)(unsafe.Pointer(&x[0]))
}

func (a *args) done() {
	for _, p := range a.frees {
		C.free(p)
	}
	for _, x := range a.wipes {
		Wipe(x)
	}
	a.pin.Unpin()
}

func u8(b []byte) *C.uint8_t {
	if len(b) == 0 {
		return nil
	}
	return (*C.uint8_t)(unsafe.Pointer(&b[0]))
}

func sized(b []byte, n int, what string) (*C.uint8_t, error) {
	if len(b) != n {
		return nil, refuse(fmt.Sprintf("%s: %d bytes", what, n))
	}
	return u8(b), nil
}

// optSized is a fixed-size optional secret: nil is NULL.
func optSized(b []byte, n int, what string) (*C.uint8_t, error) {
	if b == nil {
		return nil, nil
	}
	return sized(b, n, what)
}

// out is a variable output: one call into capacity bytes, again at the size asked for (a size query runs the call again).
func out(capacity int, f func(o unsafe.Pointer, n *C.size_t) C.ScaasUaStatus) ([]byte, error) {
	buf := make([]byte, capacity+1)
	n := C.size_t(capacity)
	err := call(func() C.ScaasUaStatus { return f(unsafe.Pointer(&buf[0]), &n) })
	if isBuffer(err) {
		buf = make([]byte, n+1)
		err = call(func() C.ScaasUaStatus { return f(unsafe.Pointer(&buf[0]), &n) })
	}
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func outStr(capacity int, f func(o unsafe.Pointer, n *C.size_t) C.ScaasUaStatus) (string, error) {
	b, err := out(capacity, f)
	if err != nil || len(b) == 0 {
		return "", err
	}
	return string(b[:len(b)-1]), nil // *out_len counts the NUL
}

// secretOut is a secret variable output whose capacity the library checks before it runs: the size, then the bytes.
func secretOut(f func(o unsafe.Pointer, n *C.size_t) C.ScaasUaStatus) ([]byte, error) {
	var n C.size_t
	if err := call(func() C.ScaasUaStatus { return f(nil, &n) }); err != nil && !isBuffer(err) {
		return nil, err
	}
	buf := make([]byte, n+1)
	if err := call(func() C.ScaasUaStatus { return f(unsafe.Pointer(&buf[0]), &n) }); err != nil {
		Wipe(buf)
		return nil, err
	}
	return buf[:n], nil
}

// --- handles ---

// handle is one library handle: freed exactly once; Close waits for calls in flight (they hold the read lock).
type handle struct {
	mu   sync.RWMutex
	p    unsafe.Pointer
	free func(unsafe.Pointer)
}

func (h *handle) use(f func(unsafe.Pointer) error) error {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if h.p == nil {
		return ErrClosed
	}
	return f(h.p)
}

// Close frees the handle once; later calls on it are ErrClosed.
func (h *handle) Close() {
	h.mu.Lock()
	p := h.p
	h.p = nil
	h.mu.Unlock()
	if p != nil {
		h.free(p)
	}
}

// useAll holds several handles (nil stays NULL; one handle listed twice is held once) for one call.
func useAll(f func([]unsafe.Pointer) error, hs ...*handle) error {
	ps := make([]unsafe.Pointer, len(hs))
	held := map[*handle]bool{}
	for i, h := range hs {
		if h == nil {
			continue
		}
		if !held[h] {
			held[h] = true
			h.mu.RLock()
			defer h.mu.RUnlock()
		}
		if h.p == nil {
			return ErrClosed
		}
		ps[i] = h.p
	}
	return f(ps)
}

type owner interface{ hd() *handle }

// track sets the finalizer that frees what Close did not.
func track[T owner](o T) T {
	runtime.SetFinalizer(o, func(o T) { o.hd().Close() })
	return o
}

// Wallet is a wallet: its secret store and manifest.
type Wallet struct{ h handle }

// Key is a UA key or a native key of a wallet.
type Key struct{ h handle }

// KemKey is a KEM key pair: a UA's or an ephemeral one.
type KemKey struct{ h handle }

// LinkSession is a device-link session of the new device.
type LinkSession struct{ h handle }

// SeedBackup is the recovery phrase of Generate: reveal once, challenge, verify, take.
type SeedBackup struct{ h handle }

// ZetherKey is a Zether key; x stays in the wallet's store.
type ZetherKey struct{ h handle }

// PqzKey is a PQZ key; seed32 stays in the wallet's store.
type PqzKey struct{ h handle }

func (w *Wallet) hd() *handle      { return &w.h }
func (k *Key) hd() *handle         { return &k.h }
func (k *KemKey) hd() *handle      { return &k.h }
func (s *LinkSession) hd() *handle { return &s.h }
func (b *SeedBackup) hd() *handle  { return &b.h }
func (k *ZetherKey) hd() *handle   { return &k.h }
func (k *PqzKey) hd() *handle      { return &k.h }

// Close frees the handle (once; the finalizer does it otherwise). Its children stay valid and answer UAKeyRevoked.
func (w *Wallet) Close()      { w.h.Close() }
func (k *Key) Close()         { k.h.Close() }
func (k *KemKey) Close()      { k.h.Close() }
func (s *LinkSession) Close() { s.h.Close() }
func (b *SeedBackup) Close()  { b.h.Close() }
func (k *ZetherKey) Close()   { k.h.Close() }
func (k *PqzKey) Close()      { k.h.Close() }

func newWallet(p *C.ScaasUaWallet) *Wallet {
	return track(&Wallet{h: handle{p: unsafe.Pointer(p), free: func(p unsafe.Pointer) { C.scaas_ua_wallet_free((*C.ScaasUaWallet)(p)) }}})
}

func newKey(p *C.ScaasUaKey) *Key {
	return track(&Key{h: handle{p: unsafe.Pointer(p), free: func(p unsafe.Pointer) { C.scaas_ua_key_free((*C.ScaasUaKey)(p)) }}})
}

func newKem(p *C.ScaasUaKemKey) *KemKey {
	return track(&KemKey{h: handle{p: unsafe.Pointer(p), free: func(p unsafe.Pointer) { C.scaas_ua_kem_free((*C.ScaasUaKemKey)(p)) }}})
}

func wp(p unsafe.Pointer) *C.ScaasUaWallet { return (*C.ScaasUaWallet)(p) }
func kp(p unsafe.Pointer) *C.ScaasUaKey    { return (*C.ScaasUaKey)(p) }
func kkp(p unsafe.Pointer) *C.ScaasUaKemKey {
	return (*C.ScaasUaKemKey)(p)
}

func hdOf[T owner](o T, isNil bool) *handle {
	if isNil {
		return nil
	}
	return o.hd()
}

// --- wallet ---

// Generate is a new 24-word wallet and its SeedBackup.
func Generate() (*Wallet, *SeedBackup, error) {
	if err := Load(); err != nil {
		return nil, nil, err
	}
	var w *C.ScaasUaWallet
	var b *C.ScaasUaSeedBackup
	if err := call(func() C.ScaasUaStatus { return C.scaas_ua_wallet_generate(&w, &b) }); err != nil {
		return nil, nil, err
	}
	sb := track(&SeedBackup{h: handle{p: unsafe.Pointer(b), free: func(p unsafe.Pointer) { C.scaas_ua_seed_backup_free((*C.ScaasUaSeedBackup)(p)) }}})
	return newWallet(w), sb, nil
}

// FromMnemonic is the wallet of a 12- to 24-word English mnemonic and its BIP-39 passphrase (nil = empty).
func FromMnemonic(words, bip39Passphrase []byte) (*Wallet, error) {
	if err := Load(); err != nil {
		return nil, err
	}
	var a args
	defer a.done()
	var w *C.ScaasUaWallet
	if err := call(func() C.ScaasUaStatus {
		return C.scaas_ua_wallet_from_mnemonic(a.secret(words), a.secret(bip39Passphrase), &w)
	}); err != nil {
		return nil, err
	}
	return newWallet(w), nil
}

// OpenVault is the wallet of a seed vault: exactly one of passphrase and prf32 (both: the PRF secret).
func OpenVault(vaultJSON string, passphrase, prf32, bip39Passphrase []byte) (*Wallet, error) {
	if err := Load(); err != nil {
		return nil, err
	}
	prf, err := optSized(prf32, 32, "prf32")
	if err != nil {
		return nil, err
	}
	var a args
	defer a.done()
	var w *C.ScaasUaWallet
	if err := call(func() C.ScaasUaStatus {
		return C.scaas_ua_wallet_open_vault(a.str(vaultJSON), a.secret(passphrase), prf, a.secret(bip39Passphrase), &w)
	}); err != nil {
		return nil, err
	}
	return newWallet(w), nil
}

// Unlock reopens a locked wallet from its seed vault; earlier handles stay revoked.
func (w *Wallet) Unlock(vaultJSON string, passphrase, prf32, bip39Passphrase []byte) error {
	prf, err := optSized(prf32, 32, "prf32")
	if err != nil {
		return err
	}
	var a args
	defer a.done()
	return w.h.use(func(p unsafe.Pointer) error {
		return call(func() C.ScaasUaStatus {
			return C.scaas_ua_wallet_unlock(wp(p), a.str(vaultJSON), a.secret(passphrase), prf, a.secret(bip39Passphrase))
		})
	})
}

func (w *Wallet) str(capacity int, f func(p, o unsafe.Pointer, n *C.size_t) C.ScaasUaStatus) (s string, err error) {
	err = w.h.use(func(p unsafe.Pointer) error {
		s, err = outStr(capacity, func(o unsafe.Pointer, n *C.size_t) C.ScaasUaStatus { return f(p, o, n) })
		return err
	})
	return
}

// SealVault is the seed vault JSON of this wallet under passphrase (a new vault each call).
func (w *Wallet) SealVault(passphrase []byte) (string, error) {
	var a args
	defer a.done()
	return w.str(1<<14, func(p, o unsafe.Pointer, n *C.size_t) C.ScaasUaStatus {
		return C.scaas_ua_wallet_seal_vault(wp(p), a.secret(passphrase), (*C.char)(o), n)
	})
}

// Lock waits for calls in flight, wipes the secrets and revokes every child handle.
func (w *Wallet) Lock() error {
	return w.h.use(func(p unsafe.Pointer) error {
		return call(func() C.ScaasUaStatus { return C.scaas_ua_wallet_lock(wp(p)) })
	})
}

// MemoryProtection is the arena's chunks, of them mlocked, of them no-dump.
type MemoryProtection struct{ Chunks, Locked, NoDump uint64 }

// MemoryProtection is the arena's protection now (all 0 while locked).
func (w *Wallet) MemoryProtection() (m MemoryProtection, err error) {
	var c C.ScaasUaMemoryProtection
	err = w.h.use(func(p unsafe.Pointer) error {
		return call(func() C.ScaasUaStatus { return C.scaas_ua_wallet_memory_protection(wp(p), &c) })
	})
	return MemoryProtection{uint64(c.chunks), uint64(c.locked), uint64(c.no_dump)}, err
}

func (w *Wallet) key(f func(p unsafe.Pointer, k **C.ScaasUaKey) C.ScaasUaStatus) (*Key, error) {
	var k *C.ScaasUaKey
	if err := w.h.use(func(p unsafe.Pointer) error { return call(func() C.ScaasUaStatus { return f(p, &k) }) }); err != nil {
		return nil, err
	}
	return newKey(k), nil
}

// UAKey is the UA key kind of account / index.
func (w *Wallet) UAKey(kind uint16, account, index uint32) (*Key, error) {
	return w.key(func(p unsafe.Pointer, k **C.ScaasUaKey) C.ScaasUaStatus {
		return C.scaas_ua_wallet_ua_key(wp(p), C.uint16_t(kind), C.uint32_t(account), C.uint32_t(index), k)
	})
}

// NativeKey is key index of network (an index of Networks), coinType CoinDefault or a coin type below 2^31.
func (w *Wallet) NativeKey(network, index, coinType uint32) (*Key, error) {
	return w.key(func(p unsafe.Pointer, k **C.ScaasUaKey) C.ScaasUaStatus {
		return C.scaas_ua_wallet_native_key(wp(p), C.uint32_t(network), C.uint32_t(index), C.uint32_t(coinType), k)
	})
}

// ImportNativeKey imports a 32-byte key of network; the caller wipes secret.
func (w *Wallet) ImportNativeKey(network uint32, secret []byte) (*Key, error) {
	return w.key(func(p unsafe.Pointer, k **C.ScaasUaKey) C.ScaasUaStatus {
		return C.scaas_ua_wallet_import_native_key(wp(p), C.uint32_t(network), u8(secret), C.size_t(len(secret)), k)
	})
}

// ImportedKey is imported key n of network.
func (w *Wallet) ImportedKey(network, n uint32) (*Key, error) {
	return w.key(func(p unsafe.Pointer, k **C.ScaasUaKey) C.ScaasUaStatus {
		return C.scaas_ua_wallet_imported_key(wp(p), C.uint32_t(network), C.uint32_t(n), k)
	})
}

// SealLabelVault is a vault of label "manifest" or "native-import:<network>:<n>" under passphrase.
func (w *Wallet) SealLabelVault(label string, passphrase []byte) (string, error) {
	var a args
	defer a.done()
	return w.str(1<<14, func(p, o unsafe.Pointer, n *C.size_t) C.ScaasUaStatus {
		return C.scaas_ua_wallet_seal_label_vault(wp(p), a.str(label), a.secret(passphrase), (*C.char)(o), n)
	})
}

// OpenLabelVault opens a label vault into this (unlocked) wallet.
func (w *Wallet) OpenLabelVault(vaultJSON string, passphrase, prf32 []byte) error {
	prf, err := optSized(prf32, 32, "prf32")
	if err != nil {
		return err
	}
	var a args
	defer a.done()
	return w.h.use(func(p unsafe.Pointer) error {
		return call(func() C.ScaasUaStatus {
			return C.scaas_ua_wallet_open_label_vault(wp(p), a.str(vaultJSON), a.secret(passphrase), prf)
		})
	})
}

// ManifestJSON is the public manifest JSON (kept by Lock).
func (w *Wallet) ManifestJSON() (string, error) {
	return w.str(1<<14, func(p, o unsafe.Pointer, n *C.size_t) C.ScaasUaStatus {
		return C.scaas_ua_wallet_manifest_json(wp(p), (*C.char)(o), n)
	})
}

// DiscoverCandidates is [{index, ua}] of the UA keys kind of account at indices 0..gap.
func (w *Wallet) DiscoverCandidates(kind uint16, account, gap uint32) (string, error) {
	return w.str(1<<17, func(p, o unsafe.Pointer, n *C.size_t) C.ScaasUaStatus {
		return C.scaas_ua_wallet_discover_candidates(wp(p), C.uint16_t(kind), C.uint32_t(account), C.uint32_t(gap), (*C.char)(o), n)
	})
}

// Recipient is a backup recipient: the KEM key KemPk of record Version of the UA of (Kind, KeyData), or an ephemeral key.
type Recipient struct {
	Kind      uint16
	KeyData   []byte
	Version   uint64
	KemPk     []byte
	Ephemeral bool
}

// BackupSeal is one scaas/backup/v1 container per recipient (a JSON array), signed by sender; it raises the backup generation
// (once per call into the 4 MiB first buffer).
func (w *Wallet) BackupSeal(sender *Key, recipients []Recipient) (s string, err error) {
	var a args
	defer a.done()
	rs := make([]C.ScaasUaRecipient, len(recipients)+1)
	for i, r := range recipients {
		rs[i] = C.ScaasUaRecipient{kind: C.uint16_t(r.Kind), key_data: u8(r.KeyData), key_data_len: C.size_t(len(r.KeyData)),
			version: C.uint64_t(r.Version), kem_pk: u8(r.KemPk), kem_pk_len: C.size_t(len(r.KemPk)), ephemeral: C.bool(r.Ephemeral)}
		if len(r.KeyData) > 0 {
			a.pin.Pin(&r.KeyData[0])
		}
		if len(r.KemPk) > 0 {
			a.pin.Pin(&r.KemPk[0])
		}
	}
	var arr *C.ScaasUaRecipient
	if len(recipients) > 0 {
		arr = &rs[0]
	}
	err = useAll(func(ps []unsafe.Pointer) error {
		s, err = outStr(4<<20, func(o unsafe.Pointer, n *C.size_t) C.ScaasUaStatus {
			return C.scaas_ua_wallet_backup_seal(wp(ps[0]), kp(ps[1]), arr, C.size_t(len(recipients)), (*C.char)(o), n)
		})
		return err
	}, &w.h, hdOf(sender, sender == nil))
	return
}

// LinkSeal is the existing device's link container to a new device's session (its KEM key and short code), signed by sender.
func (w *Wallet) LinkSeal(sender *Key, sessionKemPk []byte, shortCode string) (s string, err error) {
	var a args
	defer a.done()
	err = useAll(func(ps []unsafe.Pointer) error {
		s, err = outStr(1<<20, func(o unsafe.Pointer, n *C.size_t) C.ScaasUaStatus {
			return C.scaas_ua_wallet_link_seal(wp(ps[0]), kp(ps[1]), u8(sessionKemPk), C.size_t(len(sessionKemPk)), a.str(shortCode), (*C.char)(o), n)
		})
		return err
	}, &w.h, hdOf(sender, sender == nil))
	return
}

// ZetherKey is the Zether key of coin / account, use ZetherUseConf or ZetherUseViewing.
func (w *Wallet) ZetherKey(coin, account, use uint32) (*ZetherKey, error) {
	var k *C.ScaasUaZetherKey
	if err := w.h.use(func(p unsafe.Pointer) error {
		return call(func() C.ScaasUaStatus {
			return C.scaas_ua_wallet_zether_key(wp(p), C.uint32_t(coin), C.uint32_t(account), C.uint32_t(use), &k)
		})
	}); err != nil {
		return nil, err
	}
	return track(&ZetherKey{h: handle{p: unsafe.Pointer(k), free: func(p unsafe.Pointer) { C.scaas_ua_zether_key_free((*C.ScaasUaZetherKey)(p)) }}}), nil
}

// PqzKey is the PQZ key of account / index.
func (w *Wallet) PqzKey(account, index uint32) (*PqzKey, error) {
	var k *C.ScaasUaPqzKey
	if err := w.h.use(func(p unsafe.Pointer) error {
		return call(func() C.ScaasUaStatus {
			return C.scaas_ua_wallet_pqz_key(wp(p), C.uint32_t(account), C.uint32_t(index), &k)
		})
	}); err != nil {
		return nil, err
	}
	return track(&PqzKey{h: handle{p: unsafe.Pointer(k), free: func(p unsafe.Pointer) { C.scaas_ua_pqz_key_free((*C.ScaasUaPqzKey)(p)) }}}), nil
}

// ExportPqzLeafRaw returns a secret in the clear: the 32-byte PQZ leaf seed32. The caller wipes it (Wipe).
func (w *Wallet) ExportPqzLeafRaw(account, index uint32) ([]byte, error) {
	leaf := make([]byte, 32)
	if err := w.h.use(func(p unsafe.Pointer) error {
		return call(func() C.ScaasUaStatus {
			return C.scaas_ua_export_pqz_leaf_raw(wp(p), C.uint32_t(account), C.uint32_t(index), u8(leaf))
		})
	}); err != nil {
		return nil, err
	}
	return leaf, nil
}

func restore(rollback bool, kk *KemKey, container, expect, members, accepted string, current *Wallet, bip39Passphrase []byte) (*Wallet, error) {
	var a args
	defer a.done()
	var w *C.ScaasUaWallet
	var installed C.bool
	err := useAll(func(ps []unsafe.Pointer) error {
		return call(func() C.ScaasUaStatus {
			kk, c, e, m, ac, cur, bp := kkp(ps[0]), a.str(container), a.str(expect), a.opt(members), a.opt(accepted), wp(ps[1]), a.secret(bip39Passphrase)
			if rollback {
				return C.scaas_ua_wallet_restore_backup_rollback(kk, c, e, m, ac, cur, bp, &w, &installed)
			}
			return C.scaas_ua_wallet_restore_backup(kk, c, e, m, ac, cur, bp, &w, &installed)
		})
	}, hdOf(kk, kk == nil), hdOf(current, current == nil))
	if err != nil || !bool(installed) {
		return nil, err
	}
	return newWallet(w), nil
}

// RestoreBackup is the wallet a backup container carries, or nil when current holds that generation already (an older one is
// UABackupRollback). members and accepted "" are none.
func RestoreBackup(kk *KemKey, container, expect, members, accepted string, current *Wallet, bip39Passphrase []byte) (*Wallet, error) {
	return restore(false, kk, container, expect, members, accepted, current, bip39Passphrase)
}

// RestoreBackupRollback is RestoreBackup that may install an older backup: only after the user confirmed the rollback.
func RestoreBackupRollback(kk *KemKey, container, expect, members, accepted string, current *Wallet, bip39Passphrase []byte) (*Wallet, error) {
	return restore(true, kk, container, expect, members, accepted, current, bip39Passphrase)
}

// FromLink is the wallet a link container carries to session (which it consumes).
func FromLink(s *LinkSession, container, expect, members, accepted string, bip39Passphrase []byte) (*Wallet, error) {
	var a args
	defer a.done()
	var w *C.ScaasUaWallet
	if err := useAll(func(ps []unsafe.Pointer) error {
		return call(func() C.ScaasUaStatus {
			return C.scaas_ua_wallet_from_link((*C.ScaasUaLinkSession)(ps[0]), a.str(container), a.str(expect), a.opt(members), a.opt(accepted),
				a.secret(bip39Passphrase), &w)
		})
	}, hdOf(s, s == nil)); err != nil {
		return nil, err
	}
	return newWallet(w), nil
}

// --- seed backup ---

func sbp(p unsafe.Pointer) *C.ScaasUaSeedBackup { return (*C.ScaasUaSeedBackup)(p) }

// Reveal is the recovery phrase, once; the caller wipes it.
func (b *SeedBackup) Reveal() ([]byte, error) {
	buf := make([]byte, MnemonicMax)
	n := C.size_t(MnemonicMax)
	if err := b.h.use(func(p unsafe.Pointer) error {
		return call(func() C.ScaasUaStatus {
			return C.scaas_ua_seed_backup_reveal(sbp(p), (*C.char)(unsafe.Pointer(&buf[0])), &n)
		})
	}); err != nil {
		return nil, err
	}
	return buf[:n-1], nil
}

// Challenge is three word positions to ask, 1-based and ascending.
func (b *SeedBackup) Challenge() (pos [3]uint32, err error) {
	var c [3]C.uint32_t
	err = b.h.use(func(p unsafe.Pointer) error {
		return call(func() C.ScaasUaStatus { return C.scaas_ua_seed_backup_challenge(sbp(p), &c[0]) })
	})
	return [3]uint32{uint32(c[0]), uint32(c[1]), uint32(c[2])}, err
}

// Verify says whether answers are the words at the asked positions.
func (b *SeedBackup) Verify(answers [][]byte) (ok bool, err error) {
	var a args
	defer a.done()
	ws := make([]*C.char, len(answers)+1)
	for i, x := range answers {
		ws[i] = a.secret(x)
	}
	var r C.bool
	err = b.h.use(func(p unsafe.Pointer) error {
		return call(func() C.ScaasUaStatus {
			return C.scaas_ua_seed_backup_verify(sbp(p), &ws[0], C.size_t(len(answers)), &r)
		})
	})
	return bool(r), err
}

// Take is the entropy once the words were confirmed (nil before, and after the first take); the caller wipes it.
func (b *SeedBackup) Take() ([]byte, error) {
	buf := make([]byte, EntropyMax)
	n := C.size_t(EntropyMax)
	var taken C.bool
	if err := b.h.use(func(p unsafe.Pointer) error {
		return call(func() C.ScaasUaStatus { return C.scaas_ua_seed_backup_take(sbp(p), u8(buf), &n, &taken) })
	}); err != nil || !bool(taken) {
		return nil, err
	}
	return buf[:n], nil
}

// --- keys and signing ---

func (k *Key) out(capacity int, f func(p unsafe.Pointer, o *C.uint8_t, n *C.size_t) C.ScaasUaStatus) (r []byte, err error) {
	err = k.h.use(func(p unsafe.Pointer) error {
		r, err = out(capacity, func(o unsafe.Pointer, n *C.size_t) C.ScaasUaStatus { return f(p, (*C.uint8_t)(o), n) })
		return err
	})
	return
}

// KeyData is a UA key's key data, or a native key's public key (readable after its wallet is locked).
func (k *Key) KeyData() ([]byte, error) {
	return k.out(4096, func(p unsafe.Pointer, o *C.uint8_t, n *C.size_t) C.ScaasUaStatus {
		return C.scaas_ua_key_data(kp(p), o, n)
	})
}

// SignUA is a UA key's signature over uaMessage(kind, purpose, digest).
func (k *Key) SignUA(purpose, digest [32]byte) ([]byte, error) {
	return k.out(8192, func(p unsafe.Pointer, o *C.uint8_t, n *C.size_t) C.ScaasUaStatus {
		return C.scaas_ua_sign_ua(kp(p), (*C.uint8_t)(&purpose[0]), (*C.uint8_t)(&digest[0]), o, n)
	})
}

// SignMember is a UA key's signature as a member of the structure structureUA over its ua_msg.
func (k *Key) SignMember(structureUA, structureUAMsg [32]byte) ([]byte, error) {
	return k.out(8192, func(p unsafe.Pointer, o *C.uint8_t, n *C.size_t) C.ScaasUaStatus {
		return C.scaas_ua_sign_member(kp(p), (*C.uint8_t)(&structureUA[0]), (*C.uint8_t)(&structureUAMsg[0]), o, n)
	})
}

// SignTyped is a native EVM key's EIP-712 signature of typedData, only if expect says the user confirmed it.
func (k *Key) SignTyped(typedData, expect string) ([]byte, error) {
	var a args
	defer a.done()
	return k.out(128, func(p unsafe.Pointer, o *C.uint8_t, n *C.size_t) C.ScaasUaStatus {
		return C.scaas_ua_sign_typed(kp(p), a.str(typedData), a.str(expect), o, n)
	})
}

// SignTypedAny is SignTyped with no SCaaS check (the general EVM wallet's opt-in by this name).
func (k *Key) SignTypedAny(typedData string) ([]byte, error) {
	var a args
	defer a.done()
	return k.out(128, func(p unsafe.Pointer, o *C.uint8_t, n *C.size_t) C.ScaasUaStatus {
		return C.scaas_ua_sign_typed_any(kp(p), a.str(typedData), o, n)
	})
}

// SignTransaction is a native EVM key's signed raw transaction of tx (named fields, types 0-3).
func (k *Key) SignTransaction(tx string) ([]byte, error) {
	var a args
	defer a.done()
	return k.out(1<<15, func(p unsafe.Pointer, o *C.uint8_t, n *C.size_t) C.ScaasUaStatus {
		return C.scaas_ua_sign_transaction(kp(p), a.str(tx), o, n)
	})
}

// SignKeyProof is a native key's proof of control over challenge.
func (k *Key) SignKeyProof(challenge []byte) ([]byte, error) {
	return k.out(128, func(p unsafe.Pointer, o *C.uint8_t, n *C.size_t) C.ScaasUaStatus {
		return C.scaas_ua_sign_key_proof(kp(p), u8(challenge), C.size_t(len(challenge)), o, n)
	})
}

// SignDigestRaw is a native key's signature of a raw digest (a UA key: UARawDigestRefused).
func (k *Key) SignDigestRaw(digest [32]byte) ([]byte, error) {
	return k.out(128, func(p unsafe.Pointer, o *C.uint8_t, n *C.size_t) C.ScaasUaStatus {
		return C.scaas_ua_sign_digest_raw(kp(p), (*C.uint8_t)(&digest[0]), o, n)
	})
}

// KemKey is the UA's KEM key of record version (0 = the register key).
func (k *Key) KemKey(version uint64) (*KemKey, error) {
	var kk *C.ScaasUaKemKey
	if err := k.h.use(func(p unsafe.Pointer) error {
		return call(func() C.ScaasUaStatus { return C.scaas_ua_kem_key(kp(p), C.uint64_t(version), &kk) })
	}); err != nil {
		return nil, err
	}
	return newKem(kk), nil
}

// UASig is the UASig JSON of request (named fields; signing keys by position in keys).
func UASig(request string, keys []*Key) (s string, err error) {
	if err := Load(); err != nil {
		return "", err
	}
	var a args
	defer a.done()
	hs := make([]*handle, len(keys))
	for i, k := range keys {
		hs[i] = &k.h
	}
	err = useAll(func(ps []unsafe.Pointer) error {
		arr := make([]*C.ScaasUaKey, len(ps)+1)
		for i, p := range ps {
			arr[i] = kp(p)
		}
		s, err = outStr(1<<16, func(o unsafe.Pointer, n *C.size_t) C.ScaasUaStatus {
			return C.scaas_ua_uasig(a.str(request), &arr[0], C.size_t(len(ps)), (*C.char)(o), n)
		})
		return err
	}, hs...)
	return
}

// ExternalKeyNew is reserved (phase 2): no build of this round has an external key (UAKindUnavailable).
func ExternalKeyNew(keyRef string) (*Key, error) {
	if err := Load(); err != nil {
		return nil, err
	}
	var a args
	defer a.done()
	var k *C.ScaasUaKey
	if err := call(func() C.ScaasUaStatus { return C.scaas_ua_external_key_new(a.str(keyRef), nil, &k) }); err != nil {
		return nil, err
	}
	return newKey(k), nil
}

// --- KEM, seal, open ---

// KemEphemeral is an ephemeral KEM key (a device without a seed yet).
func KemEphemeral() (*KemKey, error) {
	if err := Load(); err != nil {
		return nil, err
	}
	var kk *C.ScaasUaKemKey
	if err := call(func() C.ScaasUaStatus { return C.scaas_ua_kem_ephemeral(&kk) }); err != nil {
		return nil, err
	}
	return newKem(kk), nil
}

// KemPk is the key's kemPk (KemPkLen bytes).
func (k *KemKey) KemPk() ([]byte, error) {
	pk := make([]byte, KemPkLen)
	err := k.h.use(func(p unsafe.Pointer) error {
		return call(func() C.ScaasUaStatus { return C.scaas_ua_kem_pk(kkp(p), u8(pk)) })
	})
	return pk, err
}

// Decaps is the 32-byte shared secret of (mlkemCt, x25519Eph); the caller wipes it.
func (k *KemKey) Decaps(mlkemCt []byte, x25519Eph [32]byte) ([]byte, error) {
	ss := make([]byte, 32)
	if err := k.h.use(func(p unsafe.Pointer) error {
		return call(func() C.ScaasUaStatus {
			return C.scaas_ua_kem_decaps(kkp(p), u8(mlkemCt), C.size_t(len(mlkemCt)), (*C.uint8_t)(&x25519Eph[0]), u8(ss))
		})
	}); err != nil {
		return nil, err
	}
	return ss, nil
}

// Open is the plaintext of a seal; the caller wipes it.
func (k *KemKey) Open(purpose string, aad, mlkemCt []byte, x25519Eph [32]byte, ct []byte) ([]byte, error) {
	var a args
	defer a.done()
	var r []byte
	err := k.h.use(func(p unsafe.Pointer) (err error) {
		r, err = secretOut(func(o unsafe.Pointer, n *C.size_t) C.ScaasUaStatus {
			return C.scaas_ua_open(kkp(p), a.str(purpose), u8(aad), C.size_t(len(aad)), u8(mlkemCt), C.size_t(len(mlkemCt)),
				(*C.uint8_t)(&x25519Eph[0]), u8(ct), C.size_t(len(ct)), (*C.uint8_t)(o), n)
		})
		return
	})
	return r, err
}

// OpenContainer is the plaintext of a sealed container accepted as expect says (members, accepted "" = none); the caller wipes it.
func (k *KemKey) OpenContainer(container, expect, members, accepted string) ([]byte, error) {
	var a args
	defer a.done()
	var r []byte
	err := k.h.use(func(p unsafe.Pointer) (err error) {
		r, err = secretOut(func(o unsafe.Pointer, n *C.size_t) C.ScaasUaStatus {
			return C.scaas_ua_open_container(kkp(p), a.str(container), a.str(expect), a.opt(members), a.opt(accepted), (*C.uint8_t)(o), n)
		})
		return
	})
	return r, err
}

// KemEncaps is an encapsulation to kemPk: the ciphertext, the ephemeral X25519 key and the shared secret (the caller wipes it).
func KemEncaps(kemPk []byte) (mlkemCt []byte, x25519Eph [32]byte, ss []byte, err error) {
	if err = Load(); err != nil {
		return
	}
	mlkemCt, ss = make([]byte, KemCtLen), make([]byte, 32)
	if err = call(func() C.ScaasUaStatus {
		return C.scaas_ua_kem_encaps(u8(kemPk), C.size_t(len(kemPk)), u8(mlkemCt), (*C.uint8_t)(&x25519Eph[0]), u8(ss))
	}); err != nil {
		return nil, x25519Eph, nil, err
	}
	return
}

// Seal is a seal of pt to kemPk under purpose and aad (no sender authenticated).
func Seal(kemPk []byte, purpose string, aad, pt []byte) (mlkemCt []byte, x25519Eph [32]byte, ct []byte, err error) {
	if err = Load(); err != nil {
		return
	}
	var a args
	defer a.done()
	mlkemCt, ct = make([]byte, KemCtLen), make([]byte, len(pt)+16)
	nm, nc := C.size_t(KemCtLen), C.size_t(len(ct))
	if err = call(func() C.ScaasUaStatus {
		return C.scaas_ua_seal(u8(kemPk), C.size_t(len(kemPk)), a.str(purpose), u8(aad), C.size_t(len(aad)), u8(pt), C.size_t(len(pt)),
			u8(mlkemCt), &nm, (*C.uint8_t)(&x25519Eph[0]), u8(ct), &nc)
	}); err != nil {
		return nil, x25519Eph, nil, err
	}
	return mlkemCt[:nm], x25519Eph, ct[:nc], nil
}

// --- link sessions ---

func lsp(p unsafe.Pointer) *C.ScaasUaLinkSession { return (*C.ScaasUaLinkSession)(p) }

// NewLinkSession is a link session on the new device.
func NewLinkSession() (*LinkSession, error) {
	if err := Load(); err != nil {
		return nil, err
	}
	var s *C.ScaasUaLinkSession
	if err := call(func() C.ScaasUaStatus { return C.scaas_ua_link_session_new(&s) }); err != nil {
		return nil, err
	}
	return track(&LinkSession{h: handle{p: unsafe.Pointer(s), free: func(p unsafe.Pointer) { C.scaas_ua_link_session_free(lsp(p)) }}}), nil
}

// KemPk is the session's kemPk, the key the existing device seals to.
func (s *LinkSession) KemPk() ([]byte, error) {
	pk := make([]byte, KemPkLen)
	err := s.h.use(func(p unsafe.Pointer) error {
		return call(func() C.ScaasUaStatus { return C.scaas_ua_link_session_kem_pk(lsp(p), u8(pk)) })
	})
	return pk, err
}

// ShortCode is the 8-digit code both screens show.
func (s *LinkSession) ShortCode() (c string, err error) {
	err = s.h.use(func(p unsafe.Pointer) error {
		c, err = outStr(16, func(o unsafe.Pointer, n *C.size_t) C.ScaasUaStatus {
			return C.scaas_ua_link_session_short_code(lsp(p), (*C.char)(o), n)
		})
		return err
	})
	return
}

// --- vaults, AEAD, HKDF, HMAC, WebAuthn ---

func loadedStr(capacity int, f func(o unsafe.Pointer, n *C.size_t) C.ScaasUaStatus) (string, error) {
	if err := Load(); err != nil {
		return "", err
	}
	return outStr(capacity, f)
}

// VaultNeedsRewrap says whether the vault's pin envelope is weaker than today's parameters.
func VaultNeedsRewrap(vaultJSON string) (bool, error) {
	if err := Load(); err != nil {
		return false, err
	}
	var a args
	defer a.done()
	var r C.bool
	err := call(func() C.ScaasUaStatus { return C.scaas_ua_vault_needs_rewrap(a.str(vaultJSON), &r) })
	return bool(r), err
}

// VaultRewrapPin is the vault under a new pin envelope (same DEK).
func VaultRewrapPin(vaultJSON string, oldPassphrase, newPassphrase []byte) (string, error) {
	var a args
	defer a.done()
	return loadedStr(1<<14, func(o unsafe.Pointer, n *C.size_t) C.ScaasUaStatus {
		return C.scaas_ua_vault_rewrap_pin(a.str(vaultJSON), a.secret(oldPassphrase), a.secret(newPassphrase), (*C.char)(o), n)
	})
}

// VaultEnablePrf is the vault with a PRF envelope, opened once by passphrase; the caller wipes prf32.
func VaultEnablePrf(vaultJSON string, passphrase, prf32 []byte, credentialID string, salt []byte) (string, error) {
	prf, err := sized(prf32, 32, "prf32")
	if err != nil {
		return "", err
	}
	var a args
	defer a.done()
	return loadedStr(1<<14, func(o unsafe.Pointer, n *C.size_t) C.ScaasUaStatus {
		return C.scaas_ua_vault_enable_prf(a.str(vaultJSON), a.secret(passphrase), prf, a.str(credentialID), u8(salt), C.size_t(len(salt)), (*C.char)(o), n)
	})
}

func aead(open bool, alg uint32, key, nonce, aad, data []byte) ([]byte, error) {
	if err := Load(); err != nil {
		return nil, err
	}
	k, err := sized(key, 32, "key")
	if err != nil {
		return nil, err
	}
	nn, err := sized(nonce, 12, "nonce")
	if err != nil {
		return nil, err
	}
	size := len(data) + 16
	if open {
		size = max(len(data)-16, 0)
	}
	o := make([]byte, size+1)
	n := C.size_t(size)
	if err := call(func() C.ScaasUaStatus {
		if open {
			return C.scaas_ua_aead_open(C.uint32_t(alg), k, nn, u8(aad), C.size_t(len(aad)), u8(data), C.size_t(len(data)), u8(o), &n)
		}
		return C.scaas_ua_aead_seal(C.uint32_t(alg), k, nn, u8(aad), C.size_t(len(aad)), u8(data), C.size_t(len(data)), u8(o), &n)
	}); err != nil {
		return nil, err
	}
	return o[:n], nil
}

// AeadSeal is ct || tag of data under the caller's 32-byte key and 12-byte nonce (nonce uniqueness is the caller's).
func AeadSeal(alg uint32, key, nonce, aad, data []byte) ([]byte, error) {
	return aead(false, alg, key, nonce, aad, data)
}

// AeadOpen is the plaintext of ct || tag (UAAead for a bad tag); the caller wipes it.
func AeadOpen(alg uint32, key, nonce, aad, data []byte) ([]byte, error) {
	return aead(true, alg, key, nonce, aad, data)
}

// HkdfSha256 is n bytes of HKDF-SHA256 (key material: the caller wipes it).
func HkdfSha256(ikm, salt, info []byte, n int) ([]byte, error) {
	if err := Load(); err != nil {
		return nil, err
	}
	o := make([]byte, n+1)
	if err := call(func() C.ScaasUaStatus {
		return C.scaas_ua_hkdf_sha256(u8(ikm), C.size_t(len(ikm)), u8(salt), C.size_t(len(salt)), u8(info), C.size_t(len(info)), u8(o), C.size_t(n))
	}); err != nil {
		return nil, err
	}
	return o[:n], nil
}

// HmacSha256 is HMAC-SHA256 of data under key.
func HmacSha256(key, data []byte) (mac [32]byte, err error) {
	if err = Load(); err != nil {
		return
	}
	err = call(func() C.ScaasUaStatus {
		return C.scaas_ua_hmac_sha256(u8(key), C.size_t(len(key)), u8(data), C.size_t(len(data)), (*C.uint8_t)(&mac[0]))
	})
	return
}

// WebAuthnChallenge is uaMessage(0x0100, purpose, digest).
func WebAuthnChallenge(purpose, digest [32]byte) (ch [32]byte, err error) {
	if err = Load(); err != nil {
		return
	}
	err = call(func() C.ScaasUaStatus {
		return C.scaas_ua_webauthn_challenge((*C.uint8_t)(&purpose[0]), (*C.uint8_t)(&digest[0]), (*C.uint8_t)(&ch[0]))
	})
	return
}

// WebAuthnAssertion is the webauthn-p256 signature of an assertion, verified with keyData against expectedChallenge.
func WebAuthnAssertion(keyData []byte, expectedChallenge [32]byte, authData, clientDataJSON []byte, r, s [32]byte) ([]byte, error) {
	if err := Load(); err != nil {
		return nil, err
	}
	return out(1024, func(o unsafe.Pointer, n *C.size_t) C.ScaasUaStatus {
		return C.scaas_ua_webauthn_assertion(u8(keyData), C.size_t(len(keyData)), (*C.uint8_t)(&expectedChallenge[0]), u8(authData),
			C.size_t(len(authData)), u8(clientDataJSON), C.size_t(len(clientDataJSON)), (*C.uint8_t)(&r[0]), (*C.uint8_t)(&s[0]), (*C.uint8_t)(o), n)
	})
}

// --- the Zether facade ---

func zkp(p unsafe.Pointer) *C.ScaasUaZetherKey { return (*C.ScaasUaZetherKey)(p) }

// Public is the key's Y (128 bytes) and its UA (readable after lock).
func (k *ZetherKey) Public() (y []byte, id [32]byte, err error) {
	y = make([]byte, ZetherYLen)
	err = k.h.use(func(p unsafe.Pointer) error {
		return call(func() C.ScaasUaStatus { return C.scaas_ua_zether_public(zkp(p), u8(y), (*C.uint8_t)(&id[0])) })
	})
	return
}

// Call is zether-prover's command cmd on request (named fields) with this key: its JSON answer.
func (k *ZetherKey) Call(cmd, request string) (s string, err error) {
	var a args
	defer a.done()
	err = k.h.use(func(p unsafe.Pointer) error {
		s, err = outStr(1<<20, func(o unsafe.Pointer, n *C.size_t) C.ScaasUaStatus {
			return C.scaas_ua_zether_call(zkp(p), a.str(cmd), a.str(request), (*C.char)(o), n)
		})
		return err
	})
	return
}

// SealBalanceCache is the box {iv, ct} of the cache entries under the key's x.
func (k *ZetherKey) SealBalanceCache(entries []byte) (s string, err error) {
	err = k.h.use(func(p unsafe.Pointer) error {
		s, err = outStr(len(entries)+256, func(o unsafe.Pointer, n *C.size_t) C.ScaasUaStatus {
			return C.scaas_ua_zether_seal_balance_cache(zkp(p), u8(entries), C.size_t(len(entries)), (*C.char)(o), n)
		})
		return err
	})
	return
}

// OpenBalanceCache is the entries of a box (UAAead for another key's box); the caller wipes them.
func (k *ZetherKey) OpenBalanceCache(box string) (r []byte, err error) {
	var a args
	defer a.done()
	err = k.h.use(func(p unsafe.Pointer) error {
		r, err = secretOut(func(o unsafe.Pointer, n *C.size_t) C.ScaasUaStatus {
			return C.scaas_ua_zether_open_balance_cache(zkp(p), a.str(box), (*C.uint8_t)(o), n)
		})
		return err
	})
	return
}

// --- the PQZ facade ---

func qkp(p unsafe.Pointer) *C.ScaasUaPqzKey { return (*C.ScaasUaPqzKey)(p) }

// PublicKey is the key's pk (the set's pkLen bytes; readable after lock).
func (k *PqzKey) PublicKey() (r []byte, err error) {
	err = k.h.use(func(p unsafe.Pointer) error {
		r, err = out(32<<10, func(o unsafe.Pointer, n *C.size_t) C.ScaasUaStatus {
			return C.scaas_ua_pqz_public(qkp(p), (*C.uint8_t)(o), n)
		})
		return err
	})
	return
}

// Call is PQZ command cmd on request with this key: its JSON answer, in one call into PqzOutMax bytes (a size query would prove
// again, and a proof's length varies).
func (k *PqzKey) Call(cmd, request string) (s string, err error) {
	var a args
	defer a.done()
	buf := make([]byte, PqzOutMax)
	n := C.size_t(PqzOutMax)
	err = k.h.use(func(p unsafe.Pointer) error {
		return call(func() C.ScaasUaStatus {
			return C.scaas_ua_pqz_call(qkp(p), a.str(cmd), a.str(request), (*C.char)(unsafe.Pointer(&buf[0])), &n)
		})
	})
	if err != nil {
		return "", err
	}
	return string(buf[:n-1]), nil
}

// SealBalanceCache is the box {iv, ct} of entries under the key's leaf.
func (k *PqzKey) SealBalanceCache(entries []byte) (s string, err error) {
	err = k.h.use(func(p unsafe.Pointer) error {
		s, err = outStr(len(entries)+256, func(o unsafe.Pointer, n *C.size_t) C.ScaasUaStatus {
			return C.scaas_ua_pqz_seal_balance_cache(qkp(p), u8(entries), C.size_t(len(entries)), (*C.char)(o), n)
		})
		return err
	})
	return
}

// OpenBalanceCache is the entries of a box (UAAead for another key or set); the caller wipes them.
func (k *PqzKey) OpenBalanceCache(box string) (r []byte, err error) {
	var a args
	defer a.done()
	err = k.h.use(func(p unsafe.Pointer) error {
		r, err = secretOut(func(o unsafe.Pointer, n *C.size_t) C.ScaasUaStatus {
			return C.scaas_ua_pqz_open_balance_cache(qkp(p), a.str(box), (*C.uint8_t)(o), n)
		})
		return err
	})
	return
}

// PqzSet is this build's PQZ parameter set as JSON {set, pkLen, pqzlId, pqzhId}.
func PqzSet() (string, error) {
	return loadedStr(1024, func(o unsafe.Pointer, n *C.size_t) C.ScaasUaStatus { return C.scaas_ua_pqz_set((*C.char)(o), n) })
}

// PqzCheckSet is nil if deployed (a token's PqzSet JSON) is this build's set, else UAPqzSetMismatch.
func PqzCheckSet(deployed string) error {
	if err := Load(); err != nil {
		return err
	}
	var a args
	defer a.done()
	return call(func() C.ScaasUaStatus { return C.scaas_ua_pqz_check_set(a.str(deployed)) })
}

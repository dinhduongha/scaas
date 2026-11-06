// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// Implements the wallet part of include/scaas_ua.hpp (ua-rs-sign T13a) over the cxx bridge of src/wallet.rs: the load check,
// Secret, the handle classes and their calls; translates rust::Error into scaas::ua::Error.
#include <stdexcept>
#include <vector>

#include "rust/cxx.h"
#include "scaas-ua-cxx/src/wallet.rs.h"
#include "scaas_ua.hpp"

namespace scaas::ua {
namespace detail {
uint32_t (*reportedAbiVersion)() = &ffi::abi_version;
uint64_t (*reportedFeatures)() = &ffi::features;
void drop(ffi::Wallet* p) noexcept { rust::Box<ffi::Wallet>::from_raw(p); }
void drop(ffi::Key* p) noexcept { rust::Box<ffi::Key>::from_raw(p); }
void drop(ffi::KemKey* p) noexcept { rust::Box<ffi::KemKey>::from_raw(p); }
void drop(ffi::LinkSession* p) noexcept { rust::Box<ffi::LinkSession>::from_raw(p); }
void drop(ffi::SeedBackup* p) noexcept { rust::Box<ffi::SeedBackup>::from_raw(p); }
void drop(ffi::ZetherKey* p) noexcept { rust::Box<ffi::ZetherKey>::from_raw(p); }
void drop(ffi::PqzKey* p) noexcept { rust::Box<ffi::PqzKey>::from_raw(p); }
}  // namespace detail

namespace {
// Overwrites `n` bytes at `p` with zeros through a volatile pointer (the compiler may not drop it).
void zero(uint8_t* p, size_t n) noexcept {
    volatile uint8_t* v = p;
    for (size_t i = 0; i < n; ++i) v[i] = 0;
}
template <class F>
auto call(F&& f) -> decltype(f()) {
    try {
        return f();
    } catch (const rust::Error& e) {
        std::string m = e.what();
        auto p = m.find(": ");
        throw p == std::string::npos ? Error(m, "") : Error(m.substr(0, p), m.substr(p + 2));
    } catch (const std::invalid_argument&) {  // a string argument that is not UTF-8
        throw Error("UAArgument", "");
    }
}
rust::Slice<const uint8_t> sl(const Bytes& b) { return {b.data(), b.size()}; }
rust::Slice<uint8_t> sec(Secret& s) { return {s.data(), s.size()}; }
rust::Str str(const std::string& s) { return rust::Str(s.data(), s.size()); }
Bytes bytes(const rust::Vec<uint8_t>& v) { return Bytes(v.begin(), v.end()); }
// A secret output: copied into a Secret, the bridge's buffer wiped before it is freed.
Secret secret(rust::Vec<uint8_t>&& v) {
    Secret s(Bytes(v.begin(), v.end()));
    zero(v.data(), v.size());
    return s;
}
template <class H, class T>
H adopt(rust::Box<T>&& b) {
    return H(b.into_raw());
}
std::optional<Wallet> restored(rust::Box<ffi::Restored>&& r) {
    if (!ffi::restored_installed(*r)) return std::nullopt;
    return adopt<Wallet>(ffi::restored_take(*r));
}
}  // namespace

void Secret::wipe() noexcept { zero(b_.data(), b_.size()); }

void load() {
    if (detail::reportedAbiVersion() != kAbiVersion) throw Error("UAAbiMismatch", "abi_version");
    if ((detail::reportedFeatures() & kRequiredFeatures) != kRequiredFeatures) throw Error("UAAbiMismatch", "features");
}
uint64_t features() { return ffi::features(); }
int64_t liveHandles() { return ffi::live_handles(); }

// --- Wallet ----------------------------------------------------------------------------------------------------------------

std::pair<Wallet, SeedBackup> Wallet::generate() {
    load();
    return call([&] {
        ffi::Generated g = ffi::wallet_generate();
        return std::pair<Wallet, SeedBackup>(adopt<Wallet>(std::move(g.wallet)), adopt<SeedBackup>(std::move(g.backup)));
    });
}
Wallet Wallet::fromMnemonic(Secret& words, Secret& bip39Passphrase) {
    load();
    return call([&] { return adopt<Wallet>(ffi::wallet_from_mnemonic(sec(words), sec(bip39Passphrase))); });
}
Wallet Wallet::openVault(const std::string& vaultJson, Secret& vaultPassphrase, Secret& prf32, Secret& bip39Passphrase) {
    load();
    return call([&] { return adopt<Wallet>(ffi::wallet_open_vault(str(vaultJson), sec(vaultPassphrase), sec(prf32), sec(bip39Passphrase))); });
}
std::optional<Wallet> Wallet::restoreBackup(const KemKey& kk, const std::string& containerJson, const std::string& expectJson,
                                            const std::string& membersJson, const std::string& acceptedJson, Secret& bip39Passphrase) {
    load();
    return call([&] {
        return restored(ffi::wallet_restore_backup(kk.ffi(), str(containerJson), str(expectJson), str(membersJson), str(acceptedJson),
                                                   sec(bip39Passphrase)));
    });
}
std::optional<Wallet> Wallet::restoreBackupOver(const KemKey& kk, const std::string& containerJson, const std::string& expectJson,
                                                const std::string& membersJson, const std::string& acceptedJson,
                                                Secret& bip39Passphrase) const {
    return call([&] {
        return restored(ffi::wallet_restore_backup_over(kk.ffi(), str(containerJson), str(expectJson), str(membersJson),
                                                        str(acceptedJson), ffi(), sec(bip39Passphrase)));
    });
}
std::optional<Wallet> Wallet::restoreBackupRollback(const KemKey& kk, const std::string& containerJson, const std::string& expectJson,
                                                    const std::string& membersJson, const std::string& acceptedJson,
                                                    Secret& bip39Passphrase) const {
    return call([&] {
        return restored(ffi::wallet_restore_backup_rollback(kk.ffi(), str(containerJson), str(expectJson), str(membersJson),
                                                            str(acceptedJson), ffi(), sec(bip39Passphrase)));
    });
}
Wallet Wallet::fromLink(const LinkSession& s, const std::string& containerJson, const std::string& expectJson,
                        const std::string& membersJson, const std::string& acceptedJson, Secret& bip39Passphrase) {
    load();
    return call([&] {
        return adopt<Wallet>(ffi::wallet_from_link(s.ffi(), str(containerJson), str(expectJson), str(membersJson), str(acceptedJson),
                                                   sec(bip39Passphrase)));
    });
}
void Wallet::unlock(const std::string& vaultJson, Secret& vaultPassphrase, Secret& prf32, Secret& bip39Passphrase) const {
    call([&] { ffi::wallet_unlock(ffi(), str(vaultJson), sec(vaultPassphrase), sec(prf32), sec(bip39Passphrase)); });
}
std::string Wallet::sealVault(Secret& vaultPassphrase) const {
    return call([&] { return std::string(ffi::wallet_seal_vault(ffi(), sec(vaultPassphrase))); });
}
void Wallet::lock() const { ffi::wallet_lock(ffi()); }
MemoryProtection Wallet::memoryProtection() const {
    auto m = ffi::wallet_memory_protection(ffi());
    return {m.chunks, m.locked, m.no_dump};
}
Key Wallet::uaKey(uint16_t kind, uint32_t account, uint32_t index) const {
    return call([&] { return adopt<Key>(ffi::wallet_ua_key(ffi(), kind, account, index)); });
}
Key Wallet::nativeKey(const std::string& network, uint32_t index, uint32_t coinType) const {
    return call([&] { return adopt<Key>(ffi::wallet_native_key(ffi(), str(network), index, coinType)); });
}
Key Wallet::importNativeKey(const std::string& network, Secret& secret) const {
    return call([&] { return adopt<Key>(ffi::wallet_import_native_key(ffi(), str(network), sec(secret))); });
}
Key Wallet::importedKey(const std::string& network, uint32_t n) const {
    return call([&] { return adopt<Key>(ffi::wallet_imported_key(ffi(), str(network), n)); });
}
std::string Wallet::sealLabelVault(const std::string& label, Secret& vaultPassphrase) const {
    return call([&] { return std::string(ffi::wallet_seal_label_vault(ffi(), str(label), sec(vaultPassphrase))); });
}
void Wallet::openLabelVault(const std::string& vaultJson, Secret& vaultPassphrase, Secret& prf32) const {
    call([&] { ffi::wallet_open_label_vault(ffi(), str(vaultJson), sec(vaultPassphrase), sec(prf32)); });
}
std::string Wallet::manifestJson() const { return std::string(ffi::wallet_manifest_json(ffi())); }
std::string Wallet::discoverCandidates(uint16_t kind, uint32_t account, uint32_t gap) const {
    return call([&] { return std::string(ffi::wallet_discover_candidates(ffi(), kind, account, gap)); });
}
std::vector<std::string> Wallet::backupSeal(const Key& sender, const std::vector<Recipient>& recipients) const {
    return call([&] {
        std::vector<ffi::Recipient> rs;
        for (auto& r : recipients) {
            rust::Vec<uint8_t> kd, pk;
            for (auto b : r.keyData) kd.push_back(b);
            for (auto b : r.kemPk) pk.push_back(b);
            rs.push_back(ffi::Recipient{r.kind, std::move(kd), r.version, std::move(pk), r.ephemeral});
        }
        std::vector<std::string> out;
        for (auto& c : ffi::wallet_backup_seal(ffi(), sender.ffi(), rust::Slice<const ffi::Recipient>{rs.data(), rs.size()})) out.emplace_back(c);
        return out;
    });
}
std::string Wallet::linkSeal(const Key& sender, const Bytes& sessionKemPk, const std::string& shortCode) const {
    return call([&] { return std::string(ffi::wallet_link_seal(ffi(), sender.ffi(), sl(sessionKemPk), str(shortCode))); });
}
ZetherKey Wallet::zetherKey(uint32_t coin, uint32_t account, uint32_t keyUse) const {
    return call([&] { return adopt<ZetherKey>(ffi::wallet_zether_key(ffi(), coin, account, keyUse)); });
}
PqzKey Wallet::pqzKey(uint32_t account, uint32_t index) const {
    return call([&] { return adopt<PqzKey>(ffi::wallet_pqz_key(ffi(), account, index)); });
}
Secret Wallet::exportPqzLeafRaw(uint32_t account, uint32_t index) const {
    return call([&] { return secret(ffi::wallet_export_pqz_leaf_raw(ffi(), account, index)); });
}

// --- SeedBackup ------------------------------------------------------------------------------------------------------------

Secret SeedBackup::reveal() const { return call([&] { return secret(ffi::seed_backup_reveal(ffi())); }); }
std::vector<uint32_t> SeedBackup::challenge() const {
    return call([&] {
        auto v = ffi::seed_backup_challenge(ffi());
        return std::vector<uint32_t>(v.begin(), v.end());
    });
}
bool SeedBackup::verify(Secret& word1, Secret& word2, Secret& word3) const {
    return call([&] { return ffi::seed_backup_verify(ffi(), sec(word1), sec(word2), sec(word3)); });
}
Secret SeedBackup::take() const { return call([&] { return secret(ffi::seed_backup_take(ffi())); }); }

// --- Key -------------------------------------------------------------------------------------------------------------------

bool Key::isUa() const { return ffi::key_is_ua(ffi()); }
uint16_t Key::kind() const { return ffi::key_kind(ffi()); }
Bytes Key::keyData() const { return bytes(ffi::key_data(ffi())); }
Bytes Key::ua() const { return call([&] { return bytes(ffi::key_ua(ffi())); }); }
std::string Key::network() const { return std::string(ffi::key_network(ffi())); }
std::string Key::address() const { return call([&] { return std::string(ffi::key_address(ffi())); }); }
Bytes Key::signUa(const Bytes& purposeTag, const Bytes& digest) const {
    return call([&] { return bytes(ffi::sign_ua(ffi(), sl(purposeTag), sl(digest))); });
}
Bytes Key::signMember(const Bytes& structureUa, const Bytes& structureUaMsg) const {
    return call([&] { return bytes(ffi::sign_member(ffi(), sl(structureUa), sl(structureUaMsg))); });
}
Bytes Key::signTyped(const std::string& typedDataJson, const std::string& expectJson) const {
    return call([&] { return bytes(ffi::sign_typed(ffi(), str(typedDataJson), str(expectJson))); });
}
Bytes Key::signTypedAny(const std::string& typedDataJson) const {
    return call([&] { return bytes(ffi::sign_typed_any(ffi(), str(typedDataJson))); });
}
Bytes Key::signTransaction(const std::string& txJson) const {
    return call([&] { return bytes(ffi::sign_transaction(ffi(), str(txJson))); });
}
Bytes Key::signKeyProof(const Bytes& challenge) const {
    return call([&] { return bytes(ffi::sign_key_proof(ffi(), sl(challenge))); });
}
Bytes Key::signDigestRaw(const Bytes& digest) const {
    return call([&] { return bytes(ffi::sign_digest_raw(ffi(), sl(digest))); });
}
KemKey Key::kemKey(uint64_t version) const {
    return call([&] { return adopt<KemKey>(ffi::kem_key(ffi(), version)); });
}
std::string uaSig(const std::string& requestJson, const std::vector<const Key*>& keys) {
    load();
    return call([&] {
        auto l = ffi::key_list_new();
        for (auto k : keys) {
            if (!k) throw Error("UAArgument", "");
            ffi::key_list_push(*l, k->ffi());
        }
        return std::string(ffi::uasig(str(requestJson), *l));
    });
}

uint64_t registerKey(const Key& k) { return ffi::key_register(k.ffi()); }
bool releaseKey(uint64_t id) { return ffi::key_release(id); }

// --- KEM, seal / open, link ------------------------------------------------------------------------------------------------

KemKey KemKey::ephemeral() {
    load();
    return call([&] { return adopt<KemKey>(ffi::kem_ephemeral()); });
}
Bytes KemKey::kemPk() const { return bytes(ffi::kem_pk(ffi())); }
Secret KemKey::decaps(const Bytes& mlkemCt, const Bytes& x25519Eph) const {
    return call([&] { return secret(ffi::kem_decaps(ffi(), sl(mlkemCt), sl(x25519Eph))); });
}
Secret KemKey::open(const std::string& purpose, const Bytes& aad, const Sealed& s) const {
    return call([&] { return secret(ffi::open(ffi(), str(purpose), sl(aad), sl(s.mlkemCt), sl(s.x25519Eph), sl(s.ciphertext))); });
}
Secret KemKey::openContainer(const std::string& containerJson, const std::string& expectJson, const std::string& membersJson,
                             const std::string& acceptedJson) const {
    return call([&] {
        return secret(ffi::open_container(ffi(), str(containerJson), str(expectJson), str(membersJson), str(acceptedJson)));
    });
}
Encapsulated kemEncaps(const Bytes& kemPk) {
    load();
    return call([&] {
        auto e = ffi::kem_encaps(sl(kemPk));
        return Encapsulated{bytes(e.mlkem_ct), bytes(e.x25519_eph), secret(std::move(e.ss))};
    });
}
Sealed seal(const Bytes& kemPk, const std::string& purpose, const Bytes& aad, const Bytes& pt) {
    load();
    return call([&] {
        auto s = ffi::seal(sl(kemPk), str(purpose), sl(aad), sl(pt));
        return Sealed{bytes(s.mlkem_ct), bytes(s.x25519_eph), bytes(s.ciphertext)};
    });
}
LinkSession LinkSession::create() {
    load();
    return call([&] { return adopt<LinkSession>(ffi::link_session_new()); });
}
Bytes LinkSession::kemPk() const { return call([&] { return bytes(ffi::link_session_kem_pk(ffi())); }); }
std::string LinkSession::shortCode() const { return call([&] { return std::string(ffi::link_session_short_code(ffi())); }); }

// --- vault, AEAD, HKDF, HMAC, WebAuthn -------------------------------------------------------------------------------------

namespace vault {
bool needsRewrap(const std::string& vaultJson) {
    load();
    return call([&] { return ffi::vault_needs_rewrap(str(vaultJson)); });
}
std::string rewrapPin(const std::string& vaultJson, Secret& oldPassphrase, Secret& newPassphrase) {
    load();
    return call([&] { return std::string(ffi::vault_rewrap_pin(str(vaultJson), sec(oldPassphrase), sec(newPassphrase))); });
}
std::string enablePrf(const std::string& vaultJson, Secret& vaultPassphrase, Secret& prf32, const std::string& credentialId,
                      const Bytes& salt) {
    load();
    return call([&] {
        return std::string(ffi::vault_enable_prf(str(vaultJson), sec(vaultPassphrase), sec(prf32), str(credentialId), sl(salt)));
    });
}
}  // namespace vault

Bytes aeadSeal(uint32_t alg, const Bytes& key, const Bytes& nonce, const Bytes& aad, const Bytes& data) {
    load();
    return call([&] { return bytes(ffi::aead_seal(alg, sl(key), sl(nonce), sl(aad), sl(data))); });
}
Secret aeadOpen(uint32_t alg, const Bytes& key, const Bytes& nonce, const Bytes& aad, const Bytes& data) {
    load();
    return call([&] { return secret(ffi::aead_open(alg, sl(key), sl(nonce), sl(aad), sl(data))); });
}
Secret hkdfSha256(const Bytes& ikm, const Bytes& salt, const Bytes& info, size_t len) {
    load();
    return call([&] { return secret(ffi::hkdf_sha256(sl(ikm), sl(salt), sl(info), len)); });
}
Bytes hmacSha256(const Bytes& key, const Bytes& data) {
    load();
    return bytes(ffi::hmac_sha256(sl(key), sl(data)));
}
Bytes webauthnChallenge(const Bytes& purposeTag, const Bytes& digest) {
    load();
    return call([&] { return bytes(ffi::webauthn_challenge(sl(purposeTag), sl(digest))); });
}
Bytes webauthnAssertion(const Bytes& keyData, const Bytes& expectedChallenge, const Bytes& authData, const Bytes& clientDataJson,
                        const Bytes& r, const Bytes& s) {
    load();
    return call([&] {
        return bytes(ffi::webauthn_assertion(sl(keyData), sl(expectedChallenge), sl(authData), sl(clientDataJson), sl(r), sl(s)));
    });
}

// --- facades ---------------------------------------------------------------------------------------------------------------

Bytes ZetherKey::y() const { return bytes(ffi::zether_y(ffi())); }
Bytes ZetherKey::ua() const { return bytes(ffi::zether_ua(ffi())); }
std::string ZetherKey::call(const std::string& cmd, const std::string& requestJson) const {
    return scaas::ua::call([&] { return std::string(ffi::zether_call(ffi(), str(cmd), str(requestJson))); });
}
std::string ZetherKey::sealBalanceCache(const Bytes& entriesJson) const {
    return scaas::ua::call([&] { return std::string(ffi::zether_seal_balance_cache(ffi(), sl(entriesJson))); });
}
Secret ZetherKey::openBalanceCache(const std::string& boxJson) const {
    return scaas::ua::call([&] { return secret(ffi::zether_open_balance_cache(ffi(), str(boxJson))); });
}
Bytes PqzKey::pk() const { return bytes(ffi::pqz_pk(ffi())); }
std::string PqzKey::call(const std::string& cmd, const std::string& requestJson) const {
    return scaas::ua::call([&] { return std::string(ffi::pqz_call(ffi(), str(cmd), str(requestJson))); });
}
std::string PqzKey::sealBalanceCache(const Bytes& entries) const {
    return scaas::ua::call([&] { return std::string(ffi::pqz_seal_balance_cache(ffi(), sl(entries))); });
}
Secret PqzKey::openBalanceCache(const std::string& boxJson) const {
    return scaas::ua::call([&] { return secret(ffi::pqz_open_balance_cache(ffi(), str(boxJson))); });
}
std::string pqzSet() {
    load();
    return std::string(ffi::pqz_set());
}
void pqzCheckSet(const std::string& deployedJson) {
    load();
    call([&] { ffi::pqz_check_set(str(deployedJson)); });
}

}  // namespace scaas::ua

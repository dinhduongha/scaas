// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// Qt Quick Test main; `vectors.load("kinds.json")` hands the shared vector files to QML as JS objects. `fixture` (ua-rs-sign
// T13b) is the C++ side of an app: it opens wallets through ua-cxx (scaas_ua.hpp, compiled into this build) and hands key
// handles to QML only by id; test-only helpers (open a seal, a raw signature, the load hook) stay on this side.
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QQmlContext>
#include <QQmlEngine>
#include <QtQuickTest/quicktest.h>

#include <map>
#include <memory>

#include "scaas_ua.hpp"

namespace su = scaas::ua;

static QJsonDocument file(const QString& name) {
    QFile f(QStringLiteral(UA_VECTORS_DIR "/") + name);
    if (!f.open(QIODevice::ReadOnly)) return {};
    return QJsonDocument::fromJson(f.readAll());
}

class Vectors : public QObject {
    Q_OBJECT
public:
    Q_INVOKABLE QVariant load(const QString& name) const { return file(name).toVariant(); }
};

static su::Bytes unhex(const QString& h) {
    QByteArray b = QByteArray::fromHex(h.startsWith("0x") ? h.mid(2).toLatin1() : h.toLatin1());
    return su::Bytes(b.begin(), b.end());
}
static QString hex(const su::Bytes& b) {
    return "0x" + QString::fromLatin1(QByteArray(reinterpret_cast<const char*>(b.data()), qsizetype(b.size())).toHex());
}

static uint32_t g_abi = 0;
static uint64_t g_features = 0;

class Fixture : public QObject {
    Q_OBJECT
public:
    Fixture() : original_abi_(su::detail::reportedAbiVersion), original_features_(su::detail::reportedFeatures) {
        for (const auto& m : file("keys.json").object()["mnemonics"].toArray()) mnemonics_[m.toObject()["id"].toString()] = m.toObject();
    }
    // the handle id of a UA / native key of the vector mnemonic `m`
    Q_INVOKABLE int key(const QString& m, int kind, int account, int index) {
        return keep(wallet(m).uaKey(uint16_t(kind), uint32_t(account), uint32_t(index)));
    }
    Q_INVOKABLE int native(const QString& m, const QString& network, int index) {
        return keep(wallet(m).nativeKey(network.toStdString(), uint32_t(index)));
    }
    Q_INVOKABLE bool release(int id) { return su::releaseKey(uint64_t(id)); }
    Q_INVOKABLE bool liveHandlesBalanced() {
        const su::Wallet& w = wallet("pq_kat");
        int64_t before = su::liveHandles();
        {
            su::Key k = w.uaKey(0x0101, 0, 0);
            uint64_t id = su::registerKey(k);
            su::releaseKey(id);
            su::releaseKey(id);
        }
        return su::liveHandles() == before;
    }
    // a raw signature of a registered native key (test only: never in QML's API)
    Q_INVOKABLE QString rawSignature(int id, const QString& digest) { return hex(keys_.at(id).signDigestRaw(unhex(digest))); }
    // opens a seal made in QML with the KEM key of (m, kind, account 0, index 0, version): the plaintext's hex, or the error code
    Q_INVOKABLE QString open(const QString& m, int kind, const QString& version, const QString& purpose, const QString& aad,
                             const QString& sealJson) {
        QJsonObject s = QJsonDocument::fromJson(sealJson.toUtf8()).object();
        try {
            su::KemKey kk = wallet(m).uaKey(uint16_t(kind), 0, 0).kemKey(version.toULongLong());
            su::Sealed sealed{unhex(s["mlkemCt"].toString()), unhex(s["x25519Eph"].toString()), unhex(s["ciphertext"].toString())};
            su::Secret pt = kk.open(purpose.toStdString(), unhex(aad), sealed);
            return hex(pt.copy());
        } catch (const su::Error& e) {
            return QString::fromStdString(e.code());
        }
    }
    Q_INVOKABLE int keyOfFreshWallet(int kind) {
        fresh_ = std::make_unique<su::Wallet>(open_mnemonic("twelve_words"));
        return keep(fresh_->uaKey(uint16_t(kind), 0, 0));
    }
    Q_INVOKABLE void lockFreshWallet() { fresh_->lock(); }
    Q_INVOKABLE bool mnemonicWipedAfterOpen() {
        auto zero = [](const su::Secret& s) {
            for (size_t i = 0; i < s.size(); ++i)
                if (s.data()[i]) return false;
            return true;
        };
        QJsonObject m = mnemonics_["pq_kat"];
        su::Secret w(m["words"].toString().toStdString()), p("a passphrase");
        su::Wallet::fromMnemonic(w, p);
        su::Secret bad("not a mnemonic at all"), none;
        try {
            su::Wallet::fromMnemonic(bad, none);
            return false;
        } catch (const su::Error&) {
        }
        return w.size() > 100 && zero(w) && zero(p) && zero(bad);
    }
    // the load hook of scaas_ua.hpp: the QML singleton runs the same check
    Q_INVOKABLE void reportAbi(int abi) {
        g_abi = uint32_t(abi);
        su::detail::reportedAbiVersion = [] { return g_abi; };
    }
    Q_INVOKABLE void reportFeaturesWithoutPqz() {
        g_features = su::features() & ~su::feature::kPqz;
        su::detail::reportedFeatures = [] { return g_features; };
    }
    Q_INVOKABLE void restoreReported() {
        su::detail::reportedAbiVersion = original_abi_;
        su::detail::reportedFeatures = original_features_;
    }

private:
    su::Wallet open_mnemonic(const QString& id) {
        QJsonObject m = mnemonics_[id];
        su::Secret w(m["words"].toString().toStdString()), p(m["passphrase"].toString().toStdString());
        return su::Wallet::fromMnemonic(w, p);
    }
    const su::Wallet& wallet(const QString& id) {
        auto it = wallets_.find(id);
        if (it == wallets_.end()) it = wallets_.emplace(id, open_mnemonic(id)).first;
        return it->second;
    }
    int keep(su::Key k) {
        int id = int(su::registerKey(k));
        keys_.emplace(id, std::move(k));
        return id;
    }
    uint32_t (*original_abi_)();
    uint64_t (*original_features_)();
    std::map<QString, QJsonObject> mnemonics_;
    std::map<QString, su::Wallet> wallets_;
    std::map<int, su::Key> keys_;
    std::unique_ptr<su::Wallet> fresh_;
};

class Setup : public QObject {
    Q_OBJECT
public slots:
    void qmlEngineAvailable(QQmlEngine* engine) {
        engine->rootContext()->setContextProperty(QStringLiteral("vectors"), new Vectors);
        engine->rootContext()->setContextProperty(QStringLiteral("fixture"), new Fixture);
    }
};

QUICK_TEST_MAIN_WITH_SETUP(ua, Setup)

#include "tst_ua.moc"

// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// Qt Quick Test main; `vectors.load("kinds.json")` hands the shared vector files to QML as JS objects.
#include <QFile>
#include <QJsonDocument>
#include <QQmlContext>
#include <QQmlEngine>
#include <QtQuickTest/quicktest.h>

class Vectors : public QObject {
    Q_OBJECT
public:
    Q_INVOKABLE QVariant load(const QString &name) const {
        QFile f(QStringLiteral(UA_VECTORS_DIR "/") + name);
        if (!f.open(QIODevice::ReadOnly)) return {};
        return QJsonDocument::fromJson(f.readAll()).toVariant();
    }
};

class Setup : public QObject {
    Q_OBJECT
public slots:
    void qmlEngineAvailable(QQmlEngine *engine) {
        engine->rootContext()->setContextProperty(QStringLiteral("vectors"), new Vectors);
    }
};

QUICK_TEST_MAIN_WITH_SETUP(ua, Setup)

#include "tst_ua.moc"

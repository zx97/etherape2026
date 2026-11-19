// SPDX-License-Identifier: GPL-2.0-or-later

#include "jsonexport.h"

#include "graphmodel.h"

#include <QDateTime>
#include <QFile>
#include <QHash>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>

#include <algorithm>

namespace etherape {

namespace {

QString kindName(NodeKind kind)
{
    switch (kind) {
    case NodeKind::Mac:
        return QStringLiteral("link");
    case NodeKind::Ipv4:
        return QStringLiteral("ip");
    case NodeKind::Ipv6:
        return QStringLiteral("ip6");
    case NodeKind::Port:
        return QStringLiteral("tcp");
    }
    return QStringLiteral("unknown");
}

struct Counters
{
    quint64 packets = 0;
    quint64 bytes = 0;
};

QJsonObject countersObject(quint64 packets, quint64 bytes)
{
    QJsonObject object;
    object.insert(QStringLiteral("packets"),
                  static_cast<qint64>(packets));
    object.insert(QStringLiteral("bytes"), static_cast<qint64>(bytes));
    return object;
}

} // namespace

bool exportGraphJson(const GraphModel &model, const QString &path,
                     const QString &source, QString *error)
{
    const auto nodes = model.nodes();
    const auto links = model.links();

    QHash<QString, Counters> in;
    QHash<QString, Counters> out;
    for (const auto &link : links) {
        if (link.a < 0 || link.b < 0 || link.a >= nodes.size()
            || link.b >= nodes.size())
            continue;
        const QString &a = nodes[link.a].id;
        const QString &b = nodes[link.b].id;

        out[a].packets += link.packetsAB;
        out[a].bytes += link.bytesAB;
        in[a].packets += link.packetsBA;
        in[a].bytes += link.bytesBA;

        out[b].packets += link.packetsBA;
        out[b].bytes += link.bytesBA;
        in[b].packets += link.packetsAB;
        in[b].bytes += link.bytesAB;
    }

    QJsonObject root;
    root.insert(QStringLiteral("version"), 1);
    root.insert(QStringLiteral("generated"),
                QDateTime::currentDateTime().toString(Qt::ISODate));
    root.insert(QStringLiteral("source"), source);
    root.insert(QStringLiteral("totals"),
                countersObject(model.totalPackets(), model.totalBytes()));
    root.insert(QStringLiteral("duration_ms"),
                static_cast<qint64>(model.startedAtMs() == 0
                                        ? 0
                                        : QDateTime::currentMSecsSinceEpoch()
                                            - model.startedAtMs()));

    QJsonArray nodeArray;
    for (const auto &node : nodes) {
        const QString &id = node.id;
        QJsonObject object;
        object.insert(QStringLiteral("id"), id);
        object.insert(QStringLiteral("name"),
                      node.label.isEmpty() ? id : node.label);
        object.insert(QStringLiteral("kind"), kindName(node.kind));
        object.insert(QStringLiteral("zone"),
                      ZoneClassifier::name(node.zone));
        object.insert(QStringLiteral("packets"),
                      static_cast<qint64>(node.packets));
        object.insert(QStringLiteral("bytes"),
                      static_cast<qint64>(node.bytes));
        object.insert(QStringLiteral("in"),
                      countersObject(in.value(id).packets,
                                     in.value(id).bytes));
        object.insert(QStringLiteral("out"),
                      countersObject(out.value(id).packets,
                                     out.value(id).bytes));
        object.insert(QStringLiteral("x"), node.x);
        object.insert(QStringLiteral("y"), node.y);
        object.insert(QStringLiteral("pinned"), node.pinned);
        if (!node.vlans.isEmpty()) {
            QJsonArray vlanArray;
            QList<quint16> ids = node.vlans.values();
            std::sort(ids.begin(), ids.end());
            for (quint16 id : std::as_const(ids))
                vlanArray.append(static_cast<int>(id));
            object.insert(QStringLiteral("vlans"), vlanArray);
        }
        nodeArray.append(object);
    }
    root.insert(QStringLiteral("nodes"), nodeArray);

    QJsonArray linkArray;
    for (const auto &link : links) {
        if (link.a < 0 || link.b < 0 || link.a >= nodes.size()
            || link.b >= nodes.size())
            continue;
        QJsonObject object;
        object.insert(QStringLiteral("source"), nodes[link.a].id);
        object.insert(QStringLiteral("target"), nodes[link.b].id);
        object.insert(QStringLiteral("protocol"), link.protocol);
        object.insert(QStringLiteral("packets"),
                      static_cast<qint64>(link.packets));
        object.insert(QStringLiteral("bytes"),
                      static_cast<qint64>(link.bytes));
        object.insert(QStringLiteral("a_to_b"),
                      countersObject(link.packetsAB, link.bytesAB));
        object.insert(QStringLiteral("b_to_a"),
                      countersObject(link.packetsBA, link.bytesBA));
        if (!link.vlans.isEmpty()) {
            QJsonArray vlanArray;
            QList<quint16> ids = link.vlans.values();
            std::sort(ids.begin(), ids.end());
            for (quint16 id : std::as_const(ids))
                vlanArray.append(static_cast<int>(id));
            object.insert(QStringLiteral("vlans"), vlanArray);
        }
        linkArray.append(object);
    }
    root.insert(QStringLiteral("links"), linkArray);

    auto protocols = model.protocols();
    QList<QString> names = protocols.keys();
    std::sort(names.begin(), names.end(),
              [&protocols](const QString &lhs, const QString &rhs) {
                  return protocols.value(lhs).bytes
                      > protocols.value(rhs).bytes;
              });
    QJsonArray protocolArray;
    for (const QString &name : std::as_const(names)) {
        QJsonObject object;
        object.insert(QStringLiteral("name"), name);
        object.insert(QStringLiteral("packets"),
                      static_cast<qint64>(protocols.value(name).packets));
        object.insert(QStringLiteral("bytes"),
                      static_cast<qint64>(protocols.value(name).bytes));
        protocolArray.append(object);
    }
    root.insert(QStringLiteral("protocols"), protocolArray);

    QFile file(path);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        if (error)
            *error = file.errorString();
        return false;
    }
    file.write(QJsonDocument(root).toJson(QJsonDocument::Indented));
    if (file.error() != QFileDevice::NoError) {
        if (error)
            *error = file.errorString();
        return false;
    }
    return true;
}

} // namespace etherape

// SPDX-License-Identifier: GPL-2.0-or-later

#include "xmlexport.h"

#include "graphmodel.h"

#include <QDateTime>
#include <QFile>
#include <QHash>
#include <QXmlStreamWriter>

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

struct DirectionCounters
{
    quint64 inPackets = 0;
    quint64 inBytes = 0;
    quint64 outPackets = 0;
    quint64 outBytes = 0;
};

} // namespace

bool exportGraphXml(const GraphModel &model, const QString &path,
                    const QString &source, QString *error)
{
    QFile file(path);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        if (error)
            *error = file.errorString();
        return false;
    }

    const auto nodes = model.nodes();
    const auto links = model.links();

    // Derive per-node in/out counters from the directional link counters.
    QHash<QString, DirectionCounters> directions;
    quint64 accumulatedBytes = 0;
    quint64 accumulatedPackets = 0;
    for (const auto &link : links) {
        if (link.a < 0 || link.b < 0 || link.a >= nodes.size()
            || link.b >= nodes.size())
            continue;
        const QString &a = nodes[link.a].id;
        const QString &b = nodes[link.b].id;

        DirectionCounters &da = directions[a];
        da.outBytes += link.bytesAB;
        da.outPackets += link.packetsAB;
        da.inBytes += link.bytesBA;
        da.inPackets += link.packetsBA;

        DirectionCounters &db = directions[b];
        db.outBytes += link.bytesBA;
        db.outPackets += link.packetsBA;
        db.inBytes += link.bytesAB;
        db.inPackets += link.packetsAB;

        accumulatedBytes += link.bytes;
        accumulatedPackets += link.packets;
    }

    QXmlStreamWriter xml(&file);
    xml.setAutoFormatting(true);
    xml.setAutoFormattingIndent(2);
    xml.writeStartDocument(QStringLiteral("1.0"));

    xml.writeStartElement(QStringLiteral("etherape"));
    xml.writeAttribute(QStringLiteral("version"), QStringLiteral("1.0.0"));

    xml.writeStartElement(QStringLiteral("header"));
    if (!source.isEmpty()) {
        const bool looksLikeFile = source.contains(QLatin1Char('/'))
            || source.endsWith(QLatin1String(".pcap"))
            || source.endsWith(QLatin1String(".pcapng"));
        xml.writeTextElement(looksLikeFile ? QStringLiteral("capture_file")
                                           : QStringLiteral("capture_device"),
                             source);
    }
    xml.writeTextElement(
        QStringLiteral("timestamp"),
        QDateTime::currentDateTime().toString(Qt::ISODate));
    xml.writeTextElement(QStringLiteral("packets"),
                         QString::number(model.totalPackets()));
    xml.writeTextElement(QStringLiteral("bytes"),
                         QString::number(model.totalBytes()));
    xml.writeTextElement(QStringLiteral("duration_ms"),
                         QString::number(model.startedAtMs() == 0
                                             ? 0
                                             : QDateTime::currentMSecsSinceEpoch()
                                                 - model.startedAtMs()));
    xml.writeEndElement();  // header

    // Nodes.
    xml.writeStartElement(QStringLiteral("nodes"));
    for (const auto &node : nodes) {
        const DirectionCounters counters = directions.value(node.id);
        xml.writeStartElement(QStringLiteral("node"));
        xml.writeAttribute(QStringLiteral("mode"), kindName(node.kind));

        xml.writeStartElement(QStringLiteral("name"));
        xml.writeTextElement(QStringLiteral("node_id"), node.id);
        xml.writeTextElement(QStringLiteral("resolved_name"),
                             node.label.isEmpty() ? node.id : node.label);
        xml.writeTextElement(QStringLiteral("numeric_name"), node.id);
        xml.writeEndElement();  // name

        xml.writeStartElement(QStringLiteral("traffic_stats"));
        xml.writeStartElement(QStringLiteral("tot"));
        xml.writeTextElement(QStringLiteral("packets"),
                             QString::number(node.packets));
        xml.writeTextElement(QStringLiteral("bytes"),
                             QString::number(node.bytes));
        xml.writeEndElement();  // tot

        xml.writeStartElement(QStringLiteral("in"));
        xml.writeTextElement(QStringLiteral("packets"),
                             QString::number(counters.inPackets));
        xml.writeTextElement(QStringLiteral("bytes"),
                             QString::number(counters.inBytes));
        xml.writeEndElement();  // in

        xml.writeStartElement(QStringLiteral("out"));
        xml.writeTextElement(QStringLiteral("packets"),
                             QString::number(counters.outPackets));
        xml.writeTextElement(QStringLiteral("bytes"),
                             QString::number(counters.outBytes));
        xml.writeEndElement();  // out
        xml.writeEndElement();  // traffic_stats

        xml.writeStartElement(QStringLiteral("position"));
        xml.writeAttribute(QStringLiteral("x"),
                           QString::number(node.x, 'f', 6));
        xml.writeAttribute(QStringLiteral("y"),
                           QString::number(node.y, 'f', 6));
        xml.writeAttribute(QStringLiteral("pinned"),
                           node.pinned ? QStringLiteral("true")
                                       : QStringLiteral("false"));
        xml.writeEndElement();  // position

        xml.writeEndElement();  // node
    }
    xml.writeEndElement();  // nodes

    // Links.
    xml.writeStartElement(QStringLiteral("links"));
    xml.writeTextElement(QStringLiteral("accumulated"),
                         QString::number(accumulatedBytes));
    xml.writeTextElement(QStringLiteral("packets"),
                         QString::number(accumulatedPackets));
    for (const auto &link : links) {
        if (link.a < 0 || link.b < 0 || link.a >= nodes.size()
            || link.b >= nodes.size())
            continue;
        xml.writeStartElement(QStringLiteral("link"));
        xml.writeTextElement(QStringLiteral("source"), nodes[link.a].id);
        xml.writeTextElement(QStringLiteral("target"), nodes[link.b].id);
        xml.writeTextElement(QStringLiteral("protocol"), link.protocol);
        xml.writeTextElement(QStringLiteral("packets"),
                             QString::number(link.packets));
        xml.writeTextElement(QStringLiteral("bytes"),
                             QString::number(link.bytes));
        xml.writeTextElement(QStringLiteral("packets_ab"),
                             QString::number(link.packetsAB));
        xml.writeTextElement(QStringLiteral("bytes_ab"),
                             QString::number(link.bytesAB));
        xml.writeTextElement(QStringLiteral("packets_ba"),
                             QString::number(link.packetsBA));
        xml.writeTextElement(QStringLiteral("bytes_ba"),
                             QString::number(link.bytesBA));
        xml.writeEndElement();  // link
    }
    xml.writeEndElement();  // links

    // Protocol summary, most significant first.
    auto protocols = model.protocols();
    QList<QString> names = protocols.keys();
    std::sort(names.begin(), names.end(),
              [&protocols](const QString &lhs, const QString &rhs) {
                  return protocols.value(lhs).bytes
                      > protocols.value(rhs).bytes;
              });
    xml.writeStartElement(QStringLiteral("protocols"));
    for (const QString &name : std::as_const(names)) {
        const auto &stat = protocols.value(name);
        xml.writeStartElement(QStringLiteral("protocol"));
        xml.writeAttribute(QStringLiteral("name"), name);
        xml.writeAttribute(QStringLiteral("packets"),
                           QString::number(stat.packets));
        xml.writeAttribute(QStringLiteral("bytes"),
                           QString::number(stat.bytes));
        xml.writeEndElement();
    }
    xml.writeEndElement();  // protocols

    xml.writeEndElement();  // etherape
    xml.writeEndDocument();

    if (file.error() != QFileDevice::NoError) {
        if (error)
            *error = file.errorString();
        return false;
    }
    return true;
}

} // namespace etherape

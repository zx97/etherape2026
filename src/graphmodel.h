// SPDX-License-Identifier: GPL-2.0-or-later
//
// Traffic graph: nodes, merged links with per-direction counters, protocol
// statistics and a small force-directed layout in the [0,1] x [0,1] space.
// Nodes can be pinned by hand and the layout saved/restored as JSON.

#pragma once

#include "decoder.h"
#include "zones.h"

#include <QHash>
#include <QObject>
#include <QSet>
#include <QString>
#include <QVector>

namespace etherape {

class GraphModel : public QObject
{
    Q_OBJECT

public:
    struct Node
    {
        QString id;
        QString label;
        QString labelSource;  ///< "dns", "netbios", "ethers" or empty
        NodeKind kind = NodeKind::Mac;
        double x = 0.5;
        double y = 0.5;
        double vx = 0.0;
        double vy = 0.0;
        quint64 bytes = 0;
        quint64 packets = 0;
        qint64 firstSeenMs = 0;
        qint64 lastSeenMs = 0;
        ZoneId zone = ZoneId::Local;  ///< cloud the node belongs to
        QSet<quint16> vlans;          ///< 802.1Q ids seen for this node
        QSet<QString> aliases;        ///< every address merged into this node
        bool pinned = false;          ///< manually placed, ignored by the layout
    };

    struct Link
    {
        int a = -1;               ///< index of the first node (arbitrary side)
        int b = -1;
        QString protocol;
        quint64 packets = 0;
        quint64 bytes = 0;
        quint64 packetsAB = 0;    ///< packets from a to b
        quint64 bytesAB = 0;
        quint64 packetsBA = 0;    ///< packets from b to a
        quint64 bytesBA = 0;
        QSet<quint16> vlans;      ///< 802.1Q ids seen on this link
        double intensity = 0.0;   ///< 0..1, decays over time
        qint64 firstSeenMs = 0;
        qint64 lastSeenMs = 0;
    };

    struct ProtoStat
    {
        quint64 packets = 0;
        quint64 bytes = 0;
    };

    explicit GraphModel(QObject *parent = nullptr);

    void clear();
    void addBatch(const QList<PacketInfo> &batch, qint64 nowMs);
    void tick(double dtSeconds, qint64 nowMs);

    void setNodeLimit(int limit);
    int nodeLimit() const { return m_nodeLimit; }
    void setDecaySeconds(double seconds);
    // Merge addresses that resolve to the same host name. MAC-based
    // merging was removed: behind a router every host shares the gateway's
    // MAC, so it merged unrelated machines.
    void setMergeByName(bool merge);
    bool mergeByName() const { return m_mergeByName; }
    double decaySeconds() const { return m_decaySeconds; }

    const QVector<Node> &nodes() const { return m_nodes; }
    QVector<Link> links() const;
    const QHash<QString, ProtoStat> &protocols() const { return m_protocols; }
    QList<int> vlanIds() const;   ///< sorted, traffic-bearing VLAN ids

    quint64 totalPackets() const { return m_totalPackets; }
    quint64 totalBytes() const { return m_totalBytes; }
    qint64 startedAtMs() const { return m_startedAtMs; }

    void setLabel(const QString &id, const QString &label,
                  const QString &source = QStringLiteral("dns"));
    void setZoneClassifier(const ZoneClassifier &classifier);
    const ZoneClassifier &zoneClassifier() const { return m_zones; }
    void setNodePosition(const QString &id, double x, double y);
    void pinNode(const QString &id, bool pinned = true);

    bool saveLayout(const QString &path, QString *error = nullptr) const;
    bool loadLayout(const QString &path, QString *error = nullptr);

signals:
    void structureChanged();

private:
    void addPacket(const PacketInfo &pkt, qint64 nowMs);
    int nodeIndex(const Endpoint &endpoint, qint64 nowMs);
    void prune(qint64 nowMs);
    void layoutStep(double dtSeconds);
    void placeNewNode(Node &node);
    void removeNodeAt(int idx);
    void rebuildIndexes();
    void mergeByName();

    QVector<Node> m_nodes;
    QHash<QString, int> m_index;        ///< address (or alias) -> node index
    QHash<quint64, Link> m_links;
    QHash<QString, ProtoStat> m_protocols;
    QHash<quint16, quint64> m_vlanPackets;
    QHash<quint16, quint64> m_vlanBytes;

    quint64 m_totalPackets = 0;
    quint64 m_totalBytes = 0;
    qint64 m_startedAtMs = 0;
    int m_nodeLimit = 300;
    double m_decaySeconds = 4.0;
    bool m_mergeByName = true;   ///< one node per resolved host name
    ZoneClassifier m_zones;
};

} // namespace etherape

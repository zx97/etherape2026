// SPDX-License-Identifier: GPL-2.0-or-later
//
// Traffic graph: nodes, directed-merged links, protocol counters and a small
// force-directed layout living in the [0,1] x [0,1] normalized space.

#pragma once

#include "decoder.h"

#include <QHash>
#include <QObject>
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
        NodeKind kind = NodeKind::Mac;
        double x = 0.5;
        double y = 0.5;
        double vx = 0.0;
        double vy = 0.0;
        quint64 bytes = 0;
        quint64 packets = 0;
        qint64 lastSeenMs = 0;
    };

    struct Link
    {
        int a = -1;
        int b = -1;
        QString protocol;
        quint64 bytes = 0;
        quint64 packets = 0;
        double intensity = 0.0;       ///< 0..1, decays over time
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
    double decaySeconds() const { return m_decaySeconds; }

    const QVector<Node> &nodes() const { return m_nodes; }
    QVector<Link> links() const;
    const QHash<QString, ProtoStat> &protocols() const { return m_protocols; }

    quint64 totalPackets() const { return m_totalPackets; }
    quint64 totalBytes() const { return m_totalBytes; }

    void setLabel(const QString &id, const QString &label);

signals:
    void structureChanged();

private:
    void addPacket(const PacketInfo &pkt, qint64 nowMs);
    int nodeIndex(const Endpoint &endpoint, qint64 nowMs);
    void prune(qint64 nowMs);
    void layoutStep(double dtSeconds);
    void placeNewNode(Node &node);
    void removeNodeAt(int idx);

    QVector<Node> m_nodes;
    QHash<QString, int> m_index;
    QHash<quint64, Link> m_links;
    QHash<QString, ProtoStat> m_protocols;

    quint64 m_totalPackets = 0;
    quint64 m_totalBytes = 0;
    int m_nodeLimit = 300;
    double m_decaySeconds = 4.0;
};

} // namespace etherape

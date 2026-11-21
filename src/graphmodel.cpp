// SPDX-License-Identifier: GPL-2.0-or-later

#include "graphmodel.h"

#include <QDateTime>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>

#include <algorithm>
#include <cmath>

namespace etherape {

namespace {

inline quint64 linkKey(int a, int b)
{
    if (a > b)
        std::swap(a, b);
    return (static_cast<quint64>(a) << 32) | static_cast<quint32>(b);
}

constexpr double kSpringLength = 0.20;
constexpr double kRepelRadius = 0.35;
constexpr double kDamping = 0.86;
constexpr double kMinDistance = 0.001;

} // namespace

GraphModel::GraphModel(QObject *parent) : QObject(parent)
{
}

void GraphModel::clear()
{
    m_nodes.clear();
    m_index.clear();
    m_links.clear();
    m_protocols.clear();
    m_vlanPackets.clear();
    m_vlanBytes.clear();
    m_totalPackets = 0;
    m_totalBytes = 0;
    m_startedAtMs = 0;
    emit structureChanged();
}

void GraphModel::setMergeFamilies(bool merge)
{
    if (m_mergeFamilies == merge)
        return;
    m_mergeFamilies = merge;
    if (merge)
        mergeDuplicates(true, true);
}

// Merges nodes that designate the same host, either by MAC (the same card
// seen over IPv4 and IPv6) or by resolved name (several addresses resolving
// to one hostname, which is the only clue on interfaces that do not expose
// destination MACs, such as 'any'). Links are re-keyed and their counters
// aggregated, keeping each direction attached to the right endpoint.
void GraphModel::mergeDuplicates(bool byMac, bool byLabel)
{
    QHash<QString, int> seen;
    QVector<bool> removed(m_nodes.size(), false);

    for (int i = 0; i < m_nodes.size(); ++i) {
        Node &node = m_nodes[i];
        QString key;
        if (byMac && !node.mac.isEmpty())
            key = QStringLiteral("mac:") + node.mac;
        if (key.isEmpty() && byLabel) {
            const QString label = node.label;
            // Only names that actually resolved: skip numeric ids, IPv6
            // literals and the "?" placeholder.
            if (!label.isEmpty() && label != node.id
                && !label.contains(QLatin1Char(':'))
                && !label.at(0).isDigit()
                && label != QLatin1String("localhost")) {
                key = QStringLiteral("name:") + label.toLower();
            }
        }
        if (key.isEmpty())
            continue;
        auto known = seen.find(key);
        if (known == seen.end()) {
            seen.insert(key, i);
            continue;
        }
        Node &target = m_nodes[known.value()];
        target.aliases.unite(node.aliases);
        target.aliases.insert(node.id);
        target.vlans.unite(node.vlans);
        target.bytes += node.bytes;
        target.packets += node.packets;
        target.lastSeenMs = std::max(target.lastSeenMs, node.lastSeenMs);
        if (target.kind == NodeKind::Ipv6 && node.kind == NodeKind::Ipv4) {
            target.id = node.id;
            target.kind = NodeKind::Ipv4;
            if (target.label.isEmpty() || target.label.contains(QLatin1Char(':')))
                target.label = node.id;
        }
        removed[i] = true;
    }

    if (!removed.contains(true))
        return;

    QVector<int> remap(m_nodes.size(), -1);
    QVector<Node> nodes;
    nodes.reserve(m_nodes.size());
    for (int i = 0; i < m_nodes.size(); ++i) {
        if (removed[i])
            continue;
        remap[i] = nodes.size();
        nodes.append(m_nodes[i]);
    }

    QHash<quint64, Link> links;
    for (const Link &old : std::as_const(m_links)) {
        const int a = remap.value(old.a, -1);
        const int b = remap.value(old.b, -1);
        if (a < 0 || b < 0 || a == b)
            continue;

        const QString sourceId = m_nodes[old.a].id;
        const quint64 key = linkKey(a, b);
        auto existing = links.find(key);
        if (existing == links.end()) {
            Link link = old;
            link.a = a;
            link.b = b;
            links.insert(key, link);
            continue;
        }

        Link &aggregate = existing.value();
        const bool sameDirection = (sourceId == nodes[aggregate.a].id);
        if (sameDirection) {
            aggregate.packetsAB += old.packetsAB;
            aggregate.bytesAB += old.bytesAB;
            aggregate.packetsBA += old.packetsBA;
            aggregate.bytesBA += old.bytesBA;
        } else {
            aggregate.packetsAB += old.packetsBA;
            aggregate.bytesAB += old.bytesBA;
            aggregate.packetsBA += old.packetsAB;
            aggregate.bytesBA += old.bytesAB;
        }
        aggregate.packets += old.packets;
        aggregate.bytes += old.bytes;
        aggregate.intensity = std::max(aggregate.intensity, old.intensity);
        aggregate.vlans.unite(old.vlans);
        aggregate.lastSeenMs = std::max(aggregate.lastSeenMs, old.lastSeenMs);
        aggregate.protocol = old.protocol;
    }

    m_nodes = nodes;
    m_links = links;
    rebuildIndexes();
    emit structureChanged();
}

void GraphModel::setNodeLimit(int limit)
{
    m_nodeLimit = std::max(1, limit);
}

void GraphModel::setDecaySeconds(double seconds)
{
    m_decaySeconds = std::max(0.5, seconds);
}

void GraphModel::placeNewNode(Node &node)
{
    // Deterministic golden-angle spiral inside the node's own cloud, so a new
    // host immediately lands in the right area of the graph.
    const QPointF anchor = ZoneClassifier::center(node.zone);
    int peers = 0;
    for (const Node &existing : std::as_const(m_nodes)) {
        if (existing.zone == node.zone)
            ++peers;
    }
    const double golden = 2.39996322972865332;  // radians
    const double radius = 0.055 + 0.045 * std::sqrt(static_cast<double>(peers + 1));
    node.x = anchor.x() + radius * std::cos(peers * golden);
    node.y = anchor.y() + radius * std::sin(peers * golden);
    node.x = std::clamp(node.x, 0.05, 0.95);
    node.y = std::clamp(node.y, 0.05, 0.95);
}

// Removes one node using a swap with the last element, keeping the link table
// consistent. Node indices are an implementation detail, so a permutation is
// perfectly acceptable.
void GraphModel::removeNodeAt(int idx)
{
    const int last = m_nodes.size() - 1;
    const QString removedId = m_nodes[idx].id;

    for (auto it = m_links.begin(); it != m_links.end();) {
        if (it->a == idx || it->b == idx)
            it = m_links.erase(it);
        else
            ++it;
    }

    if (idx != last) {
        m_nodes[idx] = m_nodes[last];
        m_index.insert(m_nodes[idx].id, idx);

        QHash<quint64, Link> remapped;
        remapped.reserve(m_links.size());
        for (Link link : std::as_const(m_links)) {
            if (link.a == last)
                link.a = idx;
            if (link.b == last)
                link.b = idx;
            remapped.insert(linkKey(link.a, link.b), link);
        }
        m_links = std::move(remapped);
    }

    m_nodes.removeLast();
    rebuildIndexes();
}

void GraphModel::rebuildIndexes()
{
    m_index.clear();
    m_macIndex.clear();
    for (int i = 0; i < m_nodes.size(); ++i) {
        m_index.insert(m_nodes[i].id, i);
        for (const QString &alias : std::as_const(m_nodes[i].aliases))
            m_index.insert(alias, i);
        if (!m_nodes[i].mac.isEmpty())
            m_macIndex.insert(m_nodes[i].mac, i);
    }
}

int GraphModel::nodeIndex(const Endpoint &endpoint, const QString &mac,
                          qint64 nowMs)
{
    auto it = m_index.find(endpoint.id);
    if (it != m_index.end()) {
        Node &node = m_nodes[it.value()];
        node.lastSeenMs = nowMs;
        if (node.label.isEmpty())
            node.label = endpoint.label;
        return it.value();
    }

    // Same hardware, other address family: merge into the existing node so a
    // host seen over IPv4 and IPv6 is a single vertex.
    if (m_mergeFamilies && !mac.isEmpty()
        && (endpoint.kind == NodeKind::Ipv4
            || endpoint.kind == NodeKind::Ipv6)) {
        auto known = m_macIndex.find(mac);
        if (known != m_macIndex.end()) {
            const int idx = known.value();
            Node &node = m_nodes[idx];
            node.aliases.insert(endpoint.id);
            m_index.insert(endpoint.id, idx);
            node.lastSeenMs = nowMs;
            // Prefer an IPv4 address as the displayed identity.
            if (endpoint.kind == NodeKind::Ipv4
                && node.kind == NodeKind::Ipv6) {
                m_index.remove(node.id);
                node.id = endpoint.id;
                node.kind = NodeKind::Ipv4;
                if (node.label.isEmpty() || node.label == endpoint.id
                    || node.label.contains(QLatin1Char(':')))
                    node.label = endpoint.id;
                m_index.insert(node.id, idx);
            }
            return idx;
        }
    }

    if (m_nodes.size() >= m_nodeLimit) {
        // Evict the quietest node.
        int victim = 0;
        qint64 oldest = m_nodes[0].lastSeenMs;
        for (int i = 1; i < m_nodes.size(); ++i) {
            if (m_nodes[i].lastSeenMs < oldest) {
                oldest = m_nodes[i].lastSeenMs;
                victim = i;
            }
        }
        removeNodeAt(victim);
    }

    Node node;
    node.id = endpoint.id;
    node.label = endpoint.label;
    node.kind = endpoint.kind;
    node.mac = mac;
    node.aliases.insert(endpoint.id);
    node.zone = m_zones.classify(endpoint.id, endpoint.kind);
    node.firstSeenMs = nowMs;
    node.lastSeenMs = nowMs;
    placeNewNode(node);
    m_nodes.append(node);
    const int index = m_nodes.size() - 1;
    m_index.insert(node.id, index);
    if (!mac.isEmpty())
        m_macIndex.insert(mac, index);
    emit structureChanged();
    return index;
}

void GraphModel::addPacket(const PacketInfo &pkt, qint64 nowMs)
{
    if (m_startedAtMs == 0)
        m_startedAtMs = nowMs;

    if (pkt.vlanId > 0) {
        const quint16 vid = static_cast<quint16>(pkt.vlanId);
        m_vlanPackets[vid] += 1;
        m_vlanBytes[vid] += pkt.origlen;
    }

    ProtoStat &stat = m_protocols[pkt.protocol];
    stat.packets += 1;
    stat.bytes += pkt.origlen;
    m_totalPackets += 1;
    m_totalBytes += pkt.origlen;

    const int srcIndex = nodeIndex(pkt.src, pkt.srcMac, nowMs);
    const int dstIndex = nodeIndex(pkt.dst, pkt.dstMac, nowMs);
    if (srcIndex < 0 || dstIndex < 0 || srcIndex == dstIndex)
        return;

    Node &sn = m_nodes[srcIndex];
    Node &dn = m_nodes[dstIndex];
    if (pkt.vlanId > 0) {
        sn.vlans.insert(static_cast<quint16>(pkt.vlanId));
        dn.vlans.insert(static_cast<quint16>(pkt.vlanId));
    }
    sn.bytes += pkt.origlen;
    sn.packets += 1;
    dn.bytes += pkt.origlen;
    dn.packets += 1;

    const quint64 key = linkKey(srcIndex, dstIndex);
    auto it = m_links.find(key);
    if (it == m_links.end()) {
        Link link;
        link.a = srcIndex;
        link.b = dstIndex;
        link.protocol = pkt.protocol;
        link.bytes = pkt.origlen;
        link.packets = 1;
        link.bytesAB = pkt.origlen;
        link.packetsAB = 1;
        link.intensity = 0.35;
        if (pkt.vlanId > 0)
            link.vlans.insert(static_cast<quint16>(pkt.vlanId));
        link.firstSeenMs = nowMs;
        link.lastSeenMs = nowMs;
        m_links.insert(key, link);
        emit structureChanged();
        return;
    }

    Link &link = it.value();
    if (pkt.vlanId > 0)
        link.vlans.insert(static_cast<quint16>(pkt.vlanId));
    link.protocol = pkt.protocol;
    link.bytes += pkt.origlen;
    link.packets += 1;
    link.lastSeenMs = nowMs;
    // Direction is resolved by identity: link.a/b keep whichever order the
    // first packet established.
    if (pkt.src.id == m_nodes[link.a].id) {
        link.bytesAB += pkt.origlen;
        link.packetsAB += 1;
    } else {
        link.bytesBA += pkt.origlen;
        link.packetsBA += 1;
    }
    link.intensity =
        std::min(1.0, link.intensity + 0.04 + 0.12 * (pkt.origlen / 1500.0));
}

void GraphModel::addBatch(const QList<PacketInfo> &batch, qint64 nowMs)
{
    for (const PacketInfo &pkt : batch)
        addPacket(pkt, nowMs);
}

QList<int> GraphModel::vlanIds() const
{
    QList<int> ids;
    ids.reserve(m_vlanPackets.size());
    for (auto it = m_vlanPackets.constBegin(); it != m_vlanPackets.constEnd();
         ++it)
        ids.append(it.key());
    std::sort(ids.begin(), ids.end());
    return ids;
}

QVector<GraphModel::Link> GraphModel::links() const
{
    QVector<Link> out;
    out.reserve(m_links.size());
    for (const Link &link : m_links)
        out.append(link);
    std::sort(out.begin(), out.end(), [](const Link &lhs, const Link &rhs) {
        return lhs.bytes > rhs.bytes;
    });
    return out;
}

void GraphModel::setLabel(const QString &id, const QString &label,
                          const QString &source)
{
    auto it = m_index.find(id);
    if (it == m_index.end() || label.isEmpty())
        return;
    Node &node = m_nodes[it.value()];
    if (node.label == label)
        return;
    node.label = label;
    node.labelSource = source;
    // The same host reached through several addresses (IPv4, IPv6, a second
    // interface) must be one vertex: merge whenever a name resolves.
    if (m_mergeFamilies)
        mergeDuplicates(false, true);
}

void GraphModel::setZoneClassifier(const ZoneClassifier &classifier)
{
    m_zones = classifier;
    bool changed = false;
    for (Node &node : m_nodes) {
        const ZoneId zone = m_zones.classify(node.id, node.kind);
        if (zone != node.zone) {
            node.zone = zone;
            changed = true;
        }
    }
    if (changed)
        emit structureChanged();
}

void GraphModel::setNodePosition(const QString &id, double x, double y)
{
    auto it = m_index.find(id);
    if (it == m_index.end())
        return;
    Node &node = m_nodes[it.value()];
    node.x = std::clamp(x, 0.02, 0.98);
    node.y = std::clamp(y, 0.02, 0.98);
    node.vx = 0.0;
    node.vy = 0.0;
    node.pinned = true;
}

void GraphModel::pinNode(const QString &id, bool pinned)
{
    auto it = m_index.find(id);
    if (it == m_index.end())
        return;
    m_nodes[it.value()].pinned = pinned;
}

bool GraphModel::saveLayout(const QString &path, QString *error) const
{
    QJsonArray nodes;
    for (const Node &node : m_nodes) {
        QJsonObject object;
        object.insert(QStringLiteral("id"), node.id);
        object.insert(QStringLiteral("x"), node.x);
        object.insert(QStringLiteral("y"), node.y);
        object.insert(QStringLiteral("pinned"), node.pinned);
        nodes.append(object);
    }

    QJsonObject root;
    root.insert(QStringLiteral("version"), 1);
    root.insert(QStringLiteral("nodes"), nodes);

    QFile file(path);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        if (error)
            *error = file.errorString();
        return false;
    }
    file.write(QJsonDocument(root).toJson(QJsonDocument::Indented));
    return true;
}

bool GraphModel::loadLayout(const QString &path, QString *error)
{
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) {
        if (error)
            *error = file.errorString();
        return false;
    }

    QJsonParseError parseError;
    const QJsonDocument document = QJsonDocument::fromJson(file.readAll(), &parseError);
    if (parseError.error != QJsonParseError::NoError) {
        if (error)
            *error = parseError.errorString();
        return false;
    }

    const QJsonArray nodes =
        document.object().value(QStringLiteral("nodes")).toArray();
    for (const QJsonValue &value : nodes) {
        const QJsonObject object = value.toObject();
        const QString id = object.value(QStringLiteral("id")).toString();
        if (id.isEmpty())
            continue;
        auto it = m_index.find(id);
        if (it == m_index.end()) {
            // The node does not exist yet: remember the position for when it
            // appears (stored as a pinned placeholder).
            Node node;
            node.id = id;
            node.label = id;
            node.x = object.value(QStringLiteral("x")).toDouble(0.5);
            node.y = object.value(QStringLiteral("y")).toDouble(0.5);
            node.pinned = object.value(QStringLiteral("pinned")).toBool(true);
            m_nodes.append(node);
            m_index.insert(id, m_nodes.size() - 1);
            continue;
        }
        Node &node = m_nodes[it.value()];
        node.x = object.value(QStringLiteral("x")).toDouble(node.x);
        node.y = object.value(QStringLiteral("y")).toDouble(node.y);
        node.pinned = object.value(QStringLiteral("pinned")).toBool(true);
        node.vx = 0.0;
        node.vy = 0.0;
    }

    emit structureChanged();
    return true;
}

void GraphModel::prune(qint64 nowMs)
{
    bool changed = false;

    for (auto it = m_links.begin(); it != m_links.end();) {
        Link &link = it.value();
        link.intensity *= std::exp(-0.025 / m_decaySeconds);
        const double idleSeconds = (nowMs - link.lastSeenMs) / 1000.0;
        if (link.intensity < 0.02 && idleSeconds > m_decaySeconds * 4.0) {
            it = m_links.erase(it);
            changed = true;
        } else {
            ++it;
        }
    }

    QVector<bool> used(m_nodes.size(), false);
    for (const Link &link : std::as_const(m_links)) {
        used[link.a] = true;
        used[link.b] = true;
    }

    for (;;) {
        int victim = -1;
        for (int i = 0; i < m_nodes.size(); ++i) {
            const double idleSeconds = (nowMs - m_nodes[i].lastSeenMs) / 1000.0;
            if (!used[i] && !m_nodes[i].pinned
                && idleSeconds > m_decaySeconds * 6.0) {
                victim = i;
                break;
            }
        }
        if (victim < 0)
            break;
        removeNodeAt(victim);
        used = QVector<bool>(m_nodes.size(), false);
        for (const Link &link : std::as_const(m_links)) {
            used[link.a] = true;
            used[link.b] = true;
        }
        changed = true;
    }

    if (changed)
        emit structureChanged();
}

void GraphModel::layoutStep(double dtSeconds)
{
    const int n = m_nodes.size();
    if (n < 2)
        return;

    for (int i = 0; i < n; ++i) {
        for (int j = i + 1; j < n; ++j) {
            Node &a = m_nodes[i];
            Node &b = m_nodes[j];
            double dx = b.x - a.x;
            double dy = b.y - a.y;
            double dist = std::sqrt(dx * dx + dy * dy);
            if (dist < kMinDistance) {
                dx = 1e-4 * (1 + i);
                dy = 1e-4 * (1 + j);
                dist = std::sqrt(dx * dx + dy * dy);
            }
            if (dist > kRepelRadius)
                continue;
            const double force = 0.004 * (1.0 - dist / kRepelRadius) / dist;
            if (!a.pinned) {
                a.vx -= dx * force;
                a.vy -= dy * force;
            }
            if (!b.pinned) {
                b.vx += dx * force;
                b.vy += dy * force;
            }
        }
    }

    for (const Link &link : std::as_const(m_links)) {
        Node &a = m_nodes[link.a];
        Node &b = m_nodes[link.b];
        double dx = b.x - a.x;
        double dy = b.y - a.y;
        double dist = std::sqrt(dx * dx + dy * dy);
        if (dist < kMinDistance)
            continue;
        const double force = 0.02 * (dist - kSpringLength) / dist;
        if (!a.pinned) {
            a.vx += dx * force;
            a.vy += dy * force;
        }
        if (!b.pinned) {
            b.vx -= dx * force;
            b.vy -= dy * force;
        }
    }

    const double step = std::clamp(dtSeconds, 0.0, 0.1);
    for (Node &node : m_nodes) {
        if (node.pinned) {
            node.vx = 0.0;
            node.vy = 0.0;
            continue;
        }
        // Zone gravity: each node is pulled towards its own cloud anchor.
        const QPointF anchor = ZoneClassifier::center(node.zone);
        node.vx += (anchor.x() - node.x) * 0.006;
        node.vy += (anchor.y() - node.y) * 0.006;
        node.vx *= kDamping;
        node.vy *= kDamping;
        node.x += node.vx * step * 60.0;
        node.y += node.vy * step * 60.0;
        node.x = std::clamp(node.x, 0.04, 0.96);
        node.y = std::clamp(node.y, 0.04, 0.96);
    }
}

void GraphModel::tick(double dtSeconds, qint64 nowMs)
{
    if (m_nodes.isEmpty() && m_links.isEmpty())
        return;
    layoutStep(dtSeconds);
    prune(nowMs);
}

} // namespace etherape

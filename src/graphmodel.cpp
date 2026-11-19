// SPDX-License-Identifier: GPL-2.0-or-later

#include "graphmodel.h"

#include <QtMath>

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
    m_totalPackets = 0;
    m_totalBytes = 0;
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
    // Deterministic golden-angle spiral: stable and evenly spread.
    const int n = static_cast<int>(m_nodes.size());
    const double golden = 2.39996322972865332; // radians
    const double radius = 0.42 * std::sqrt((n + 1.0) / (m_nodeLimit + 1.0));
    node.x = 0.5 + radius * std::cos(n * golden);
    node.y = 0.5 + radius * std::sin(n * golden);
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

    // Drop every link touching the removed node.
    for (auto it = m_links.begin(); it != m_links.end();) {
        if (it->a == idx || it->b == idx)
            it = m_links.erase(it);
        else
            ++it;
    }

    m_index.remove(removedId);

    if (idx != last) {
        m_nodes[idx] = m_nodes[last];
        m_index.insert(m_nodes[idx].id, idx);

        // Re-key the links that referenced the moved node.
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
}

int GraphModel::nodeIndex(const Endpoint &endpoint, qint64 nowMs)
{
    auto it = m_index.find(endpoint.id);
    if (it != m_index.end()) {
        Node &node = m_nodes[it.value()];
        node.lastSeenMs = nowMs;
        if (node.label.isEmpty())
            node.label = endpoint.label;
        return it.value();
    }

    if (m_nodes.size() >= m_nodeLimit) {
        // Evict the quietest node; prefer one that grew cold some time ago.
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
    node.lastSeenMs = nowMs;
    placeNewNode(node);
    m_nodes.append(node);
    m_index.insert(node.id, m_nodes.size() - 1);
    emit structureChanged();
    return m_nodes.size() - 1;
}

void GraphModel::addPacket(const PacketInfo &pkt, qint64 nowMs)
{
    ProtoStat &stat = m_protocols[pkt.protocol];
    stat.packets += 1;
    stat.bytes += pkt.origlen;
    m_totalPackets += 1;
    m_totalBytes += pkt.origlen;

    const int a = nodeIndex(pkt.src, nowMs);
    const int b = nodeIndex(pkt.dst, nowMs);
    if (a < 0 || b < 0 || a == b)
        return;

    Node &sn = m_nodes[a];
    Node &dn = m_nodes[b];
    sn.bytes += pkt.origlen;
    sn.packets += 1;
    dn.bytes += pkt.origlen;
    dn.packets += 1;

    const quint64 key = linkKey(a, b);
    auto it = m_links.find(key);
    if (it == m_links.end()) {
        Link link;
        link.a = a;
        link.b = b;
        link.protocol = pkt.protocol;
        link.bytes = pkt.origlen;
        link.packets = 1;
        link.intensity = 0.35;
        link.lastSeenMs = nowMs;
        m_links.insert(key, link);
        emit structureChanged();
    } else {
        Link &link = it.value();
        link.a = a;
        link.b = b;
        link.protocol = pkt.protocol;
        link.bytes += pkt.origlen;
        link.packets += 1;
        link.intensity =
            std::min(1.0, link.intensity + 0.04 + 0.12 * (pkt.origlen / 1500.0));
        link.lastSeenMs = nowMs;
    }
}

void GraphModel::addBatch(const QList<PacketInfo> &batch, qint64 nowMs)
{
    for (const PacketInfo &pkt : batch)
        addPacket(pkt, nowMs);
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

void GraphModel::setLabel(const QString &id, const QString &label)
{
    auto it = m_index.find(id);
    if (it == m_index.end() || label.isEmpty())
        return;
    m_nodes[it.value()].label = label;
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
            if (!used[i] && idleSeconds > m_decaySeconds * 6.0) {
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
            a.vx -= dx * force;
            a.vy -= dy * force;
            b.vx += dx * force;
            b.vy += dy * force;
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
        a.vx += dx * force;
        a.vy += dy * force;
        b.vx -= dx * force;
        b.vy -= dy * force;
    }

    for (Node &node : m_nodes) {
        node.vx += (0.5 - node.x) * 0.0015;
        node.vy += (0.5 - node.y) * 0.0015;
    }

    const double step = std::clamp(dtSeconds, 0.0, 0.1);
    for (Node &node : m_nodes) {
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

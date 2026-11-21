// SPDX-License-Identifier: GPL-2.0-or-later
//
// IPv4/IPv6 fragment reassembly.
//
// A fragmented datagram carries no L4 header in its first fragment alone, so
// without reassembly a fragmented UDP/TCP flow is attributed to the wrong
// protocol (and shows no ports). This keeps a small, bounded table of pending
// datagrams and returns the complete payload once every byte is present.
//
// Security: overlapping fragments are rejected (RFC 5722 for IPv6; the same
// rule is safer for IPv4 than "first wins"), and the table is capped in count
// and size so a flood cannot exhaust memory.

#pragma once

#include <QByteArray>
#include <QHash>
#include <QString>
#include <QVector>

#include <optional>

namespace etherape {

class IpReassembler
{
public:
    // Adds one fragment. Returns the full L4 payload when the datagram is
    // complete, std::nullopt while it is still incomplete, and nothing more
    // if the fragment was rejected (overlap, too large, table full).
    std::optional<QByteArray> feed(const QString &key, quint32 offsetBytes,
                                   bool moreFragments, const uchar *payload,
                                   quint32 length, qint64 tsUsec);

    void clear() { m_pending.clear(); }
    int pending() const { return m_pending.size(); }

private:
    struct Segment
    {
        quint32 offset = 0;
        QByteArray data;
    };

    struct Entry
    {
        QVector<Segment> segments;
        quint32 totalLength = 0;  ///< known once the last fragment arrived
        qint64 firstSeenUsec = 0;
        bool hasLast = false;
    };

    static constexpr int kMaxPending = 64;
    static constexpr quint32 kMaxDatagram = 65535;
    static constexpr int kMaxSegments = 64;
    static constexpr qint64 kTimeoutUsec = 30LL * 1000 * 1000;

    void purge(qint64 nowUsec);

    QHash<QString, Entry> m_pending;
};

} // namespace etherape

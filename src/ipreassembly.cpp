// SPDX-License-Identifier: GPL-2.0-or-later

#include "ipreassembly.h"

#include <algorithm>

namespace etherape {

void IpReassembler::purge(qint64 nowUsec)
{
    for (auto it = m_pending.begin(); it != m_pending.end();) {
        if (nowUsec - it->firstSeenUsec > kTimeoutUsec)
            it = m_pending.erase(it);
        else
            ++it;
    }
}

std::optional<QByteArray> IpReassembler::feed(const QString &key,
                                              quint32 offsetBytes,
                                              bool moreFragments,
                                              const uchar *payload,
                                              quint32 length, qint64 tsUsec)
{
    if (length == 0 || offsetBytes + length > kMaxDatagram)
        return std::nullopt;
    if ((offsetBytes & 0x7) != 0)
        return std::nullopt;  // offsets are multiples of 8 in both protocols

    purge(tsUsec);

    auto it = m_pending.find(key);
    if (it == m_pending.end()) {
        if (m_pending.size() >= kMaxPending)
            return std::nullopt;
        Entry entry;
        entry.firstSeenUsec = tsUsec;
        it = m_pending.insert(key, entry);
    }

    Entry &entry = it.value();
    if (entry.segments.size() >= kMaxSegments) {
        m_pending.erase(it);
        return std::nullopt;
    }

    // Reject overlaps rather than guessing which copy is authoritative.
    for (const Segment &segment : std::as_const(entry.segments)) {
        const quint32 segEnd = segment.offset + segment.data.size();
        if (offsetBytes < segEnd && segment.offset < offsetBytes + length) {
            m_pending.erase(it);
            return std::nullopt;
        }
    }

    Segment segment;
    segment.offset = offsetBytes;
    segment.data = QByteArray(reinterpret_cast<const char *>(payload),
                              static_cast<int>(length));
    entry.segments.append(segment);

    if (!moreFragments) {
        entry.totalLength = offsetBytes + length;
        entry.hasLast = true;
    }

    if (!entry.hasLast)
        return std::nullopt;

    // Complete if the segments cover [0, totalLength) without a hole.
    QVector<const Segment *> ordered;
    ordered.reserve(entry.segments.size());
    for (const Segment &s : std::as_const(entry.segments))
        ordered.append(&s);
    std::sort(ordered.begin(), ordered.end(),
              [](const Segment *lhs, const Segment *rhs) {
                  return lhs->offset < rhs->offset;
              });

    quint32 covered = 0;
    for (const Segment *s : std::as_const(ordered)) {
        if (s->offset != covered)
            return std::nullopt;  // hole (or a segment past the end)
        covered = s->offset + static_cast<quint32>(s->data.size());
        if (covered >= entry.totalLength)
            break;
    }
    if (covered < entry.totalLength)
        return std::nullopt;

    QByteArray complete(static_cast<int>(entry.totalLength), '\0');
    for (const Segment *s : std::as_const(ordered)) {
        const int offset = static_cast<int>(s->offset);
        const int room = complete.size() - offset;
        if (room <= 0)
            break;
        const int count = std::min(room, static_cast<int>(s->data.size()));
        std::copy_n(s->data.constData(), count, complete.data() + offset);
    }

    m_pending.erase(it);
    return complete;
}

} // namespace etherape

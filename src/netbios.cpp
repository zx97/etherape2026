// SPDX-License-Identifier: GPL-2.0-or-later

#include "netbios.h"

#include <QHostAddress>

namespace etherape {

namespace {

constexpr quint16 kTypeNb = 0x0020;  // NetBIOS general name service

inline quint16 rd16(const uchar *p)
{
    return static_cast<quint16>((p[0] << 8) | p[1]);
}

inline quint32 rd32(const uchar *p)
{
    return (static_cast<quint32>(p[0]) << 24)
        | (static_cast<quint32>(p[1]) << 16)
        | (static_cast<quint32>(p[2]) << 8) | static_cast<quint32>(p[3]);
}

// NetBIOS names are encoded as 32 ASCII nibbles, each byte being 'A' + value.
bool decodeName(const uchar *data, quint32 length, quint32 offset,
                QString *name)
{
    if (offset + 1 > length)
        return false;

    quint8 first = data[offset];
    if ((first & 0xC0) == 0xC0) {
        // Compression pointer: 14-bit offset from the message start.
        if (offset + 1 >= length)
            return false;
        const quint32 target =
            ((first & 0x3F) << 8) | static_cast<quint32>(data[offset + 1]);
        if (target >= offset || target + 33 > length)
            return false;
        return decodeName(data, length, target, name);
    }

    const quint32 encodedLength = first;
    if (encodedLength == 0 || offset + 1 + encodedLength > length)
        return false;
    if (encodedLength % 2 != 0 || encodedLength < 32)
        return false;

    QByteArray raw;
    raw.reserve(static_cast<int>(encodedLength / 2));
    for (quint32 i = 0; i < encodedLength; i += 2) {
        const int high = data[offset + 1 + i] - 'A';
        const int low = data[offset + 2 + i] - 'A';
        if (high < 0 || high > 15 || low < 0 || low > 15)
            return false;
        raw.append(static_cast<char>((high << 4) | low));
    }

    // 16 bytes: 15-byte name plus a one-byte suffix (0x00 = workstation).
    QString text = QString::fromLatin1(raw.constData(), 15).trimmed();
    if (text.isEmpty())
        return false;
    *name = text;
    return true;
}

} // namespace

std::optional<NetbiosName> parseNetbiosResponse(const uchar *data,
                                                quint32 length)
{
    if (length < 12)
        return std::nullopt;

    const quint16 flags = rd16(data + 2);
    const bool isResponse = (flags & 0x8000) != 0;
    const quint16 questions = rd16(data + 4);
    const quint16 answers = rd16(data + 6);
    if (!isResponse || answers == 0)
        return std::nullopt;

    quint32 offset = 12;

    // Skip the question section.
    for (quint16 i = 0; i < questions; ++i) {
        QString ignored;
        if (!decodeName(data, length, offset, &ignored))
            return std::nullopt;
        // Length byte + encoded nibbles, then a zero terminator.
        const quint32 encodedLength = data[offset];
        offset += 1 + encodedLength + 1;
        if (offset + 4 > length)
            return std::nullopt;
        offset += 4;  // type + class
    }

    for (quint16 i = 0; i < answers; ++i) {
        QString name;
        if (!decodeName(data, length, offset, &name))
            return std::nullopt;

        const quint32 encodedLength = data[offset];
        offset += 1 + encodedLength + 1;
        if (offset + 10 > length)
            return std::nullopt;

        const quint16 type = rd16(data + offset);
        offset += 2;  // type
        offset += 2;  // class
        offset += 4;  // ttl
        const quint16 rdLength = rd16(data + offset);
        offset += 2;
        if (offset + rdLength > length)
            return std::nullopt;

        if (type == kTypeNb && rdLength >= 6) {
            // rdata: NB flags (2 bytes) + IPv4 address (4 bytes).
            QHostAddress address;
            address.setAddress(static_cast<quint32>(data[offset + 2]) << 24
                               | static_cast<quint32>(data[offset + 3]) << 16
                               | static_cast<quint32>(data[offset + 4]) << 8
                               | static_cast<quint32>(data[offset + 5]));
            NetbiosName result;
            result.name = name;
            result.ip = address.toString();
            return result;
        }

        offset += rdLength;
    }

    return std::nullopt;
}

} // namespace etherape

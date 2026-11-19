// SPDX-License-Identifier: GPL-2.0-or-later
//
// EtherApe 2026 - Qt 6 port of EtherApe's packet decoding layer.
// Decodes Ethernet (with 802.1Q/802.1ad), IPv4, IPv6, ARP, TCP and UDP
// into a mode-dependent pair of endpoints.

#pragma once

#include <QList>
#include <QMetaType>
#include <QString>
#include <QtGlobal>

namespace etherape {

enum class Mode { Link = 0, Ip = 1, Tcp = 2 };

enum class NodeKind { Mac, Ipv4, Ipv6, Port };

struct Endpoint
{
    QString id;                 ///< stable identifier used as hash key
    QString label;              ///< displayed name (may be resolved later)
    NodeKind kind = NodeKind::Mac;
};

struct PacketInfo
{
    qint64 tsUsec = 0;
    quint32 caplen = 0;
    quint32 origlen = 0;
    QString protocol;           ///< "TCP", "UDP", "ICMP", "ICMPv6", "ARP", ...
    Endpoint src;
    Endpoint dst;
    quint16 sport = 0;
    quint16 dport = 0;
};

// Decodes link-layer frames into PacketInfo records.
class Decoder
{
public:
    explicit Decoder(Mode mode = Mode::Ip) : m_mode(mode) {}

    void setMode(Mode mode) { m_mode = mode; }
    Mode mode() const { return m_mode; }

    PacketInfo decode(const uchar *data, quint32 caplen, quint32 origlen,
                      qint64 tsUsec) const;

private:
    Mode m_mode;
};

QString macToString(const uchar *mac);

} // namespace etherape

Q_DECLARE_METATYPE(etherape::PacketInfo)
Q_DECLARE_METATYPE(QList<etherape::PacketInfo>)

// SPDX-License-Identifier: GPL-2.0-or-later
//
// EtherApe 2026 - packet decoding layer.
// Handles Ethernet (802.1Q/802.1ad), Linux cooked capture (SLL/SLL2), raw IP,
// IPv4, IPv6, ARP, TCP and UDP.

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
    int vlanId = -1;      ///< outer 802.1Q id, -1 when untagged
    int vlanInner = -1;   ///< inner id for QinQ (802.1ad), -1 otherwise
    // Passive NetBIOS name service hint (UDP/137 responses only).
    QString nbName;
    QString nbIp;
};

// Decodes link-layer frames into PacketInfo records. The link type follows the
// libpcap DLT_* constants (1 = Ethernet, 113 = Linux SLL, 276 = SLL2,
// 12/101 = raw IP).
class Decoder
{
public:
    explicit Decoder(Mode mode = Mode::Ip, int linkType = 1)
        : m_mode(mode), m_linkType(linkType)
    {
    }

    void setMode(Mode mode) { m_mode = mode; }
    Mode mode() const { return m_mode; }

    void setLinkType(int linkType) { m_linkType = linkType; }
    int linkType() const { return m_linkType; }

    PacketInfo decode(const uchar *data, quint32 caplen, quint32 origlen,
                      qint64 tsUsec) const;

private:
    struct LinkLayer
    {
        quint16 etherType = 0;
        quint32 offset = 0;
        QString srcMac;
        QString dstMac;
        bool hasMac = false;
    };

    bool parseLinkLayer(const uchar *data, quint32 caplen,
                        LinkLayer &layer) const;

    Mode m_mode;
    int m_linkType;
};

QString macToString(const uchar *mac);

} // namespace etherape

Q_DECLARE_METATYPE(etherape::PacketInfo)
Q_DECLARE_METATYPE(QList<etherape::PacketInfo>)

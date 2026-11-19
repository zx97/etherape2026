// SPDX-License-Identifier: GPL-2.0-or-later

#include "decoder.h"

#include "netbios.h"

#include <QHash>
#include <QHostAddress>

#include <algorithm>

namespace etherape {

namespace {

constexpr quint16 kEtherTypeIPv4 = 0x0800;
constexpr quint16 kEtherTypeARP = 0x0806;
constexpr quint16 kEtherTypeIPv6 = 0x86dd;
constexpr quint16 kEtherTypeVlan = 0x8100;
constexpr quint16 kEtherTypeQinQ = 0x88a8;

// libpcap DLT_* values we understand.
constexpr int kDltEthernet = 1;
constexpr int kDltRaw = 12;         // DLT_RAW (Linux)
constexpr int kDltRawBsd = 101;     // DLT_RAW (BSD)
constexpr int kDltLinuxSll = 113;
constexpr int kDltLinuxSll2 = 276;

inline quint16 rd16(const uchar *p)
{
    return static_cast<quint16>((p[0] << 8) | p[1]);
}

QString ipv4ToString(const uchar *p)
{
    QHostAddress address;
    address.setAddress(static_cast<quint32>(p[0]) << 24
                       | static_cast<quint32>(p[1]) << 16
                       | static_cast<quint32>(p[2]) << 8
                       | static_cast<quint32>(p[3]));
    return address.toString();
}

QString ipv6ToString(const uchar *p)
{
    QHostAddress address(p);
    return address.toString();
}

QString applicationProtocol(const QString &transport, quint16 sport,
                            quint16 dport)
{
    static const QHash<quint16, QString> tcpPorts = {
        {22, QStringLiteral("SSH")},     {23, QStringLiteral("Telnet")},
        {25, QStringLiteral("SMTP")},    {53, QStringLiteral("DNS")},
        {80, QStringLiteral("HTTP")},    {110, QStringLiteral("POP3")},
        {143, QStringLiteral("IMAP")},   {389, QStringLiteral("LDAP")},
        {443, QStringLiteral("TLS")},    {445, QStringLiteral("SMB")},
        {636, QStringLiteral("LDAPS")},  {993, QStringLiteral("IMAPS")},
        {995, QStringLiteral("POP3S")},  {1433, QStringLiteral("MSSQL")},
        {1521, QStringLiteral("Oracle")}, {3306, QStringLiteral("MySQL")},
        {3389, QStringLiteral("RDP")},   {5432, QStringLiteral("PostgreSQL")},
        {5900, QStringLiteral("VNC")},   {6379, QStringLiteral("Redis")},
        {8080, QStringLiteral("HTTP")},  {8443, QStringLiteral("TLS")},
    };
    static const QHash<quint16, QString> udpPorts = {
        {53, QStringLiteral("DNS")},     {67, QStringLiteral("DHCP")},
        {68, QStringLiteral("DHCP")},    {69, QStringLiteral("TFTP")},
        {123, QStringLiteral("NTP")},    {137, QStringLiteral("NBNS")},
        {138, QStringLiteral("NBDS")},   {161, QStringLiteral("SNMP")},
        {162, QStringLiteral("SNMP")},   {500, QStringLiteral("IKE")},
        {514, QStringLiteral("Syslog")}, {1900, QStringLiteral("SSDP")},
        {4500, QStringLiteral("IPsec")}, {5353, QStringLiteral("mDNS")},
        {5355, QStringLiteral("LLMNR")},
    };

    const auto &table = (transport == QLatin1String("TCP")) ? tcpPorts : udpPorts;
    const bool sourceKnown = table.contains(sport);
    const bool destKnown = table.contains(dport);
    // The service is the well-known end of the connection; prefer the lower
    // port, which resolves both "client -> server" and the reply direction.
    if (destKnown && (!sourceKnown || dport <= sport))
        return table.value(dport);
    if (sourceKnown)
        return table.value(sport);
    if (destKnown)
        return table.value(dport);
    return transport;
}

QString portLabel(const QString &addr, quint16 port)
{
    return QStringLiteral("%1:%2").arg(addr).arg(port);
}

} // namespace

QString macToString(const uchar *mac)
{
    return QStringLiteral("%1:%2:%3:%4:%5:%6")
        .arg(mac[0], 2, 16, QLatin1Char('0'))
        .arg(mac[1], 2, 16, QLatin1Char('0'))
        .arg(mac[2], 2, 16, QLatin1Char('0'))
        .arg(mac[3], 2, 16, QLatin1Char('0'))
        .arg(mac[4], 2, 16, QLatin1Char('0'))
        .arg(mac[5], 2, 16, QLatin1Char('0'))
        .toUpper();
}

bool Decoder::parseLinkLayer(const uchar *data, quint32 caplen,
                             LinkLayer &layer) const
{
    switch (m_linkType) {
    case kDltLinuxSll: {
        // 16-byte header: pkttype, arphrd, halen, addr[8], protocol.
        if (caplen < 16)
            return false;
        layer.offset = 16;
        layer.etherType = rd16(data + 14);
        const quint16 halen = rd16(data + 4);
        if (halen == 6) {
            layer.srcMac = macToString(data + 6);
            // SLL only carries the source hardware address.
            layer.dstMac = QStringLiteral("?");
            layer.hasMac = true;
        }
        return true;
    }
    case kDltLinuxSll2: {
        // 20-byte header: protocol, reserved, ifindex, arphrd, pkttype,
        // halen, addr[8].
        if (caplen < 20)
            return false;
        layer.offset = 20;
        layer.etherType = rd16(data);
        const quint8 halen = data[11];
        if (halen == 6) {
            layer.srcMac = macToString(data + 12);
            layer.dstMac = QStringLiteral("?");
            layer.hasMac = true;
        }
        return true;
    }
    case kDltRaw:
    case kDltRawBsd: {
        if (caplen < 1)
            return false;
        layer.offset = 0;
        const quint8 version = data[0] >> 4;
        layer.etherType = (version == 6) ? kEtherTypeIPv6 : kEtherTypeIPv4;
        return true;
    }
    case kDltEthernet:
    default: {
        if (caplen < 14)
            return false;
        layer.offset = 14;
        layer.etherType = rd16(data + 12);
        layer.srcMac = macToString(data + 6);
        layer.dstMac = macToString(data);
        layer.hasMac = true;
        return true;
    }
    }
}

PacketInfo Decoder::decode(const uchar *data, quint32 caplen, quint32 origlen,
                           qint64 tsUsec) const
{
    PacketInfo pkt;
    pkt.tsUsec = tsUsec;
    pkt.caplen = caplen;
    pkt.origlen = origlen;
    pkt.protocol = QStringLiteral("Other");

    LinkLayer ll;
    if (!parseLinkLayer(data, caplen, ll) || caplen < ll.offset)
        return pkt;

    quint32 off = ll.offset;
    quint16 etherType = ll.etherType;

    // Default endpoints: MAC pair when the link layer provides one, otherwise
    // let the L3 parser fill them in.
    if (ll.hasMac) {
        pkt.src = {ll.srcMac, ll.srcMac, NodeKind::Mac};
        pkt.dst = {ll.dstMac, ll.dstMac, NodeKind::Mac};
    }

    if (m_mode == Mode::Link && ll.hasMac)
        return pkt;

    // Walk VLAN tags (802.1Q and 802.1ad/QinQ), keeping the identifiers.
    int vlanCount = 0;
    while ((etherType == kEtherTypeVlan || etherType == kEtherTypeQinQ)
           && caplen >= off + 4) {
        const quint16 tag = rd16(data + off);
        const int vid = tag & 0x0fff;
        if (vlanCount == 0)
            pkt.vlanId = vid;
        else if (vlanCount == 1)
            pkt.vlanInner = vid;
        ++vlanCount;
        etherType = rd16(data + off + 2);
        off += 4;
    }

    auto setAddresses = [&](const QString &srcAddr, const QString &dstAddr,
                            NodeKind kind) {
        if (m_mode == Mode::Tcp && kind == NodeKind::Port)
            return;  // ports are filled by the TCP/UDP parser
        pkt.src = {srcAddr, srcAddr, kind};
        pkt.dst = {dstAddr, dstAddr, kind};
    };

    if (etherType == kEtherTypeIPv4) {
        if (caplen < off + 20)
            return pkt;
        const uchar *ip = data + off;
        const quint32 ihl = (ip[0] & 0x0f) * 4u;
        if (ihl < 20 || caplen < off + ihl)
            return pkt;

        const quint8 proto = ip[9];
        const QString src = ipv4ToString(ip + 12);
        const QString dst = ipv4ToString(ip + 16);
        setAddresses(src, dst, NodeKind::Ipv4);

        switch (proto) {
        case 6:
            pkt.protocol = QStringLiteral("TCP");
            break;
        case 17:
            pkt.protocol = QStringLiteral("UDP");
            break;
        case 1:
            pkt.protocol = QStringLiteral("ICMP");
            break;
        case 2:
            pkt.protocol = QStringLiteral("IGMP");
            break;
        default:
            pkt.protocol = QStringLiteral("IP/%1").arg(proto);
            break;
        }

        const quint32 l4 = off + ihl;
        if ((proto == 6 || proto == 17) && caplen >= l4 + 4) {
            pkt.sport = rd16(data + l4);
            pkt.dport = rd16(data + l4 + 2);
            pkt.protocol = applicationProtocol(pkt.protocol, pkt.sport,
                                               pkt.dport);
            if (m_mode == Mode::Tcp) {
                pkt.src = {portLabel(src, pkt.sport), portLabel(src, pkt.sport),
                           NodeKind::Port};
                pkt.dst = {portLabel(dst, pkt.dport), portLabel(dst, pkt.dport),
                           NodeKind::Port};
            }
            if (proto == 17 && (pkt.sport == 137 || pkt.dport == 137)
                && caplen >= l4 + 8) {
                const quint32 udpLength = rd16(data + l4 + 4);
                const quint32 available = caplen - (l4 + 8);
                const quint32 payloadLength =
                    (udpLength >= 8) ? std::min(udpLength - 8, available)
                                     : available;
                if (auto nb =
                        parseNetbiosResponse(data + l4 + 8, payloadLength)) {
                    pkt.nbName = nb->name;
                    pkt.nbIp = nb->ip;
                }
            }
        }
        return pkt;
    }

    if (etherType == kEtherTypeIPv6) {
        if (caplen < off + 40)
            return pkt;
        const uchar *ip6 = data + off;
        const QString src = ipv6ToString(ip6 + 8);
        const QString dst = ipv6ToString(ip6 + 24);
        setAddresses(src, dst, NodeKind::Ipv6);

        quint8 next = ip6[6];
        quint32 l4 = off + 40;

        // Skip the common extension headers.
        for (int guard = 0; guard < 8; ++guard) {
            const bool ext = (next == 0 || next == 43 || next == 44
                              || next == 60 || next == 51);
            if (!ext || caplen < l4 + 2)
                break;
            const quint8 hdrNext = data[l4];
            quint32 hlen = (next == 44) ? 8u : (data[l4 + 1] + 1u) * 8u;
            if (next == 51)  // AH length is in 4-byte units plus two
                hlen = (data[l4 + 1] + 2u) * 4u;
            next = hdrNext;
            l4 += hlen;
        }

        if (next == 6) {
            pkt.protocol = QStringLiteral("TCP");
        } else if (next == 17) {
            pkt.protocol = QStringLiteral("UDP");
        } else if (next == 58) {
            pkt.protocol = QStringLiteral("ICMPv6");
        } else {
            pkt.protocol = QStringLiteral("IPv6/%1").arg(next);
        }

        if ((next == 6 || next == 17) && caplen >= l4 + 4) {
            pkt.sport = rd16(data + l4);
            pkt.dport = rd16(data + l4 + 2);
            pkt.protocol = applicationProtocol(pkt.protocol, pkt.sport,
                                               pkt.dport);
            if (m_mode == Mode::Tcp) {
                pkt.src = {portLabel(src, pkt.sport), portLabel(src, pkt.sport),
                           NodeKind::Port};
                pkt.dst = {portLabel(dst, pkt.dport), portLabel(dst, pkt.dport),
                           NodeKind::Port};
            }
            if (next == 17 && (pkt.sport == 137 || pkt.dport == 137)
                && caplen >= l4 + 8) {
                const quint32 udpLength = rd16(data + l4 + 4);
                const quint32 available = caplen - (l4 + 8);
                const quint32 payloadLength =
                    (udpLength >= 8) ? std::min(udpLength - 8, available)
                                     : available;
                if (auto nb =
                        parseNetbiosResponse(data + l4 + 8, payloadLength)) {
                    pkt.nbName = nb->name;
                    pkt.nbIp = nb->ip;
                }
            }
        }
        return pkt;
    }

    if (etherType == kEtherTypeARP) {
        pkt.protocol = QStringLiteral("ARP");
        if (caplen >= off + 28) {
            const uchar *arp = data + off;
            const QString src = ipv4ToString(arp + 14);
            const QString dst = ipv4ToString(arp + 24);
            setAddresses(src, dst, NodeKind::Ipv4);
        }
        return pkt;
    }

    pkt.protocol =
        QStringLiteral("0x%1").arg(etherType, 4, 16, QLatin1Char('0'));
    return pkt;
}

} // namespace etherape

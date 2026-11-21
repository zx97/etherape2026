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

inline quint32 rd32(const uchar *p)
{
    return (static_cast<quint32>(p[0]) << 24)
        | (static_cast<quint32>(p[1]) << 16) | (static_cast<quint32>(p[2]) << 8)
        | static_cast<quint32>(p[3]);
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

QString ipProtocolName(quint8 protocol)
{
    switch (protocol) {
    case 1:
        return QStringLiteral("ICMP");
    case 2:
        return QStringLiteral("IGMP");
    case 6:
        return QStringLiteral("TCP");
    case 17:
        return QStringLiteral("UDP");
    case 41:
        return QStringLiteral("IPv6");
    case 47:
        return QStringLiteral("GRE");
    case 50:
        return QStringLiteral("ESP");
    case 51:
        return QStringLiteral("AH");
    case 58:
        return QStringLiteral("ICMPv6");
    case 89:
        return QStringLiteral("OSPF");
    case 103:
        return QStringLiteral("PIM");
    default:
        break;
    }
    return QStringLiteral("IP/%1").arg(protocol);
}

QString applicationProtocol(const QString &transport, quint16 sport,
                            quint16 dport)
{
    static const QHash<quint16, QString> tcpPorts = {
        {22, QStringLiteral("SSH")},      {23, QStringLiteral("Telnet")},
        {25, QStringLiteral("SMTP")},     {53, QStringLiteral("DNS")},
        {80, QStringLiteral("HTTP")},     {110, QStringLiteral("POP3")},
        {143, QStringLiteral("IMAP")},    {389, QStringLiteral("LDAP")},
        {443, QStringLiteral("TLS")},     {445, QStringLiteral("SMB")},
        {636, QStringLiteral("LDAPS")},   {993, QStringLiteral("IMAPS")},
        {995, QStringLiteral("POP3S")},   {1433, QStringLiteral("MSSQL")},
        {1521, QStringLiteral("Oracle")}, {3306, QStringLiteral("MySQL")},
        {3389, QStringLiteral("RDP")},    {5432, QStringLiteral("PostgreSQL")},
        {5900, QStringLiteral("VNC")},    {6379, QStringLiteral("Redis")},
        {8080, QStringLiteral("HTTP")},   {8443, QStringLiteral("TLS")},
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

QString etherTypeName(quint16 etherType)
{
    switch (etherType) {
    case 0x88cc:
        return QStringLiteral("LLDP");
    case 0x888e:
        return QStringLiteral("EAPOL");
    case 0x88f7:
        return QStringLiteral("gPTP");
    case 0x88e5:
        return QStringLiteral("MACsec");
    case 0x8847:
        return QStringLiteral("MPLS");
    case 0x8863:
    case 0x8864:
        return QStringLiteral("PPPoE");
    case 0x8100:
        return QStringLiteral("802.1Q");
    case 0x88a8:
        return QStringLiteral("802.1ad");
    case 0x2000:
        return QStringLiteral("CDP");
    case 0x9000:
        return QStringLiteral("Loopback");
    default:
        break;
    }
    return QStringLiteral("0x%1").arg(etherType, 4, 16, QLatin1Char('0'));
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
            // SLL only carries the source hardware address: the destination
            // is unknown, and inventing a placeholder creates a fake node
            // gathering every non-IP frame.
            layer.dstMac.clear();
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
            layer.dstMac.clear();
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

// Fills protocol, ports and (in TCP mode) endpoints from a transport header.
void Decoder::fillTransport(PacketInfo &pkt, quint8 protocol, const uchar *data,
                            quint32 length, const QString &src,
                            const QString &dst) const
{
    pkt.protocol = ipProtocolName(protocol);
    if ((protocol != 6 && protocol != 17) || length < 4)
        return;

    pkt.sport = rd16(data);
    pkt.dport = rd16(data + 2);
    pkt.protocol = applicationProtocol(pkt.protocol, pkt.sport, pkt.dport);

    if (m_mode == Mode::Tcp) {
        pkt.src = {portLabel(src, pkt.sport), portLabel(src, pkt.sport),
                   NodeKind::Port};
        pkt.dst = {portLabel(dst, pkt.dport), portLabel(dst, pkt.dport),
                   NodeKind::Port};
    }

    if (protocol == 17 && (pkt.sport == 137 || pkt.dport == 137)
        && length >= 8) {
        const quint32 udpLength = rd16(data + 4);
        const quint32 available = length - 8;
        const quint32 payloadLength = (udpLength >= 8)
            ? std::min(udpLength - 8, available)
            : available;
        if (auto nb = parseNetbiosResponse(data + 8, payloadLength)) {
            pkt.nbName = nb->name;
            pkt.nbIp = nb->ip;
        }
    }
}

PacketInfo Decoder::decode(const uchar *data, quint32 caplen, quint32 origlen,
                           qint64 tsUsec)
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

    if (ll.hasMac) {
        pkt.src = {ll.srcMac, ll.srcMac, NodeKind::Mac};
        pkt.dst = {ll.dstMac, ll.dstMac, NodeKind::Mac};
    }

    if (m_mode == Mode::Link && ll.hasMac)
        return pkt;

    // Walk VLAN tags (802.1Q and 802.1ad/QinQ), keeping the outer id.
    int vlanCount = 0;
    while ((etherType == kEtherTypeVlan || etherType == kEtherTypeQinQ)
           && caplen >= off + 4) {
        const quint16 tag = rd16(data + off);
        if (vlanCount == 0)
            pkt.vlanId = tag & 0x0fff;
        ++vlanCount;
        etherType = rd16(data + off + 2);
        off += 4;
    }

    auto setAddresses = [&](const QString &srcAddr, const QString &dstAddr,
                            NodeKind kind) {
        if (m_mode == Mode::Tcp && kind == NodeKind::Port)
            return;
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
        const quint16 totalLength = rd16(ip + 2);
        const quint16 fragmentField = rd16(ip + 6);
        const bool moreFragments = (fragmentField & 0x2000) != 0;
        const quint32 fragmentOffset = (fragmentField & 0x1fff) * 8u;
        const quint16 identification = rd16(ip + 4);

        const QString src = ipv4ToString(ip + 12);
        const QString dst = ipv4ToString(ip + 16);
        setAddresses(src, dst, NodeKind::Ipv4);

        const quint32 l4 = off + ihl;
        quint32 available = caplen > l4 ? caplen - l4 : 0;
        if (totalLength > ihl)
            available = std::min(available, totalLength - ihl);

        if (moreFragments || fragmentOffset != 0) {
            pkt.protocol = ipProtocolName(proto);  // no ports yet
            const QString key = QStringLiteral("4|%1|%2|%3|%4")
                                    .arg(src, dst)
                                    .arg(identification)
                                    .arg(proto);
            if (auto complete = m_reassembler.feed(
                    key, fragmentOffset, moreFragments, data + l4, available,
                    tsUsec)) {
                fillTransport(pkt, proto,
                              reinterpret_cast<const uchar *>(
                                  complete->constData()),
                              static_cast<quint32>(complete->size()), src, dst);
            }
            return pkt;
        }

        fillTransport(pkt, proto, data + l4, available, src, dst);
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

        // Walk extension headers, stopping at a fragment header.
        bool fragmented = false;
        quint32 fragmentOffset = 0;
        bool moreFragments = false;
        quint32 fragmentId = 0;
        quint8 transport = next;

        for (int guard = 0; guard < 8; ++guard) {
            if (next == 44) {  // fragment header
                if (caplen < l4 + 8)
                    return pkt;
                const quint16 field = rd16(data + l4 + 2);
                fragmentOffset = ((field >> 3) & 0x1fff) * 8u;
                moreFragments = (field & 0x1) != 0;
                fragmentId = rd32(data + l4 + 4);
                transport = data[l4];  // next header after the fragment
                l4 += 8;
                next = transport;
                fragmented = fragmentOffset != 0 || moreFragments;
                if (fragmented)
                    break;
                continue;
            }
            const bool extension =
                (next == 0 || next == 43 || next == 60 || next == 51);
            if (!extension || caplen < l4 + 2)
                break;
            const quint8 headerNext = data[l4];
            quint32 headerLength = (data[l4 + 1] + 1u) * 8u;
            if (next == 51)  // AH length is in 4-byte units plus two
                headerLength = (data[l4 + 1] + 2u) * 4u;
            next = headerNext;
            l4 += headerLength;
        }

        const quint32 available = caplen > l4 ? caplen - l4 : 0;

        if (fragmented) {
            pkt.protocol = ipProtocolName(transport);
            const QString key = QStringLiteral("6|%1|%2|%3|%4")
                                    .arg(src, dst)
                                    .arg(fragmentId)
                                    .arg(transport);
            if (auto complete = m_reassembler.feed(
                    key, fragmentOffset, moreFragments, data + l4, available,
                    tsUsec)) {
                fillTransport(pkt, transport,
                              reinterpret_cast<const uchar *>(
                                  complete->constData()),
                              static_cast<quint32>(complete->size()), src, dst);
            }
            return pkt;
        }

        fillTransport(pkt, transport, data + l4, available, src, dst);
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

    pkt.protocol = etherTypeName(etherType);

    // Linux SLL (interface "any") has no destination hardware address. Label
    // the peer with the protocol itself rather than a placeholder that would
    // merge every non-IP frame into one bogus node.
    if (ll.hasMac && ll.dstMac.isEmpty()) {
        pkt.dst = {pkt.protocol, pkt.protocol, NodeKind::Mac};
    }
    return pkt;
}

} // namespace etherape

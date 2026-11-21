// SPDX-License-Identifier: GPL-2.0-or-later
//
// Core unit tests: decoding, NetBIOS, zones, XML/JSON export.
// No GUI is required, so they run headless in CI.

#include "decoder.h"
#include "displayfilter.h"
#include "graphmodel.h"
#include "jsonexport.h"
#include "netbios.h"
#include "xmlexport.h"
#include "zones.h"

#include <QFile>
#include <QTemporaryDir>
#include <QtTest>

using namespace etherape;

namespace {

QByteArray ethernetHeader(const QByteArray &dst, const QByteArray &src,
                          quint16 etherType)
{
    QByteArray frame;
    frame.append(QByteArray::fromHex(dst.toHex()));
    frame.append(QByteArray::fromHex(src.toHex()));
    frame.append(char(etherType >> 8));
    frame.append(char(etherType & 0xff));
    return frame;
}

QByteArray ipv4Header(quint8 proto, quint32 src, quint32 dst, quint16 length)
{
    QByteArray header(20, '\0');
    header[0] = char(0x45);
    header[2] = char(length >> 8);
    header[3] = char(length & 0xff);
    header[8] = 64;
    header[9] = char(proto);
    header[12] = char(src >> 24);
    header[13] = char(src >> 16);
    header[14] = char(src >> 8);
    header[15] = char(src);
    header[16] = char(dst >> 24);
    header[17] = char(dst >> 16);
    header[18] = char(dst >> 8);
    header[19] = char(dst);
    return header;
}

QByteArray tcpHeader(quint16 sport, quint16 dport)
{
    QByteArray tcp(20, '\0');
    tcp[0] = char(sport >> 8);
    tcp[1] = char(sport & 0xff);
    tcp[2] = char(dport >> 8);
    tcp[3] = char(dport & 0xff);
    tcp[12] = char(5 << 4);
    return tcp;
}

QByteArray udpHeader(quint16 sport, quint16 dport, const QByteArray &payload)
{
    QByteArray udp(8, '\0');
    udp[0] = char(sport >> 8);
    udp[1] = char(sport & 0xff);
    udp[2] = char(dport >> 8);
    udp[3] = char(dport & 0xff);
    udp[4] = char((8 + payload.size()) >> 8);
    udp[5] = char((8 + payload.size()) & 0xff);
    return udp + payload;
}

QByteArray netbiosResponse(const QByteArray &name, const QByteArray &ip)
{
    QByteArray encoded;
    encoded.append(char(0x20));
    QByteArray raw = name.leftJustified(15, ' ');
    raw.append('\0');
    for (char byte : raw) {
        encoded.append(char('A' + ((byte >> 4) & 0x0f)));
        encoded.append(char('A' + (byte & 0x0f)));
    }
    encoded.append('\0');

    QByteArray rr;
    rr.append(encoded);
    rr.append(QByteArray::fromHex("0020"));  // NB
    rr.append(QByteArray::fromHex("0001"));  // IN
    rr.append(QByteArray::fromHex("00000000"));  // TTL
    rr.append(QByteArray::fromHex("0006"));  // RDLENGTH
    rr.append(QByteArray::fromHex("0000"));  // NB flags
    rr.append(ip);

    QByteArray message;
    message.append(QByteArray::fromHex("1234"));  // TID
    message.append(QByteArray::fromHex("8500"));  // response + authoritative
    message.append(QByteArray::fromHex("0000"));  // QDCOUNT
    message.append(QByteArray::fromHex("0001"));  // ANCOUNT
    message.append(QByteArray::fromHex("0000"));  // NSCOUNT
    message.append(QByteArray::fromHex("0000"));  // ARCOUNT
    message.append(rr);
    return message;
}

} // namespace

class CoreTests : public QObject
{
    Q_OBJECT

private slots:
    void decodesIpv4TcpWithApplicationProtocol();
    void decodesVlan();
    void decodesLinuxCookedCapture();
    void sllNonIpUsesProtocolAsPeer();
    void decodesArp();
    void decodesUdpDns();
    void parsesNetbiosResponse();
    void classifiesZones();
    void exportsXml();
    void exportsJson();
    void modeTcpUsesPorts();
    void nodeStaysInItsZone();
    void mergesNodesByResolvedName();
    void filterAcceptsEqualsAndAliases();
    void filterWarnsOnUnknownKey();
};

void CoreTests::decodesIpv4TcpWithApplicationProtocol()
{
    QByteArray frame = ethernetHeader(QByteArray::fromHex("001122334455"),
                                      QByteArray::fromHex("66778899aabb"),
                                      0x0800);
    frame.append(ipv4Header(6, 0x0a000001, 0x0a000002, 40));
    frame.append(tcpHeader(80, 52000));

    Decoder decoder(Mode::Ip, 1);
    const PacketInfo packet = decoder.decode(
        reinterpret_cast<const uchar *>(frame.constData()), frame.size(),
        frame.size(), 1234);

    QCOMPARE(packet.protocol, QStringLiteral("HTTP"));
    QCOMPARE(packet.vlanId, -1);  // untagged
    QCOMPARE(packet.src.id, QStringLiteral("10.0.0.1"));
    QCOMPARE(packet.dst.id, QStringLiteral("10.0.0.2"));
}

void CoreTests::decodesVlan()
{
    QByteArray frame = ethernetHeader(QByteArray::fromHex("001122334455"),
                                      QByteArray::fromHex("66778899aabb"),
                                      0x8100);
    frame.append(QByteArray::fromHex("0064"));  // VLAN id 100
    frame.append(QByteArray::fromHex("0800"));
    frame.append(ipv4Header(17, 0xc0a80101, 0x08080808, 28));
    frame.append(udpHeader(5353, 53, QByteArray(4, '\0')));

    Decoder decoder(Mode::Ip, 1);
    const PacketInfo packet = decoder.decode(
        reinterpret_cast<const uchar *>(frame.constData()), frame.size(),
        frame.size(), 0);

    QCOMPARE(packet.protocol, QStringLiteral("DNS"));
    QCOMPARE(packet.src.id, QStringLiteral("192.168.1.1"));
    QCOMPARE(packet.dst.id, QStringLiteral("8.8.8.8"));
    QCOMPARE(packet.vlanId, 100);
    QCOMPARE(packet.vlanInner, -1);
}

void CoreTests::decodesLinuxCookedCapture()
{
    QByteArray frame(16, '\0');
    frame[0] = 0;  // packet type
    frame[4] = 0;
    frame[5] = 6;  // hardware address length
    const QByteArray mac = QByteArray::fromHex("66778899aabb");
    for (int i = 0; i < 6; ++i)
        frame[6 + i] = mac[i];
    frame[14] = char(0x08);
    frame[15] = char(0x00);
    frame.append(ipv4Header(17, 0x0a00000a, 0x0a00000b, 28));
    frame.append(udpHeader(123, 123, QByteArray(4, '\0')));

    Decoder decoder(Mode::Ip, 113);  // DLT_LINUX_SLL
    const PacketInfo packet = decoder.decode(
        reinterpret_cast<const uchar *>(frame.constData()), frame.size(),
        frame.size(), 0);

    QCOMPARE(packet.protocol, QStringLiteral("NTP"));
    QCOMPARE(packet.src.id, QStringLiteral("10.0.0.10"));
    // SLL has no destination MAC: no bogus "?" node
    QCOMPARE(packet.dstMac, QString());
}

void CoreTests::sllNonIpUsesProtocolAsPeer()
{
    // SLL header + LLDP ethertype (0x88cc), no IP payload.
    QByteArray frame(16, '\0');
    frame[4] = 0;
    frame[5] = 6;
    const QByteArray mac = QByteArray::fromHex("66778899aabb");
    for (int i = 0; i < 6; ++i)
        frame[6 + i] = mac[i];
    frame[14] = char(0x88);
    frame[15] = char(0xcc);
    frame.append(QByteArray(40, '\0'));

    Decoder decoder(Mode::Ip, 113);
    const PacketInfo packet = decoder.decode(
        reinterpret_cast<const uchar *>(frame.constData()), frame.size(),
        frame.size(), 0);

    QCOMPARE(packet.protocol, QStringLiteral("LLDP"));
    QVERIFY(packet.dstMac.isEmpty());
    QCOMPARE(packet.dst.id, QStringLiteral("LLDP"));
    QVERIFY(packet.dst.id != QStringLiteral("?"));
}

void CoreTests::decodesArp()
{
    QByteArray frame = ethernetHeader(QByteArray::fromHex("ffffffffffff"),
                                      QByteArray::fromHex("001122334455"),
                                      0x0806);
    QByteArray arp(28, '\0');
    arp[0] = 0;
    arp[1] = 1;  // Ethernet
    arp[2] = 0x08;
    arp[3] = 0x00;  // IPv4
    arp[4] = 6;
    arp[5] = 4;
    arp.replace(14, 4, QByteArray::fromHex("c0a8010a"));  // sender IP
    arp.replace(24, 4, QByteArray::fromHex("c0a80101"));  // target IP
    frame.append(arp);

    Decoder decoder(Mode::Ip, 1);
    const PacketInfo packet = decoder.decode(
        reinterpret_cast<const uchar *>(frame.constData()), frame.size(),
        frame.size(), 0);

    QCOMPARE(packet.protocol, QStringLiteral("ARP"));
    QCOMPARE(packet.src.id, QStringLiteral("192.168.1.10"));
    QCOMPARE(packet.dst.id, QStringLiteral("192.168.1.1"));
}

void CoreTests::decodesUdpDns()
{
    QByteArray frame = ethernetHeader(QByteArray::fromHex("001122334455"),
                                      QByteArray::fromHex("66778899aabb"),
                                      0x0800);
    frame.append(ipv4Header(17, 0x0a000001, 0x0a0000fe, 28));
    frame.append(udpHeader(40000, 53, QByteArray(4, '\0')));

    Decoder decoder(Mode::Ip, 1);
    const PacketInfo packet = decoder.decode(
        reinterpret_cast<const uchar *>(frame.constData()), frame.size(),
        frame.size(), 0);

    QCOMPARE(packet.protocol, QStringLiteral("DNS"));
    QCOMPARE(packet.dport, quint16(53));
}

void CoreTests::parsesNetbiosResponse()
{
    const QByteArray message =
        netbiosResponse("WORKSTATION", QByteArray::fromHex("0a000002"));
    const auto result = parseNetbiosResponse(
        reinterpret_cast<const uchar *>(message.constData()), message.size());

    QVERIFY(result.has_value());
    QCOMPARE(result->name, QStringLiteral("WORKSTATION"));
    QCOMPARE(result->ip, QStringLiteral("10.0.0.2"));
}

void CoreTests::classifiesZones()
{
    ZoneClassifier classifier;
    classifier.setRulesFromText(ZoneId::Dmz, QStringLiteral("192.0.2.0/24"));
    classifier.setRulesFromText(ZoneId::Vpn, QStringLiteral("10.8.0.0/24, fd00::/64"));

    QCOMPARE(classifier.classify(QStringLiteral("10.0.0.5"), NodeKind::Ipv4),
             ZoneId::Local);
    QCOMPARE(classifier.classify(QStringLiteral("192.168.1.10"), NodeKind::Ipv4),
             ZoneId::Local);
    QCOMPARE(classifier.classify(QStringLiteral("8.8.8.8"), NodeKind::Ipv4),
             ZoneId::Internet);
    QCOMPARE(classifier.classify(QStringLiteral("192.0.2.20"), NodeKind::Ipv4),
             ZoneId::Dmz);
    QCOMPARE(classifier.classify(QStringLiteral("10.8.0.5"), NodeKind::Ipv4),
             ZoneId::Vpn);
    QCOMPARE(classifier.classify(QStringLiteral("10.8.0.5:22"), NodeKind::Port),
             ZoneId::Vpn);
    QCOMPARE(classifier.classify(QStringLiteral("fd00::1"), NodeKind::Ipv6),
             ZoneId::Vpn);
    QCOMPARE(classifier.classify(QStringLiteral("00:11:22:33:44:55"), NodeKind::Mac),
             ZoneId::Local);
}

void CoreTests::exportsXml()
{
    QTemporaryDir dir;
    QVERIFY(dir.isValid());

    GraphModel model;
    PacketInfo packet;
    packet.protocol = QStringLiteral("HTTP");
    packet.origlen = 120;
    packet.src = {QStringLiteral("10.0.0.1"), QStringLiteral("10.0.0.1"),
                  NodeKind::Ipv4};
    packet.dst = {QStringLiteral("10.0.0.2"), QStringLiteral("10.0.0.2"),
                  NodeKind::Ipv4};
    model.addBatch({packet}, 1000);

    const QString path = dir.filePath(QStringLiteral("out.xml"));
    QString error;
    QVERIFY2(exportGraphXml(model, path, QStringLiteral("capture.pcap"), &error),
             qPrintable(error));

    QFile file(path);
    QVERIFY(file.open(QIODevice::ReadOnly));
    const QString content = QString::fromUtf8(file.readAll());
    QVERIFY(content.contains(QStringLiteral("<node_id>10.0.0.1</node_id>")));
    QVERIFY(content.contains(QStringLiteral("<protocol name=\"HTTP\"")));
    QVERIFY(content.contains(QStringLiteral("<capture_file>capture.pcap</capture_file>")));
}

void CoreTests::exportsJson()
{
    QTemporaryDir dir;
    QVERIFY(dir.isValid());

    GraphModel model;
    PacketInfo packet;
    packet.protocol = QStringLiteral("DNS");
    packet.origlen = 64;
    packet.src = {QStringLiteral("10.0.0.1"), QStringLiteral("10.0.0.1"),
                  NodeKind::Ipv4};
    packet.dst = {QStringLiteral("10.0.0.254"), QStringLiteral("10.0.0.254"),
                  NodeKind::Ipv4};
    model.addBatch({packet}, 1000);

    const QString path = dir.filePath(QStringLiteral("out.json"));
    QString error;
    QVERIFY2(exportGraphJson(model, path, QStringLiteral("test0"), &error),
             qPrintable(error));

    QFile file(path);
    QVERIFY(file.open(QIODevice::ReadOnly));
    const QString content = QString::fromUtf8(file.readAll());
    QVERIFY(content.contains(QStringLiteral("\"id\": \"10.0.0.1\"")));
    QVERIFY(content.contains(QStringLiteral("\"protocol\": \"DNS\"")));
    QVERIFY(content.contains(QStringLiteral("\"zone\": \"LAN\"")));
}

void CoreTests::modeTcpUsesPorts()
{
    QByteArray frame = ethernetHeader(QByteArray::fromHex("001122334455"),
                                      QByteArray::fromHex("66778899aabb"),
                                      0x0800);
    frame.append(ipv4Header(6, 0x0a000001, 0x0a000002, 40));
    frame.append(tcpHeader(22, 51000));

    Decoder decoder(Mode::Tcp, 1);
    const PacketInfo packet = decoder.decode(
        reinterpret_cast<const uchar *>(frame.constData()), frame.size(),
        frame.size(), 0);

    QCOMPARE(packet.protocol, QStringLiteral("SSH"));
    QCOMPARE(packet.src.id, QStringLiteral("10.0.0.1:22"));
    QCOMPARE(packet.dst.id, QStringLiteral("10.0.0.2:51000"));
}

void CoreTests::nodeStaysInItsZone()
{
    GraphModel model;
    ZoneClassifier classifier;
    classifier.setRulesFromText(ZoneId::Dmz, QStringLiteral("192.0.2.0/24"));
    model.setZoneClassifier(classifier);

    PacketInfo packet;
    packet.protocol = QStringLiteral("HTTP");
    packet.origlen = 100;
    packet.src = {QStringLiteral("192.0.2.20"), QStringLiteral("192.0.2.20"),
                  NodeKind::Ipv4};
    packet.dst = {QStringLiteral("8.8.8.8"), QStringLiteral("8.8.8.8"),
                  NodeKind::Ipv4};
    model.addBatch({packet}, 1000);

    const auto nodes = model.nodes();
    QCOMPARE(nodes.size(), 2);
    for (const auto &node : nodes) {
        if (node.id == QLatin1String("192.0.2.20"))
            QCOMPARE(node.zone, ZoneId::Dmz);
        else
            QCOMPARE(node.zone, ZoneId::Internet);
    }
}

void CoreTests::mergesNodesByResolvedName()
{
    GraphModel model;
    PacketInfo v4;
    v4.protocol = QStringLiteral("TCP");
    v4.origlen = 10;
    v4.src = {QStringLiteral("10.0.0.5"), QStringLiteral("10.0.0.5"),
              NodeKind::Ipv4};
    v4.dst = {QStringLiteral("10.0.0.9"), QStringLiteral("10.0.0.9"),
              NodeKind::Ipv4};
    PacketInfo v6;
    v6.protocol = QStringLiteral("TCP");
    v6.origlen = 10;
    v6.src = {QStringLiteral("fe80::5"), QStringLiteral("fe80::5"),
              NodeKind::Ipv6};
    v6.dst = {QStringLiteral("fe80::9"), QStringLiteral("fe80::9"),
              NodeKind::Ipv6};
    model.addBatch({v4, v6}, 1000);
    QCOMPARE(model.nodes().size(), 4);

    // No MAC here (as on the 'any' interface): the name is the only clue.
    model.setLabel(QStringLiteral("10.0.0.5"), QStringLiteral("manux"));
    model.setLabel(QStringLiteral("fe80::5"), QStringLiteral("manux"));

    int manux = 0;
    for (const auto &node : model.nodes()) {
        if (node.label == QLatin1String("manux"))
            ++manux;
    }
    QCOMPARE(manux, 1);
    QCOMPARE(model.nodes().size(), 3);
}

void CoreTests::filterAcceptsEqualsAndAliases()
{
    GraphModel::Node node;
    node.id = QStringLiteral("10.0.0.1");
    node.label = QStringLiteral("manux");
    node.kind = NodeKind::Ipv4;

    // Both separators and the 'hostname' alias must work.
    QVERIFY(DisplayFilter(QStringLiteral("hostname=manux")).acceptsNode(node));
    QVERIFY(DisplayFilter(QStringLiteral("host:manux")).acceptsNode(node));
    QVERIFY(DisplayFilter(QStringLiteral("hostname:10.0.0.1")).acceptsNode(node));
    QVERIFY(DisplayFilter(QStringLiteral("name=manux")).acceptsNode(node));
    QVERIFY(!DisplayFilter(QStringLiteral("hostname=autre")).acceptsNode(node));
    QVERIFY(DisplayFilter(QStringLiteral("-hostname=autre")).acceptsNode(node));
    QVERIFY(!DisplayFilter(QStringLiteral("-hostname=manux")).acceptsNode(node));
    QVERIFY(DisplayFilter().acceptsNode(node));

    // Unknown keys are reported but still usable as free text.
    const DisplayFilter unknown(QStringLiteral("foo:bar"));
    QCOMPARE(unknown.warnings().size(), 1);
    QVERIFY(unknown.acceptsNode(node) == false);
}

void CoreTests::filterWarnsOnUnknownKey()
{
    const DisplayFilter filter(QStringLiteral("bogus:value"));
    QCOMPARE(filter.warnings().size(), 1);
    QCOMPARE(filter.warnings().first(), QStringLiteral("bogus:value"));
    QVERIFY(DisplayFilter(QStringLiteral("proto:http")).warnings().isEmpty());
    QVERIFY(DisplayFilter(QStringLiteral("host=")).warnings().size() == 1);
}

QTEST_GUILESS_MAIN(CoreTests)
#include "tst_core.moc"

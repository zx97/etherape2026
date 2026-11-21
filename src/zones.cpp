// SPDX-License-Identifier: GPL-2.0-or-later

#include "zones.h"

#include <QAbstractSocket>
#include <QNetworkInterface>
#include <QStringList>

#include <algorithm>

namespace etherape {

namespace {

const QStringList kDefaultLocal = {
    QStringLiteral("10.0.0.0/8"),    QStringLiteral("172.16.0.0/12"),
    QStringLiteral("192.168.0.0/16"), QStringLiteral("169.254.0.0/16"),
    QStringLiteral("127.0.0.0/8"),   QStringLiteral("fc00::/7"),
    QStringLiteral("fe80::/10"),     QStringLiteral("::1/128"),
};

} // namespace

ZoneClassifier::ZoneClassifier()
{
    m_local = parseRules(kDefaultLocal);
}

QVector<ZoneId> ZoneClassifier::allZones()
{
    return {ZoneId::Local, ZoneId::Dmz, ZoneId::Vpn, ZoneId::Internet};
}

QString ZoneClassifier::name(ZoneId zone)
{
    switch (zone) {
    case ZoneId::Local:
        return QStringLiteral("LAN");
    case ZoneId::Dmz:
        return QStringLiteral("DMZ");
    case ZoneId::Vpn:
        return QStringLiteral("VPN");
    case ZoneId::Internet:
        return QStringLiteral("Internet");
    }
    return QStringLiteral("?");
}

QColor ZoneClassifier::color(ZoneId zone)
{
    switch (zone) {
    case ZoneId::Local:
        return QColor(0x35, 0xa8, 0x5b);
    case ZoneId::Dmz:
        return QColor(0xe0, 0x8a, 0x2e);
    case ZoneId::Vpn:
        return QColor(0x9a, 0x62, 0xd0);
    case ZoneId::Internet:
        return QColor(0x3f, 0x7f, 0xd1);
    }
    return QColor(0x90, 0x90, 0x90);
}

QPointF ZoneClassifier::center(ZoneId zone)
{
    // Internet at the top, LAN at the bottom, DMZ/VPN on the sides: this keeps
    // the four clouds apart without overlapping their halos.
    switch (zone) {
    case ZoneId::Local:
        return QPointF(0.50, 0.80);
    case ZoneId::Dmz:
        return QPointF(0.82, 0.44);
    case ZoneId::Vpn:
        return QPointF(0.18, 0.44);
    case ZoneId::Internet:
        return QPointF(0.50, 0.18);
    }
    return QPointF(0.5, 0.5);
}

QVector<ZoneClassifier::Rule>
ZoneClassifier::parseRules(const QStringList &cidrs)
{
    QVector<Rule> rules;
    for (const QString &entry : cidrs) {
        const QString text = entry.trimmed();
        if (text.isEmpty())
            continue;
        const int slash = text.lastIndexOf(QLatin1Char('/'));
        if (slash <= 0)
            continue;
        bool ok = false;
        const int prefix = text.mid(slash + 1).toInt(&ok);
        const QHostAddress network(text.left(slash));
        if (!ok || network.isNull() || prefix < 0)
            continue;
        const int maxPrefix = network.protocol() == QAbstractSocket::IPv6Protocol
            ? 128
            : 32;
        if (prefix > maxPrefix)
            continue;
        rules.append({network, prefix});
    }
    return rules;
}

void ZoneClassifier::setRules(ZoneId zone, const QStringList &cidrs)
{
    QVector<Rule> rules = parseRules(cidrs);
    switch (zone) {
    case ZoneId::Local:
        m_local = rules;
        break;
    case ZoneId::Dmz:
        m_dmz = rules;
        break;
    case ZoneId::Vpn:
        m_vpn = rules;
        break;
    case ZoneId::Internet:
        break;  // Internet is the fallback, not a rule list
    }
}

void ZoneClassifier::setRulesFromText(ZoneId zone, const QString &text)
{
    QStringList entries = text.split(QLatin1Char(','), Qt::SkipEmptyParts);
    for (QString &entry : entries)
        entry = entry.trimmed();
    setRules(zone, entries);
}

QStringList ZoneClassifier::rules(ZoneId zone) const
{
    const QVector<Rule> *rules = nullptr;
    switch (zone) {
    case ZoneId::Local:
        rules = &m_local;
        break;
    case ZoneId::Dmz:
        rules = &m_dmz;
        break;
    case ZoneId::Vpn:
        rules = &m_vpn;
        break;
    case ZoneId::Internet:
        return {};
    }

    QStringList out;
    for (const Rule &rule : *rules)
        out.append(QStringLiteral("%1/%2").arg(rule.network.toString()).arg(rule.prefix));
    return out;
}

QString ZoneClassifier::rulesAsText(ZoneId zone) const
{
    return rules(zone).join(QStringLiteral(", "));
}

void ZoneClassifier::addInterfacePrefixes()
{
    const auto addNetwork = [](QVector<Rule> &list, const QHostAddress &address,
                               int prefix) {
        if (address.protocol() == QAbstractSocket::IPv4Protocol) {
            const quint32 value = address.toIPv4Address();
            const quint32 mask =
                prefix == 0 ? 0u : (~0u << (32 - prefix));
            QHostAddress network;
            network.setAddress(value & mask);
            list.append({network, prefix});
        } else if (address.protocol() == QAbstractSocket::IPv6Protocol) {
            QIPv6Address raw = address.toIPv6Address();
            int remaining = prefix;
            for (int i = 0; i < 16 && remaining > 0; ++i) {
                const int bits = std::min(8, remaining);
                raw.c[i] &= static_cast<quint8>(0xff << (8 - bits) & 0xff);
                remaining -= bits;
            }
            list.append({QHostAddress(raw), prefix});
        }
    };

    const auto interfaces = QNetworkInterface::allInterfaces();
    for (const QNetworkInterface &iface : interfaces) {
        if (!(iface.flags() & QNetworkInterface::IsUp))
            continue;
        const QString name = iface.name().toLower();
        const bool vpnLike = name.startsWith(QLatin1String("tun"))
            || name.startsWith(QLatin1String("tap"))
            || name.startsWith(QLatin1String("wg"))
            || name.startsWith(QLatin1String("ppp"))
            || name.startsWith(QLatin1String("vti"))
            || name.contains(QLatin1String("ipsec"));
        for (const QNetworkAddressEntry &entry : iface.addressEntries()) {
            const QHostAddress address = entry.ip();
            if (address.isNull() || address.isLoopback()
                || address.isLinkLocal())
                continue;
            if (entry.prefixLength() <= 0)
                continue;
            addNetwork(vpnLike ? m_autoVpn : m_autoLocal, address,
                       entry.prefixLength());
        }
    }
}

bool ZoneClassifier::matches(const QVector<Rule> &rules,
                             const QHostAddress &address) const
{
    for (const Rule &rule : rules) {
        if (address.isInSubnet(rule.network, rule.prefix))
            return true;
    }
    return false;
}

QString ZoneClassifier::addressPart(const QString &nodeId, NodeKind kind)
{
    switch (kind) {
    case NodeKind::Mac:
        return QString();
    case NodeKind::Ipv4:
    case NodeKind::Ipv6:
        return nodeId;
    case NodeKind::Port: {
        // "addr:port"; IPv6 addresses contain colons, so take the last one.
        const int colon = nodeId.lastIndexOf(QLatin1Char(':'));
        return colon > 0 ? nodeId.left(colon) : nodeId;
    }
    }
    return QString();
}

ZoneId ZoneClassifier::classify(const QString &nodeId, NodeKind kind) const
{
    const QString text = addressPart(nodeId, kind);
    if (text.isEmpty())
        return ZoneId::Local;  // MAC mode: everything seen is local

    QHostAddress address(text);
    if (address.isNull()) {
        if (text.contains(QLatin1Char(':')))
            address.setAddress(text);  // IPv6 fallback
        if (address.isNull())
            return ZoneId::Internet;
    }

    if (matches(m_dmz, address))
        return ZoneId::Dmz;
    if (matches(m_vpn, address) || matches(m_autoVpn, address))
        return ZoneId::Vpn;
    if (matches(m_local, address) || matches(m_autoLocal, address))
        return ZoneId::Local;
    return ZoneId::Internet;
}

} // namespace etherape

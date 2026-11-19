// SPDX-License-Identifier: GPL-2.0-or-later
//
// Shared formatting helpers: protocol colours and human-readable sizes.
// Keeping a single source of truth guarantees the graph, the legend and the
// statistics panel never disagree on what "TCP" looks like.

#pragma once

#include <QColor>
#include <QString>
#include <QtGlobal>

namespace etherape {

inline QColor protocolColor(const QString &protocol)
{
    if (protocol == QLatin1String("TCP"))
        return QColor(0x5a, 0xa9, 0xff);
    if (protocol == QLatin1String("UDP"))
        return QColor(0x5f, 0xd1, 0x8a);
    if (protocol == QLatin1String("ICMP") || protocol == QLatin1String("ICMPv6"))
        return QColor(0xff, 0xb4, 0x54);
    if (protocol == QLatin1String("ARP"))
        return QColor(0xff, 0x7a, 0x5c);
    if (protocol.startsWith(QLatin1String("IPv6")))
        return QColor(0xb1, 0x8c, 0xff);
    if (protocol.startsWith(QLatin1String("IP/")))
        return QColor(0xc0, 0xc8, 0xd4);
    if (protocol == QLatin1String("HTTP"))
        return QColor(0x4d, 0xab, 0xf7);
    if (protocol == QLatin1String("TLS") || protocol == QLatin1String("LDAPS"))
        return QColor(0x2e, 0xc4, 0xb6);
    if (protocol == QLatin1String("DNS"))
        return QColor(0xff, 0x9f, 0x43);
    if (protocol == QLatin1String("SSH") || protocol == QLatin1String("RDP")
        || protocol == QLatin1String("VNC"))
        return QColor(0xba, 0x68, 0xc8);
    if (protocol == QLatin1String("SMB"))
        return QColor(0xd4, 0x6a, 0x6a);
    if (protocol == QLatin1String("NBNS"))
        return QColor(0xc0, 0xa0, 0x50);
    if (protocol == QLatin1String("NTP") || protocol == QLatin1String("SNMP")
        || protocol == QLatin1String("DHCP"))
        return QColor(0x8b, 0xc3, 0x4a);
    if (protocol.startsWith(QLatin1String("0x")))
        return QColor(0x78, 0x90, 0x9c);
    return QColor(0x9a, 0xa5, 0xb1);
}

inline QString humanBytes(quint64 bytes)
{
    static const char *units[] = {"B", "KB", "MB", "GB", "TB"};
    double value = static_cast<double>(bytes);
    int unit = 0;
    while (value >= 1024.0 && unit < 4) {
        value /= 1024.0;
        ++unit;
    }
    return QStringLiteral("%1 %2")
        .arg(value, 0, 'f', unit == 0 ? 0 : 1)
        .arg(QLatin1String(units[unit]));
}

} // namespace etherape

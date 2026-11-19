// SPDX-License-Identifier: GPL-2.0-or-later
//
// Network zones: Local / DMZ / VPN / Internet.
//
// Each node is classified from its address using configurable CIDR rules and
// the force layout pulls it towards the centre of its zone, so the graph
// groups itself into visible "clouds".

#pragma once

#include "decoder.h"

#include <QColor>
#include <QHostAddress>
#include <QPointF>
#include <QString>
#include <QStringList>
#include <QVector>

namespace etherape {

enum class ZoneId { Local = 0, Dmz = 1, Vpn = 2, Internet = 3 };

class ZoneClassifier
{
public:
    ZoneClassifier();

    // Rules are comma- or space-separated CIDR blocks, e.g. "10.8.0.0/24".
    void setRules(ZoneId zone, const QStringList &cidrs);
    void setRulesFromText(ZoneId zone, const QString &text);
    QStringList rules(ZoneId zone) const;
    QString rulesAsText(ZoneId zone) const;

    ZoneId classify(const QString &nodeId, NodeKind kind) const;

    static QString name(ZoneId zone);
    static QColor color(ZoneId zone);
    static QPointF center(ZoneId zone);  ///< normalized anchor in [0,1]²

    static QVector<ZoneId> allZones();

private:
    struct Rule
    {
        QHostAddress network;
        int prefix = 0;
    };

    bool matches(const QVector<Rule> &rules, const QHostAddress &address) const;
    static QVector<Rule> parseRules(const QStringList &cidrs);
    static QString addressPart(const QString &nodeId, NodeKind kind);

    QVector<Rule> m_local;
    QVector<Rule> m_dmz;
    QVector<Rule> m_vpn;
};

} // namespace etherape

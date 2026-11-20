// SPDX-License-Identifier: GPL-2.0-or-later
//
// Display filter: narrows what the graph and the statistics show, without
// touching the capture. Unlike the BPF filter (which drops packets), this only
// hides elements; counters keep accumulating.
//
// Syntax: space-separated terms, each either "key:value" or free text.
//   proto:http        protocol (case-insensitive substring)
//   host:10.0.0       node id or label substring
//   vlan:100          VLAN id
//   zone:dmz          zone name (LAN, DMZ, VPN, Internet)
//   -term             negation
//   text              id or label substring
// With several keys, all of them must match (AND).

#pragma once

#include "graphmodel.h"

#include <QString>
#include <QStringList>
#include <QVector>

namespace etherape {

class DisplayFilter
{
public:
    DisplayFilter() = default;
    explicit DisplayFilter(const QString &expression);

    bool isEmpty() const { return m_terms.isEmpty(); }
    // True when a term constrains links (protocol), i.e. nodes without a
    // matching link are irrelevant.
    bool constrainsLinks() const;
    QString expression() const { return m_expression; }

    bool acceptsNode(const GraphModel::Node &node) const;
    bool acceptsLink(const GraphModel::Link &link,
                     const GraphModel::Node &source,
                     const GraphModel::Node &target) const;

private:
    enum class Key { Free, Protocol, Host, Vlan, Zone };

    struct Term
    {
        Key key = Key::Free;
        QString value;
        bool negated = false;
    };

    bool matchesTerm(const Term &term, const GraphModel::Node &node,
                     const GraphModel::Link *link) const;

    QString m_expression;
    QVector<Term> m_terms;
};

} // namespace etherape

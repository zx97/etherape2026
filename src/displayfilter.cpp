// SPDX-License-Identifier: GPL-2.0-or-later

#include "displayfilter.h"

#include <QStringList>

namespace etherape {

QStringList DisplayFilter::keyHelp()
{
    return {
        QStringLiteral("proto:http or protocol=http"),
        QStringLiteral("host:10.0.0 or hostname=manux"),
        QStringLiteral("vlan:100"),
        QStringLiteral("zone:dmz  (LAN, DMZ, VPN, Internet)"),
        QStringLiteral("free text matches node id, label or protocol"),
        QStringLiteral("-term excludes (e.g. -proto:arp)"),
    };
}

DisplayFilter::DisplayFilter(const QString &expression) : m_expression(expression)
{
    const QStringList tokens =
        expression.split(QLatin1Char(' '), Qt::SkipEmptyParts);
    for (QString token : tokens) {
        Term term;
        if (token.startsWith(QLatin1Char('-'))) {
            term.negated = true;
            token.remove(0, 1);
        }
        // Both "key:value" and "key=value" are accepted.
        int separator = token.indexOf(QLatin1Char(':'));
        if (separator < 0)
            separator = token.indexOf(QLatin1Char('='));
        if (separator > 0) {
            const QString key = token.left(separator).toLower();
            term.value = token.mid(separator + 1);
            if (key == QLatin1String("proto") || key == QLatin1String("protocol")
                || key == QLatin1String("prot"))
                term.key = Key::Protocol;
            else if (key == QLatin1String("host") || key == QLatin1String("hostname")
                     || key == QLatin1String("name") || key == QLatin1String("node")
                     || key == QLatin1String("ip") || key == QLatin1String("addr")
                     || key == QLatin1String("address") || key == QLatin1String("mac"))
                term.key = Key::Host;
            else if (key == QLatin1String("vlan") || key == QLatin1String("vid"))
                term.key = Key::Vlan;
            else if (key == QLatin1String("zone") || key == QLatin1String("cloud"))
                term.key = Key::Zone;
            else {
                // Unknown key: keep the whole token as free text, but say so.
                m_warnings.append(QStringLiteral("%1:%2")
                                      .arg(token.left(separator), term.value));
                term.key = Key::Free;
                term.value = token;
            }
        } else {
            term.key = Key::Free;
            term.value = token;
        }
        if (term.value.isEmpty()) {
            if (separator > 0)
                m_warnings.append(token);
            continue;
        }
        m_terms.append(term);
    }
}

bool DisplayFilter::matchesTerm(const Term &term, const GraphModel::Node &node,
                                const GraphModel::Link *link) const
{
    const QString value = term.value;
    const Qt::CaseSensitivity cs = Qt::CaseInsensitive;
    switch (term.key) {
    case Key::Protocol:
        return link && link->protocol.contains(value, cs);
    case Key::Host: {
        if (node.id.contains(value, cs) || node.label.contains(value, cs))
            return true;
        for (const QString &alias : node.aliases) {
            if (alias.contains(value, cs))
                return true;
        }
        return false;
    }
    case Key::Vlan: {
        bool ok = false;
        const int id = value.toInt(&ok);
        if (!ok)
            return false;
        if (node.vlans.contains(static_cast<quint16>(id)))
            return true;
        return link && link->vlans.contains(static_cast<quint16>(id));
    }
    case Key::Zone:
        return ZoneClassifier::name(node.zone).contains(value, cs);
    case Key::Free:
        return node.id.contains(value, cs) || node.label.contains(value, cs)
            || (link && link->protocol.contains(value, cs));
    }
    return false;
}

bool DisplayFilter::constrainsLinks() const
{
    for (const Term &term : m_terms) {
        if (term.key == Key::Protocol)
            return true;
    }
    return false;
}

bool DisplayFilter::acceptsNode(const GraphModel::Node &node) const
{
    if (m_terms.isEmpty())
        return true;
    for (const Term &term : m_terms) {
        // Protocol terms say nothing about a node: ignore them here.
        if (term.key == Key::Protocol)
            continue;
        const bool matched = matchesTerm(term, node, nullptr);
        if (term.negated ? matched : !matched)
            return false;
    }
    return true;
}

bool DisplayFilter::acceptsLink(const GraphModel::Link &link,
                                const GraphModel::Node &source,
                                const GraphModel::Node &target) const
{
    if (m_terms.isEmpty())
        return true;
    if (!acceptsNode(source) || !acceptsNode(target))
        return false;
    for (const Term &term : m_terms) {
        if (term.key != Key::Protocol && term.key != Key::Free
            && term.key != Key::Vlan)
            continue;
        const bool matched =
            matchesTerm(term, source, &link) || matchesTerm(term, target, &link);
        if (term.negated ? matched : !matched)
            return false;
    }
    return true;
}

} // namespace etherape

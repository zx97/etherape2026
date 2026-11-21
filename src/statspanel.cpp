// SPDX-License-Identifier: GPL-2.0-or-later

#include "statspanel.h"

#include "formatting.h"
#include "displayfilter.h"
#include "graphmodel.h"
#include "trafficchart.h"

#include <QHeaderView>
#include <QIcon>
#include <QPainter>
#include <QPixmap>
#include <QStandardItemModel>
#include <QTabWidget>
#include <QTextBrowser>
#include <QTreeView>
#include <QVBoxLayout>

#include <algorithm>

namespace etherape {

namespace {

QString vlanText(const QSet<quint16> &vlans)
{
    if (vlans.isEmpty())
        return QStringLiteral("—");
    QList<quint16> ids = vlans.values();
    std::sort(ids.begin(), ids.end());
    QStringList parts;
    for (quint16 id : std::as_const(ids))
        parts.append(QString::number(id));
    return parts.join(QStringLiteral(", "));
}

QIcon colorDot(const QColor &color)
{
    QPixmap pixmap(12, 12);
    pixmap.fill(Qt::transparent);
    QPainter painter(&pixmap);
    painter.setRenderHint(QPainter::Antialiasing, true);
    painter.setPen(Qt::NoPen);
    painter.setBrush(color);
    painter.drawEllipse(1, 1, 10, 10);
    painter.end();
    return QIcon(pixmap);
}

QStandardItem *numberItem(quint64 value)
{
    auto *item = new QStandardItem(QString::number(value));
    item->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
    item->setData(QVariant::fromValue<qulonglong>(value), Qt::UserRole);
    return item;
}

void configureView(QTreeView *view)
{
    view->setRootIsDecorated(false);
    view->setAlternatingRowColors(true);
    view->setUniformRowHeights(true);
    view->setSortingEnabled(true);
    view->setSelectionMode(QAbstractItemView::SingleSelection);
    view->header()->setSectionResizeMode(QHeaderView::ResizeToContents);
    view->header()->setStretchLastSection(true);
}

} // namespace

StatsPanel::StatsPanel(QWidget *parent) : QWidget(parent)
{
    m_tabs = new QTabWidget(this);

    m_nodesView = new QTreeView(m_tabs);
    m_nodesModel = new QStandardItemModel(this);
    m_nodesModel->setHorizontalHeaderLabels(
        {tr("Node"), tr("Packets"), tr("Traffic"), tr("VLAN")});
    m_nodesView->setModel(m_nodesModel);
    configureView(m_nodesView);

    m_linksView = new QTreeView(m_tabs);
    m_linksModel = new QStandardItemModel(this);
    m_linksModel->setHorizontalHeaderLabels(
        {tr("Source"), tr("Destination"), tr("Protocol"), tr("VLAN"),
         tr("Packets"), tr("Traffic")});
    m_linksView->setModel(m_linksModel);
    configureView(m_linksView);

    m_protocolsView = new QTreeView(m_tabs);
    m_protocolsModel = new QStandardItemModel(this);
    m_protocolsModel->setHorizontalHeaderLabels(
        {tr("Protocol"), tr("Packets"), tr("Traffic")});
    m_protocolsView->setModel(m_protocolsModel);
    configureView(m_protocolsView);

    m_info = new QTextBrowser(m_tabs);
    m_info->setOpenExternalLinks(false);
    m_info->setHtml(tr("<p style='color:gray'>Click a node to pin its "
                       "details here.</p>"));

    m_chart = new TrafficChart(m_tabs);
    m_tabs->addTab(m_nodesView, tr("Nodes"));
    m_tabs->addTab(m_linksView, tr("Links"));
    m_tabs->addTab(m_protocolsView, tr("Protocols"));
    m_tabs->addTab(m_chart, tr("Traffic"));
    m_tabs->addTab(m_info, tr("Node"));

    auto *layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->addWidget(m_tabs);
}

void StatsPanel::setSelectedNode(const QString &id)
{
    m_selectedId = id;
    // The user just clicked a node: show its details.
    if (m_tabs && m_info)
        m_tabs->setCurrentWidget(m_info);
}

void StatsPanel::addTrafficSample(double bytesPerSecond)
{
    if (m_chart)
        m_chart->addSample(bytesPerSecond);
}

void StatsPanel::clearTraffic()
{
    if (m_chart)
        m_chart->clear();
}

void StatsPanel::refresh(const GraphModel &model, const DisplayFilter &filter)
{
    // Selection panel: rebuilt on every refresh so it follows the traffic
    // while staying readable (the hover tooltip disappears as the graph moves).
    if (m_info) {
        const auto &nodes = model.nodes();
        const GraphModel::Node *selected = nullptr;
        for (const auto &node : nodes) {
            if (node.id == m_selectedId) {
                selected = &node;
                break;
            }
        }
        if (!selected) {
            m_info->setHtml(tr("<p style='color:gray'>Click a node to pin its "
                               "details here.</p>"));
        } else {
            QString vlans;
            QList<quint16> ids = selected->vlans.values();
            std::sort(ids.begin(), ids.end());
            for (quint16 id : std::as_const(ids))
                vlans += (vlans.isEmpty() ? QString() : QStringLiteral(", "))
                    + QString::number(id);

            QString html = QStringLiteral("<h3>%1</h3>").arg(
                (selected->label.isEmpty() ? selected->id : selected->label)
                    .toHtmlEscaped());
            html += QStringLiteral("<p><code>%1</code></p>")
                        .arg(selected->id.toHtmlEscaped());
            html += QStringLiteral("<table cellspacing='4'>");
            auto row = [&html](const QString &key, const QString &value) {
                html += QStringLiteral("<tr><td><b>%1</b></td><td>%2</td></tr>")
                            .arg(key.toHtmlEscaped(), value.toHtmlEscaped());
            };
            row(tr("Zone"), ZoneClassifier::name(selected->zone));
            row(tr("Packets"), QString::number(selected->packets));
            row(tr("Traffic"), humanBytes(selected->bytes));
            row(tr("VLAN"), vlans.isEmpty() ? QStringLiteral("—") : vlans);
            html += QStringLiteral("</table>");

            // One address per line: a comma-separated list of IPv6 addresses
            // is unreadable.
            if (selected->aliases.size() > 1) {
                QStringList others;
                for (const QString &alias : selected->aliases) {
                    if (alias != selected->id)
                        others.append(alias);
                }
                others.sort();
                html += QStringLiteral("<h4>%1</h4>")
                            .arg(tr("Also known as"));
                html += QStringLiteral("<table cellspacing='4'>");
                for (const QString &alias : std::as_const(others)) {
                    html += QStringLiteral("<tr><td><code>%1</code></td></tr>")
                                .arg(alias.toHtmlEscaped());
                }
                html += QStringLiteral("</table>");
            }

            // Neighbours, heaviest first.
            struct Neighbour
            {
                QString name;
                QString protocol;
                quint64 bytes;
            };
            QVector<Neighbour> peers;
            for (const auto &link : model.links()) {
                if (link.a < 0 || link.b < 0 || link.a >= nodes.size()
                    || link.b >= nodes.size())
                    continue;
                int peer = -1;
                if (nodes[link.a].id == selected->id)
                    peer = link.b;
                else if (nodes[link.b].id == selected->id)
                    peer = link.a;
                if (peer < 0)
                    continue;
                const auto &other = nodes[peer];
                peers.append({other.label.isEmpty() ? other.id : other.label,
                              link.protocol, link.bytes});
            }
            std::sort(peers.begin(), peers.end(),
                      [](const Neighbour &lhs, const Neighbour &rhs) {
                          return lhs.bytes > rhs.bytes;
                      });
            if (!peers.isEmpty()) {
                html += QStringLiteral("<h4>%1</h4>").arg(tr("Links"));
                html += QStringLiteral("<table cellspacing='4'>");
                for (int i = 0; i < peers.size() && i < 12; ++i) {
                    html += QStringLiteral(
                                "<tr><td>%1</td><td>%2</td><td>%3</td></tr>")
                                .arg(peers[i].name.toHtmlEscaped(),
                                     peers[i].protocol.toHtmlEscaped(),
                                     humanBytes(peers[i].bytes));
                }
                html += QStringLiteral("</table>");
            }
            m_info->setHtml(html);
        }
    }

    // Nodes. When the filter targets protocols, only endpoints of a visible
    // link are listed, matching what the graph draws.
    QSet<QString> linked;
    if (filter.constrainsLinks()) {
        const auto allNodes = model.nodes();
        for (const auto &link : model.links()) {
            if (link.a < 0 || link.b < 0 || link.a >= allNodes.size()
                || link.b >= allNodes.size())
                continue;
            if (filter.acceptsLink(link, allNodes[link.a], allNodes[link.b])) {
                linked.insert(allNodes[link.a].id);
                linked.insert(allNodes[link.b].id);
            }
        }
    }

    m_nodesModel->removeRows(0, m_nodesModel->rowCount());
    for (const auto &node : model.nodes()) {
        if (!filter.isEmpty() && !filter.acceptsNode(node))
            continue;
        if (filter.constrainsLinks() && !linked.contains(node.id))
            continue;
        QList<QStandardItem *> row;
        auto *name = new QStandardItem(node.label.isEmpty() ? node.id : node.label);
        name->setToolTip(node.id);
        row << name << numberItem(node.packets)
            << new QStandardItem(humanBytes(node.bytes))
            << new QStandardItem(vlanText(node.vlans));
        m_nodesModel->appendRow(row);
    }

    // Links.
    m_linksModel->removeRows(0, m_linksModel->rowCount());
    const auto nodes = model.nodes();
    for (const auto &link : model.links()) {
        if (link.a < 0 || link.b < 0 || link.a >= nodes.size()
            || link.b >= nodes.size())
            continue;
        if (!filter.isEmpty()
            && !filter.acceptsLink(link, nodes[link.a], nodes[link.b]))
            continue;
        const auto labelFor = [&nodes](int index) {
            const auto &node = nodes[index];
            return node.label.isEmpty() ? node.id : node.label;
        };
        QList<QStandardItem *> row;
        row << new QStandardItem(labelFor(link.a))
            << new QStandardItem(labelFor(link.b))
            << new QStandardItem(link.protocol)
            << new QStandardItem(vlanText(link.vlans))
            << numberItem(link.packets)
            << new QStandardItem(humanBytes(link.bytes));
        m_linksModel->appendRow(row);
    }

    // Protocols.
    m_protocolsModel->removeRows(0, m_protocolsModel->rowCount());
    auto protocols = model.protocols();
    QList<QString> names = protocols.keys();
    std::sort(names.begin(), names.end(), [&protocols](const QString &lhs,
                                                       const QString &rhs) {
        return protocols.value(lhs).bytes > protocols.value(rhs).bytes;
    });
    for (const QString &name : std::as_const(names)) {
        const auto &stat = protocols.value(name);
        auto *protocolItem = new QStandardItem(colorDot(protocolColor(name)),
                                               name);
        m_protocolsModel->appendRow({protocolItem, numberItem(stat.packets),
                                     new QStandardItem(humanBytes(stat.bytes))});
    }
}

} // namespace etherape

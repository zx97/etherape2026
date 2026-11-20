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

    m_chart = new TrafficChart(m_tabs);
    m_tabs->addTab(m_nodesView, tr("Nodes"));
    m_tabs->addTab(m_linksView, tr("Links"));
    m_tabs->addTab(m_protocolsView, tr("Protocols"));
    m_tabs->addTab(m_chart, tr("Traffic"));

    auto *layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->addWidget(m_tabs);
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

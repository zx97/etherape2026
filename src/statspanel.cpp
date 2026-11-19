// SPDX-License-Identifier: GPL-2.0-or-later

#include "statspanel.h"

#include "graphmodel.h"

#include <QHeaderView>
#include <QStandardItemModel>
#include <QTabWidget>
#include <QTreeView>
#include <QVBoxLayout>

#include <algorithm>

namespace etherape {

namespace {

QString humanBytes(quint64 bytes)
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
        {tr("Node"), tr("Packets"), tr("Traffic")});
    m_nodesView->setModel(m_nodesModel);
    configureView(m_nodesView);

    m_linksView = new QTreeView(m_tabs);
    m_linksModel = new QStandardItemModel(this);
    m_linksModel->setHorizontalHeaderLabels({tr("Source"), tr("Destination"),
                                             tr("Protocol"), tr("Packets"),
                                             tr("Traffic")});
    m_linksView->setModel(m_linksModel);
    configureView(m_linksView);

    m_protocolsView = new QTreeView(m_tabs);
    m_protocolsModel = new QStandardItemModel(this);
    m_protocolsModel->setHorizontalHeaderLabels(
        {tr("Protocol"), tr("Packets"), tr("Traffic")});
    m_protocolsView->setModel(m_protocolsModel);
    configureView(m_protocolsView);

    m_tabs->addTab(m_nodesView, tr("Nodes"));
    m_tabs->addTab(m_linksView, tr("Links"));
    m_tabs->addTab(m_protocolsView, tr("Protocols"));

    auto *layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->addWidget(m_tabs);
}

void StatsPanel::refresh(const GraphModel &model)
{
    // Nodes.
    m_nodesModel->removeRows(0, m_nodesModel->rowCount());
    for (const auto &node : model.nodes()) {
        QList<QStandardItem *> row;
        auto *name = new QStandardItem(node.label.isEmpty() ? node.id : node.label);
        name->setToolTip(node.id);
        row << name << numberItem(node.packets)
            << new QStandardItem(humanBytes(node.bytes));
        m_nodesModel->appendRow(row);
    }

    // Links.
    m_linksModel->removeRows(0, m_linksModel->rowCount());
    const auto nodes = model.nodes();
    for (const auto &link : model.links()) {
        if (link.a < 0 || link.b < 0 || link.a >= nodes.size()
            || link.b >= nodes.size())
            continue;
        const auto labelFor = [&nodes](int index) {
            const auto &node = nodes[index];
            return node.label.isEmpty() ? node.id : node.label;
        };
        QList<QStandardItem *> row;
        row << new QStandardItem(labelFor(link.a))
            << new QStandardItem(labelFor(link.b))
            << new QStandardItem(link.protocol) << numberItem(link.packets)
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
        m_protocolsModel->appendRow({new QStandardItem(name),
                                     numberItem(stat.packets),
                                     new QStandardItem(humanBytes(stat.bytes))});
    }
}

} // namespace etherape

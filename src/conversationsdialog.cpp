// SPDX-License-Identifier: GPL-2.0-or-later

#include "conversationsdialog.h"

#include "formatting.h"
#include "graphmodel.h"

#include <QBrush>
#include <QHeaderView>
#include <QStandardItemModel>
#include <QTimer>
#include <QTreeView>
#include <QVBoxLayout>

#include <algorithm>

namespace etherape {

namespace {

// QStandardItem sorting is lexical; keep the numeric value for comparisons.
class NumericItem : public QStandardItem
{
public:
    NumericItem(const QString &text, qulonglong value)
        : QStandardItem(text), m_value(value)
    {
    }

    bool operator<(const QStandardItem &other) const override
    {
        const auto *numeric = dynamic_cast<const NumericItem *>(&other);
        if (!numeric)
            return QStandardItem::operator<(other);
        return m_value < numeric->m_value;
    }

private:
    qulonglong m_value;
};

QString durationText(qint64 firstMs, qint64 lastMs)
{
    const double seconds = std::max<qint64>(0, lastMs - firstMs) / 1000.0;
    if (seconds < 60.0)
        return QStringLiteral("%1 s").arg(seconds, 0, 'f', 1);
    const int minutes = static_cast<int>(seconds) / 60;
    return QStringLiteral("%1 min %2 s")
        .arg(minutes)
        .arg(static_cast<int>(seconds) % 60);
}

} // namespace

ConversationsDialog::ConversationsDialog(const GraphModel *model,
                                         QWidget *parent)
    : QDialog(parent), m_model(model)
{
    setWindowTitle(tr("Conversations"));
    resize(980, 520);

    m_rows = new QStandardItemModel(this);
    m_rows->setHorizontalHeaderLabels(
        {tr("Source"), tr("Destination"), tr("Protocol"), tr("Pkts A→B"),
         tr("Bytes A→B"), tr("Pkts B→A"), tr("Bytes B→A"), tr("Protocol mix"),
         tr("Duration")});

    m_view = new QTreeView(this);
    m_view->setModel(m_rows);
    m_view->setRootIsDecorated(false);
    m_view->setAlternatingRowColors(true);
    m_view->setUniformRowHeights(true);
    m_view->setSortingEnabled(true);
    m_view->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_view->header()->setSectionResizeMode(QHeaderView::ResizeToContents);
    m_view->header()->setStretchLastSection(true);

    connect(m_view, &QTreeView::doubleClicked, this,
            [this](const QModelIndex &index) {
                QStandardItem *item = m_rows->item(index.row(), 0);
                if (item)
                    emit nodeActivated(item->data(Qt::UserRole).toString());
            });

    auto *layout = new QVBoxLayout(this);
    layout->setContentsMargins(4, 4, 4, 4);
    layout->addWidget(m_view);

    m_timer = new QTimer(this);
    m_timer->setInterval(1000);
    connect(m_timer, &QTimer::timeout, this, &ConversationsDialog::refresh);
    m_timer->start();

    refresh();
}

void ConversationsDialog::refresh()
{
    if (!m_model)
        return;

    const auto nodes = m_model->nodes();
    const auto links = m_model->links();

    m_rows->removeRows(0, m_rows->rowCount());
    for (const auto &link : links) {
        if (link.a < 0 || link.b < 0 || link.a >= nodes.size()
            || link.b >= nodes.size())
            continue;

        const auto &source = nodes[link.a];
        const auto &target = nodes[link.b];
        const QString sourceLabel =
            source.label.isEmpty() ? source.id : source.label;
        const QString targetLabel =
            target.label.isEmpty() ? target.id : target.label;

        auto *sourceItem = new QStandardItem(
            QStringLiteral("%1  (%2)").arg(sourceLabel, source.id));
        sourceItem->setData(source.id, Qt::UserRole);
        auto *targetItem = new QStandardItem(
            QStringLiteral("%1  (%2)").arg(targetLabel, target.id));

        auto *protocolItem = new QStandardItem(link.protocol);
        protocolItem->setForeground(QBrush(protocolColor(link.protocol)));

        m_rows->appendRow({
            sourceItem,
            targetItem,
            protocolItem,
            new NumericItem(QString::number(link.packetsAB), link.packetsAB),
            new NumericItem(humanBytes(link.bytesAB), link.bytesAB),
            new NumericItem(QString::number(link.packetsBA), link.packetsBA),
            new NumericItem(humanBytes(link.bytesBA), link.bytesBA),
            new QStandardItem(
                QStringLiteral("%1 %2%").arg(link.protocol).arg(
                    link.bytes > 0
                        ? static_cast<int>(100.0 * link.bytesAB / link.bytes)
                        : 0)),
            new QStandardItem(durationText(link.firstSeenMs, link.lastSeenMs)),
        });
    }
}

} // namespace etherape

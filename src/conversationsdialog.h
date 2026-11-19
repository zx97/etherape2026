// SPDX-License-Identifier: GPL-2.0-or-later
//
// Conversations window: one row per graph link, with per-direction packet and
// byte counters, duration and throughput.

#pragma once

#include <QDialog>
#include <QString>

class QStandardItemModel;
class QTreeView;
class QTimer;

namespace etherape {

class GraphModel;

class ConversationsDialog : public QDialog
{
    Q_OBJECT

public:
    explicit ConversationsDialog(const GraphModel *model,
                                 QWidget *parent = nullptr);

signals:
    void nodeActivated(const QString &id);

private:
    void refresh();

    const GraphModel *m_model = nullptr;
    QStandardItemModel *m_rows = nullptr;
    QTreeView *m_view = nullptr;
    QTimer *m_timer = nullptr;
};

} // namespace etherape

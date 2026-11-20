// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <QWidget>

class QStandardItemModel;
class QTreeView;
class QTabWidget;

namespace etherape {

class GraphModel;
class TrafficChart;
class DisplayFilter;

class StatsPanel : public QWidget
{
    Q_OBJECT

public:
    explicit StatsPanel(QWidget *parent = nullptr);

    void refresh(const GraphModel &model, const DisplayFilter &filter);
    void addTrafficSample(double bytesPerSecond);
    void clearTraffic();

private:
    QTabWidget *m_tabs = nullptr;
    TrafficChart *m_chart = nullptr;
    QTreeView *m_nodesView = nullptr;
    QTreeView *m_linksView = nullptr;
    QTreeView *m_protocolsView = nullptr;
    QStandardItemModel *m_nodesModel = nullptr;
    QStandardItemModel *m_linksModel = nullptr;
    QStandardItemModel *m_protocolsModel = nullptr;
};

} // namespace etherape

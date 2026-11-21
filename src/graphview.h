// SPDX-License-Identifier: GPL-2.0-or-later
//
// Custom-painted traffic graph. QPainter gives us full control over the
// EtherApe look (animated link thickness/colour, node labels, zoom/pan, node
// dragging) with far less code than a scene graph and no per-item overhead.

#pragma once

#include "displayfilter.h"

#include <QColor>
#include <QPointF>
#include <QString>
#include <QTimer>
#include <QVector>
#include <QWidget>

namespace etherape {

class GraphModel;

class GraphView : public QWidget
{
    Q_OBJECT

public:
    explicit GraphView(QWidget *parent = nullptr);

    void setModel(GraphModel *model);
    void setFontScale(double scale);
    double fontScale() const { return m_fontScale; }
    void setNodeLimitHint(int limit);

    void setLegendVisible(bool visible);
    bool legendVisible() const { return m_showLegend; }

    void setZonesVisible(bool visible);
    // When no capture is running the graph must stay frozen: the decay would
    // otherwise erase every node a few seconds after Stop.
    void setCaptureActive(bool active);
    bool zonesVisible() const { return m_showZones; }

    void selectNode(const QString &id);
    void centerOnNode(const QString &id);
    void setDisplayFilter(const DisplayFilter &filter);
    void resetView();

signals:
    void nodeClicked(const QString &id);
    void nodeHovered(const QString &id);
    void layoutChanged();

protected:
    void paintEvent(QPaintEvent *event) override;
    void mousePressEvent(QMouseEvent *event) override;
    void mouseMoveEvent(QMouseEvent *event) override;
    void mouseReleaseEvent(QMouseEvent *event) override;
    void wheelEvent(QWheelEvent *event) override;
    void leaveEvent(QEvent *event) override;

private:
    QPointF toScreen(double nx, double ny) const;
    QPointF toNormalized(const QPointF &pos) const;
    int nodeAt(const QPointF &pos) const;
    void rebuildScreenPositions();
    void drawLegend(QPainter &painter, const QFont &baseFont);
    void drawZones(QPainter &painter, const QFont &baseFont,
                   const QVector<bool> &visible);

    GraphModel *m_model = nullptr;
    QTimer m_timer;
    std::chrono::steady_clock::time_point m_lastTick;

    QVector<QPointF> m_screenPos;
    QVector<double> m_radii;

    double m_zoom = 1.0;
    QPointF m_pan;
    double m_fontScale = 1.0;
    bool m_showLegend = true;
    bool m_showZones = true;
    bool m_captureActive = false;
    int m_hover = -1;
    QString m_selected;
    DisplayFilter m_displayFilter;
    int m_dragNode = -1;
    bool m_dragging = false;
    QPointF m_dragStart;
    QPointF m_panStart;
};

} // namespace etherape

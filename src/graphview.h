// SPDX-License-Identifier: GPL-2.0-or-later
//
// Custom-painted traffic graph. QPainter gives us full control over the
// EtherApe look (animated link thickness/colour, node labels, zoom/pan) with
// far less code than a scene graph and no per-item overhead.

#pragma once

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
    void resetView();

signals:
    void nodeClicked(const QString &id);
    void nodeHovered(const QString &id);

protected:
    void paintEvent(QPaintEvent *event) override;
    void mousePressEvent(QMouseEvent *event) override;
    void mouseMoveEvent(QMouseEvent *event) override;
    void mouseReleaseEvent(QMouseEvent *event) override;
    void wheelEvent(QWheelEvent *event) override;
    void leaveEvent(QEvent *event) override;

private:
    QPointF toScreen(double nx, double ny) const;
    int nodeAt(const QPointF &pos) const;
    static QColor protocolColor(const QString &protocol);
    void rebuildScreenPositions();

    GraphModel *m_model = nullptr;
    QTimer m_timer;
    std::chrono::steady_clock::time_point m_lastTick;

    QVector<QPointF> m_screenPos;
    QVector<double> m_radii;

    double m_zoom = 1.0;
    QPointF m_pan;
    double m_fontScale = 1.0;
    int m_hover = -1;
    QString m_selected;
    bool m_dragging = false;
    QPointF m_dragStart;
    QPointF m_panStart;
};

} // namespace etherape

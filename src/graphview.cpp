// SPDX-License-Identifier: GPL-2.0-or-later

#include "graphview.h"

#include "graphmodel.h"

#include <QDateTime>
#include <QFontMetrics>
#include <QMouseEvent>
#include <QPainter>
#include <QPainterPath>
#include <QToolTip>
#include <QWheelEvent>

#include <algorithm>
#include <chrono>
#include <cmath>

namespace etherape {

namespace {

constexpr double kMinRadius = 5.0;
constexpr double kMaxRadius = 22.0;

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

} // namespace

GraphView::GraphView(QWidget *parent) : QWidget(parent)
{
    setMinimumSize(480, 320);
    setMouseTracking(true);
    setFocusPolicy(Qt::StrongFocus);
    setToolTipDuration(0);

    m_timer.setInterval(40);
    connect(&m_timer, &QTimer::timeout, this, [this] {
        if (!m_model)
            return;
        const auto now = std::chrono::steady_clock::now();
        const double dt =
            std::chrono::duration<double>(now - m_lastTick).count();
        m_lastTick = now;
        m_model->tick(std::min(dt, 0.2), QDateTime::currentMSecsSinceEpoch());
        update();
    });
    m_lastTick = std::chrono::steady_clock::now();
    m_timer.start();
}

void GraphView::setModel(GraphModel *model)
{
    m_model = model;
    m_screenPos.clear();
    m_radii.clear();
    update();
}

void GraphView::setFontScale(double scale)
{
    m_fontScale = std::clamp(scale, 0.6, 2.5);
    update();
}

void GraphView::setNodeLimitHint(int limit)
{
    if (m_model)
        m_model->setNodeLimit(limit);
}

void GraphView::resetView()
{
    m_zoom = 1.0;
    m_pan = QPointF();
    update();
}

QPointF GraphView::toScreen(double nx, double ny) const
{
    const QPointF center(width() / 2.0, height() / 2.0);
    return center + m_pan
        + QPointF((nx - 0.5) * width(), (ny - 0.5) * height()) * m_zoom;
}

QColor GraphView::protocolColor(const QString &protocol)
{
    if (protocol == QLatin1String("TCP"))
        return QColor(0x5a, 0xa9, 0xff);
    if (protocol == QLatin1String("UDP"))
        return QColor(0x5f, 0xd1, 0x8a);
    if (protocol == QLatin1String("ICMP") || protocol == QLatin1String("ICMPv6"))
        return QColor(0xff, 0xb4, 0x54);
    if (protocol == QLatin1String("ARP"))
        return QColor(0xff, 0x7a, 0x5c);
    if (protocol.startsWith(QLatin1String("IPv6")))
        return QColor(0xb1, 0x8c, 0xff);
    if (protocol.startsWith(QLatin1String("IP/")))
        return QColor(0xc0, 0xc8, 0xd4);
    return QColor(0x9a, 0xa5, 0xb1);
}

void GraphView::rebuildScreenPositions()
{
    m_screenPos.resize(m_model->nodes().size());
    m_radii.resize(m_model->nodes().size());

    quint64 maxBytes = 1;
    for (const auto &node : m_model->nodes())
        maxBytes = std::max(maxBytes, node.bytes);

    for (int i = 0; i < m_model->nodes().size(); ++i) {
        const auto &node = m_model->nodes()[i];
        m_screenPos[i] = toScreen(node.x, node.y);
        const double ratio =
            std::sqrt(static_cast<double>(node.bytes) / static_cast<double>(maxBytes));
        m_radii[i] = (kMinRadius + (kMaxRadius - kMinRadius) * ratio) * m_zoom;
    }
}

int GraphView::nodeAt(const QPointF &pos) const
{
    int best = -1;
    double bestDist = 0.0;
    for (int i = 0; i < m_screenPos.size(); ++i) {
        const QPointF delta = pos - m_screenPos[i];
        const double dist = std::hypot(delta.x(), delta.y());
        if (dist <= m_radii[i] + 3.0 && (best < 0 || dist < bestDist)) {
            best = i;
            bestDist = dist;
        }
    }
    return best;
}

void GraphView::paintEvent(QPaintEvent *)
{
    QPainter painter(this);
    painter.setRenderHint(QPainter::Antialiasing, true);
    painter.setRenderHint(QPainter::TextAntialiasing, true);

    const QPalette pal = palette();
    QLinearGradient gradient(rect().topLeft(), rect().bottomRight());
    gradient.setColorAt(0.0, pal.color(QPalette::Base));
    gradient.setColorAt(1.0, pal.color(QPalette::AlternateBase));
    painter.fillRect(rect(), gradient);

    if (!m_model) {
        painter.setPen(pal.color(QPalette::Text));
        painter.drawText(rect(), Qt::AlignCenter,
                         tr("No capture in progress."));
        return;
    }

    rebuildScreenPositions();

    const auto nodes = m_model->nodes();
    const auto links = m_model->links();

    // Links first, so nodes sit on top.
    for (const auto &link : links) {
        if (link.a < 0 || link.b < 0 || link.a >= m_screenPos.size()
            || link.b >= m_screenPos.size())
            continue;

        const double intensity = std::clamp(link.intensity, 0.0, 1.0);
        QColor color = protocolColor(link.protocol);
        color.setAlphaF(0.18 + 0.72 * intensity);

        const bool incident =
            m_selected.isEmpty() || nodes[link.a].id == m_selected
            || nodes[link.b].id == m_selected;

        QPen pen(color);
        pen.setWidthF(0.6 + 7.0 * intensity * (incident ? 1.0 : 0.25));
        pen.setCapStyle(Qt::RoundCap);
        painter.setPen(pen);
        painter.drawLine(m_screenPos[link.a], m_screenPos[link.b]);
    }

    // Nodes.
    QFont font = painter.font();
    font.setPointSizeF(std::max(6.0, font.pointSizeF() * m_fontScale));
    painter.setFont(font);
    const QFontMetrics metrics(font);

    for (int i = 0; i < nodes.size(); ++i) {
        const auto &node = nodes[i];
        const QPointF center = m_screenPos[i];
        const double radius = m_radii[i];

        QColor fill;
        switch (node.kind) {
        case NodeKind::Mac:
            fill = QColor(0x7f, 0x8c, 0x9d);
            break;
        case NodeKind::Ipv4:
            fill = QColor(0x4c, 0xaf, 0x50);
            break;
        case NodeKind::Ipv6:
            fill = QColor(0x95, 0x75, 0xcd);
            break;
        case NodeKind::Port:
            fill = QColor(0x29, 0xb6, 0xf6);
            break;
        }

        const bool isHover = (i == m_hover);
        const bool isSelected = (!m_selected.isEmpty() && node.id == m_selected);

        painter.setBrush(fill);
        painter.setPen(QPen(isSelected ? QColor(0xff, 0xd1, 0x66)
                                      : pal.color(QPalette::Base),
                            isSelected || isHover ? 2.5 : 1.2));
        painter.drawEllipse(center, radius, radius);

        if (isHover) {
            painter.setBrush(Qt::NoBrush);
            painter.setPen(QPen(QColor(255, 255, 255, 90), 1.0));
            painter.drawEllipse(center, radius + 4, radius + 4);
        }

        const QString label = metrics.elidedText(
            node.label.isEmpty() ? node.id : node.label, Qt::ElideMiddle, 170);
        const QRectF textRect(center.x() - 90, center.y() + radius + 3, 180,
                              metrics.height());
        painter.setPen(pal.color(QPalette::Text));
        painter.drawText(textRect, Qt::AlignHCenter | Qt::AlignTop, label);
    }

    // Legend.
    painter.setPen(pal.color(QPalette::Text));
    QFont small = font;
    small.setPointSizeF(std::max(6.0, font.pointSizeF() * 0.85));
    painter.setFont(small);
    int y = height() - 8;
    const QStringList legend = {QStringLiteral("TCP"), QStringLiteral("UDP"),
                                QStringLiteral("ICMP"), QStringLiteral("ARP"),
                                QStringLiteral("IPv6")};
    for (const QString &name : legend) {
        y -= 15;
        painter.setBrush(protocolColor(name));
        painter.setPen(Qt::NoPen);
        painter.drawEllipse(QPointF(14, y + 4), 4, 4);
        painter.setPen(pal.color(QPalette::Text));
        painter.drawText(QPointF(24, y + 8), name);
    }
    y -= 20;
    painter.drawText(QPointF(10, y + 8),
                     tr("%1 nodes · %2 links · zoom %3%")
                         .arg(nodes.size())
                         .arg(links.size())
                         .arg(static_cast<int>(m_zoom * 100)));
}

void GraphView::mousePressEvent(QMouseEvent *event)
{
    if (event->button() == Qt::LeftButton) {
        const int index = nodeAt(event->position());
        if (index >= 0 && m_model) {
            m_selected = m_model->nodes()[index].id;
            emit nodeClicked(m_selected);
            update();
        } else {
            m_selected.clear();
            m_dragging = true;
            m_dragStart = event->position();
            m_panStart = m_pan;
        }
    } else if (event->button() == Qt::MiddleButton
               || event->button() == Qt::RightButton) {
        m_dragging = true;
        m_dragStart = event->position();
        m_panStart = m_pan;
    }
}

void GraphView::mouseMoveEvent(QMouseEvent *event)
{
    if (m_dragging) {
        m_pan = m_panStart + (event->position() - m_dragStart);
        update();
        return;
    }

    const int index = nodeAt(event->position());
    if (index != m_hover) {
        m_hover = index;
        if (index >= 0 && m_model) {
            const auto &node = m_model->nodes()[index];
            setToolTip(tr("%1\n%2 packets · %3")
                           .arg(node.label.isEmpty() ? node.id : node.label)
                           .arg(node.packets)
                           .arg(humanBytes(node.bytes)));
            emit nodeHovered(node.id);
        } else {
            setToolTip(QString());
        }
        update();
    }
}

void GraphView::mouseReleaseEvent(QMouseEvent *event)
{
    Q_UNUSED(event);
    m_dragging = false;
}

void GraphView::wheelEvent(QWheelEvent *event)
{
    const double factor = event->angleDelta().y() > 0 ? 1.12 : 1.0 / 1.12;
    m_zoom = std::clamp(m_zoom * factor, 0.3, 4.0);
    update();
    event->accept();
}

void GraphView::leaveEvent(QEvent *event)
{
    Q_UNUSED(event);
    m_hover = -1;
    update();
}

} // namespace etherape

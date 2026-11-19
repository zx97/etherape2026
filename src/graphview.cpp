// SPDX-License-Identifier: GPL-2.0-or-later

#include "graphview.h"

#include "formatting.h"
#include "graphmodel.h"

#include <QDateTime>
#include <QFontMetrics>
#include <QMouseEvent>
#include <QPainter>
#include <QWheelEvent>

#include <algorithm>
#include <chrono>
#include <cmath>

namespace etherape {

namespace {

constexpr double kMinRadius = 5.0;
constexpr double kMaxRadius = 22.0;
constexpr int kLegendMaxRows = 12;

QString vlanText(const QSet<quint16> &vlans)
{
    if (vlans.isEmpty())
        return QString();
    QList<quint16> ids = vlans.values();
    std::sort(ids.begin(), ids.end());
    QStringList parts;
    for (quint16 id : std::as_const(ids))
        parts.append(QString::number(id));
    return parts.join(QStringLiteral(", "));
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
        const double dt = std::chrono::duration<double>(now - m_lastTick).count();
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

void GraphView::setLegendVisible(bool visible)
{
    m_showLegend = visible;
    update();
}

void GraphView::setZonesVisible(bool visible)
{
    m_showZones = visible;
    update();
}

void GraphView::drawZones(QPainter &painter, const QFont &baseFont)
{
    if (!m_model || !m_showZones)
        return;

    const auto nodes = m_model->nodes();
    QFont font = baseFont;
    font.setPointSizeF(std::max(7.0, baseFont.pointSizeF() * 1.0));
    font.setBold(true);

    for (ZoneId zone : ZoneClassifier::allZones()) {
        bool any = false;
        QRectF bounds;
        int count = 0;
        for (int i = 0; i < nodes.size() && i < m_screenPos.size(); ++i) {
            if (nodes[i].zone != zone)
                continue;
            const QPointF p = m_screenPos[i];
            const double r = m_radii[i];
            const QRectF nodeRect(p.x() - r, p.y() - r, 2 * r, 2 * r);
            bounds = any ? bounds.united(nodeRect) : nodeRect;
            any = true;
            ++count;
        }
        if (!any)
            continue;  // an empty cloud would only add clutter

        const double pad = 26.0 * m_zoom;
        bounds.adjust(-pad, -pad, pad, pad);
        if (bounds.width() < 120)
            bounds.setWidth(120);
        if (bounds.height() < 80)
            bounds.setHeight(80);

        QColor color = ZoneClassifier::color(zone);
        QColor fill = color;
        fill.setAlpha(18);
        QColor border = color;
        border.setAlpha(120);

        painter.setBrush(fill);
        painter.setPen(QPen(border, 1.3, Qt::DashLine));
        painter.drawRoundedRect(bounds, bounds.height() / 2.0,
                                bounds.height() / 2.0);

        painter.setFont(font);
        painter.setPen(color.darker(115));
        const QString label = QStringLiteral("%1 · %2")
                                  .arg(ZoneClassifier::name(zone))
                                  .arg(count);
        painter.drawText(QRectF(bounds.left(), bounds.top() + 4, bounds.width(), 18),
                         Qt::AlignHCenter | Qt::AlignTop, label);

        QFont restored = baseFont;
        painter.setFont(restored);
    }
}

void GraphView::selectNode(const QString &id)
{
    m_selected = id;
    update();
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

QPointF GraphView::toNormalized(const QPointF &pos) const
{
    const QPointF center(width() / 2.0, height() / 2.0);
    const QPointF relative = (pos - center - m_pan) / (m_zoom * width());
    return QPointF(relative.x() + 0.5,
                   ((pos.y() - center.y() - m_pan.y())
                    / (m_zoom * height()))
                       + 0.5);
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
        const double ratio = std::sqrt(static_cast<double>(node.bytes)
                                       / static_cast<double>(maxBytes));
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

void GraphView::drawLegend(QPainter &painter, const QFont &baseFont)
{
    if (!m_model)
        return;

    const auto protocols = m_model->protocols();
    if (protocols.isEmpty())
        return;

    QList<QPair<QString, GraphModel::ProtoStat>> entries;
    entries.reserve(protocols.size());
    for (auto it = protocols.constBegin(); it != protocols.constEnd(); ++it)
        entries.append({it.key(), it.value()});
    std::sort(entries.begin(), entries.end(),
              [](const auto &lhs, const auto &rhs) {
                  return lhs.second.bytes > rhs.second.bytes;
              });
    if (entries.size() > kLegendMaxRows)
        entries.resize(kLegendMaxRows);

    QFont font = baseFont;
    font.setPointSizeF(std::max(6.0, baseFont.pointSizeF() * 0.9));
    painter.setFont(font);
    const QFontMetrics metrics(font);

    int textWidth = 0;
    for (const auto &entry : entries) {
        const QString text = QStringLiteral("%1   %2")
                                 .arg(entry.first,
                                      humanBytes(entry.second.bytes));
        textWidth = std::max(textWidth, metrics.horizontalAdvance(text));
    }

    const int rowHeight = metrics.height() + 3;
    const int boxWidth = textWidth + 38;
    const int boxHeight = rowHeight * entries.size() + 14;
    QRectF box(10, height() - boxHeight - 10, boxWidth, boxHeight);

    const QPalette pal = palette();
    QColor background = pal.color(QPalette::Base);
    background.setAlpha(215);
    painter.setBrush(background);
    painter.setPen(QPen(pal.color(QPalette::Mid), 1.0));
    painter.drawRoundedRect(box, 6, 6);

    int y = static_cast<int>(box.top()) + 7;
    for (const auto &entry : entries) {
        painter.setPen(Qt::NoPen);
        painter.setBrush(protocolColor(entry.first));
        painter.drawEllipse(QPointF(box.left() + 13, y + metrics.height() / 2.0),
                            4.5, 4.5);
        painter.setPen(pal.color(QPalette::Text));
        painter.drawText(QPointF(box.left() + 25, y + metrics.ascent()),
                         QStringLiteral("%1   %2")
                             .arg(entry.first, humanBytes(entry.second.bytes)));
        y += rowHeight;
    }
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
        painter.drawText(rect(), Qt::AlignCenter, tr("No capture in progress."));
        return;
    }

    rebuildScreenPositions();

    const auto nodes = m_model->nodes();
    const auto links = m_model->links();

    // Zone clouds first: they are the visual grouping of the graph.
    drawZones(painter, painter.font());

    // Links next, so nodes sit on top.
    for (const auto &link : links) {
        if (link.a < 0 || link.b < 0 || link.a >= m_screenPos.size()
            || link.b >= m_screenPos.size())
            continue;

        const double intensity = std::clamp(link.intensity, 0.0, 1.0);
        QColor color = protocolColor(link.protocol);
        color.setAlphaF(0.18 + 0.72 * intensity);

        const bool incident = m_selected.isEmpty()
            || nodes[link.a].id == m_selected || nodes[link.b].id == m_selected;

        QPen pen(color);
        pen.setWidthF(0.6 + 7.0 * intensity * (incident ? 1.0 : 0.25));
        pen.setCapStyle(Qt::RoundCap);
        painter.setPen(pen);
        painter.drawLine(m_screenPos[link.a], m_screenPos[link.b]);
    }

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

        if (node.pinned) {
            // Small anchor marker: this node ignores the force layout.
            painter.setBrush(Qt::NoBrush);
            painter.setPen(QPen(QColor(0xff, 0xd1, 0x66, 200), 1.0,
                                Qt::DotLine));
            painter.drawEllipse(center, radius + 3, radius + 3);
        }

        if (isHover) {
            painter.setBrush(Qt::NoBrush);
            painter.setPen(QPen(QColor(255, 255, 255, 90), 1.0));
            painter.drawEllipse(center, radius + 5, radius + 5);
        }

        const QString label = metrics.elidedText(
            node.label.isEmpty() ? node.id : node.label, Qt::ElideMiddle, 170);
        const QRectF textRect(center.x() - 90, center.y() + radius + 3, 180,
                              metrics.height());
        painter.setPen(pal.color(QPalette::Text));
        painter.drawText(textRect, Qt::AlignHCenter | Qt::AlignTop, label);
    }

    // Top-left counters, with a light background so they stay readable over
    // links crossing that corner.
    QFont small = font;
    small.setPointSizeF(std::max(6.0, font.pointSizeF() * 0.85));
    const QString counters = tr("%1 nodes · %2 links · zoom %3%")
                                 .arg(nodes.size())
                                 .arg(links.size())
                                 .arg(static_cast<int>(m_zoom * 100));
    const QFontMetrics smallMetrics(small);
    const QRectF counterRect(10, 10, smallMetrics.horizontalAdvance(counters) + 16,
                             smallMetrics.height() + 8);
    QColor counterBackground = pal.color(QPalette::Base);
    counterBackground.setAlpha(190);
    painter.setFont(small);
    painter.setBrush(counterBackground);
    painter.setPen(QPen(pal.color(QPalette::Mid), 1.0));
    painter.drawRoundedRect(counterRect, 5, 5);
    painter.setPen(pal.color(QPalette::Text));
    painter.drawText(counterRect, Qt::AlignCenter, counters);

    if (m_showLegend)
        drawLegend(painter, font);
}

void GraphView::mousePressEvent(QMouseEvent *event)
{
    const int index = nodeAt(event->position());

    if (event->button() == Qt::LeftButton) {
        if (index >= 0 && m_model) {
            m_selected = m_model->nodes()[index].id;
            m_dragNode = index;
            emit nodeClicked(m_selected);
            update();
        } else {
            m_selected.clear();
            m_dragging = true;
            m_dragStart = event->position();
            m_panStart = m_pan;
        }
    } else if (event->button() == Qt::RightButton && index >= 0 && m_model) {
        // Right click releases a manually placed node.
        m_model->pinNode(m_model->nodes()[index].id, false);
        update();
    } else if (event->button() == Qt::MiddleButton
               || event->button() == Qt::RightButton) {
        m_dragging = true;
        m_dragStart = event->position();
        m_panStart = m_pan;
    }
}

void GraphView::mouseMoveEvent(QMouseEvent *event)
{
    if (m_dragNode >= 0 && m_model) {
        const auto nodes = m_model->nodes();
        if (m_dragNode < nodes.size()) {
            const QPointF normalized = toNormalized(event->position());
            m_model->setNodePosition(nodes[m_dragNode].id,
                                     std::clamp(normalized.x(), 0.02, 0.98),
                                     std::clamp(normalized.y(), 0.02, 0.98));
            emit layoutChanged();
            update();
        }
        return;
    }

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
            const QString vlans = vlanText(node.vlans);
            setToolTip(
                tr("%1\n%2 packets · %3\n%4\n%5")
                    .arg(node.label.isEmpty() ? node.id : node.label)
                    .arg(node.packets)
                    .arg(humanBytes(node.bytes))
                    .arg(vlans.isEmpty() ? tr("untagged")
                                         : tr("VLAN %1").arg(vlans))
                    .arg(node.pinned ? tr("position locked (right-click to release)")
                                     : tr("drag to pin")));
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
    m_dragNode = -1;
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

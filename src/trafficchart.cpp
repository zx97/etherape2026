// SPDX-License-Identifier: GPL-2.0-or-later

#include "trafficchart.h"

#include "formatting.h"

#include <QPainter>
#include <QPainterPath>

#include <algorithm>

namespace etherape {

TrafficChart::TrafficChart(QWidget *parent) : QWidget(parent)
{
    setMinimumHeight(90);
    setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
    setToolTip(tr("Throughput over the last five minutes."));
}

void TrafficChart::addSample(double bytesPerSecond)
{
    m_samples.append(std::max(0.0, bytesPerSecond));
    while (m_samples.size() > kCapacity)
        m_samples.removeFirst();
    m_peak = 0.0;
    for (double sample : std::as_const(m_samples))
        m_peak = std::max(m_peak, sample);
    update();
}

void TrafficChart::clear()
{
    m_samples.clear();
    m_peak = 0.0;
    update();
}

double TrafficChart::current() const
{
    return m_samples.isEmpty() ? 0.0 : m_samples.last();
}

void TrafficChart::paintEvent(QPaintEvent *)
{
    QPainter painter(this);
    painter.setRenderHint(QPainter::Antialiasing, true);

    const QPalette pal = palette();
    painter.fillRect(rect(), pal.color(QPalette::Base));

    const QRectF plot = rect().adjusted(8, 8, -8, -18);
    painter.setPen(QPen(pal.color(QPalette::Mid), 1.0));
    painter.drawRect(plot);

    QFont font = painter.font();
    font.setPointSizeF(std::max(6.0, font.pointSizeF() * 0.85));
    painter.setFont(font);

    if (m_samples.size() < 2) {
        painter.setPen(pal.color(QPalette::Text));
        painter.drawText(plot, Qt::AlignCenter, tr("waiting for traffic…"));
        return;
    }

    const double scale = m_peak > 0 ? m_peak : 1.0;
    QPainterPath path;
    const double step = plot.width() / (kCapacity - 1);
    // Right-align: the newest sample sits at the right edge.
    const double offset = plot.right() - (m_samples.size() - 1) * step;
    for (int i = 0; i < m_samples.size(); ++i) {
        const double x = offset + i * step;
        const double y = plot.bottom()
            - (m_samples[i] / scale) * (plot.height() - 2);
        if (i == 0)
            path.moveTo(x, y);
        else
            path.lineTo(x, y);
    }

    QPainterPath filled = path;
    filled.lineTo(offset + (m_samples.size() - 1) * step, plot.bottom());
    filled.lineTo(offset, plot.bottom());
    filled.closeSubpath();

    QColor fill(0x3f, 0x7f, 0xd1);
    fill.setAlpha(70);
    painter.fillPath(filled, fill);
    painter.setPen(QPen(QColor(0x3f, 0x7f, 0xd1), 1.6));
    painter.drawPath(path);

    painter.setPen(pal.color(QPalette::Text));
    painter.drawText(QRectF(plot.left(), plot.bottom() + 2, plot.width(), 14),
                     Qt::AlignLeft | Qt::AlignVCenter,
                     tr("peak %1/s").arg(humanBytes(static_cast<quint64>(m_peak))));
    painter.drawText(QRectF(plot.left(), plot.bottom() + 2, plot.width(), 14),
                     Qt::AlignRight | Qt::AlignVCenter,
                     tr("now %1/s").arg(humanBytes(
                         static_cast<quint64>(current()))));
}

} // namespace etherape

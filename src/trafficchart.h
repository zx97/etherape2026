// SPDX-License-Identifier: GPL-2.0-or-later
//
// Throughput history: a small ring buffer rendered as a filled curve. One
// sample per second, five minutes of history.

#pragma once

#include <QVector>
#include <QWidget>

namespace etherape {

class TrafficChart : public QWidget
{
    Q_OBJECT

public:
    explicit TrafficChart(QWidget *parent = nullptr);

    void addSample(double bytesPerSecond);
    void clear();
    double peak() const { return m_peak; }
    double current() const;

protected:
    void paintEvent(QPaintEvent *event) override;

private:
    static constexpr int kCapacity = 300;  // 5 minutes at 1 Hz
    QVector<double> m_samples;
    double m_peak = 0.0;
};

} // namespace etherape

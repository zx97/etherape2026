// SPDX-License-Identifier: GPL-2.0-or-later
//
// libpcap capture worker. Runs in its own thread; supports live capture and
// offline replay. Batch emission keeps the GUI thread responsive.

#pragma once

#include "decoder.h"

#include <QList>
#include <QObject>
#include <QString>
#include <QStringList>

#include <atomic>

#include <pcap.h>

namespace etherape {

class CaptureWorker : public QObject
{
    Q_OBJECT

public:
    explicit CaptureWorker(QObject *parent = nullptr);
    ~CaptureWorker() override;

    // Thread-safe: may be called from any thread while run() is executing.
    void requestStop();

public slots:
    void openLive(const QString &device, const QString &filter, int mode);
    void openOffline(const QString &file, const QString &filter, int mode,
                     int speedPercent);
    void stop() { requestStop(); }

signals:
    void batchReady(const QList<etherape::PacketInfo> &batch);
    void errorOccurred(const QString &message);
    void captureStarted(const QString &source);
    void captureStopped();
    void counters(quint64 packets, quint64 bytes);

private:
    void run(pcap_t *handle, bool offline, int speedPercent);
    void flush();
    static pcap_t *openWithFilter(const QString &source, const QString &filter,
                                  bool live, QString *error);
    static void onPacket(u_char *user, const struct pcap_pkthdr *header,
                         const u_char *bytes);

    std::atomic<pcap_t *> m_handle{nullptr};
    Decoder m_decoder;
    QList<PacketInfo> m_batch;
    quint64 m_packets = 0;
    quint64 m_bytes = 0;
    qint64 m_firstTsUsec = -1;   ///< first packet timestamp of the replay
    qint64 m_lastTsUsec = -1;    ///< last packet timestamp seen
    std::atomic_bool m_stop{true};
};

// Enumerates capture interfaces without requiring privileges.
QStringList captureInterfaces();

} // namespace etherape

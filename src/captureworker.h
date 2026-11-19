// SPDX-License-Identifier: GPL-2.0-or-later
//
// libpcap capture worker. Runs in its own thread; supports live capture
// (direct, or through the pkexec helper on POSIX), offline replay and the pcap
// stream produced by the privileged helper.

#pragma once

#include "decoder.h"

#include <QByteArray>
#include <QList>
#include <QMutex>
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
    void openPrivileged(const QString &device, const QString &filter, int mode);
    void openOffline(const QString &file, const QString &filter, int mode,
                     int speedPercent);
    void stop() { requestStop(); }

signals:
    void batchReady(const QList<etherape::PacketInfo> &batch);
    void errorOccurred(const QString &message);
    void permissionDenied(const QString &device, const QString &message);
    void captureStarted(const QString &source);
    void captureStopped();
    void counters(quint64 packets, quint64 bytes);

private:
    pcap_t *openWithFilter(const QString &source, const QString &filter,
                           bool live, QString *error, int *activateRc);
    void run(pcap_t *handle, bool offline, int speedPercent);
    void readPcapStream(int outFd, int errFd);
    bool ensureHelper();
    bool sendCommand(unsigned type, const QByteArray &payload);
    bool waitForOpenStatus();
    void closeHelper();
    void flush();
    static void onPacket(u_char *user, const struct pcap_pkthdr *header,
                         const u_char *bytes);

    std::atomic<pcap_t *> m_handle{nullptr};
    std::atomic<qint64> m_childPid{-1};
    int m_ctlFd = -1;
    int m_dataFd = -1;
    QMutex m_ctlMutex;
    Decoder m_decoder;
    QList<PacketInfo> m_batch;
    quint64 m_packets = 0;
    quint64 m_bytes = 0;
    qint64 m_firstTsUsec = -1;
    qint64 m_lastTsUsec = -1;
    std::atomic_bool m_stop{true};
};

// Enumerates capture interfaces without requiring privileges.
QStringList captureInterfaces();

} // namespace etherape

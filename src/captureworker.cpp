// SPDX-License-Identifier: GPL-2.0-or-later

#include "captureworker.h"

#include <QElapsedTimer>
#include <QThread>

#include <poll.h>
#include <sys/time.h>

#include <algorithm>

namespace etherape {

namespace {
constexpr int kBatchSize = 512;
constexpr int kMaxSleepUsec = 20000;  // keeps requestStop() responsive
} // namespace

QStringList captureInterfaces()
{
    QStringList result;
    pcap_if_t *devices = nullptr;
    char errbuf[PCAP_ERRBUF_SIZE] = {0};

    if (pcap_findalldevs(&devices, errbuf) == -1)
        return result;

    for (pcap_if_t *dev = devices; dev; dev = dev->next) {
        if (!dev->name)
            continue;
        result.append(QString::fromLocal8Bit(dev->name));
    }
    pcap_freealldevs(devices);
    return result;
}

CaptureWorker::CaptureWorker(QObject *parent) : QObject(parent)
{
}

CaptureWorker::~CaptureWorker()
{
    requestStop();
}

void CaptureWorker::requestStop()
{
    m_stop.store(true, std::memory_order_relaxed);
    if (pcap_t *handle = m_handle.load(std::memory_order_relaxed))
        pcap_breakloop(handle);  // documented as safe from another thread
}

pcap_t *CaptureWorker::openWithFilter(const QString &source,
                                      const QString &filter, bool live,
                                      QString *error)
{
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    pcap_t *handle = nullptr;

    if (live) {
        handle = pcap_create(source.toLocal8Bit().constData(), errbuf);
        if (!handle) {
            *error = QString::fromLocal8Bit(errbuf);
            return nullptr;
        }
        pcap_set_snaplen(handle, 262144);
        pcap_set_promisc(handle, 1);
        pcap_set_timeout(handle, 100);
        const int rc = pcap_activate(handle);
        if (rc < 0) {
            *error = QString::fromLocal8Bit(pcap_geterr(handle));
            pcap_close(handle);
            return nullptr;
        }
    } else {
        handle = pcap_open_offline(source.toLocal8Bit().constData(), errbuf);
        if (!handle) {
            *error = QString::fromLocal8Bit(errbuf);
            return nullptr;
        }
    }

    if (!filter.isEmpty()) {
        struct bpf_program program;
        if (pcap_compile(handle, &program, filter.toLocal8Bit().constData(), 1,
                         PCAP_NETMASK_UNKNOWN) < 0) {
            *error = QString::fromLocal8Bit(pcap_geterr(handle));
            pcap_close(handle);
            return nullptr;
        }
        if (pcap_setfilter(handle, &program) < 0) {
            *error = QString::fromLocal8Bit(pcap_geterr(handle));
            pcap_freecode(&program);
            pcap_close(handle);
            return nullptr;
        }
        pcap_freecode(&program);
    }

    return handle;
}

void CaptureWorker::onPacket(u_char *user, const struct pcap_pkthdr *header,
                             const u_char *bytes)
{
    auto *self = reinterpret_cast<CaptureWorker *>(user);
    const qint64 tsUsec =
        static_cast<qint64>(header->ts.tv_sec) * 1000000 + header->ts.tv_usec;

    self->m_batch.append(
        self->m_decoder.decode(bytes, header->caplen, header->len, tsUsec));
    self->m_packets += 1;
    self->m_bytes += header->len;
    if (self->m_firstTsUsec < 0)
        self->m_firstTsUsec = tsUsec;
    self->m_lastTsUsec = tsUsec;

    if (self->m_batch.size() >= kBatchSize)
        self->flush();
}

void CaptureWorker::flush()
{
    if (m_batch.isEmpty())
        return;
    emit batchReady(m_batch);
    m_batch.clear();
}

void CaptureWorker::openLive(const QString &device, const QString &filter,
                             int mode)
{
    m_stop.store(false, std::memory_order_relaxed);
    m_decoder.setMode(static_cast<Mode>(mode));

    QString error;
    pcap_t *handle = openWithFilter(device, filter, true, &error);
    if (!handle) {
        emit errorOccurred(error);
        emit captureStopped();
        return;
    }

    m_packets = 0;
    m_bytes = 0;
    emit captureStarted(device);
    run(handle, false, 100);
}

void CaptureWorker::openOffline(const QString &file, const QString &filter,
                               int mode, int speedPercent)
{
    m_stop.store(false, std::memory_order_relaxed);
    m_decoder.setMode(static_cast<Mode>(mode));

    QString error;
    pcap_t *handle = openWithFilter(file, filter, false, &error);
    if (!handle) {
        emit errorOccurred(error);
        emit captureStopped();
        return;
    }

    m_packets = 0;
    m_bytes = 0;
    emit captureStarted(file);
    run(handle, true, speedPercent);
}

void CaptureWorker::run(pcap_t *handle, bool offline, int speedPercent)
{
    m_handle.store(handle, std::memory_order_relaxed);

    // Non-blocking mode lets us poll, so requestStop() is honoured promptly
    // even on a silent interface.
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    pcap_setnonblock(handle, 1, errbuf);

    m_firstTsUsec = -1;
    m_lastTsUsec = -1;

    const int fd = pcap_get_selectable_fd(handle);
    QElapsedTimer wall;
    wall.start();
    int batches = 0;

    while (!m_stop.load(std::memory_order_relaxed)) {
        if (fd >= 0 && !offline) {
            struct pollfd pfd = {fd, POLLIN, 0};
            ::poll(&pfd, 1, 100);
        }

        const int rc = pcap_dispatch(handle, 64, &CaptureWorker::onPacket,
                                     reinterpret_cast<u_char *>(this));
        flush();

        if (rc == -2)  // EOF on a savefile
            break;
        if (rc == -1) {
            emit errorOccurred(QString::fromLocal8Bit(pcap_geterr(handle)));
            break;
        }

        if (rc == 0 && !offline)
            continue;

        ++batches;
        if (batches % 16 == 0)
            emit counters(m_packets, m_bytes);

        if (offline) {
            if (speedPercent > 0 && m_firstTsUsec >= 0
                && m_lastTsUsec > m_firstTsUsec) {
                // Replay at the recorded pace, scaled by the requested speed.
                const qint64 mediaUsec =
                    (m_lastTsUsec - m_firstTsUsec) * 100 / speedPercent;
                const qint64 sleepUsec = std::clamp<qint64>(
                    mediaUsec - wall.nsecsElapsed() / 1000, 0, kMaxSleepUsec);
                if (sleepUsec > 0)
                    QThread::usleep(static_cast<unsigned long>(sleepUsec));
            } else if (speedPercent <= 0 && batches % 32 == 0) {
                QThread::usleep(1000);  // unbounded speed: yield to the GUI
            }
        }
    }

    flush();
    emit counters(m_packets, m_bytes);

    m_handle.store(nullptr, std::memory_order_relaxed);
    pcap_close(handle);
    emit captureStopped();
}

} // namespace etherape

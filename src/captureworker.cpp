// SPDX-License-Identifier: GPL-2.0-or-later

#include "captureworker.h"

#include <QCoreApplication>
#include <QElapsedTimer>
#include <QThread>

#include <algorithm>
#include <cerrno>
#include <cstring>

#ifndef Q_OS_WIN
#include <poll.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace etherape {

namespace {
constexpr int kBatchSize = 512;
constexpr int kMaxSleepUsec = 20000;
constexpr quint32 kMaxCaplen = 64u * 1024u * 1024u;

inline quint32 readU32(const uchar *p, bool swapped)
{
    const quint32 value = static_cast<quint32>(p[0])
        | (static_cast<quint32>(p[1]) << 8) | (static_cast<quint32>(p[2]) << 16)
        | (static_cast<quint32>(p[3]) << 24);
    if (!swapped)
        return value;
    return (value >> 24) | ((value >> 8) & 0x0000ff00u)
        | ((value << 8) & 0x00ff0000u) | (value << 24);
}
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

#ifndef Q_OS_WIN
    const qint64 pid = m_childPid.load(std::memory_order_relaxed);
    if (pid > 0) {
        // The child created its own process group (see openPrivileged), so a
        // negative pid terminates pkexec and the helper together.
        ::kill(-static_cast<pid_t>(pid), SIGTERM);
    }
#endif
}

pcap_t *CaptureWorker::openWithFilter(const QString &source,
                                      const QString &filter, bool live,
                                      QString *error, int *activateRc)
{
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    pcap_t *handle = nullptr;
    *activateRc = 0;

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
        *activateRc = rc;
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

    m_decoder.setLinkType(pcap_datalink(handle));

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
    int activateRc = 0;
    pcap_t *handle = openWithFilter(device, filter, true, &error, &activateRc);
    if (!handle) {
        if (activateRc == PCAP_ERROR_PERM_DENIED
            || error.contains(QLatin1String("permission"), Qt::CaseInsensitive)
            || error.contains(QLatin1String("not permitted"),
                              Qt::CaseInsensitive)
            || error.contains(QLatin1String("Access is denied"),
                              Qt::CaseInsensitive)) {
            emit permissionDenied(device, error);
        } else {
            emit errorOccurred(error);
        }
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
    int activateRc = 0;
    pcap_t *handle = openWithFilter(file, filter, false, &error, &activateRc);
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

void CaptureWorker::openPrivileged(const QString &device,
                                   const QString &filter, int mode)
{
#ifdef Q_OS_WIN
    // Windows has no pkexec; the GUI relaunches itself elevated through UAC
    // (see MainWindow::onPermissionDenied). Just capture directly here.
    openLive(device, filter, mode);
#else
    m_stop.store(false, std::memory_order_relaxed);
    m_decoder.setMode(static_cast<Mode>(mode));

    int outPipe[2] = {-1, -1};
    int errPipe[2] = {-1, -1};
    if (::pipe(outPipe) != 0 || ::pipe(errPipe) != 0) {
        emit errorOccurred(QString::fromLocal8Bit(std::strerror(errno)));
        emit captureStopped();
        return;
    }

    const QByteArray exe =
        QCoreApplication::applicationFilePath().toLocal8Bit();
    const QByteArray dev = device.toLocal8Bit();
    const QByteArray flt = filter.toLocal8Bit();

    const pid_t pid = ::fork();
    if (pid < 0) {
        emit errorOccurred(QString::fromLocal8Bit(std::strerror(errno)));
        ::close(outPipe[0]);
        ::close(outPipe[1]);
        ::close(errPipe[0]);
        ::close(errPipe[1]);
        emit captureStopped();
        return;
    }

    if (pid == 0) {
        ::setpgid(0, 0);
        ::dup2(outPipe[1], STDOUT_FILENO);
        ::dup2(errPipe[1], STDERR_FILENO);
        ::close(outPipe[0]);
        ::close(outPipe[1]);
        ::close(errPipe[0]);
        ::close(errPipe[1]);
        ::execlp("pkexec", "pkexec", exe.constData(), "--capture-helper", "-i",
                 dev.constData(), "-f", flt.constData(),
                 static_cast<char *>(nullptr));
        _exit(127);
    }

    ::close(outPipe[1]);
    ::close(errPipe[1]);
    m_childPid.store(pid, std::memory_order_relaxed);

    m_packets = 0;
    m_bytes = 0;
    emit captureStarted(device);

    readPcapStream(outPipe[0], errPipe[0]);
    ::close(outPipe[0]);
    ::close(errPipe[0]);

    int status = 0;
    ::waitpid(pid, &status, 0);
    m_childPid.store(-1, std::memory_order_relaxed);

    if (!m_stop.load(std::memory_order_relaxed) && WIFEXITED(status)
        && WEXITSTATUS(status) != 0) {
        emit errorOccurred(tr("Privileged capture helper exited with code %1.")
                               .arg(WEXITSTATUS(status)));
    }

    flush();
    emit counters(m_packets, m_bytes);
    emit captureStopped();
#endif
}

void CaptureWorker::readPcapStream(int outFd, int errFd)
{
#ifdef Q_OS_WIN
    Q_UNUSED(outFd);
    Q_UNUSED(errFd);
#else
    QByteArray buffer;
    QByteArray errors;
    bool headerDone = false;
    bool swapped = false;

    for (;;) {
        if (m_stop.load(std::memory_order_relaxed))
            break;

        struct pollfd fds[2] = {{outFd, POLLIN, 0}, {errFd, POLLIN, 0}};
        const int polled = ::poll(fds, 2, 200);
        if (polled < 0) {
            if (errno == EINTR)
                continue;
            break;
        }

        if (fds[1].revents & (POLLIN | POLLHUP)) {
            char tmp[512];
            const ssize_t n = ::read(errFd, tmp, sizeof(tmp));
            if (n > 0)
                errors.append(tmp, static_cast<int>(n));
        }

        if (fds[0].revents & (POLLIN | POLLHUP)) {
            char tmp[65536];
            const ssize_t n = ::read(outFd, tmp, sizeof(tmp));
            if (n > 0) {
                buffer.append(tmp, static_cast<int>(n));
            } else if (n == 0) {
                break;  // helper closed its output
            } else if (errno != EINTR && errno != EAGAIN) {
                break;
            }
        }

        if (!headerDone && buffer.size() >= 24) {
            const auto *header =
                reinterpret_cast<const uchar *>(buffer.constData());
            const quint32 magic = readU32(header, false);
            switch (magic) {
            case 0xa1b2c3d4:
                swapped = false;
                break;
            case 0xd4c3b2a4:
                swapped = true;
                break;
            case 0xa1b23c4d:  // nanosecond timestamps
            case 0x4d3cb2a1:
                swapped = (magic == 0x4d3cb2a1);
                break;
            default:
                emit errorOccurred(
                    tr("Privileged helper sent an invalid pcap stream."));
                return;
            }
            const quint32 linkType = readU32(header + 20, swapped);
            m_decoder.setLinkType(static_cast<int>(linkType));
            headerDone = true;
            buffer.remove(0, 24);
        }

        while (headerDone && buffer.size() >= 16) {
            const auto *record =
                reinterpret_cast<const uchar *>(buffer.constData());
            const quint32 tsSec = readU32(record, swapped);
            const quint32 tsUsec = readU32(record + 4, swapped);
            const quint32 caplen = readU32(record + 8, swapped);
            const quint32 origlen = readU32(record + 12, swapped);
            if (caplen > kMaxCaplen) {
                emit errorOccurred(
                    tr("Privileged helper sent a corrupt packet record."));
                return;
            }
            if (static_cast<quint32>(buffer.size()) < 16 + caplen)
                break;

            const qint64 tsUsecTotal =
                static_cast<qint64>(tsSec) * 1000000 + tsUsec;
            m_batch.append(m_decoder.decode(record + 16, caplen, origlen,
                                            tsUsecTotal));
            m_packets += 1;
            m_bytes += origlen;
            buffer.remove(0, static_cast<int>(16 + caplen));

            if (m_batch.size() >= kBatchSize)
                flush();
        }
    }

    if (!headerDone && !errors.isEmpty() && !m_stop.load())
        emit errorOccurred(QString::fromLocal8Bit(errors).trimmed());
#endif
}

void CaptureWorker::run(pcap_t *handle, bool offline, int speedPercent)
{
    m_handle.store(handle, std::memory_order_relaxed);
    m_firstTsUsec = -1;
    m_lastTsUsec = -1;

    QElapsedTimer wall;
    wall.start();
    int batches = 0;
    bool first = true;

    while (!m_stop.load(std::memory_order_relaxed)) {
        struct pcap_pkthdr *header = nullptr;
        const u_char *data = nullptr;
        const int rc = pcap_next_ex(handle, &header, &data);

        if (rc == 0) {
            // Live capture read timeout: nothing to do.
            continue;
        }
        if (rc == -2) {
            // EOF on a savefile, or breakloop on a live handle.
            if (offline)
                break;
            continue;
        }
        if (rc == -1) {
            emit errorOccurred(QString::fromLocal8Bit(pcap_geterr(handle)));
            break;
        }

        if (first) {
            first = false;
            m_firstTsUsec = static_cast<qint64>(header->ts.tv_sec) * 1000000
                + header->ts.tv_usec;
        }
        onPacket(reinterpret_cast<u_char *>(this), header, data);
        flush();

        ++batches;
        if (batches % 16 == 0)
            emit counters(m_packets, m_bytes);

        if (offline) {
            if (speedPercent > 0 && m_firstTsUsec >= 0
                && m_lastTsUsec > m_firstTsUsec) {
                const qint64 mediaUsec =
                    (m_lastTsUsec - m_firstTsUsec) * 100 / speedPercent;
                const qint64 sleepUsec = std::clamp<qint64>(
                    mediaUsec - wall.nsecsElapsed() / 1000, 0, kMaxSleepUsec);
                if (sleepUsec > 0)
                    QThread::usleep(static_cast<unsigned long>(sleepUsec));
            } else if (speedPercent <= 0 && batches % 64 == 0) {
                QThread::usleep(500);  // unbounded speed: yield to the GUI
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

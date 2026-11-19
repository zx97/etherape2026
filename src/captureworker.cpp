// SPDX-License-Identifier: GPL-2.0-or-later

#include "captureworker.h"

#include "capturehelper.h"

#include <QCoreApplication>
#include <QElapsedTimer>
#include <QThread>

#include <algorithm>
#include <cerrno>
#include <cstring>

#ifndef Q_OS_WIN
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>
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
    closeHelper();
}

void CaptureWorker::requestStop()
{
    m_stop.store(true, std::memory_order_relaxed);
    if (pcap_t *handle = m_handle.load(std::memory_order_relaxed))
        pcap_breakloop(handle);  // documented as safe from another thread

#ifndef Q_OS_WIN
    // Ask the persistent helper to stop the current session. The helper runs
    // as root: signals from this unprivileged process would be rejected.
    sendCommand(kHelperCmdStop, QByteArray());
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

bool CaptureWorker::ensureHelper()
{
#ifdef Q_OS_WIN
    return false;
#else
    const qint64 existing = m_childPid.load(std::memory_order_relaxed);
    if (existing > 0) {
        int status = 0;
        if (::waitpid(static_cast<pid_t>(existing), &status, WNOHANG) == 0)
            return true;  // helper still alive: reuse the authenticated session
        // Helper died (killed, session ended): forget it and start over.
        m_childPid.store(-1, std::memory_order_relaxed);
        QMutexLocker lock(&m_ctlMutex);
        if (m_ctlFd >= 0) {
            ::close(m_ctlFd);
            m_ctlFd = -1;
        }
        if (m_dataFd >= 0) {
            ::close(m_dataFd);
            m_dataFd = -1;
        }
    }

    int ctl[2] = {-1, -1};
    int data[2] = {-1, -1};
    if (::socketpair(AF_UNIX, SOCK_STREAM, 0, ctl) != 0)
        return false;
    if (::pipe(data) != 0) {
        ::close(ctl[0]);
        ::close(ctl[1]);
        return false;
    }

    const QByteArray exe =
        QCoreApplication::applicationFilePath().toLocal8Bit();
    const pid_t pid = ::fork();
    if (pid == 0) {
        ::setpgid(0, 0);
        ::close(ctl[0]);
        ::close(data[0]);
        char ctlArg[32];
        char dataArg[32];
        std::snprintf(ctlArg, sizeof(ctlArg), "--ctl-fd=%d", ctl[1]);
        std::snprintf(dataArg, sizeof(dataArg), "--data-fd=%d", data[1]);
        ::execlp("pkexec", "pkexec", exe.constData(), "--capture-helper",
                 ctlArg, dataArg, static_cast<char *>(nullptr));
        _exit(127);
    }

    ::close(ctl[1]);
    ::close(data[1]);
    if (pid < 0) {
        ::close(ctl[0]);
        ::close(data[0]);
        return false;
    }

    m_ctlFd = ctl[0];
    m_dataFd = data[0];
    m_childPid.store(pid, std::memory_order_relaxed);
    return true;
#endif
}

bool CaptureWorker::sendCommand(unsigned type, const QByteArray &payload)
{
#ifndef Q_OS_WIN
    QMutexLocker lock(&m_ctlMutex);
    if (m_ctlFd < 0)
        return false;

    HelperCommand command{type, static_cast<unsigned>(payload.size())};
    auto writeAll = [](int fd, const char *data, size_t length) {
        size_t done = 0;
        while (done < length) {
            const ssize_t n = ::write(fd, data + done, length - done);
            if (n > 0)
                done += static_cast<size_t>(n);
            else if (n < 0 && errno == EINTR)
                continue;
            else
                return false;
        }
        return true;
    };

    if (!writeAll(m_ctlFd, reinterpret_cast<const char *>(&command),
                  sizeof(command)))
        return false;
    if (!payload.isEmpty()
        && !writeAll(m_ctlFd, payload.constData(),
                     static_cast<size_t>(payload.size())))
        return false;
    return true;
#else
    Q_UNUSED(type);
    Q_UNUSED(payload);
    return false;
#endif
}

bool CaptureWorker::waitForOpenStatus()
{
#ifndef Q_OS_WIN
    // The very first OPEN blocks until pkexec has authenticated the user, so
    // poll in a loop and stay responsive to Stop.
    for (;;) {
        if (m_stop.load(std::memory_order_relaxed))
            return false;

        struct pollfd pfd = {m_ctlFd, POLLIN, 0};
        const int polled = ::poll(&pfd, 1, 200);
        if (polled < 0) {
            if (errno == EINTR)
                continue;
            return false;
        }
        if (polled == 0)
            continue;
        if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL))
            return false;
        if (pfd.revents & POLLIN) {
            unsigned char status = 1;
            if (::read(m_ctlFd, &status, 1) != 1)
                return false;
            return status == 0;
        }
    }
#else
    return false;
#endif
}

void CaptureWorker::closeHelper()
{
#ifndef Q_OS_WIN
    if (m_childPid.load(std::memory_order_relaxed) <= 0)
        return;
    sendCommand(kHelperCmdQuit, QByteArray());
    QMutexLocker lock(&m_ctlMutex);
    if (m_ctlFd >= 0) {
        ::close(m_ctlFd);
        m_ctlFd = -1;
    }
    if (m_dataFd >= 0) {
        ::close(m_dataFd);
        m_dataFd = -1;
    }
#endif
}

void CaptureWorker::openPrivileged(const QString &device,
                                   const QString &filter, int mode)
{
#ifdef Q_OS_WIN
    // Windows has no pkexec; the GUI relaunches itself elevated through UAC.
    openLive(device, filter, mode);
#else
    m_stop.store(false, std::memory_order_relaxed);
    m_decoder.setMode(static_cast<Mode>(mode));

    if (!ensureHelper()) {
        emit errorOccurred(tr("Cannot start the privileged capture helper."));
        emit captureStopped();
        return;
    }

    // Discard whatever the previous session may have left in the pipe so the
    // new pcap stream starts on a clean header.
    char drain[8192];
    while (::read(m_dataFd, drain, sizeof(drain)) > 0) {
    }

    QByteArray payload;
    payload.append(device.toLocal8Bit());
    payload.append('\0');
    payload.append(filter.toLocal8Bit());
    payload.append('\0');

    if (!sendCommand(kHelperCmdOpen, payload)) {
        emit errorOccurred(tr("Cannot talk to the privileged capture helper."));
        emit captureStopped();
        return;
    }

    if (!waitForOpenStatus()) {
        emit errorOccurred(
            m_stop.load() ? tr("Capture cancelled.")
                          : tr("The privileged helper could not open the "
                               "capture (denied or cancelled)."));
        emit captureStopped();
        return;
    }

    m_packets = 0;
    m_bytes = 0;
    emit captureStarted(device);
    readPcapStream(m_dataFd, -1);
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
                qint64 remaining = std::clamp<qint64>(
                    mediaUsec - wall.nsecsElapsed() / 1000, 0, 10000000);
                while (remaining > 0
                       && !m_stop.load(std::memory_order_relaxed)) {
                    const qint64 chunk =
                        std::min<qint64>(remaining, kMaxSleepUsec);
                    QThread::usleep(static_cast<unsigned long>(chunk));
                    remaining -= chunk;
                }
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

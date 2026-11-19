// SPDX-License-Identifier: GPL-2.0-or-later

#include "captureworker.h"

#include "capturehelper.h"

#include <QCoreApplication>
#include <QElapsedTimer>
#include <QFile>
#include <QStandardPaths>
#include <QThread>

#include <algorithm>
#include <cerrno>
#include <cstring>

#ifndef Q_OS_WIN
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
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
        const pid_t reaped = ::waitpid(static_cast<pid_t>(existing), &status, WNOHANG);
        if (qEnvironmentVariableIsSet("ETHERAPE_DEBUG"))
            std::fprintf(stderr, "[etherape] ensureHelper existing=%lld reap=%d errno=%d\n",
                         static_cast<long long>(existing), int(reaped), errno);
        if (reaped == 0)
            return true;  // helper still alive: reuse the authenticated session
        // Helper died (killed, session ended): forget it and start over.
        m_childPid.store(-1, std::memory_order_relaxed);
        if (qEnvironmentVariableIsSet("ETHERAPE_DEBUG"))
            std::fprintf(stderr, "[etherape] helper died, respawning\n");
        QMutexLocker lock(&m_ctlMutex);
        if (m_dataFd >= 0)
            ::close(m_dataFd);
        if (m_ctlFd >= 0 && m_ctlFd != m_dataFd)
            ::close(m_ctlFd);
        m_ctlFd = -1;
        m_dataFd = -1;
    }

    // fd 0 and 1 are the only descriptors a setuid program (pkexec) is
    // guaranteed to preserve, so commands go to stdin and data comes back on
    // stdout.
    m_helperLogPath = QStringLiteral("/dev/shm/etherape2026-helper-%1.log")
                          .arg(QCoreApplication::applicationPid());
    const int logFd = ::open(m_helperLogPath.toLocal8Bit().constData(),
                             O_CREAT | O_WRONLY | O_TRUNC, 0600);

    ::signal(SIGPIPE, SIG_IGN);

    // A named UNIX socket, because a setuid pkexec may close every inherited
    // descriptor and even redirect stdin. The path is passed as an argument.
    QString runtimeDir =
        QStandardPaths::writableLocation(QStandardPaths::RuntimeLocation);
    if (runtimeDir.isEmpty())
        runtimeDir = QStringLiteral("/dev/shm");
    const QString socketPath =
        QStringLiteral("%1/etherape2026-%2.sock")
            .arg(runtimeDir)
            .arg(QCoreApplication::applicationPid());
    const QByteArray socketPathBytes = socketPath.toLocal8Bit();
    ::unlink(socketPathBytes.constData());

    const int server = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (server < 0) {
        if (logFd >= 0)
            ::close(logFd);
        return false;
    }
    struct sockaddr_un address = {};
    address.sun_family = AF_UNIX;
    std::snprintf(address.sun_path, sizeof(address.sun_path), "%s",
                  socketPathBytes.constData());
    if (::bind(server,
               reinterpret_cast<struct sockaddr *>(&address),
               sizeof(address)) != 0
        || ::chmod(socketPathBytes.constData(), 0600) != 0
        || ::listen(server, 1) != 0) {
        ::close(server);
        if (logFd >= 0)
            ::close(logFd);
        return false;
    }

    const QByteArray exe =
        QCoreApplication::applicationFilePath().toLocal8Bit();
    const bool debug = qEnvironmentVariableIsSet("ETHERAPE_DEBUG");
    const bool direct = qEnvironmentVariableIsSet("ETHERAPE_HELPER_DIRECT");
    const pid_t pid = ::fork();
    if (pid == 0) {
        ::setpgid(0, 0);
        if (logFd >= 0)
            ::dup2(logFd, STDERR_FILENO);
        if (debug)  // read before fork(): getenv is not async-signal-safe
            ::write(STDERR_FILENO, "[etherape] child: exec now\n", 28);
        if (direct) {
            if (debug)
                ::execl(exe.constData(), exe.constData(), "--capture-helper",
                        "--socket", socketPathBytes.constData(), "--debug",
                        static_cast<char *>(nullptr));
            else
                ::execl(exe.constData(), exe.constData(), "--capture-helper",
                        "--socket", socketPathBytes.constData(),
                        static_cast<char *>(nullptr));
        } else {
            if (debug)
                ::execlp("pkexec", "pkexec", exe.constData(),
                         "--capture-helper", "--socket",
                         socketPathBytes.constData(), "--debug",
                         static_cast<char *>(nullptr));
            else
                ::execlp("pkexec", "pkexec", exe.constData(),
                         "--capture-helper", "--socket",
                         socketPathBytes.constData(),
                         static_cast<char *>(nullptr));
        }
        const char failure[] = "[etherape] child: exec failed\n";
        ::write(STDERR_FILENO, failure, sizeof(failure) - 1);
        _exit(127);
    }

    if (logFd >= 0)
        ::close(logFd);
    if (pid < 0) {
        ::close(server);
        ::unlink(socketPathBytes.constData());
        return false;
    }

    // Wait for the helper to connect; this is where pkexec asks the password,
    // so poll in a loop and stay interruptible.
    int client = -1;
    for (;;) {
        if (m_stop.load(std::memory_order_relaxed))
            break;
        struct pollfd pfd = {server, POLLIN, 0};
        const int polled = ::poll(&pfd, 1, 200);
        if (polled < 0 && errno != EINTR)
            break;
        if (polled > 0 && (pfd.revents & POLLIN)) {
            client = ::accept(server, nullptr, nullptr);
            break;
        }
    }
    ::close(server);
    ::unlink(socketPathBytes.constData());

    if (client < 0) {
        // Authentication refused or cancelled: reap the child so it does not
        // linger as a zombie.
        ::kill(pid, SIGTERM);
        int status = 0;
        ::waitpid(pid, &status, WNOHANG);
        if (debug)
            std::fprintf(stderr, "[etherape] helper never connected\n");
        return false;
    }

    // Remember the helper: this is what makes the next Start skip pkexec.
    m_childPid.store(pid, std::memory_order_relaxed);
    m_ctlFd = client;    // full-duplex: commands out, status + pcap in
    m_dataFd = client;
    if (debug)
        std::fprintf(stderr, "[etherape] helper connected fd=%d%s\n",
                     client, direct ? " (direct)" : " (pkexec)");
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

bool CaptureWorker::waitForOpenStatus(QString *detail)
{
#ifndef Q_OS_WIN
    const bool debug = qEnvironmentVariableIsSet("ETHERAPE_DEBUG");
    // The very first OPEN blocks until pkexec has authenticated the user, so
    // poll in a loop and stay responsive to Stop. Bound the wait so a silent
    // helper can never freeze the worker (and the Start button) forever.
    QElapsedTimer deadline;
    deadline.start();
    for (;;) {
        if (deadline.elapsed() > 120000) {
            if (debug)
                std::fprintf(stderr, "[etherape] OPEN timed out\n");
            return false;
        }
        if (m_stop.load(std::memory_order_relaxed))
            return false;

        struct pollfd pfd = {m_dataFd, POLLIN, 0};
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
            if (::read(m_dataFd, &status, 1) != 1) {
                if (debug)
                    std::fprintf(stderr, "[etherape] OPEN read failed\n");
                return false;
            }
            if (debug)
                std::fprintf(stderr, "[etherape] OPEN status=%u\n",
                             unsigned(status));
            if (status == 0)
                return true;
            if (status != 1) {
                // The stream started before the status byte (older helper):
                // keep the byte and let the pcap parser see it first.
                m_streamPrefix = status;
                if (debug)
                    std::fprintf(stderr,
                                 "[etherape] OPEN status missing, byte=0x%02x\n",
                                 unsigned(status));
                return true;
            }

            // Status 1 is followed by a length and the helper's error text.
            unsigned length = 0;
            if (::read(m_dataFd, &length, sizeof(length)) == sizeof(length)
                && length > 0 && length < 65536) {
                QByteArray message(static_cast<int>(length), '\0');
                size_t done = 0;
                while (done < length) {
                    const ssize_t n = ::read(m_dataFd,
                                            message.data() + done,
                                            length - done);
                    if (n <= 0)
                        break;
                    done += static_cast<size_t>(n);
                }
                if (detail)
                    *detail = QString::fromLocal8Bit(message.constData(),
                                                     static_cast<int>(done));
                if (debug)
                    std::fprintf(stderr, "[etherape] helper error: %s\n",
                                 message.constData());
            }
            return false;
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
    // Commands and data share the same socket: close it exactly once, or the
    // second close() hits a descriptor Qt may have reused in between.
    if (m_dataFd >= 0)
        ::close(m_dataFd);
    if (m_ctlFd >= 0 && m_ctlFd != m_dataFd)
        ::close(m_ctlFd);
    m_ctlFd = -1;
    m_dataFd = -1;
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
    // new pcap stream starts on a clean header. The pipe is blocking: a plain
    // read() with no data would freeze the worker before sending OPEN.
    const int flags = ::fcntl(m_dataFd, F_GETFL, 0);
    ::fcntl(m_dataFd, F_SETFL, flags | O_NONBLOCK);
    char drain[8192];
    while (::read(m_dataFd, drain, sizeof(drain)) > 0) {
    }
    ::fcntl(m_dataFd, F_SETFL, flags);

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

    QString detail;
    if (!waitForOpenStatus(&detail)) {
        if (m_stop.load(std::memory_order_relaxed)) {
            emit errorOccurred(tr("Capture cancelled."));
        } else if (!detail.isEmpty()) {
            emit errorOccurred(tr("The privileged helper could not open the "
                                  "capture: %1")
                                   .arg(detail));
        } else {
            // No structured answer: pkexec itself probably refused or the
            // helper died. Include its stderr log when available.
            QString extra;
            if (!m_helperLogPath.isEmpty()) {
                QFile log(m_helperLogPath);
                if (log.open(QIODevice::ReadOnly)) {
                    extra = QString::fromLocal8Bit(log.readAll()).trimmed();
                }
            }
            emit errorOccurred(
                extra.isEmpty()
                    ? tr("The privileged helper did not answer (pkexec refused "
                         "or the helper exited).")
                    : tr("The privileged helper did not answer: %1").arg(extra));
        }
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

    if (m_streamPrefix >= 0) {
        buffer.append(static_cast<char>(m_streamPrefix));
        m_streamPrefix = -1;
    }

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

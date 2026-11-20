// SPDX-License-Identifier: GPL-2.0-or-later

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <iphlpapi.h>
#endif

#include "captureworker.h"

#include <QCoreApplication>
#include <QDateTime>
#include <QDir>
#include <QElapsedTimer>
#include <QFile>
#include <QFileInfo>
#include <QHash>
#include <QThread>

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>

#ifndef Q_OS_WIN
#include <fcntl.h>
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

#ifdef _WIN32
namespace {

// Maps "{GUID}" to the friendly connection name Windows shows
// ("Ethernet 2", "Wi-Fi"...).
QHash<QString, QString> friendlyAdapterNames()
{
    QHash<QString, QString> names;
    ULONG size = 0;
    if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, nullptr,
                             nullptr, &size)
        != ERROR_BUFFER_OVERFLOW) {
        return names;
    }
    QByteArray buffer(static_cast<int>(size), '\0');
    auto *addresses = reinterpret_cast<IP_ADAPTER_ADDRESSES *>(buffer.data());
    if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, nullptr,
                             addresses, &size)
        != NO_ERROR) {
        return names;
    }
    for (auto *entry = addresses; entry; entry = entry->Next) {
        // AdapterName is char* on MinGW and wchar_t* on MSVC.
        const QString guid = QString::fromLocal8Bit(entry->AdapterName);
        const QString friendly = QString::fromWCharArray(entry->FriendlyName);
        if (!guid.isEmpty() && !friendly.isEmpty())
            names.insert(guid.toUpper(), friendly);
    }
    return names;
}

QString guidFromNpfDevice(const QString &device)
{
    const int marker = device.indexOf(QLatin1String("NPF_"));
    return marker >= 0 ? device.mid(marker + 4).toUpper() : QString();
}

} // namespace
#endif

QList<CaptureInterface> captureInterfaces()
{
    QList<CaptureInterface> result;
    pcap_if_t *devices = nullptr;
    char errbuf[PCAP_ERRBUF_SIZE] = {0};

    if (pcap_findalldevs(&devices, errbuf) == -1)
        return result;

#ifdef _WIN32
    const QHash<QString, QString> friendly = friendlyAdapterNames();
#endif

    for (pcap_if_t *dev = devices; dev; dev = dev->next) {
        if (!dev->name)
            continue;
        CaptureInterface entry;
        entry.device = QString::fromLocal8Bit(dev->name);
        entry.display = entry.device;
        entry.description = dev->description
            ? QString::fromLocal8Bit(dev->description)
            : QString();
#ifdef _WIN32
        const QString friendlyName =
            friendly.value(guidFromNpfDevice(entry.device));
        if (!friendlyName.isEmpty())
            entry.display = friendlyName;
        else if (!entry.description.isEmpty())
            entry.display = entry.description;
#endif
        result.append(entry);
    }
    pcap_freealldevs(devices);
    return result;
}

CaptureWorker::CaptureWorker(QObject *parent) : QObject(parent)
{
    pruneHelperLogs();
}

CaptureWorker::~CaptureWorker()
{
    requestStop();
#ifndef Q_OS_WIN
    if (!m_helperLogPath.isEmpty())
        QFile::remove(m_helperLogPath);
#endif
}

// Removes helper logs left behind by previous runs (older than a day).
void CaptureWorker::pruneHelperLogs()
{
#ifndef Q_OS_WIN
    QDir dir(QStringLiteral("/dev/shm"));
    const QDateTime cutoff = QDateTime::currentDateTime().addDays(-1);
    const QStringList stale = dir.entryList(
        {QStringLiteral("etherape2026-helper-*.log")}, QDir::Files);
    for (const QString &name : stale) {
        const QFileInfo info(dir.filePath(name));
        if (info.lastModified() < cutoff)
            QFile::remove(info.filePath());
    }
#endif
}

void CaptureWorker::requestStop()
{
    m_stop.store(true, std::memory_order_relaxed);
    if (pcap_t *handle = m_handle.load(std::memory_order_relaxed))
        pcap_breakloop(handle);  // documented as safe from another thread
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

// One pkexec per capture: interface and filter in argv, pcap stream on
// stdout. See docs/PORTING.md for why the persistent helper was dropped.
void CaptureWorker::openPrivileged(const QString &device,
                                   const QString &filter, int mode)
{
#ifdef Q_OS_WIN
    // Windows has no pkexec; the GUI relaunches itself elevated through UAC.
    openLive(device, filter, mode);
#else
    m_stop.store(false, std::memory_order_relaxed);
    m_decoder.setMode(static_cast<Mode>(mode));

    int data[2] = {-1, -1};
    if (::pipe(data) != 0) {
        emit errorOccurred(QString::fromLocal8Bit(std::strerror(errno)));
        emit captureStopped();
        return;
    }

    m_helperLogPath =
        QStringLiteral("/dev/shm/etherape2026-helper-%1.log")
            .arg(QCoreApplication::applicationPid());
    const int logFd = ::open(m_helperLogPath.toLocal8Bit().constData(),
                             O_CREAT | O_WRONLY | O_TRUNC, 0600);

    const QByteArray exe =
        QCoreApplication::applicationFilePath().toLocal8Bit();
    const QByteArray dev = device.toLocal8Bit();
    const QByteArray flt = filter.toLocal8Bit();
    const bool debug = qEnvironmentVariableIsSet("ETHERAPE_DEBUG");
    const bool direct = qEnvironmentVariableIsSet("ETHERAPE_HELPER_DIRECT");

    const pid_t pid = ::fork();
    if (pid == 0) {
        ::setpgid(0, 0);
        ::dup2(data[1], STDOUT_FILENO);
        if (logFd >= 0)
            ::dup2(logFd, STDERR_FILENO);
        ::close(data[0]);
        ::close(data[1]);
        if (logFd >= 0)
            ::close(logFd);
        if (direct) {
            if (debug)
                ::execl(exe.constData(), exe.constData(), "--capture-helper",
                        "-i", dev.constData(), "-f", flt.constData(),
                        "--debug", static_cast<char *>(nullptr));
            else
                ::execl(exe.constData(), exe.constData(), "--capture-helper",
                        "-i", dev.constData(), "-f", flt.constData(),
                        static_cast<char *>(nullptr));
        } else {
            if (debug)
                ::execlp("pkexec", "pkexec", exe.constData(),
                         "--capture-helper", "-i", dev.constData(), "-f",
                         flt.constData(), "--debug",
                         static_cast<char *>(nullptr));
            else
                ::execlp("pkexec", "pkexec", exe.constData(),
                         "--capture-helper", "-i", dev.constData(), "-f",
                         flt.constData(), static_cast<char *>(nullptr));
        }
        _exit(127);
    }

    ::close(data[1]);
    if (logFd >= 0)
        ::close(logFd);
    if (pid < 0) {
        ::close(data[0]);
        emit errorOccurred(QString::fromLocal8Bit(std::strerror(errno)));
        emit captureStopped();
        return;
    }

    ::signal(SIGPIPE, SIG_IGN);
    m_childPid.store(pid, std::memory_order_relaxed);
    m_packets = 0;
    m_bytes = 0;
    emit captureStarted(device);
    readPcapStream(data[0]);
    ::close(data[0]);

    // The helper runs as root: we cannot signal it, and closing the pipe is
    // what stops it. Never block the UI on its exit.
    int status = 0;
    for (int attempt = 0; attempt < 40; ++attempt) {  // up to 2 s
        const pid_t result = ::waitpid(pid, &status, WNOHANG);
        if (result == pid || result < 0)
            break;
        QThread::usleep(50000);
    }
    m_childPid.store(-1, std::memory_order_relaxed);

    if (m_packets == 0 && !m_stop.load(std::memory_order_relaxed)) {
        QString extra;
        QFile log(m_helperLogPath);
        if (log.open(QIODevice::ReadOnly))
            extra = QString::fromLocal8Bit(log.readAll()).trimmed();
        if (debug)
            std::fprintf(stderr, "[etherape] one-shot failure: %s\n",
                         extra.toLocal8Bit().constData());
        emit errorOccurred(
            extra.isEmpty()
                ? tr("The privileged helper could not start the capture.")
                : tr("The privileged helper could not start the capture: %1")
                      .arg(extra));
    }

    flush();
    emit counters(m_packets, m_bytes);
    emit captureStopped();
#endif
}

void CaptureWorker::readPcapStream(int fd)
{
#ifdef Q_OS_WIN
    Q_UNUSED(fd);  // the one-shot helper is POSIX-only
#else
    QByteArray buffer;
    bool headerDone = false;
    bool swapped = false;

    for (;;) {
        if (m_stop.load(std::memory_order_relaxed))
            break;

        struct pollfd pfd = {fd, POLLIN, 0};
        const int polled = ::poll(&pfd, 1, 200);
        if (polled < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        if (polled == 0)
            continue;
        if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL))
            break;

        if (pfd.revents & POLLIN) {
            char tmp[65536];
            const ssize_t n = ::read(fd, tmp, sizeof(tmp));
            if (n > 0)
                buffer.append(tmp, static_cast<int>(n));
            else if (n == 0)
                break;
            else if (errno != EINTR && errno != EAGAIN)
                break;
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
            case 0xa1b23c4d:
            case 0x4d3cb2a1:
                swapped = (magic == 0x4d3cb2a1);
                break;
            default: {
                QString hex;
                for (int i = 0; i < qMin(12, buffer.size()); ++i) {
                    hex += QStringLiteral("%1 ")
                               .arg(static_cast<quint8>(buffer.at(i)), 2, 16,
                                    QLatin1Char('0'));
                }
                emit errorOccurred(
                    tr("Privileged helper sent an invalid pcap stream "
                       "(first bytes: %1).")
                        .arg(hex.trimmed()));
                return;
            }
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
            m_batch.append(
                m_decoder.decode(record + 16, caplen, origlen, tsUsecTotal));
            m_packets += 1;
            m_bytes += origlen;
            buffer.remove(0, static_cast<int>(16 + caplen));

            if (m_batch.size() >= kBatchSize)
                flush();
        }
    }
#endif
}

void CaptureWorker::run(pcap_t *handle, bool offline, int speedPercent)
{
    m_handle.store(handle, std::memory_order_relaxed);
    m_firstTsUsec = -1;
    m_lastTsUsec = -1;

    // Savefiles must stay blocking: in non-blocking mode libpcap reports 0
    // instead of -2 at EOF and the loop would spin forever.
    if (!offline) {
        char errbuf[PCAP_ERRBUF_SIZE] = {0};
        pcap_setnonblock(handle, 1, errbuf);
    }

    QElapsedTimer wall;
    wall.start();
    int batches = 0;

    while (!m_stop.load(std::memory_order_relaxed)) {
        struct pcap_pkthdr *header = nullptr;
        const u_char *data = nullptr;
        const int rc = pcap_next_ex(handle, &header, &data);

        if (rc == 0)
            continue;  // read timeout (live)
        if (rc == -2) {
            if (offline)
                break;  // EOF
            continue;
        }
        if (rc == -1) {
            emit errorOccurred(QString::fromLocal8Bit(pcap_geterr(handle)));
            break;
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
                QThread::usleep(500);
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

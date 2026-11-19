// SPDX-License-Identifier: GPL-2.0-or-later
//
// Privileged capture helper.
//
// Started once per GUI session through pkexec, then kept alive: the GUI
// creates a UNIX socket, passes its path on the command line, and the helper
// reconnects for every capture session (one connection per session, so no
// pcap bytes can leak from one session into the next).
//
// The password is asked only once, because the helper outlives Stop. No
// password is ever stored.

#include "capturehelper.h"

#include <pcap.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#ifndef _WIN32
#include <csignal>
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#endif

namespace {

using etherape::HelperCommand;
using etherape::kHelperCmdOpen;
using etherape::kHelperCmdQuit;
using etherape::kHelperCmdStop;

constexpr int kSnapLen = 262144;
const char kSessionMagic[4] = {'E', 'T', 'H', 'P'};

void dumpRecord(u_char *user, const struct pcap_pkthdr *header,
                const u_char *bytes)
{
    pcap_dump(user, header, bytes);
}

#ifndef _WIN32

bool readExact(int fd, void *buffer, size_t length)
{
    auto *bytes = static_cast<char *>(buffer);
    size_t done = 0;
    while (done < length) {
        const ssize_t n = ::read(fd, bytes + done, length - done);
        if (n > 0) {
            done += static_cast<size_t>(n);
        } else if (n == 0) {
            return false;
        } else if (errno != EINTR) {
            return false;
        }
    }
    return true;
}

bool writeExact(int fd, const void *buffer, size_t length)
{
    const auto *bytes = static_cast<const char *>(buffer);
    size_t done = 0;
    while (done < length) {
        const ssize_t n = ::write(fd, bytes + done, length - done);
        if (n > 0) {
            done += static_cast<size_t>(n);
        } else if (n < 0 && errno == EINTR) {
            continue;
        } else {
            return false;
        }
    }
    return true;
}

// Opens a live capture, applies the filter and streams a pcap file on fd.
// The first byte sent is the status: 0 = streaming, 1 = failure followed by a
// length-prefixed error message. The status MUST leave before
// pcap_dump_fopen(), which writes the 24-byte pcap global header immediately.
void captureSession(int fd, const char *device, const char *filter)
{
    unsigned char status = 1;
    auto reportFailure = [&status, fd](const char *what) {
        writeExact(fd, &status, 1);
        const unsigned length =
            what ? static_cast<unsigned>(std::strlen(what)) : 0u;
        writeExact(fd, &length, sizeof(length));
        if (length > 0)
            writeExact(fd, what, length);
    };

    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    pcap_t *handle = pcap_create(device, errbuf);
    if (!handle) {
        reportFailure(errbuf);
        return;
    }
    pcap_set_snaplen(handle, kSnapLen);
    pcap_set_promisc(handle, 1);
    pcap_set_timeout(handle, 100);
    if (pcap_activate(handle) < 0) {
        char message[512] = {0};
        std::snprintf(message, sizeof(message), "%s", pcap_geterr(handle));
        std::fprintf(stderr, "etherape2026: %s\n", message);
        reportFailure(message);
        pcap_close(handle);
        return;
    }
    if (filter && *filter) {
        struct bpf_program program;
        if (pcap_compile(handle, &program, filter, 1, PCAP_NETMASK_UNKNOWN)
                < 0
            || pcap_setfilter(handle, &program) < 0) {
            char message[512] = {0};
            std::snprintf(message, sizeof(message), "%s", pcap_geterr(handle));
            std::fprintf(stderr, "etherape2026: %s\n", message);
            reportFailure(message);
            pcap_close(handle);
            return;
        }
        pcap_freecode(&program);
    }

    if (!writeExact(fd, &status, 1)) {  // 0 = streaming
        pcap_close(handle);
        return;
    }
    status = 0;
    // Session marker: lets the GUI resynchronise if anything was misread.
    if (!writeExact(fd, kSessionMagic, sizeof(kSessionMagic))) {
        pcap_close(handle);
        return;
    }

    FILE *sink = ::fdopen(::dup(fd), "wb");
    if (!sink) {
        pcap_close(handle);
        return;
    }
    std::setvbuf(sink, nullptr, _IONBF, 0);
    pcap_dumper_t *dumper = pcap_dump_fopen(handle, sink);
    if (!dumper) {
        std::fclose(sink);
        pcap_close(handle);
        return;
    }

    for (;;) {
        struct pollfd dataPoll = {fd, POLLOUT, 0};
        if (::poll(&dataPoll, 1, 0) > 0
            && (dataPoll.revents & (POLLERR | POLLHUP | POLLNVAL))) {
            break;  // GUI gone
        }

        struct pollfd ctlPoll = {fd, POLLIN, 0};
        if (::poll(&ctlPoll, 1, 0) > 0 && (ctlPoll.revents & POLLIN)) {
            HelperCommand command{};
            if (!readExact(fd, &command, sizeof(command))
                || command.type == kHelperCmdStop
                || command.type == kHelperCmdQuit)
                break;
        }

        const int processed = pcap_dispatch(
            handle, 64, dumpRecord, reinterpret_cast<u_char *>(dumper));
        if (processed < 0)
            break;
    }

    pcap_dump_close(dumper);  // closes the duplicated fd
    pcap_close(handle);
}

// Streams a live capture on stdout until the reader disappears. pcap_dump
// ignores write errors, and SIGPIPE is ignored, so the closed pipe is detected
// with poll() on stdout.
void dumpLoop(pcap_t *handle, pcap_dumper_t *dumper)
{
    for (;;) {
        struct pollfd dataPoll = {STDOUT_FILENO, POLLOUT, 0};
        if (::poll(&dataPoll, 1, 0) > 0
            && (dataPoll.revents & (POLLERR | POLLHUP | POLLNVAL))) {
            break;
        }
        const int processed = pcap_dispatch(
            handle, 64, dumpRecord, reinterpret_cast<u_char *>(dumper));
        if (processed < 0)
            break;
    }
}

// Serves one connection: OPEN starts a capture, STOP ends it, QUIT exits.
// Returns true when the helper should terminate.
bool serveChannel(int fd, bool debug)
{
    for (;;) {
        HelperCommand command{};
        if (!readExact(fd, &command, sizeof(command))) {
            if (debug)
                std::fprintf(stderr, "[helper] peer closed\n");
            return false;
        }
        if (debug)
            std::fprintf(stderr, "[helper] command type=%u len=%u\n",
                         command.type, command.length);

        if (command.type == kHelperCmdQuit)
            return true;
        if (command.type != kHelperCmdOpen) {
            if (command.length > 0 && command.length < 65536) {
                char drain[4096];
                size_t left = command.length;
                while (left > 0) {
                    const size_t chunk =
                        left < sizeof(drain) ? left : sizeof(drain);
                    if (!readExact(fd, drain, chunk))
                        return false;
                    left -= chunk;
                }
            }
            continue;
        }

        char payload[65536] = {0};
        const size_t length =
            command.length < sizeof(payload) ? command.length
                                             : sizeof(payload) - 1;
        if (length > 0 && !readExact(fd, payload, length))
            return false;
        payload[length] = '\0';

        const char *dev = payload;
        const char *flt = payload + std::strlen(payload) + 1;
        if (dev >= payload + length)
            dev = "";

        if (debug)
            std::fprintf(stderr, "[helper] session start dev='%s'\n", dev);
        captureSession(fd, dev, flt);
        if (debug)
            std::fprintf(stderr, "[helper] session end\n");
    }
}

const char *valueAfter(int &index, int argc, char **argv)
{
    if (index + 1 >= argc)
        return nullptr;
    return argv[++index];
}

#endif  // !_WIN32

} // namespace

namespace etherape {

bool isCaptureHelperInvocation(int argc, char **argv)
{
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--capture-helper") == 0)
            return true;
    }
    return false;
}

int runCaptureHelper(int argc, char **argv)
{
#ifdef _WIN32
    std::fprintf(stderr, "etherape2026: the capture helper is POSIX-only\n");
    return 2;
#else
    const char *device = nullptr;
    const char *filter = "";
    const char *socketPath = nullptr;
    bool debug = std::getenv("ETHERAPE_DEBUG") != nullptr;

    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--capture-helper") == 0)
            continue;
        if (std::strcmp(argv[i], "--debug") == 0) {
            debug = true;
            continue;
        }
        if (std::strcmp(argv[i], "--socket") == 0) {
            socketPath = valueAfter(i, argc, argv);
            if (!socketPath) {
                std::fprintf(stderr, "etherape2026: --socket needs a path\n");
                return 2;
            }
            continue;
        }
        // Legacy descriptors from the first persistent design: ignored.
        if (std::strncmp(argv[i], "--ctl-fd=", 9) == 0
            || std::strncmp(argv[i], "--data-fd=", 10) == 0) {
            continue;
        }
        if (std::strcmp(argv[i], "-i") == 0
            || std::strcmp(argv[i], "--interface") == 0) {
            device = valueAfter(i, argc, argv);
            if (!device) {
                std::fprintf(stderr,
                             "etherape2026: --interface needs a device\n");
                return 2;
            }
            continue;
        }
        if (std::strcmp(argv[i], "-f") == 0
            || std::strcmp(argv[i], "--filter") == 0) {
            filter = valueAfter(i, argc, argv);
            if (!filter)
                filter = "";
            continue;
        }
        std::fprintf(stderr, "etherape2026: unknown helper argument: %s\n",
                     argv[i]);
        return 2;
    }

    std::signal(SIGPIPE, SIG_IGN);

    if (debug) {
        std::fprintf(stderr,
                     "[helper] uid=%d euid=%d gid=%d egid=%d\n", (int)getuid(),
                     (int)geteuid(), (int)getgid(), (int)getegid());
#ifdef __linux__
        FILE *status = std::fopen("/proc/self/status", "r");
        if (status) {
            char line[256];
            while (std::fgets(line, sizeof(line), status)) {
                if (std::strncmp(line, "CapEff:", 7) == 0
                    || std::strncmp(line, "NoNewPrivs:", 11) == 0)
                    std::fprintf(stderr, "[helper] %s", line);
            }
            std::fclose(status);
        }
        FILE *label = std::fopen("/proc/self/attr/current", "r");
        if (label) {
            char context[256] = {0};
            if (std::fgets(context, sizeof(context), label))
                std::fprintf(stderr, "[helper] selinux=%s", context);
            std::fclose(label);
        }
#endif
    }

    // Legacy one-shot mode (debugging): -i/-f without a socket.
    if (!socketPath && device) {
        char errbuf[PCAP_ERRBUF_SIZE] = {0};
        pcap_t *handle = pcap_create(device, errbuf);
        if (!handle) {
            std::fprintf(stderr, "etherape2026: %s\n", errbuf);
            return 1;
        }
        pcap_set_snaplen(handle, kSnapLen);
        pcap_set_promisc(handle, 1);
        pcap_set_timeout(handle, 100);
        if (pcap_activate(handle) < 0) {
            std::fprintf(stderr, "etherape2026: %s\n", pcap_geterr(handle));
            pcap_close(handle);
            return 1;
        }
        if (*filter) {
            struct bpf_program program;
            if (pcap_compile(handle, &program, filter, 1,
                             PCAP_NETMASK_UNKNOWN)
                    < 0
                || pcap_setfilter(handle, &program) < 0) {
                std::fprintf(stderr, "etherape2026: %s\n",
                             pcap_geterr(handle));
                pcap_close(handle);
                return 1;
            }
            pcap_freecode(&program);
        }
        std::setvbuf(stdout, nullptr, _IONBF, 0);
        pcap_dumper_t *dumper = pcap_dump_fopen(handle, stdout);
        if (!dumper) {
            pcap_close(handle);
            return 1;
        }
        dumpLoop(handle, dumper);
        pcap_dump_close(dumper);
        pcap_close(handle);
        return 0;
    }

    if (!socketPath || !*socketPath) {
        std::fprintf(stderr,
                     "etherape2026: --capture-helper needs --socket <path>\n");
        return 2;
    }

    // Long-lived mode: one connection per capture session. Reconnecting after
    // STOP guarantees the GUI never reads leftovers as the next status.
    int connectAttempts = 0;
    for (;;) {
        struct sockaddr_un address = {};
        address.sun_family = AF_UNIX;
        std::snprintf(address.sun_path, sizeof(address.sun_path), "%s",
                      socketPath);

        int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd < 0)
            return 1;
        if (::connect(fd, reinterpret_cast<struct sockaddr *>(&address),
                      sizeof(address)) != 0) {
            ::close(fd);
            // The GUI may still be starting: retry ~10 s, then give up so an
            // orphan helper never lingers.
            if (++connectAttempts > 50) {
                std::fprintf(stderr,
                             "etherape2026: cannot connect to %s: %s\n",
                             socketPath, std::strerror(errno));
                return 1;
            }
            ::usleep(200000);
            continue;
        }
        connectAttempts = 0;

        if (debug)
            std::fprintf(stderr, "[helper] connected fd=%d\n", fd);

        const bool quit = serveChannel(fd, debug);
        ::close(fd);
        if (quit)
            break;
    }

    return 0;
#endif
}

} // namespace etherape

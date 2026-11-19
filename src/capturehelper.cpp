// SPDX-License-Identifier: GPL-2.0-or-later

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
using etherape::kHelperCmdQuit;
using etherape::kHelperCmdStop;

constexpr int kSnapLen = 262144;

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

// Runs one capture session until STOP, the GUI closing the pipe, or an error.
// Command channel is stdin, data channel is stdout; fd 0/1 are the only ones
// guaranteed to survive pkexec (a setuid program may close everything else).
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
        std::fprintf(stderr, "etherape2026: %s\n", errbuf);
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
        pcap_close(handle);
        reportFailure(message);
        return;
    }
    if (filter && *filter) {
        struct bpf_program program;
        if (pcap_compile(handle, &program, filter, 1, PCAP_NETMASK_UNKNOWN) < 0
            || pcap_setfilter(handle, &program) < 0) {
            char message[512] = {0};
            std::snprintf(message, sizeof(message), "%s", pcap_geterr(handle));
            std::fprintf(stderr, "etherape2026: %s\n", message);
            pcap_close(handle);
            reportFailure(message);
            return;
        }
        pcap_freecode(&program);
    }

    // The status byte must leave BEFORE pcap_dump_fopen(), which writes the
    // 24-byte pcap global header immediately. Otherwise the GUI reads 0xd4
    // (the first magic byte) instead of the status.
    status = 0;
    if (!writeExact(fd, &status, 1)) {
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

#endif  // !_WIN32

const char *valueAfter(int &index, int argc, char **argv)
{
    if (index + 1 >= argc)
        return nullptr;
    return argv[++index];
}

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

    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--capture-helper") == 0)
            continue;
        // Legacy fd arguments (ignored: stdin/stdout are used instead).
        // Legacy fd arguments: no longer used, ignore them.
        if (std::strncmp(argv[i], "--ctl-fd=", 9) == 0
            || std::strncmp(argv[i], "--data-fd=", 10) == 0) {
            continue;
        }
        if (std::strcmp(argv[i], "--socket") == 0) {
            if (!valueAfter(i, argc, argv)) {
                std::fprintf(stderr,
                             "etherape2026: --socket needs a path\n");
                return 2;
            }
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

    // Legacy one-shot mode, kept for debugging: -i/-f only.
    if (device) {
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
        pcap_loop(handle, -1, pcap_dump, reinterpret_cast<u_char *>(dumper));
        pcap_dump_close(dumper);
        pcap_close(handle);
        return 0;
    }

    // Long-lived mode: commands and data share one full-duplex descriptor.
    int channel = -1;
    const char *socketPath = nullptr;
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--socket") == 0 && i + 1 < argc) {
            socketPath = argv[i + 1];
            break;
        }
    }

    if (socketPath && *socketPath) {
        struct sockaddr_un address = {};
        address.sun_family = AF_UNIX;
        std::snprintf(address.sun_path, sizeof(address.sun_path), "%s",
                      socketPath);
        channel = ::socket(AF_UNIX, SOCK_STREAM, 0);
        if (channel < 0 || ::connect(channel,
                                     reinterpret_cast<struct sockaddr *>(&address),
                                     sizeof(address)) != 0) {
            std::fprintf(stderr,
                         "etherape2026: cannot connect to %s: %s\n",
                         socketPath, std::strerror(errno));
            return 1;
        }
    } else {
        channel = STDIN_FILENO;  // legacy: stdin for commands, stdout for data
    }

    if (std::getenv("ETHERAPE_DEBUG"))
        std::fprintf(stderr, "[helper] serving on fd=%d\n", channel);

    for (;;) {
        HelperCommand command{};
        if (!readExact(channel, &command, sizeof(command)))
            break;
        if (command.type == kHelperCmdQuit)
            break;
        if (command.type != kHelperCmdOpen) {
            if (command.length > 0 && command.length < 65536) {
                char drain[4096];
                size_t left = command.length;
                while (left > 0) {
                    const size_t chunk =
                        left < sizeof(drain) ? left : sizeof(drain);
                    if (!readExact(channel, drain, chunk))
                        return 0;
                    left -= chunk;
                }
            }
            continue;
        }

        char payload[65536] = {0};
        const size_t length =
            command.length < sizeof(payload) ? command.length
                                             : sizeof(payload) - 1;
        if (length > 0 && !readExact(channel, payload, length))
            break;
        payload[length] = '\0';

        const char *dev = payload;
        const char *flt = payload + std::strlen(payload) + 1;
        if (dev >= payload + length)
            dev = "";

        captureSession(channel, dev, flt);
    }

    return 0;
#endif
}

} // namespace etherape

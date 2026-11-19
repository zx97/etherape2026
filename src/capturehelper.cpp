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
// A one-byte status is sent back on the control socket first (0 = streaming).
void captureSession(int ctlFd, int dataFd, const char *device,
                    const char *filter)
{
    unsigned char status = 1;

    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    pcap_t *handle = pcap_create(device, errbuf);
    if (!handle) {
        std::fprintf(stderr, "etherape2026: %s\n", errbuf);
        writeExact(ctlFd, &status, 1);
        return;
    }
    pcap_set_snaplen(handle, kSnapLen);
    pcap_set_promisc(handle, 1);
    pcap_set_timeout(handle, 100);
    if (pcap_activate(handle) < 0) {
        std::fprintf(stderr, "etherape2026: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        writeExact(ctlFd, &status, 1);
        return;
    }
    if (filter && *filter) {
        struct bpf_program program;
        if (pcap_compile(handle, &program, filter, 1, PCAP_NETMASK_UNKNOWN) < 0
            || pcap_setfilter(handle, &program) < 0) {
            std::fprintf(stderr, "etherape2026: %s\n", pcap_geterr(handle));
            pcap_close(handle);
            writeExact(ctlFd, &status, 1);
            return;
        }
        pcap_freecode(&program);
    }

    // Each session gets its own duplicate of the data pipe, so closing the
    // dumper never closes the GUI's channel.
    FILE *sink = ::fdopen(::dup(dataFd), "wb");
    if (!sink) {
        pcap_close(handle);
        return;
    }
    std::setvbuf(sink, nullptr, _IONBF, 0);
    pcap_dumper_t *dumper = pcap_dump_fopen(handle, sink);
    if (!dumper) {
        std::fclose(sink);
        pcap_close(handle);
        writeExact(ctlFd, &status, 1);
        return;
    }

    status = 0;
    if (!writeExact(ctlFd, &status, 1)) {
        pcap_dump_close(dumper);
        pcap_close(handle);
        return;
    }

    for (;;) {
        struct pollfd dataPoll = {dataFd, POLLOUT, 0};
        if (::poll(&dataPoll, 1, 0) > 0
            && (dataPoll.revents & (POLLERR | POLLHUP | POLLNVAL))) {
            break;  // GUI gone
        }

        struct pollfd ctlPoll = {ctlFd, POLLIN, 0};
        if (::poll(&ctlPoll, 1, 0) > 0 && (ctlPoll.revents & POLLIN)) {
            HelperCommand command{};
            if (!readExact(ctlFd, &command, sizeof(command))
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
    int ctlFd = -1;
    int dataFd = -1;
    const char *device = nullptr;
    const char *filter = "";

    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--capture-helper") == 0)
            continue;
        if (std::strncmp(argv[i], "--ctl-fd=", 9) == 0) {
            ctlFd = std::atoi(argv[i] + 9);
            continue;
        }
        if (std::strncmp(argv[i], "--data-fd=", 10) == 0) {
            dataFd = std::atoi(argv[i] + 10);
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

    // Legacy one-shot mode, kept for debugging: -i/-f without file descriptors.
    if (ctlFd < 0 && device) {
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

    if (ctlFd < 0 || dataFd < 0) {
        std::fprintf(stderr,
                     "etherape2026: --capture-helper needs --ctl-fd and "
                     "--data-fd\n");
        return 2;
    }

    // Long-lived mode: serve sessions until QUIT or the GUI disappears.
    for (;;) {
        HelperCommand command{};
        if (!readExact(ctlFd, &command, sizeof(command)))
            break;
        if (command.type == kHelperCmdQuit)
            break;
        if (command.type != kHelperCmdOpen) {
            if (command.length > 0 && command.length < 65536) {
                char drain[4096];
                size_t left = command.length;
                while (left > 0) {
                    const size_t chunk = left < sizeof(drain) ? left : sizeof(drain);
                    if (!readExact(ctlFd, drain, chunk))
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
        if (length > 0 && !readExact(ctlFd, payload, length))
            break;
        payload[length] = '\0';

        // Payload: "device\0filter\0"
        const char *dev = payload;
        const char *flt = payload + std::strlen(payload) + 1;
        if (dev >= payload + length)
            dev = "";

        captureSession(ctlFd, dataFd, dev, flt);
    }

    ::close(ctlFd);
    ::close(dataFd);
    return 0;
#endif
}

} // namespace etherape

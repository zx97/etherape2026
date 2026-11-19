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
// Command channel is stdin, data channel is stdout; fd 0/1 are the only ones
// guaranteed to survive pkexec (a setuid program may close everything else).
void captureSession(const char *device, const char *filter)
{
    unsigned char status = 1;

    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    pcap_t *handle = pcap_create(device, errbuf);
    if (!handle) {
        std::fprintf(stderr, "etherape2026: %s\n", errbuf);
        writeExact(STDOUT_FILENO, &status, 1);
        return;
    }
    pcap_set_snaplen(handle, kSnapLen);
    pcap_set_promisc(handle, 1);
    pcap_set_timeout(handle, 100);
    if (pcap_activate(handle) < 0) {
        std::fprintf(stderr, "etherape2026: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        writeExact(STDOUT_FILENO, &status, 1);
        return;
    }
    if (filter && *filter) {
        struct bpf_program program;
        if (pcap_compile(handle, &program, filter, 1, PCAP_NETMASK_UNKNOWN) < 0
            || pcap_setfilter(handle, &program) < 0) {
            std::fprintf(stderr, "etherape2026: %s\n", pcap_geterr(handle));
            pcap_close(handle);
            writeExact(STDOUT_FILENO, &status, 1);
            return;
        }
        pcap_freecode(&program);
    }

    // Each session gets its own duplicate of the data pipe, so closing the
    // dumper never closes the GUI's channel.
    FILE *sink = ::fdopen(::dup(STDOUT_FILENO), "wb");
    if (!sink) {
        pcap_close(handle);
        return;
    }
    std::setvbuf(sink, nullptr, _IONBF, 0);
    pcap_dumper_t *dumper = pcap_dump_fopen(handle, sink);
    if (!dumper) {
        std::fclose(sink);
        pcap_close(handle);
        writeExact(STDOUT_FILENO, &status, 1);
        return;
    }

    status = 0;
    if (!writeExact(STDOUT_FILENO, &status, 1)) {
        pcap_dump_close(dumper);
        pcap_close(handle);
        return;
    }

    for (;;) {
        struct pollfd dataPoll = {STDOUT_FILENO, POLLOUT, 0};
        if (::poll(&dataPoll, 1, 0) > 0
            && (dataPoll.revents & (POLLERR | POLLHUP | POLLNVAL))) {
            break;  // GUI gone
        }

        struct pollfd ctlPoll = {STDIN_FILENO, POLLIN, 0};
        if (::poll(&ctlPoll, 1, 0) > 0 && (ctlPoll.revents & POLLIN)) {
            HelperCommand command{};
            if (!readExact(STDIN_FILENO, &command, sizeof(command))
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
        // Legacy fd arguments: stdin/stdout are used now, ignore them.
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

    // Long-lived mode: commands on stdin, status + pcap stream on stdout.
    for (;;) {
        HelperCommand command{};
        if (!readExact(STDIN_FILENO, &command, sizeof(command)))
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
                    if (!readExact(STDIN_FILENO, drain, chunk))
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
        if (length > 0 && !readExact(STDIN_FILENO, payload, length))
            break;
        payload[length] = '\0';

        const char *dev = payload;
        const char *flt = payload + std::strlen(payload) + 1;
        if (dev >= payload + length)
            dev = "";

        captureSession(dev, flt);
    }

    return 0;
#endif
}

} // namespace etherape

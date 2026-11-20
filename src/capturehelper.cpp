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

constexpr int kSnapLen = 262144;

#ifndef _WIN32

// Streams a live capture on stdout until the reader disappears. pcap_dump
// ignores write errors and SIGPIPE is ignored, so the closed pipe is detected
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
            handle, 64, pcap_dump, reinterpret_cast<u_char *>(dumper));
        if (processed < 0)
            break;
    }
}

#endif

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
    bool debug = std::getenv("ETHERAPE_DEBUG") != nullptr;

    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--capture-helper") == 0)
            continue;
        if (std::strcmp(argv[i], "--debug") == 0) {
            debug = true;
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

    if (!device) {
        std::fprintf(stderr, "etherape2026: --capture-helper requires -i\n");
        return 2;
    }

    std::signal(SIGPIPE, SIG_IGN);

    if (debug) {
        std::fprintf(stderr, "[helper] uid=%d euid=%d gid=%d\n", (int)getuid(),
                     (int)geteuid(), (int)getgid());
        FILE *status = std::fopen("/proc/self/status", "r");
        if (status) {
            char line[256];
            while (std::fgets(line, sizeof(line), status)) {
                if (std::strncmp(line, "CapEff:", 7) == 0)
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
    }

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
        if (pcap_compile(handle, &program, filter, 1, PCAP_NETMASK_UNKNOWN)
                < 0
            || pcap_setfilter(handle, &program) < 0) {
            std::fprintf(stderr, "etherape2026: %s\n", pcap_geterr(handle));
            pcap_close(handle);
            return 1;
        }
        pcap_freecode(&program);
    }

    std::setvbuf(stdout, nullptr, _IONBF, 0);
    pcap_dumper_t *dumper = pcap_dump_fopen(handle, stdout);
    if (!dumper) {
        std::fprintf(stderr, "etherape2026: cannot write pcap stream: %s\n",
                     pcap_geterr(handle));
        pcap_close(handle);
        return 1;
    }

    dumpLoop(handle, dumper);
    pcap_dump_close(dumper);
    pcap_close(handle);
    return 0;
#endif
}

} // namespace etherape

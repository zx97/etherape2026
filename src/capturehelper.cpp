// SPDX-License-Identifier: GPL-2.0-or-later

#include "capturehelper.h"

#include <pcap.h>

#include <cstdio>
#include <cstring>

namespace {

constexpr int kSnapLen = 262144;

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
    const char *device = nullptr;
    const char *filter = "";

    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--capture-helper") == 0)
            continue;
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
            if (!filter) {
                std::fprintf(stderr, "etherape2026: --filter needs a value\n");
                return 2;
            }
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

    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    pcap_t *handle = pcap_create(device, errbuf);
    if (!handle) {
        std::fprintf(stderr, "etherape2026: %s\n", errbuf);
        return 1;
    }

    pcap_set_snaplen(handle, kSnapLen);
    pcap_set_promisc(handle, 1);
    pcap_set_timeout(handle, 100);

    const int activateRc = pcap_activate(handle);
    if (activateRc < 0) {
        std::fprintf(stderr, "etherape2026: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return 1;
    }

    if (*filter) {
        struct bpf_program program;
        if (pcap_compile(handle, &program, filter, 1, PCAP_NETMASK_UNKNOWN)
            < 0) {
            std::fprintf(stderr, "etherape2026: %s\n", pcap_geterr(handle));
            pcap_close(handle);
            return 1;
        }
        if (pcap_setfilter(handle, &program) < 0) {
            std::fprintf(stderr, "etherape2026: %s\n", pcap_geterr(handle));
            pcap_freecode(&program);
            pcap_close(handle);
            return 1;
        }
        pcap_freecode(&program);
    }

    // Unbuffered output keeps the GUI latency low.
    std::setvbuf(stdout, nullptr, _IONBF, 0);

    pcap_dumper_t *dumper = pcap_dump_fopen(handle, stdout);
    if (!dumper) {
        std::fprintf(stderr, "etherape2026: cannot write pcap stream: %s\n",
                     pcap_geterr(handle));
        pcap_close(handle);
        return 1;
    }

    // Runs until SIGTERM (GUI closing the pipe) or an unrecoverable error.
    pcap_loop(handle, -1, pcap_dump, reinterpret_cast<u_char *>(dumper));

    pcap_dump_close(dumper);
    pcap_close(handle);
    return 0;
}

} // namespace etherape

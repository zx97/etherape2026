// SPDX-License-Identifier: GPL-2.0-or-later
//
// Privileged capture helper.
//
// The main process never runs as root. When libpcap is denied, the GUI asks
// pkexec to run this very binary with --capture-helper; the helper opens the
// live capture and streams a pcap file on stdout, which the GUI parses while
// decoding in its own thread. One-way pipe, no protocol, no shared memory.

#pragma once

namespace etherape {

bool isCaptureHelperInvocation(int argc, char **argv);
int runCaptureHelper(int argc, char **argv);

} // namespace etherape

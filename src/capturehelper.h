// SPDX-License-Identifier: GPL-2.0-or-later
//
// Privileged capture helper.
//
// Started once per GUI session through pkexec, then kept alive: the GUI sends
// OPEN/STOP/QUIT commands over a socketpair and reads a pcap stream from a
// pipe. This is why the password is asked only once, and why no password is
// ever stored anywhere.

#pragma once

namespace etherape {

bool isCaptureHelperInvocation(int argc, char **argv);
int runCaptureHelper(int argc, char **argv);

// Wire protocol (little-endian, native structs on purpose: same host).
enum : unsigned {
    kHelperCmdOpen = 1,
    kHelperCmdStop = 2,
    kHelperCmdQuit = 3,
};

struct HelperCommand
{
    unsigned type;
    unsigned length;
};

} // namespace etherape

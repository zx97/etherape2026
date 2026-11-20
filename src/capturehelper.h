// SPDX-License-Identifier: GPL-2.0-or-later
//
// Privileged capture helper.
//
// Started through pkexec for one capture at a time: the interface and filter
// come from argv and a pcap file is streamed on stdout. This is the only
// mechanism that behaves reliably with a setuid pkexec (which closes
// inherited descriptors and sanitises the environment); the persistent
// helper experiment was abandoned — see docs/PORTING.md.

#pragma once

namespace etherape {

bool isCaptureHelperInvocation(int argc, char **argv);
int runCaptureHelper(int argc, char **argv);

} // namespace etherape

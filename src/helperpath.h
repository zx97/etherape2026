// SPDX-License-Identifier: GPL-2.0-or-later
//
// Helper log location.
//
// The privileged capture helper writes its diagnostics to a file created by
// the unprivileged GUI before the fork. /dev/shm is world-writable (1777), so
// a predictable path there lets another local user pre-create the name: a
// symlink would redirect the write, a readable file would leak interface
// names and BPF filters. Both are avoided by using a per-user directory with
// mode 0700 and by refusing symlinks when opening the file.

#pragma once

#include <QString>

namespace etherape {

// Creates (if needed) and returns the private per-user log directory,
// /dev/shm/etherape2026-<uid>, with mode 0700. Returns an empty string when
// the directory exists but is not a directory owned by the current user, so
// callers can simply skip logging. Always empty on Windows.
QString helperLogDirectory();

// Opens a helper log for writing, creating it with mode 0600. Refuses to
// follow a symlink and never truncates a file it did not create.
// Returns a file descriptor, or -1 when the path is unsafe or unavailable.
int openHelperLog(const QString &path);

} // namespace etherape

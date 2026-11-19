// SPDX-License-Identifier: GPL-2.0-or-later
//
// Passive NetBIOS name service (NBNS) decoding.
//
// The historical implementation sent active name queries. We instead read the
// responses that Windows hosts broadcast anyway: zero extra traffic, no
// privileges, and it keeps working when outbound NBNS is filtered.

#pragma once

#include <QString>
#include <QtGlobal>

#include <optional>

namespace etherape {

struct NetbiosName
{
    QString name;
    QString ip;
};

// Parses a UDP/137 payload; returns a name mapping only for a positive
// response carrying an NB resource record.
std::optional<NetbiosName> parseNetbiosResponse(const uchar *data, quint32 length);

} // namespace etherape

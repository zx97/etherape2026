// SPDX-License-Identifier: GPL-2.0-or-later
//
// XML export, modelled on the historical EtherApe export schema:
// header / nodes / links / protocols. Per-node in/out counters are derived
// from the link directions, which the graph keeps anyway.

#pragma once

#include <QString>

namespace etherape {

class GraphModel;

bool exportGraphXml(const GraphModel &model, const QString &path,
                    const QString &source = QString(),
                    QString *error = nullptr);

} // namespace etherape

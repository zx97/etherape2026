// SPDX-License-Identifier: GPL-2.0-or-later
//
// JSON export: the machine-readable twin of the XML export. Same fields so a
// consumer can pick either format without losing information.

#pragma once

#include <QString>

namespace etherape {

class GraphModel;

bool exportGraphJson(const GraphModel &model, const QString &path,
                     const QString &source = QString(),
                     QString *error = nullptr);

} // namespace etherape

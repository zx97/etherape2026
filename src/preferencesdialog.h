// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <QDialog>

class QCheckBox;
class QDoubleSpinBox;
class QSpinBox;

namespace etherape {

class PreferencesDialog : public QDialog
{
    Q_OBJECT

public:
    struct Values
    {
        int nodeLimit = 300;
        double decaySeconds = 4.0;
        bool resolveNames = false;
        double fontScale = 1.0;
        int replaySpeed = 100;
        bool usePolkit = false;
    };

    explicit PreferencesDialog(const Values &values, QWidget *parent = nullptr);

    Values values() const;

private:
    QSpinBox *m_nodeLimit = nullptr;
    QDoubleSpinBox *m_decay = nullptr;
    QCheckBox *m_resolve = nullptr;
    QDoubleSpinBox *m_font = nullptr;
    QSpinBox *m_speed = nullptr;
    QCheckBox *m_polkit = nullptr;
};

} // namespace etherape

// SPDX-License-Identifier: GPL-2.0-or-later

#include "preferencesdialog.h"

#include <QCheckBox>
#include <QDialogButtonBox>
#include <QDoubleSpinBox>
#include <QFormLayout>
#include <QSpinBox>
#include <QVBoxLayout>

namespace etherape {

PreferencesDialog::PreferencesDialog(const Values &values, QWidget *parent)
    : QDialog(parent)
{
    setWindowTitle(tr("Preferences"));

    m_nodeLimit = new QSpinBox(this);
    m_nodeLimit->setRange(10, 5000);
    m_nodeLimit->setValue(values.nodeLimit);
    m_nodeLimit->setToolTip(
        tr("Maximum number of nodes kept in the graph at any time."));

    m_decay = new QDoubleSpinBox(this);
    m_decay->setRange(1.0, 120.0);
    m_decay->setDecimals(1);
    m_decay->setSuffix(tr(" s"));
    m_decay->setValue(values.decaySeconds);
    m_decay->setToolTip(
        tr("How long a link stays visible after the last packet."));

    m_resolve = new QCheckBox(tr("Resolve addresses to names (DNS)"), this);
    m_resolve->setChecked(values.resolveNames);
    m_resolve->setToolTip(
        tr("Reverse DNS lookups run asynchronously; disabled keeps the graph "
           "strictly numeric."));

    m_font = new QDoubleSpinBox(this);
    m_font->setRange(0.7, 2.0);
    m_font->setSingleStep(0.1);
    m_font->setDecimals(1);
    m_font->setValue(values.fontScale);

    m_speed = new QSpinBox(this);
    m_speed->setRange(0, 1000);
    m_speed->setSpecialValueText(tr("as fast as possible"));
    m_speed->setSuffix(tr(" %"));
    m_speed->setValue(values.replaySpeed);
    m_speed->setToolTip(tr("Replay speed for capture files."));

    m_polkit = new QCheckBox(
        tr("Ask for the root password (polkit) when capture is denied"), this);
    m_polkit->setChecked(values.usePolkit);
    m_polkit->setToolTip(
        tr("Runs a small helper through pkexec; the GUI itself stays "
           "unprivileged."));

    auto *form = new QFormLayout;
    form->addRow(tr("Node limit:"), m_nodeLimit);
    form->addRow(tr("Link decay:"), m_decay);
    form->addRow(tr("Labels:"), m_font);
    form->addRow(tr("Replay speed:"), m_speed);
    form->addRow(QString(), m_resolve);
    form->addRow(QString(), m_polkit);

    auto *buttons =
        new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel,
                             Qt::Horizontal, this);
    connect(buttons, &QDialogButtonBox::accepted, this, &QDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);

    auto *layout = new QVBoxLayout(this);
    layout->addLayout(form);
    layout->addWidget(buttons);
}

PreferencesDialog::Values PreferencesDialog::values() const
{
    Values values;
    values.nodeLimit = m_nodeLimit->value();
    values.decaySeconds = m_decay->value();
    values.resolveNames = m_resolve->isChecked();
    values.fontScale = m_font->value();
    values.replaySpeed = m_speed->value();
    values.usePolkit = m_polkit->isChecked();
    return values;
}

} // namespace etherape

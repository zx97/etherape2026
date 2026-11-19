// SPDX-License-Identifier: GPL-2.0-or-later

#include "preferencesdialog.h"

#include <QCheckBox>
#include <QComboBox>
#include <QDialogButtonBox>
#include <QDoubleSpinBox>
#include <QFormLayout>
#include <QLineEdit>
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

    m_merge = new QCheckBox(
        tr("Merge a host's IPv4 and IPv6 addresses into one node (by MAC)"),
        this);
    m_merge->setChecked(values.mergeFamilies);
    m_merge->setToolTip(
        tr("A host that talks over both families then appears once, with its "
           "MAC as the common identity."));

    m_polkit = new QCheckBox(
        tr("Ask for the root password (polkit) when capture is denied"), this);
    m_polkit->setChecked(values.usePolkit);
    m_polkit->setToolTip(
        tr("Runs a small helper through pkexec once per session; Start and "
           "Stop then reuse it without asking again. The GUI itself stays "
           "unprivileged."));

    m_localZones = new QLineEdit(values.localZones, this);
    m_localZones->setPlaceholderText(QStringLiteral("10.0.0.0/8, 192.168.0.0/16"));
    m_dmzZones = new QLineEdit(values.dmzZones, this);
    m_dmzZones->setPlaceholderText(QStringLiteral("192.0.2.0/24"));
    m_vpnZones = new QLineEdit(values.vpnZones, this);
    m_vpnZones->setPlaceholderText(QStringLiteral("10.8.0.0/24, fd00::/64"));
    m_localZones->setToolTip(tr("CIDR blocks considered local (LAN)."));
    m_dmzZones->setToolTip(tr("CIDR blocks rendered in the DMZ cloud."));
    m_vpnZones->setToolTip(tr("CIDR blocks rendered in the VPN cloud."));

    m_language = new QComboBox(this);
    m_language->addItem(tr("System default"), QString());
    m_language->addItem(QStringLiteral("Français (fr)"), QStringLiteral("fr"));
    m_language->addItem(QStringLiteral("Español (es)"), QStringLiteral("es"));
    m_language->addItem(QStringLiteral("Português do Brasil (pt_BR)"), QStringLiteral("pt_BR"));
    m_language->addItem(QStringLiteral("Русский (ru)"), QStringLiteral("ru"));
    m_language->addItem(QStringLiteral("简体中文 (zh_CN)"), QStringLiteral("zh_CN"));
    m_language->addItem(QStringLiteral("العربية (ar)"), QStringLiteral("ar"));
    m_language->addItem(QStringLiteral("हिन्दी (hi)"), QStringLiteral("hi"));
    m_language->addItem(QStringLiteral("বাংলা (bn)"), QStringLiteral("bn"));
    m_language->addItem(QStringLiteral("اردو (ur)"), QStringLiteral("ur"));
    const int languageIndex = m_language->findData(values.language);
    m_language->setCurrentIndex(languageIndex >= 0 ? languageIndex : 0);
    m_language->setToolTip(
        tr("Technical terms (VLAN, MAC, BPF, DNS, TCP/IP...) stay in English. "
           "The change applies at the next start."));

    auto *form = new QFormLayout;
    form->addRow(tr("Node limit:"), m_nodeLimit);
    form->addRow(tr("Link decay:"), m_decay);
    form->addRow(tr("Labels:"), m_font);
    form->addRow(tr("Replay speed:"), m_speed);
    form->addRow(QString(), m_resolve);
    form->addRow(QString(), m_merge);
    form->addRow(QString(), m_polkit);
    form->addRow(tr("Language:"), m_language);
    form->addRow(tr("LAN zones:"), m_localZones);
    form->addRow(tr("DMZ zones:"), m_dmzZones);
    form->addRow(tr("VPN zones:"), m_vpnZones);

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
    values.mergeFamilies = m_merge->isChecked();
    values.language = m_language->currentData().toString();
    values.localZones = m_localZones->text();
    values.dmzZones = m_dmzZones->text();
    values.vpnZones = m_vpnZones->text();
    return values;
}

} // namespace etherape

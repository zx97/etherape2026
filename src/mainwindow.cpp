// SPDX-License-Identifier: GPL-2.0-or-later

#include "mainwindow.h"

#include "captureworker.h"
#include "conversationsdialog.h"
#include "graphmodel.h"
#include "graphview.h"
#include "statspanel.h"
#include "jsonexport.h"
#include "xmlexport.h"

#include <QAction>
#include <QActionGroup>
#include <QApplication>
#include <QCloseEvent>
#include <QComboBox>
#include <QCoreApplication>
#include <QDateTime>
#include <QDir>
#include <QFileDialog>
#include <QFileInfo>
#include <QCompleter>
#include <QInputDialog>
#include <cstdio>
#include <QStringListModel>
#include <QToolButton>
#include <QDnsLookup>
#include <QHostInfo>
#include <QIcon>
#include <QKeySequence>
#include <QLabel>
#include <QLineEdit>
#include <QMenuBar>
#include <QMessageBox>
#include <QMetaObject>
#include <QSettings>
#include <QSignalBlocker>
#include <QSplitter>
#include <QStatusBar>
#include <QStyle>

#include <algorithm>
#include <cstdio>
#include <QThread>
#include <QTimer>
#include <QToolBar>
#include <QVBoxLayout>

#ifdef Q_OS_WIN
#include <windows.h>
#include <shellapi.h>
#endif

#ifndef APP_VERSION
#define APP_VERSION "1.0.0"
#endif

namespace etherape {

namespace {

QString humanBytes(quint64 bytes)
{
    static const char *units[] = {"B", "KB", "MB", "GB", "TB"};
    double value = static_cast<double>(bytes);
    int unit = 0;
    while (value >= 1024.0 && unit < 4) {
        value /= 1024.0;
        ++unit;
    }
    return QStringLiteral("%1 %2")
        .arg(value, 0, 'f', unit == 0 ? 0 : 1)
        .arg(QLatin1String(units[unit]));
}

constexpr int kMaxPendingLookups = 24;

} // namespace

MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent)
{
    qRegisterMetaType<QList<etherape::PacketInfo>>(
        "QList<etherape::PacketInfo>");

    m_model = new GraphModel(this);

    m_graph = new GraphView(this);
    m_graph->setModel(m_model);

    m_stats = new StatsPanel(this);

    auto *splitter = new QSplitter(Qt::Horizontal, this);
    splitter->addWidget(m_graph);
    splitter->addWidget(m_stats);
    splitter->setStretchFactor(0, 4);
    splitter->setStretchFactor(1, 1);
    splitter->setSizes({900, 380});
    setCentralWidget(splitter);

    // Capture worker lives in its own thread.
    m_captureThread = new QThread(this);
    m_worker = new CaptureWorker;
    m_worker->moveToThread(m_captureThread);
    connect(m_graph, &GraphView::nodeClicked, this, [this](const QString &id) {
        m_stats->setSelectedNode(id);
        m_stats->refresh(*m_model, m_displayFilter);
    });
    connect(m_worker, &CaptureWorker::batchReady, this, &MainWindow::onBatch);
    connect(m_worker, &CaptureWorker::captureStarted, this,
            &MainWindow::onCaptureStarted);
    connect(m_worker, &CaptureWorker::captureStopped, this,
            &MainWindow::onCaptureStopped);
    connect(m_worker, &CaptureWorker::errorOccurred, this,
            &MainWindow::onCaptureError);
    connect(m_worker, &CaptureWorker::permissionDenied, this,
            &MainWindow::onPermissionDenied);
    connect(m_worker, &CaptureWorker::counters, this, &MainWindow::onCounters);
    connect(m_captureThread, &QThread::finished, m_worker.data(),
            &QObject::deleteLater);
    m_captureThread->start();

    buildUi();
    buildMenus();
    resize(1280, 800);
    loadSettings();
    loadEthers();

    m_refreshTimer = new QTimer(this);
    m_refreshTimer->setInterval(700);
    connect(m_refreshTimer, &QTimer::timeout, this, &MainWindow::refreshView);
    m_refreshTimer->start();

    m_filterTimer = new QTimer(this);
    m_filterTimer->setSingleShot(true);
    m_filterTimer->setInterval(250);
    connect(m_filterTimer, &QTimer::timeout, this,
            &MainWindow::applyDisplayFilter);
    connect(m_showEdit, &QLineEdit::textChanged, this,
            [this] { m_filterTimer->start(); });

    m_trafficTimer = new QTimer(this);
    m_trafficTimer->setInterval(1000);
    connect(m_trafficTimer, &QTimer::timeout, this, &MainWindow::updateTraffic);
    m_trafficTimer->start();

    setRunning(false);
    updateStatus();
}

MainWindow::~MainWindow()
{
    if (m_worker)
        m_worker->requestStop();
    if (m_captureThread) {
        m_captureThread->quit();
        m_captureThread->wait(3000);
    }
}

void MainWindow::buildUi()
{
    setWindowTitle(tr("EtherApe 2026"));
    QIcon appIcon = QIcon::fromTheme(QStringLiteral("etherape"));
    if (appIcon.isNull())
        appIcon = QIcon(QStringLiteral(":/etherape.png"));
    if (appIcon.isNull())
        appIcon = QApplication::style()->standardIcon(QStyle::SP_ComputerIcon);
    setWindowIcon(appIcon);

    auto *toolbar = addToolBar(tr("Capture"));
    toolbar->setMovable(false);
    toolbar->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);

    m_startAction = toolbar->addAction(
        QIcon::fromTheme(QStringLiteral("media-playback-start"),
                         style()->standardIcon(QStyle::SP_MediaPlay)),
        tr("Start"));
    connect(m_startAction, &QAction::triggered, this, &MainWindow::startCapture);

    m_stopAction = toolbar->addAction(
        QIcon::fromTheme(QStringLiteral("media-playback-stop"),
                         style()->standardIcon(QStyle::SP_MediaStop)),
        tr("Stop"));
    connect(m_stopAction, &QAction::triggered, this, &MainWindow::stopCapture);

    auto *openAction = toolbar->addAction(
        QIcon::fromTheme(QStringLiteral("document-open"),
                         style()->standardIcon(QStyle::SP_DialogOpenButton)),
        tr("Open"));
    connect(openAction, &QAction::triggered, this,
            &MainWindow::openCaptureFile);

    toolbar->addSeparator();
    toolbar->addWidget(new QLabel(tr(" Interface "), toolbar));
    m_interfaceBox = new QComboBox(toolbar);
    m_interfaceBox->setMinimumWidth(160);
    QList<CaptureInterface> interfaces = captureInterfaces();
    // "any" first: capturing on a single interface by accident (loopback is
    // often listed first) is a common surprise.
    std::stable_sort(interfaces.begin(), interfaces.end(),
                     [](const CaptureInterface &lhs, const CaptureInterface &rhs) {
                         return lhs.device == QLatin1String("any")
                             && rhs.device != QLatin1String("any");
                     });
    for (const CaptureInterface &entry : std::as_const(interfaces)) {
        m_interfaceBox->addItem(entry.display, entry.device);
        const int index = m_interfaceBox->count() - 1;
        m_interfaceBox->setItemData(
            index, entry.description.isEmpty()
                       ? entry.device
                       : QStringLiteral("%1\n%2").arg(entry.device,
                                                       entry.description),
            Qt::ToolTipRole);
    }
    toolbar->addWidget(m_interfaceBox);

    toolbar->addWidget(new QLabel(tr(" Filter "), toolbar));
    m_filterEdit = new QLineEdit(toolbar);
    m_filterEdit->setPlaceholderText(tr("BPF, e.g. tcp port 443"));
    m_filterEdit->setClearButtonEnabled(true);
    m_filterEdit->setMinimumWidth(220);
    toolbar->addWidget(m_filterEdit);

    toolbar->addWidget(new QLabel(tr(" Show "), toolbar));
    m_showEdit = new QLineEdit(toolbar);
    m_showEdit->setPlaceholderText(
        tr("proto:http host:10.0 -vlan:100 zone:dmz"));
    m_showEdit->setClearButtonEnabled(true);
    m_showEdit->setMinimumWidth(210);
    m_showEdit->setToolTip(
        tr("Display filter: hides nodes and links without touching the "
           "capture. Keys: proto, host, vlan, zone; prefix a term with '-' "
           "to exclude it."));
    m_showModel = new QStringListModel(this);
    m_showCompleter = new QCompleter(m_showModel, this);
    m_showCompleter->setCaseSensitivity(Qt::CaseInsensitive);
    m_showCompleter->setFilterMode(Qt::MatchContains);
    m_showCompleter->setCompletionMode(QCompleter::PopupCompletion);
    m_showEdit->setCompleter(m_showCompleter);
    connect(m_showEdit, &QLineEdit::textEdited, this, [this] {
        if (m_showCompleter)
            m_showCompleter->complete();
    });
    toolbar->addWidget(m_showEdit);

    auto *helpButton = new QToolButton(toolbar);
    helpButton->setText(QStringLiteral("?"));
    helpButton->setToolTip(tr("Display filter syntax"));
    helpButton->setAutoRaise(true);
    connect(helpButton, &QToolButton::clicked, this,
            &MainWindow::showFilterHelp);
    toolbar->addWidget(helpButton);

    toolbar->addWidget(new QLabel(tr(" Mode "), toolbar));
    m_modeBox = new QComboBox(toolbar);
    m_modeBox->addItems({tr("Link"), tr("IP"), tr("TCP")});
    toolbar->addWidget(m_modeBox);
    connect(m_modeBox, &QComboBox::currentIndexChanged, this, [this](int index) {
        setMode(static_cast<Mode>(index));
    });

    m_sourceLabel = new QLabel(this);
    m_countersLabel = new QLabel(this);
    m_graphLabel = new QLabel(this);
    statusBar()->addWidget(m_sourceLabel, 1);
    statusBar()->addPermanentWidget(m_graphLabel);
    statusBar()->addPermanentWidget(m_countersLabel);
}

void MainWindow::buildMenus()
{
    auto *fileMenu = menuBar()->addMenu(tr("&File"));
    auto *openAction = fileMenu->addAction(
        QIcon::fromTheme(QStringLiteral("document-open")),
        tr("Open Capture &File…"));
    openAction->setShortcut(QKeySequence::Open);
    connect(openAction, &QAction::triggered, this,
            &MainWindow::openCaptureFile);
    auto *exportAction = fileMenu->addAction(tr("&Export Graph as XML…"));
    exportAction->setShortcut(QKeySequence(QStringLiteral("Ctrl+E")));
    connect(exportAction, &QAction::triggered, this, &MainWindow::exportXml);

    fileMenu->addSeparator();
    auto *saveLayoutAction = fileMenu->addAction(tr("Save &Layout…"));
    connect(saveLayoutAction, &QAction::triggered, this,
            &MainWindow::saveLayoutAs);
    auto *openLayoutAction = fileMenu->addAction(tr("Load Layout…"));
    connect(openLayoutAction, &QAction::triggered, this,
            &MainWindow::openLayout);

    fileMenu->addSeparator();
    auto *quitAction = fileMenu->addAction(tr("&Quit"));
    quitAction->setShortcut(QKeySequence::Quit);
    connect(quitAction, &QAction::triggered, this, &QWidget::close);

    auto *captureMenu = menuBar()->addMenu(tr("&Capture"));
    captureMenu->addAction(m_startAction);
    captureMenu->addAction(m_stopAction);
    m_startAction->setShortcut(QKeySequence(Qt::Key_F5));
    m_stopAction->setShortcut(QKeySequence(Qt::SHIFT | Qt::Key_F5));
    captureMenu->addSeparator();
    auto *clearAction = captureMenu->addAction(tr("&Clear Graph"));
    clearAction->setShortcut(QKeySequence(QStringLiteral("Ctrl+L")));
    connect(clearAction, &QAction::triggered, this, &MainWindow::resetGraph);

    auto *viewMenu = menuBar()->addMenu(tr("&View"));
    auto *modeMenu = viewMenu->addMenu(tr("&Mode"));
    auto *group = new QActionGroup(this);
    group->setExclusive(true);
    const QStringList names = {tr("Link"), tr("IP"), tr("TCP")};
    for (int i = 0; i < names.size(); ++i) {
        auto *action = modeMenu->addAction(names[i]);
        action->setCheckable(true);
        action->setData(i);
        action->setChecked(i == static_cast<int>(m_mode));
        group->addAction(action);
        connect(action, &QAction::triggered, this, [this, i] {
            setMode(static_cast<Mode>(i));
            m_modeBox->setCurrentIndex(i);
        });
    }

    viewMenu->addSeparator();
    m_numericAction = viewMenu->addAction(tr("&Numeric Addresses"));
    m_numericAction->setCheckable(true);
    m_numericAction->setShortcut(QKeySequence(QStringLiteral("Ctrl+N")));
    connect(m_numericAction, &QAction::toggled, this, [this](bool checked) {
        setNumeric(checked);
    });

    m_legendAction = viewMenu->addAction(tr("Protocol &Legend"));
    m_legendAction->setCheckable(true);
    m_legendAction->setChecked(true);
    connect(m_legendAction, &QAction::toggled, this, [this](bool checked) {
        m_graph->setLegendVisible(checked);
        QSettings().setValue(QStringLiteral("view/legend"), checked);
    });

    m_zonesAction = viewMenu->addAction(tr("Zone &Clouds"));
    m_zonesAction->setCheckable(true);
    m_zonesAction->setChecked(true);
    connect(m_zonesAction, &QAction::toggled, this, [this](bool checked) {
        m_graph->setZonesVisible(checked);
        QSettings().setValue(QStringLiteral("view/zones"), checked);
    });

    auto *conversationsAction = viewMenu->addAction(tr("&Conversations…"));
    conversationsAction->setShortcut(QKeySequence(QStringLiteral("Ctrl+T")));
    connect(conversationsAction, &QAction::triggered, this,
            &MainWindow::showConversations);

    viewMenu->addSeparator();
    m_resolveAction = viewMenu->addAction(tr("&Resolve Names (DNS)"));
    m_resolveAction->setCheckable(true);
    connect(m_resolveAction, &QAction::toggled, this,
            &MainWindow::setResolveNames);

    m_mergeAction = viewMenu->addAction(tr("&Merge IPv4/IPv6 Hosts"));
    m_mergeAction->setCheckable(true);
    connect(m_mergeAction, &QAction::toggled, this,
            &MainWindow::setMergeFamilies);

    auto *findAction = viewMenu->addAction(tr("&Find Node…"));
    findAction->setShortcut(QKeySequence::Find);
    connect(findAction, &QAction::triggered, this, &MainWindow::findNode);

    auto *resetZoom = viewMenu->addAction(tr("Reset &Zoom"));
    resetZoom->setShortcut(QKeySequence(QStringLiteral("Ctrl+0")));
    connect(resetZoom, &QAction::triggered, m_graph, &GraphView::resetView);

    auto *settingsMenu = menuBar()->addMenu(tr("&Settings"));
    auto *prefsAction = settingsMenu->addAction(tr("&Preferences…"));
    prefsAction->setShortcut(QKeySequence::Preferences);
    connect(prefsAction, &QAction::triggered, this,
            &MainWindow::showPreferences);

    auto *helpMenu = menuBar()->addMenu(tr("&Help"));
    auto *aboutAction = helpMenu->addAction(tr("&About EtherApe 2026"));
    connect(aboutAction, &QAction::triggered, this, &MainWindow::showAbout);
    helpMenu->addAction(tr("About &Qt"), qApp, &QApplication::aboutQt);
}

void MainWindow::loadSettings()
{
    QSettings settings;
    restoreGeometry(settings.value(QStringLiteral("window/geometry")).toByteArray());

    const int nodeLimit =
        settings.value(QStringLiteral("graph/nodeLimit"), 300).toInt();
    const double decay =
        settings.value(QStringLiteral("graph/decaySeconds"), 4.0).toDouble();
    const double fontScale =
        settings.value(QStringLiteral("graph/fontScale"), 1.0).toDouble();
    m_replaySpeed = settings.value(QStringLiteral("capture/replaySpeed"), 100).toInt();
    m_resolveNames =
        settings.value(QStringLiteral("names/resolve"), false).toBool();
    m_usePolkit =
        settings.value(QStringLiteral("capture/usePolkit"), false).toBool();
    m_mergeFamilies =
        settings.value(QStringLiteral("graph/mergeFamilies"), true).toBool();
    m_dnsOnly = settings.value(QStringLiteral("names/dnsOnly"), false).toBool();
    m_language = settings.value(QStringLiteral("ui/language")).toString();
    m_model->setMergeFamilies(m_mergeFamilies);
    if (m_mergeAction) {
        const QSignalBlocker blocker(m_mergeAction);
        m_mergeAction->setChecked(m_mergeFamilies);
    }
    m_numeric = settings.value(QStringLiteral("names/numeric"), false).toBool();
    m_localZones = settings
                       .value(QStringLiteral("zones/local"),
                              QStringLiteral("10.0.0.0/8, 172.16.0.0/12, "
                                             "192.168.0.0/16, 169.254.0.0/16, "
                                             "127.0.0.0/8, fc00::/7, "
                                             "fe80::/10, ::1/128"))
                       .toString();
    m_dmzZones = settings.value(QStringLiteral("zones/dmz")).toString();
    m_vpnZones = settings.value(QStringLiteral("zones/vpn")).toString();
    applyZoneRules();

    const bool zones = settings.value(QStringLiteral("view/zones"), true).toBool();
    m_graph->setZonesVisible(zones);
    if (m_zonesAction)
        m_zonesAction->setChecked(zones);

    const bool legend =
        settings.value(QStringLiteral("view/legend"), true).toBool();
    m_graph->setLegendVisible(legend);
    if (m_legendAction)
        m_legendAction->setChecked(legend);

    m_mode = static_cast<Mode>(
        settings.value(QStringLiteral("capture/mode"), 1).toInt());
    m_modeBox->setCurrentIndex(static_cast<int>(m_mode));

    // 'interface' is a keyword on Windows (combaseapi.h), hence the name.
    // 'interface' is a keyword on Windows (combaseapi.h), hence the name.
    const QString interfaceName =
        settings.value(QStringLiteral("capture/interface")).toString();
    int selected = interfaceName.isEmpty()
        ? -1
        : m_interfaceBox->findData(interfaceName);
    if (selected < 0) {
        selected = m_interfaceBox->findData(QStringLiteral("any"));
        if (selected < 0) {
            // Fall back to the first device that is not a loopback adapter
            // (Windows names it "Adapter for loopback traffic capture", the
            // technical name still contains NPF_Loopback).
            for (int i = 0; i < m_interfaceBox->count(); ++i) {
                const QString device = m_interfaceBox->itemData(i).toString();
                const QString display = m_interfaceBox->itemText(i);
                const bool loopback =
                    display.contains(QLatin1String("loopback"),
                                     Qt::CaseInsensitive)
                    || device.contains(QLatin1String("Loopback"),
                                       Qt::CaseInsensitive)
                    || device == QLatin1String("lo")
                    || device.startsWith(QLatin1String("lo"));
                if (!loopback) {
                    selected = i;
                    break;
                }
            }
        }
    }
    if (selected >= 0)
        m_interfaceBox->setCurrentIndex(selected);
    m_filterEdit->setText(
        settings.value(QStringLiteral("capture/filter")).toString());

    m_model->setNodeLimit(nodeLimit);
    m_model->setDecaySeconds(decay);
    m_graph->setFontScale(fontScale);
    {
        const QSignalBlocker blocker(m_numericAction);
        m_numericAction->setChecked(m_numeric);
    }
    if (m_resolveAction) {
        const QSignalBlocker blocker(m_resolveAction);
        m_resolveAction->setChecked(m_resolveNames);
    }
}

void MainWindow::saveSettings()
{
    QSettings settings;
    settings.setValue(QStringLiteral("window/geometry"), saveGeometry());
    settings.setValue(QStringLiteral("graph/nodeLimit"), m_model->nodeLimit());
    settings.setValue(QStringLiteral("graph/decaySeconds"),
                      m_model->decaySeconds());
    settings.setValue(QStringLiteral("graph/fontScale"), m_graph->fontScale());
    settings.setValue(QStringLiteral("capture/replaySpeed"), m_replaySpeed);
    settings.setValue(QStringLiteral("capture/mode"), static_cast<int>(m_mode));
    settings.setValue(QStringLiteral("capture/interface"),
                      m_interfaceBox->currentData().toString());
    settings.setValue(QStringLiteral("capture/filter"), m_filterEdit->text());
    settings.setValue(QStringLiteral("names/resolve"), m_resolveNames);
    settings.setValue(QStringLiteral("names/numeric"), m_numeric);
    settings.setValue(QStringLiteral("capture/usePolkit"), m_usePolkit);
    settings.setValue(QStringLiteral("graph/mergeFamilies"), m_mergeFamilies);
    settings.setValue(QStringLiteral("names/dnsOnly"), m_dnsOnly);
    settings.setValue(QStringLiteral("zones/local"), m_localZones);
    settings.setValue(QStringLiteral("zones/dmz"), m_dmzZones);
    settings.setValue(QStringLiteral("zones/vpn"), m_vpnZones);
}

void MainWindow::showPreferences()
{
    PreferencesDialog::Values values;
    values.nodeLimit = m_model->nodeLimit();
    values.decaySeconds = m_model->decaySeconds();
    values.resolveNames = m_resolveNames;
    values.fontScale = m_graph->fontScale();
    values.replaySpeed = m_replaySpeed;
    values.usePolkit = m_usePolkit;
    values.mergeFamilies = m_mergeFamilies;
    values.dnsOnly = m_dnsOnly;
    values.language = m_language;
    values.localZones = m_localZones;
    values.dmzZones = m_dmzZones;
    values.vpnZones = m_vpnZones;

    PreferencesDialog dialog(values, this);
    if (dialog.exec() != QDialog::Accepted)
        return;

    const auto updated = dialog.values();
    m_model->setNodeLimit(updated.nodeLimit);
    m_model->setDecaySeconds(updated.decaySeconds);
    m_resolveNames = updated.resolveNames;
    if (m_resolveAction) {
        const QSignalBlocker blocker(m_resolveAction);
        m_resolveAction->setChecked(m_resolveNames);
    }
    m_replaySpeed = updated.replaySpeed;
    m_usePolkit = updated.usePolkit;
    m_mergeFamilies = updated.mergeFamilies;
    m_dnsOnly = updated.dnsOnly;
    if (updated.language != m_language) {
        m_language = updated.language;
        QSettings().setValue(QStringLiteral("ui/language"), m_language);
        statusBar()->showMessage(
            tr("Language will change at the next start."), 6000);
    }
    m_model->setMergeFamilies(m_mergeFamilies);
    if (m_mergeAction) {
        const QSignalBlocker blocker(m_mergeAction);
        m_mergeAction->setChecked(m_mergeFamilies);
    }
    m_localZones = updated.localZones;
    m_dmzZones = updated.dmzZones;
    m_vpnZones = updated.vpnZones;
    applyZoneRules();
    m_graph->setFontScale(updated.fontScale);
    saveSettings();
    updateStatus();
}

void MainWindow::applyZoneRules()
{
    ZoneClassifier classifier;
    if (!m_localZones.trimmed().isEmpty())
        classifier.setRulesFromText(ZoneId::Local, m_localZones);
    classifier.setRulesFromText(ZoneId::Dmz, m_dmzZones);
    classifier.setRulesFromText(ZoneId::Vpn, m_vpnZones);
    m_model->setZoneClassifier(classifier);
}

void MainWindow::setMode(Mode mode)
{
    if (m_mode == mode)
        return;
    m_mode = mode;

    if (m_running && m_replayFile.isEmpty()) {
        // Live capture: restart so the worker decodes with the new mode.
        m_restartPending = true;
        m_worker->requestStop();
    } else if (m_running) {
        statusBar()->showMessage(
            tr("Mode will apply to the next capture."), 4000);
    }
}

void MainWindow::setNumeric(bool numeric)
{
    m_numeric = numeric;
    // "numeric" only controls the display: the resolve preference is kept
    // as-is (maybeResolve already ignores it while numeric is on). Tying the
    // two together used to reset the saved preference at every start.
    if (m_numericAction->isChecked() != numeric) {
        const QSignalBlocker blocker(m_numericAction);
        m_numericAction->setChecked(numeric);
    }
    saveSettings();  // this was the only toggle that was never persisted
    updateStatus();
}

void MainWindow::setResolveNames(bool enabled)
{
    m_resolveNames = enabled;
    // The two options contradict each other: asking for names while 'numeric'
    // is on would silently do nothing, which is exactly how a working DNS
    // setup looks broken.
    if (enabled && m_numeric) {
        m_numeric = false;
        if (m_numericAction) {
            const QSignalBlocker blocker(m_numericAction);
            m_numericAction->setChecked(false);
        }
    }
    if (m_resolveAction && m_resolveAction->isChecked() != enabled) {
        const QSignalBlocker blocker(m_resolveAction);
        m_resolveAction->setChecked(enabled);
    }
    saveSettings();
    statusBar()->showMessage(
        enabled ? tr("Reverse DNS enabled for new nodes.")
                : tr("Reverse DNS disabled."),
        3000);
}

void MainWindow::setMergeFamilies(bool enabled)
{
    m_mergeFamilies = enabled;
    if (m_mergeAction && m_mergeAction->isChecked() != enabled) {
        const QSignalBlocker blocker(m_mergeAction);
        m_mergeAction->setChecked(enabled);
    }
    m_model->setMergeFamilies(enabled);
    saveSettings();
    statusBar()->showMessage(
        enabled ? tr("IPv4/IPv6 addresses of the same host are merged.")
                : tr("IPv4/IPv6 addresses are kept as separate nodes."),
        4000);
}

void MainWindow::applyDisplayFilter()
{
    if (!m_showEdit)
        return;
    m_displayFilter = DisplayFilter(m_showEdit->text());
    m_graph->setDisplayFilter(m_displayFilter);
    m_stats->refresh(*m_model, m_displayFilter);

    // Tell the user when a term was not understood instead of silently
    // showing everything (e.g. a typo in a key name).
    const QStringList warnings = m_displayFilter.warnings();
    if (warnings.isEmpty()) {
        m_showEdit->setStyleSheet(QString());
        m_showEdit->setToolTip(
            tr("Display filter: proto, host, vlan, zone; '-' excludes."));
    } else {
        m_showEdit->setStyleSheet(
            QStringLiteral("QLineEdit { background: rgba(220,80,60,60); }"));
        m_showEdit->setToolTip(
            tr("Not understood: %1\n\nUse proto:, host:, vlan:, zone: "
               "(or = instead of :). Click ? for help.")
                .arg(warnings.join(QStringLiteral(", "))));
    }
    updateShowCompletions();
    updateStatus();
}

void MainWindow::showFilterHelp()
{
    QString text = tr("<b>Display filter</b><br><br>"
                      "Hides nodes and links; the capture keeps running and "
                      "counters keep accumulating.<br><br>");
    text += tr("Keys (both <code>key:value</code> and "
               "<code>key=value</code> work):<br><ul>");
    for (const QString &line : DisplayFilter::keyHelp())
        text += QStringLiteral("<li><code>%1</code></li>").arg(line.toHtmlEscaped());
    text += tr("</ul>Several terms are combined with AND; prefix one with "
               "<code>-</code> to exclude it.<br><br>"
               "Examples: <code>hostname=manux</code>, "
               "<code>proto:http -vlan:100</code>, "
               "<code>zone:dmz</code>.");
    QMessageBox::information(this, tr("Display filter"), text);
}

void MainWindow::updateShowCompletions()
{
    if (!m_showModel)
        return;
    QStringList words{QStringLiteral("proto:"), QStringLiteral("host:"),
                      QStringLiteral("vlan:"), QStringLiteral("zone:")};
    const auto protocols = m_model->protocols();
    for (auto it = protocols.constBegin(); it != protocols.constEnd(); ++it)
        words.append(QStringLiteral("proto:") + it.key());
    words << QStringLiteral("zone:LAN") << QStringLiteral("zone:DMZ")
          << QStringLiteral("zone:VPN") << QStringLiteral("zone:Internet");
    for (int vlan : m_model->vlanIds())
        words.append(QStringLiteral("vlan:%1").arg(vlan));
    int count = 0;
    for (const auto &node : m_model->nodes()) {
        const QString name = node.label.isEmpty() ? node.id : node.label;
        words.append(QStringLiteral("host:") + name);
        if (!node.id.isEmpty() && node.id != name)
            words.append(QStringLiteral("host=") + node.id);
        if (++count >= 80)
            break;
    }
    words.removeDuplicates();
    m_showModel->setStringList(words);
}

void MainWindow::findNode()
{
    bool accepted = false;
    const QString text = QInputDialog::getText(
        this, tr("Find node"),
        tr("Node name, address or protocol (current display filter applies):"),
        QLineEdit::Normal, QString(), &accepted);
    if (!accepted || text.trimmed().isEmpty())
        return;

    const QString needle = text.trimmed();
    for (const auto &node : m_model->nodes()) {
        const bool hit = node.id.contains(needle, Qt::CaseInsensitive)
            || node.label.contains(needle, Qt::CaseInsensitive);
        if (!hit)
            continue;
        m_graph->selectNode(node.id);
        m_graph->centerOnNode(node.id);
        statusBar()->showMessage(tr("Found %1").arg(node.id), 3000);
        return;
    }
    statusBar()->showMessage(tr("No node matches \"%1\".").arg(needle), 4000);
}

void MainWindow::updateTraffic()
{
    const quint64 delta =
        m_bytes >= m_lastTrafficBytes ? m_bytes - m_lastTrafficBytes : 0;
    m_lastTrafficBytes = m_bytes;
    // Counters arrive in bursts (whole replay files): spread them over the
    // sampling interval so the curve stays readable.
    m_stats->addTrafficSample(static_cast<double>(delta));
}

void MainWindow::loadEthers()
{
    // The original EtherApe read /etc/ethers to name MAC addresses; keep it
    // for link mode, where there is no DNS to ask.
    QFile file(QStringLiteral("/etc/ethers"));
    if (!file.open(QIODevice::ReadOnly))
        return;
    while (!file.atEnd()) {
        const QByteArray line = file.readLine().trimmed();
        if (line.isEmpty() || line.startsWith('#'))
            continue;
        const QList<QByteArray> parts =
            line.simplified().split(' ');
        if (parts.size() < 2)
            continue;
        const QString mac = QString::fromLatin1(parts.at(0)).toUpper();
        const QString name = QString::fromLatin1(parts.at(1));
        m_ethers.insert(mac, name);
    }
}

void MainWindow::setNodeLimit(int limit)
{
    m_model->setNodeLimit(limit);
}

void MainWindow::setFilter(const QString &filter)
{
    m_filterEdit->setText(filter);
}

void MainWindow::selectNode(const QString &id)
{
    m_graph->selectNode(id);
    m_graph->centerOnNode(id);
    m_stats->setSelectedNode(id);
    m_stats->refresh(*m_model, m_displayFilter);
}

void MainWindow::setDisplayFilterExpression(const QString &expression)
{
    m_showEdit->setText(expression);
    applyDisplayFilter();
}

void MainWindow::startLiveCapture(const QString &device)
{
    const int index = m_interfaceBox->findData(device);
    if (index >= 0)
        m_interfaceBox->setCurrentIndex(index);
    startCapture();
}

void MainWindow::startReplay(const QString &file, int speedPercent)
{
    if (file.isEmpty())
        return;
    resetGraph();
    m_replayFile = file;
    m_replaySpeed = speedPercent;
    m_worker->requestStop();  // in case something is still running
    QMetaObject::invokeMethod(
        m_worker.data(), "openOffline", Qt::QueuedConnection, Q_ARG(QString, file),
        Q_ARG(QString, m_filterEdit->text()), Q_ARG(int, static_cast<int>(m_mode)),
        Q_ARG(int, speedPercent));
}

void MainWindow::startCapture()
{
    if (m_running)
        return;
    const QString device = m_interfaceBox->currentData().toString().trimmed();
    if (device.isEmpty()) {
        statusBar()->showMessage(tr("No capture interface available."), 5000);
        return;
    }

    resetGraph();
    m_replayFile.clear();
    m_pendingDevice = device;
    m_worker->requestStop();
    if (m_usePolkit) {
        QMetaObject::invokeMethod(
            m_worker.data(), "openPrivileged", Qt::QueuedConnection,
            Q_ARG(QString, device), Q_ARG(QString, m_filterEdit->text()),
            Q_ARG(int, static_cast<int>(m_mode)));
    } else {
        QMetaObject::invokeMethod(
            m_worker.data(), "openLive", Qt::QueuedConnection, Q_ARG(QString, device),
            Q_ARG(QString, m_filterEdit->text()),
            Q_ARG(int, static_cast<int>(m_mode)));
    }
}

void MainWindow::onPermissionDenied(const QString &device,
                                    const QString &message)
{
#ifdef Q_OS_WIN
    // Windows has no pkexec: relaunch the whole application elevated (UAC),
    // Npcap then opens the capture without further prompts.
    const auto relaunch = QMessageBox::question(
        this, tr("Administrator rights required"),
        tr("Capturing on \"%1\" requires administrator rights:\n%2\n\n"
           "Restart EtherApe 2026 elevated?")
            .arg(device, message),
        QMessageBox::Yes | QMessageBox::No, QMessageBox::Yes);
    if (relaunch != QMessageBox::Yes) {
        updateStatus();
        return;
    }
    const std::wstring exe = QDir::toNativeSeparators(
                                 QCoreApplication::applicationFilePath())
                                 .toStdWString();
    SHELLEXECUTEINFOW info = {};
    info.cbSize = sizeof(info);
    info.fMask = SEE_MASK_NOCLOSEPROCESS;
    info.lpVerb = L"runas";
    info.lpFile = exe.c_str();
    info.nShow = SW_SHOWNORMAL;
    if (ShellExecuteExW(&info))
        QCoreApplication::quit();
    else
        statusBar()->showMessage(tr("Elevation was cancelled."), 6000);
#else
    const auto answer = QMessageBox::question(
        this, tr("Root privileges required"),
        tr("Capturing on \"%1\" was denied:\n%2\n\n"
           "Elevate through polkit? The password is asked once per "
           "application session: the privileged helper is then reused by "
           "Start/Stop, and the GUI itself stays unprivileged.")
            .arg(device, message),
        QMessageBox::Yes | QMessageBox::No, QMessageBox::Yes);

    if (answer != QMessageBox::Yes) {
        updateStatus();
        return;
    }

    m_usePolkit = true;
    saveSettings();
    resetGraph();
    m_pendingDevice = device;
    QMetaObject::invokeMethod(
        m_worker.data(), "openPrivileged", Qt::QueuedConnection, Q_ARG(QString, device),
        Q_ARG(QString, m_filterEdit->text()),
        Q_ARG(int, static_cast<int>(m_mode)));
#endif
}

void MainWindow::stopCapture()
{
    m_restartPending = false;
    if (m_worker)
        m_worker->requestStop();
}

void MainWindow::openCaptureFile()
{
    const QString file = QFileDialog::getOpenFileName(
        this, tr("Open capture file"), QString(),
        tr("Capture files (*.pcap *.pcapng *.cap);;All files (*)"));
    if (file.isEmpty())
        return;
    startReplay(file, m_replaySpeed);
}

void MainWindow::resetGraph()
{
    m_graph->setCaptureActive(false);
    m_model->clear();
    m_packets = 0;
    m_bytes = 0;
    m_nameCache.clear();
    m_pendingNames.clear();
    m_sourceText.clear();
    m_stats->clearTraffic();
    m_stats->refresh(*m_model, m_displayFilter);
    m_lastTrafficBytes = 0;
    updateStatus();
}

void MainWindow::onBatch(const QList<etherape::PacketInfo> &batch)
{
    if (batch.isEmpty())
        return;

    m_model->addBatch(batch, QDateTime::currentMSecsSinceEpoch());

    for (const auto &packet : batch) {
        // /etc/ethers: static MAC -> name mapping, as in the original.
        if (!m_ethers.isEmpty()) {
            if (qEnvironmentVariableIsSet("ETHERAPE_DEBUG")
                && m_ethers.contains(packet.src.id))
                std::fprintf(stderr, "[etherape] ethers: %s -> %s\n",
                             packet.src.id.toLocal8Bit().constData(),
                             m_ethers.value(packet.src.id)
                                 .toLocal8Bit().constData());
            if (packet.src.kind == NodeKind::Mac) {
                const auto it = m_ethers.constFind(packet.src.id);
                if (it != m_ethers.constEnd())
                    m_model->setLabel(packet.src.id, *it,
                                      QStringLiteral("ethers"));
            }
            if (packet.dst.kind == NodeKind::Mac) {
                const auto it = m_ethers.constFind(packet.dst.id);
                if (it != m_ethers.constEnd())
                    m_model->setLabel(packet.dst.id, *it,
                                      QStringLiteral("ethers"));
            }
        }
        // Passive NetBIOS name service: names Windows hosts announce anyway.
        if (!packet.nbName.isEmpty() && !packet.nbIp.isEmpty()) {
            if (qEnvironmentVariableIsSet("ETHERAPE_DEBUG"))
                std::fprintf(stderr, "[etherape] netbios: %s -> %s\n",
                             packet.nbIp.toLocal8Bit().constData(),
                             packet.nbName.toLocal8Bit().constData());
            m_nameCache.insert(packet.nbIp, packet.nbName);
            m_model->setLabel(packet.nbIp, packet.nbName,
                              QStringLiteral("netbios"));
        }
        if (!packet.src.id.isEmpty())
            maybeResolve(packet.src.id, packet.src.kind);
        if (!packet.dst.id.isEmpty())
            maybeResolve(packet.dst.id, packet.dst.kind);
        if (m_pendingNames.size() >= kMaxPendingLookups)
            break;
    }
}

void MainWindow::maybeResolve(const QString &id, NodeKind kind)
{
    if (!m_resolveNames || m_numeric)
        return;
    if (kind != NodeKind::Ipv4 && kind != NodeKind::Ipv6)
        return;
    if (m_nameCache.contains(id) || m_pendingNames.contains(id))
        return;

    m_pendingNames.insert(id);

    if (m_dnsOnly) {
        // QDnsLookup asks the DNS directly: no NSS, no LDAP, no /etc/hosts.
        auto *lookup = new QDnsLookup(QDnsLookup::PTR, id, this);
        connect(lookup, &QDnsLookup::finished, this, [this, id, lookup] {
            m_pendingNames.remove(id);
            QString name;
            if (lookup->error() == QDnsLookup::NoError
                && !lookup->pointerRecords().isEmpty()) {
                name = lookup->pointerRecords().first().value();
            }
            lookup->deleteLater();
            if (name.isEmpty() || name == id) {
                m_nameCache.insert(id, QString());
                return;
            }
            if (name.endsWith(QLatin1Char('.')))
                name.chop(1);
            m_nameCache.insert(id, name);
            m_model->setLabel(id, name, QStringLiteral("dns"));
        });
        lookup->lookup();
        return;
    }

    QHostInfo::lookupHost(id, this, [this, id](const QHostInfo &info) {
        m_pendingNames.remove(id);
        if (info.error() != QHostInfo::NoError) {
            m_nameCache.insert(id, QString());
            if (qEnvironmentVariableIsSet("ETHERAPE_DEBUG"))
                std::fprintf(stderr, "[etherape] dns: %s -> (no PTR)\n",
                             id.toLocal8Bit().constData());
            return;
        }
        QString name = info.hostName();
        if (qEnvironmentVariableIsSet("ETHERAPE_DEBUG"))
            std::fprintf(stderr, "[etherape] dns: %s -> %s\n",
                         id.toLocal8Bit().constData(),
                         name.toLocal8Bit().constData());
        if (name.isEmpty() || name == id) {
            m_nameCache.insert(id, QString());
            return;
        }
        // Keep the full name (the view elides long labels): cutting at the
        // first dot turned "dns.google" into "dns" and "one.one.one.one"
        // into "one", which is both wrong and ambiguous.
        if (name.endsWith(QLatin1Char('.')))
            name.chop(1);
        m_nameCache.insert(id, name);
        m_model->setLabel(id, name);
    });
}

void MainWindow::onCaptureStarted(const QString &source)
{
    m_graph->setCaptureActive(true);
    m_running = true;
    m_sourceText =
        m_replayFile.isEmpty() ? source : QFileInfo(source).fileName();
    setRunning(true);
    updateStatus();
}

void MainWindow::onCaptureStopped()
{
    m_graph->setCaptureActive(false);
    const bool replayEnded = !m_replayFile.isEmpty();
    m_running = false;
    setRunning(false);

    // --final-export: dump the graph at the end of a replay, then exit.
    if (replayEnded && !m_finalExportPath.isEmpty()) {
        QString error;
        if (!writeExport(m_finalExportPath, &error))
            statusBar()->showMessage(tr("Final export failed: %1").arg(error));
        else
            statusBar()->showMessage(
                tr("Exported to %1").arg(m_finalExportPath), 5000);
        m_finalExportPath.clear();
        QTimer::singleShot(0, this, &QWidget::close);
        return;
    }

    if (m_restartPending) {
        m_restartPending = false;
        QTimer::singleShot(0, this, &MainWindow::startCapture);
    }
    updateStatus();
}

void MainWindow::onCaptureError(const QString &message)
{
    statusBar()->showMessage(tr("Capture error: %1").arg(message), 8000);
    if (message.contains(QLatin1String("permission"), Qt::CaseInsensitive)
        || message.contains(QLatin1String("Operation not permitted"),
                            Qt::CaseInsensitive)) {
        QMessageBox::warning(
            this, tr("Capture denied"),
            tr("libpcap needs CAP_NET_RAW. Either run as root or grant the "
               "capability once:\n\nsudo setcap cap_net_raw,cap_net_admin+eip "
               "%1")
                .arg(QApplication::applicationFilePath()));
    }
}

void MainWindow::onCounters(quint64 packets, quint64 bytes)
{
    m_packets = packets;
    m_bytes = bytes;
    updateStatus();
}

void MainWindow::refreshView()
{
    m_stats->clearTraffic();
    m_stats->refresh(*m_model, m_displayFilter);
    m_lastTrafficBytes = 0;
    updateStatus();
}

void MainWindow::setRunning(bool running)
{
    m_running = running;
    m_startAction->setEnabled(!running);
    m_stopAction->setEnabled(running);
    m_interfaceBox->setEnabled(!running);
}

void MainWindow::updateStatus()
{
    const QString source =
        m_sourceText.isEmpty() ? tr("idle") : m_sourceText;
    m_sourceLabel->setText(source);
    m_countersLabel->setText(
        tr("%1 packets · %2").arg(m_packets).arg(humanBytes(m_bytes)));
    m_graphLabel->setText(tr("%1 nodes · %2 links")
                              .arg(m_model->nodes().size())
                              .arg(m_model->links().size()));
}

void MainWindow::requestStopCapture()
{
    stopCapture();
}

void MainWindow::requestStartCapture()
{
    startCapture();
}

void MainWindow::setFinalExport(const QString &path)
{
    m_finalExportPath = path;
}

void MainWindow::loadLayoutFile(const QString &path)
{
    QString error;
    if (!m_model->loadLayout(path, &error))
        statusBar()->showMessage(tr("Cannot load layout: %1").arg(error), 6000);
}

void MainWindow::exportXml()
{
    QString path = QFileDialog::getSaveFileName(
        this, tr("Export graph"), QStringLiteral("etherape.xml"),
        tr("XML files (*.xml);;JSON files (*.json);;All files (*)"));
    if (path.isEmpty())
        return;

    QString error;
    if (writeExport(path, &error))
        statusBar()->showMessage(tr("Exported to %1").arg(path), 5000);
    else
        QMessageBox::warning(this, tr("Export failed"), error);
}

bool MainWindow::writeExport(const QString &path, QString *error)
{
    if (path.endsWith(QLatin1String(".json"), Qt::CaseInsensitive))
        return exportGraphJson(*m_model, path, m_sourceText, error);
    return exportGraphXml(*m_model, path, m_sourceText, error);
}

void MainWindow::saveLayoutAs()
{
    const QString path = QFileDialog::getSaveFileName(
        this, tr("Save node layout"), QStringLiteral("etherape-layout.json"),
        tr("JSON files (*.json);;All files (*)"));
    if (path.isEmpty())
        return;

    QString error;
    if (m_model->saveLayout(path, &error))
        statusBar()->showMessage(tr("Layout saved to %1").arg(path), 5000);
    else
        QMessageBox::warning(this, tr("Save failed"), error);
}

void MainWindow::openLayout()
{
    const QString path = QFileDialog::getOpenFileName(
        this, tr("Load node layout"), QString(),
        tr("JSON files (*.json);;All files (*)"));
    if (path.isEmpty())
        return;
    loadLayoutFile(path);
}

void MainWindow::showConversations()
{
    if (!m_conversations) {
        m_conversations = new ConversationsDialog(m_model, this);
        m_conversations->setAttribute(Qt::WA_DeleteOnClose);
        connect(m_conversations, &ConversationsDialog::nodeActivated, this,
                [this](const QString &id) {
                    m_graph->selectNode(id);
                    raise();
                    activateWindow();
                });
        connect(m_conversations, &QObject::destroyed, this,
                [this] { m_conversations = nullptr; });
    }
    m_conversations->show();
    m_conversations->raise();
    m_conversations->activateWindow();
}

void MainWindow::showAbout()
{
    QMessageBox::about(
        this, tr("About EtherApe 2026"),
        tr("<h3>EtherApe 2026 %1</h3>"
           "<p>Graphical network traffic monitor, Qt 6 port of EtherApe.</p>"
           "<p>Original EtherApe © 2001 Juan Toledo, Riccardo Ghetta and "
           "contributors.<br>"
           "This port: GPL-2.0-or-later.</p>"
           "<p>Capture powered by libpcap.</p>")
            .arg(QLatin1String(APP_VERSION)));
}

void MainWindow::closeEvent(QCloseEvent *event)
{
    saveSettings();
    if (!m_finalExportPath.isEmpty()) {
        QString error;
        if (!writeExport(m_finalExportPath, &error))
            statusBar()->showMessage(tr("Final export failed: %1").arg(error));
    }
    if (m_worker)
        m_worker->requestStop();
    if (m_captureThread) {
        m_captureThread->quit();
        m_captureThread->wait(3000);
    }
    event->accept();
}

} // namespace etherape

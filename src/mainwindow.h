// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include "decoder.h"
#include "displayfilter.h"
#include "preferencesdialog.h"

#include <QHash>
#include <QMainWindow>
#include <QPointer>
#include <QSet>
#include <QString>

class QAction;
class QComboBox;
class QCompleter;
class QStringListModel;
class QLabel;
class QLineEdit;
class QThread;
class QTimer;

namespace etherape {

class CaptureWorker;
class ConversationsDialog;
class GraphModel;
class GraphView;
class StatsPanel;

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow() override;

    void setMode(Mode mode);
    void setNumeric(bool numeric);
    void setNodeLimit(int limit);
    void setFilter(const QString &filter);
    void setDisplayFilterExpression(const QString &expression);
    void selectNode(const QString &id);
    void startLiveCapture(const QString &device);
    void startReplay(const QString &file, int speedPercent);
    void setFinalExport(const QString &path);
    void requestStopCapture();
    void requestStartCapture();
    void loadLayoutFile(const QString &path);

protected:
    void closeEvent(QCloseEvent *event) override;

private slots:
    void startCapture();
    void stopCapture();
    void openCaptureFile();
    void showPreferences();
    void onBatch(const QList<etherape::PacketInfo> &batch);
    void onCaptureStarted(const QString &source);
    void onCaptureStopped();
    void onCaptureError(const QString &message);
    void onPermissionDenied(const QString &device, const QString &message);
    void onCounters(quint64 packets, quint64 bytes);
    void refreshView();
    void showAbout();
    void exportXml();
    bool writeExport(const QString &path, QString *error);
    void saveLayoutAs();
    void openLayout();
    void showConversations();

private:
    void buildUi();
    void buildMenus();
    void loadSettings();
    void saveSettings();
    void resetGraph();
    void setRunning(bool running);
    void updateStatus();
    void setResolveNames(bool enabled);
    void setMergeFamilies(bool enabled);
    void applyDisplayFilter();
    void findNode();
    void updateTraffic();
    void loadEthers();
    void updateShowCompletions();
    void showFilterHelp();
    void applyZoneRules();
    void maybeResolve(const QString &id, NodeKind kind);

    GraphModel *m_model = nullptr;
    GraphView *m_graph = nullptr;
    StatsPanel *m_stats = nullptr;

    QComboBox *m_interfaceBox = nullptr;
    QComboBox *m_modeBox = nullptr;
    QLineEdit *m_filterEdit = nullptr;
    QLineEdit *m_showEdit = nullptr;
    QCompleter *m_showCompleter = nullptr;
    QStringListModel *m_showModel = nullptr;
    QAction *m_startAction = nullptr;
    QAction *m_stopAction = nullptr;
    QAction *m_numericAction = nullptr;
    QAction *m_resolveAction = nullptr;
    QAction *m_mergeAction = nullptr;
    QAction *m_legendAction = nullptr;
    QAction *m_zonesAction = nullptr;
    QLabel *m_sourceLabel = nullptr;
    QLabel *m_countersLabel = nullptr;
    QLabel *m_graphLabel = nullptr;

    QPointer<CaptureWorker> m_worker;
    QThread *m_captureThread = nullptr;
    QTimer *m_refreshTimer = nullptr;
    QTimer *m_filterTimer = nullptr;
    QTimer *m_trafficTimer = nullptr;
    DisplayFilter m_displayFilter;
    QHash<QString, QString> m_ethers;
    quint64 m_lastTrafficBytes = 0;

    Mode m_mode = Mode::Ip;
    bool m_running = false;
    bool m_restartPending = false;
    bool m_numeric = false;
    bool m_resolveNames = false;
    bool m_usePolkit = false;
    bool m_mergeFamilies = true;
    QString m_language;
    QString m_pendingDevice;
    QString m_replayFile;
    int m_replaySpeed = 100;

    quint64 m_packets = 0;
    quint64 m_bytes = 0;
    QString m_sourceText;

    ConversationsDialog *m_conversations = nullptr;
    QString m_finalExportPath;
    QString m_localZones;
    QString m_dmzZones;
    QString m_vpnZones;

    QHash<QString, QString> m_nameCache;
    QSet<QString> m_pendingNames;
};

} // namespace etherape

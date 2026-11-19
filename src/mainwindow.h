// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include "decoder.h"
#include "preferencesdialog.h"

#include <QHash>
#include <QMainWindow>
#include <QSet>
#include <QString>

class QAction;
class QComboBox;
class QLabel;
class QLineEdit;
class QThread;
class QTimer;

namespace etherape {

class CaptureWorker;
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
    void startLiveCapture(const QString &device);
    void startReplay(const QString &file, int speedPercent);

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

private:
    void buildUi();
    void buildMenus();
    void loadSettings();
    void saveSettings();
    void resetGraph();
    void setRunning(bool running);
    void updateStatus();
    void maybeResolve(const QString &id, NodeKind kind);

    GraphModel *m_model = nullptr;
    GraphView *m_graph = nullptr;
    StatsPanel *m_stats = nullptr;

    QComboBox *m_interfaceBox = nullptr;
    QComboBox *m_modeBox = nullptr;
    QLineEdit *m_filterEdit = nullptr;
    QAction *m_startAction = nullptr;
    QAction *m_stopAction = nullptr;
    QAction *m_numericAction = nullptr;
    QLabel *m_sourceLabel = nullptr;
    QLabel *m_countersLabel = nullptr;
    QLabel *m_graphLabel = nullptr;

    CaptureWorker *m_worker = nullptr;
    QThread *m_captureThread = nullptr;
    QTimer *m_refreshTimer = nullptr;

    Mode m_mode = Mode::Ip;
    bool m_running = false;
    bool m_restartPending = false;
    bool m_numeric = false;
    bool m_resolveNames = false;
    bool m_usePolkit = false;
    QString m_pendingDevice;
    QString m_replayFile;
    int m_replaySpeed = 100;

    quint64 m_packets = 0;
    quint64 m_bytes = 0;
    QString m_sourceText;

    QHash<QString, QString> m_nameCache;
    QSet<QString> m_pendingNames;
};

} // namespace etherape

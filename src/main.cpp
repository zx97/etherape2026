// SPDX-License-Identifier: GPL-2.0-or-later
//
// EtherApe 2026 - graphical network traffic monitor, Qt 6 port.

#include "capturehelper.h"
#include "decoder.h"
#include "mainwindow.h"

#include <QApplication>
#include <QCommandLineOption>
#include <QCommandLineParser>
#include <QTimer>

#ifndef APP_VERSION
#define APP_VERSION "1.0.0"
#endif

namespace {

etherape::Mode parseMode(const QString &text, bool *ok)
{
    const QString value = text.trimmed().toLower();
    *ok = true;
    if (value == QLatin1String("link"))
        return etherape::Mode::Link;
    if (value == QLatin1String("ip"))
        return etherape::Mode::Ip;
    if (value == QLatin1String("tcp"))
        return etherape::Mode::Tcp;
    if (value == QLatin1String("mac"))
        return etherape::Mode::Link;
    *ok = false;
    return etherape::Mode::Ip;
}

} // namespace

int main(int argc, char *argv[])
{
    // Privileged capture helper: never creates a GUI, never keeps privileges.
    if (etherape::isCaptureHelperInvocation(argc, argv))
        return etherape::runCaptureHelper(argc, argv);

    QApplication app(argc, argv);
    QApplication::setApplicationName(QStringLiteral("etherape2026"));
    QApplication::setOrganizationName(QStringLiteral("etherape"));
    QApplication::setApplicationVersion(QLatin1String(APP_VERSION));
    QApplication::setDesktopFileName(QStringLiteral("etherape2026"));

    QCommandLineParser parser;
    parser.setApplicationDescription(
        QObject::tr("Graphical network traffic monitor."));
    parser.addHelpOption();
    parser.addVersionOption();

    QCommandLineOption interfaceOption(
        {QStringLiteral("i"), QStringLiteral("interface")},
        QObject::tr("Capture on <device>."), QObject::tr("device"));
    QCommandLineOption replayOption(
        {QStringLiteral("r"), QStringLiteral("replay")},
        QObject::tr("Replay packets from <file>."), QObject::tr("file"));
    QCommandLineOption filterOption(
        {QStringLiteral("f"), QStringLiteral("filter")},
        QObject::tr("Apply the BPF <filter>."), QObject::tr("filter"));
    QCommandLineOption modeOption(
        {QStringLiteral("m"), QStringLiteral("mode")},
        QObject::tr("Operation mode: link, ip or tcp."), QObject::tr("mode"),
        QStringLiteral("ip"));
    QCommandLineOption numericOption(
        {QStringLiteral("n"), QStringLiteral("numeric")},
        QObject::tr("Keep addresses numeric (no reverse DNS)."));
    QCommandLineOption nodeLimitOption(
        QStringLiteral("node-limit"),
        QObject::tr("Keep at most <count> nodes."), QObject::tr("count"));
    QCommandLineOption finalExportOption(
        QStringLiteral("final-export"),
        QObject::tr("Export the graph as XML to <file> on exit."),
        QObject::tr("file"));
    QCommandLineOption positionOption(
        QStringLiteral("position"),
        QObject::tr("Load the node layout from <file>."),
        QObject::tr("file"));
    QCommandLineOption exitAfterOption(
        QStringLiteral("exit-after"),
        QObject::tr("Close the window after <ms> (testing aid)."),
        QObject::tr("ms"));
    QCommandLineOption screenshotOption(
        QStringLiteral("screenshot"),
        QObject::tr("Save a window snapshot to <file> and exit (testing aid)."),
        QObject::tr("file"));
    QCommandLineOption screenshotDelayOption(
        QStringLiteral("screenshot-delay"),
        QObject::tr("Wait <ms> before taking the snapshot."),
        QObject::tr("ms"), QStringLiteral("2000"));
    QCommandLineOption speedOption(
        QStringLiteral("speed"),
        QObject::tr("Replay speed in percent (0 = as fast as possible)."),
        QObject::tr("percent"), QStringLiteral("100"));

    parser.addOptions({interfaceOption, replayOption, filterOption, modeOption,
                       numericOption, nodeLimitOption, speedOption,
                       finalExportOption, positionOption, screenshotOption,
                       screenshotDelayOption, exitAfterOption});
    parser.process(app);

    etherape::MainWindow window;

    if (parser.isSet(numericOption))
        window.setNumeric(true);
    if (parser.isSet(nodeLimitOption)) {
        bool ok = false;
        const int limit = parser.value(nodeLimitOption).toInt(&ok);
        if (ok && limit > 0)
            window.setNodeLimit(limit);
    }
    if (parser.isSet(filterOption))
        window.setFilter(parser.value(filterOption));
    if (parser.isSet(modeOption)) {
        bool ok = false;
        const etherape::Mode mode = parseMode(parser.value(modeOption), &ok);
        if (ok)
            window.setMode(mode);
    }

    if (parser.isSet(finalExportOption))
        window.setFinalExport(parser.value(finalExportOption));

    window.show();

    if (parser.isSet(positionOption))
        window.loadLayoutFile(parser.value(positionOption));

    if (parser.isSet(exitAfterOption)) {
        const int delay = parser.value(exitAfterOption).toInt();
        QTimer::singleShot(delay, &window, &QWidget::close);
    }

    if (parser.isSet(screenshotOption)) {
        const QString path = parser.value(screenshotOption);
        const int delay = parser.value(screenshotDelayOption).toInt();
        QTimer::singleShot(delay, &window, [&window, path] {
            window.grab().save(path);
            window.close();
        });
    }

    if (parser.isSet(replayOption)) {
        const QString file = parser.value(replayOption);
        const int speed = parser.value(speedOption).toInt();
        QTimer::singleShot(0, &window, [&window, file, speed] {
            window.startReplay(file, speed);
        });
    } else if (parser.isSet(interfaceOption)) {
        const QString device = parser.value(interfaceOption);
        QTimer::singleShot(0, &window, [&window, device] {
            window.startLiveCapture(device);
        });
    }

    return app.exec();
}

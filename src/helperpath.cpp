// SPDX-License-Identifier: GPL-2.0-or-later

#include "helperpath.h"

#ifndef Q_OS_WIN

#include <QFile>

#include <cerrno>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif
#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

#endif

namespace etherape {

#ifdef Q_OS_WIN

QString helperLogDirectory()
{
    return QString();
}

int openHelperLog(const QString &)
{
    return -1;
}

#else

QString helperLogDirectory()
{
    const QString path =
        QStringLiteral("/dev/shm/etherape2026-%1").arg(::getuid());
    const QByteArray native = QFile::encodeName(path);

    if (::mkdir(native.constData(), 0700) != 0 && errno != EEXIST)
        return QString();

    struct stat info;
    if (::lstat(native.constData(), &info) != 0)
        return QString();

    // lstat() sees a symlink as a symlink, so a planted link is rejected here.
    if (!S_ISDIR(info.st_mode) || info.st_uid != ::getuid())
        return QString();

    // Tighten a directory left with looser permissions by a previous version;
    // never touch one owned by another user (already rejected above).
    if ((info.st_mode & (S_IRWXG | S_IRWXO)) != 0
        && ::chmod(native.constData(), 0700) != 0)
        return QString();

    return path;
}

int openHelperLog(const QString &path)
{
    const QByteArray native = QFile::encodeName(path);
    return ::open(native.constData(),
                  O_CREAT | O_WRONLY | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
}

#endif

} // namespace etherape

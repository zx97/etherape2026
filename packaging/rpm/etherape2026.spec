# SPDX-License-Identifier: GPL-2.0-or-later
#
# Binary RPM: the release archive already contains the executable, built by
# scripts/package-linux.sh (Qt 6 and libpcap are distribution packages, so the
# binary is not rebuilt here).
#
#   ./scripts/package-linux.sh build dist
#   cp dist/etherape2026-1.0.1-linux-x86_64.tar.gz ~/rpmbuild/SOURCES/
#   rpmbuild -bb packaging/rpm/etherape2026.spec
#
# Building from source would need the Qt 6 toolchain on the build host; this
# keeps packaging reproducible on any machine that has rpmbuild.

Name:           etherape2026
Version:        1.0.1
Release:        1%{?dist}
Summary:        Graphical network traffic monitor (Qt 6 port of EtherApe)
License:        GPL-2.0-or-later
URL:            https://github.com/zx97/etherape2026
Source0:        %{name}-%{version}-linux-x86_64.tar.gz

Requires:       qt6-qtbase
Requires:       libpcap
Requires:       hicolor-icon-theme

%description
EtherApe 2026 displays network activity graphically: hosts, links between
them, per-protocol colours and traffic statistics. Qt 6 port of EtherApe.
Live capture uses libpcap and needs CAP_NET_RAW (see the README).

%prep
%setup -q -n %{name}-%{version}-linux-x86_64

%build
# Nothing to build: the archive ships the compiled executable.

%install
install -Dm0755 etherape2026 %{buildroot}%{_bindir}/etherape2026
install -Dm0644 etherape2026.desktop \
    %{buildroot}%{_datadir}/applications/etherape2026.desktop
install -Dm0644 etherape2026.png \
    %{buildroot}%{_datadir}/pixmaps/etherape2026.png
install -Dm0644 etherape2026.1 \
    %{buildroot}%{_mandir}/man1/etherape2026.1

%files
%{_bindir}/etherape2026
%{_datadir}/applications/etherape2026.desktop
%{_datadir}/pixmaps/etherape2026.png
%{_mandir}/man1/etherape2026.1

%changelog
* Sat Nov 28 2026 zx97 <zx97@users.noreply.github.com> - 1.0.1-1
- Documentation and release text in English; no functional change
* Sat Nov 21 2026 zx97 <zx97@users.noreply.github.com> - 1.0.0-1
- Initial package

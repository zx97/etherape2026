# SPDX-License-Identifier: GPL-2.0-or-later
#
# RPM spec. Build with:  rpmbuild -bb packaging/rpm/etherape2026.spec
# (the source tarball is produced by scripts/package-linux.sh)

Name:           etherape2026
Version:        1.0.0
Release:        1%{?dist}
Summary:        Graphical network traffic monitor (Qt 6 port of EtherApe)
License:        GPL-2.0-or-later
URL:            https://gitlab.com/rghetta/etherape
Source0:        %{name}-%{version}-linux-x86_64.tar.gz

BuildRequires:  gcc-c++
BuildRequires:  cmake
BuildRequires:  ninja-build
BuildRequires:  qt6-qtbase-devel
BuildRequires:  libpcap-devel
Requires:       libpcap
Requires:       hicolor-icon-theme

%description
EtherApe 2026 displays network activity graphically: hosts, links between
them, per-protocol colours and traffic statistics. Qt 6 port of EtherApe.

%prep
%setup -q -n etherape2026-%{version}-linux-x86_64

%build
%cmake -G Ninja -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON
%cmake_build

%check
%ctest --output-on-failure

%install
%cmake_install

%files
%{_bindir}/etherape2026
%{_datadir}/applications/etherape2026.desktop
%{_datadir}/pixmaps/etherape2026.png
%{_mandir}/man1/etherape2026.1*

%changelog
* Sat Nov 21 2026 zx97 <manuel.flury@gmail.com> - 1.0.0-1
- Initial package

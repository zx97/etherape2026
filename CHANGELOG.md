# Changelog

## 1.0.1 — 2026-11-28

Documentation, release notes and packaging text are now in **English**, the
language this project documents in. No functional change: the code is identical
to 1.0.0, the release is rebuilt so that the shipped README and the release
notes match the repository.

## 1.0.0 — 2026-11-21

First publishable release. Qt 6 port of EtherApe (base 0.9.22 / 0.9.23).

### Features

- Live capture through libpcap (Npcap on Windows), BPF filter.
- pcap file replay, adjustable speed.
- **Link** (MAC), **IP**, **TCP** (address:port) modes.
- Ethernet, 802.1Q/QinQ VLAN, IPv4, IPv6 (+ extension headers), ARP, TCP, UDP,
  ICMP decoding; IPv4/IPv6 **fragment reassembly**.
- Application dissection: HTTP, TLS, DNS, SSH, SMB, RDP, MySQL, NTP, NBNS…
- Animated graph (force-directed layout), zoom, node pinning.
- LAN / DMZ / VPN / Internet zone clouds, with local interface prefixes
  detected automatically.
- Addresses resolving to the same host name are merged.
- Statistics panel (nodes, links, protocols) + 5-minute throughput chart.
- Display filter (`proto:`, `host:`, `vlan:`, `zone:`, negation) that does not
  touch the capture; completion and help.
- Node search (`Ctrl+F`), detailed conversations with CSV export.
- XML and JSON export; node layout as JSON.
- Asynchronous reverse DNS, passive NetBIOS, `/etc/ethers`.
- 10 languages (English source, fr, es, pt_BR, ru, zh_CN, ar, hi, bn, ur).
- polkit elevation on Linux, UAC on Windows.
- NSIS installer, RPM/AppImage/Flatpak recipes.

### Binaries

Every `v*` tag automatically produces: a Linux AppImage (Qt 6 bundled), a Linux
archive with `install.sh`, a Windows NSIS installer and `SHA256SUMS`
(see `docs/PACKAGING.md`).

### Notes

- MAC-based merging was removed: behind a router every host carries the
  gateway's MAC.
- Live capture does not work inside a Flatpak sandbox (no `CAP_NET_RAW`).

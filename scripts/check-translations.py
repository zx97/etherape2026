#!/usr/bin/env python3
"""Check that technical terms stay in English in every translation.

Usage: scripts/check-translations.py [translations/*.ts]
Exit code 1 when a translation drops a term the source contains.
"""
import re
import sys
import xml.etree.ElementTree as ET

TERMS = [
    "VLAN", "MAC", "BPF", "DNS", "TLS", "TCP", "UDP", "ICMP", "IPv4", "IPv6",
    "ARP", "pcap", "Npcap", "pkexec", "polkit", "CAP_NET_RAW", "CIDR", "LAN",
    "DMZ", "VPN", "XML", "JSON", "Qt", "EtherApe", "HTTP", "SSH", "SMB", "RDP",
    "NTP", "NBNS", "mDNS",
]


def terms_in(text):
    return {
        term
        for term in TERMS
        if re.search(r"(?<![A-Za-z0-9])" + re.escape(term) + r"(?![A-Za-z0-9])", text)
    }


def main(paths):
    failures = 0
    for path in paths:
        root = ET.parse(path).getroot()
        for context in root.findall("context"):
            for message in context.findall("message"):
                source = message.findtext("source") or ""
                translation = message.find("translation")
                if translation is None:
                    continue
                if translation.get("type") in ("unfinished", "vanished", "obsolete"):
                    continue
                lost = terms_in(source) - terms_in(translation.text or "")
                if lost:
                    failures += 1
                    print(f"{path}: {sorted(lost)} lost in {source[:60]!r}")
    if failures:
        print(f"{failures} translation(s) changed a technical term")
        return 1
    print("all translations keep the technical terms in English")
    return 0


if __name__ == "__main__":
    args = sys.argv[1:] or ["translations"]
    import glob
    import os
    files = []
    for arg in args:
        files.extend(glob.glob(os.path.join(arg, "*.ts")) if os.path.isdir(arg) else [arg])
    sys.exit(main(files))

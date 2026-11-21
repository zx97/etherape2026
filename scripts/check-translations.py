#!/usr/bin/env python3
"""Check translation hygiene.

Rules enforced (each one has already caught a real defect):

1. technical terms stay in English: a translation may not drop a term the
   source contains (VLAN, MAC, BPF, DNS, TCP/IP, pkexec, CIDR, LAN...);
2. identifiers and mode names are kept verbatim (IP, TCP, Link, VLAN, DNS,
   NetBIOS, /etc/ethers, EtherApe 2026): translating "Link" to "Lien" made
   the mode selector inconsistent with IP and TCP;
3. placeholders (%1, %2...) and rich-text tags survive, otherwise the string
   silently loses data or formatting;
4. every <translation> uses element content: lrelease only accepts the
   "unfinished"/"vanished"/"obsolete" values in the type attribute, so
   hand-written text placed there is dropped.

Usage: scripts/check-translations.py [translations/*.ts]
Exit code 1 when a rule is broken.
"""
import glob
import os
import re
import sys
import xml.etree.ElementTree as ET

TERMS = [
    "VLAN", "MAC", "BPF", "DNS", "TLS", "TCP", "UDP", "ICMP", "IPv4", "IPv6",
    "ARP", "pcap", "Npcap", "libpcap", "pkexec", "polkit", "CAP_NET_RAW",
    "CIDR", "LAN", "DMZ", "VPN", "XML", "JSON", "CSV", "Qt", "EtherApe",
    "HTTP", "SSH", "SMB", "RDP", "NTP", "NBNS", "mDNS", "NetBIOS", "LDAP",
    "NSS", "SSSD", "PTR",
]

# Sources that are names, not words: they must be identical in every language.
IDENTICAL = [
    "Link", "IP", "TCP", "VLAN", "VLAN %1", "DNS", "NetBIOS", "/etc/ethers",
    "EtherApe 2026",
]

PLACEHOLDER = re.compile(r"%\d+")
TAG = re.compile(r"</?(?:b|i|br|p|ul|li|code|h3|ms)>")
VALID_TYPES = {"unfinished", "vanished", "obsolete"}


def terms_in(text):
    return {
        term
        for term in TERMS
        if re.search(r"(?<![A-Za-z0-9])" + re.escape(term) + r"(?![A-Za-z0-9])", text)
    }


def check(path):
    failures = []

    raw = open(path, encoding="utf-8").read()
    for value in re.findall(r'type="([^"]*)"', raw):
        if value not in VALID_TYPES:
            failures.append(f"invalid translation type {value!r}")

    for context in ET.parse(path).getroot().findall("context"):
        for message in context.findall("message"):
            source = message.findtext("source") or ""
            translation = message.find("translation")
            if translation is None:
                continue
            if translation.get("type") in VALID_TYPES:
                continue
            text = translation.text or ""
            stripped = source.strip()

            if stripped in IDENTICAL and text.strip() != stripped:
                failures.append(
                    f"{stripped!r} must stay untranslated, found {text.strip()!r}"
                )
            lost = terms_in(source) - terms_in(text)
            if lost:
                failures.append(f"{sorted(lost)} lost in {source[:60]!r}")
            if PLACEHOLDER.findall(source) != PLACEHOLDER.findall(text):
                failures.append(
                    f"placeholders differ: {PLACEHOLDER.findall(source)} vs "
                    f"{PLACEHOLDER.findall(text)} in {source[:50]!r}"
                )
            if TAG.findall(source) != TAG.findall(text):
                failures.append(f"markup differs in {source[:50]!r}")
    return failures


def main(paths):
    total = 0
    for path in paths:
        failures = check(path)
        total += len(failures)
        for failure in failures:
            print(f"{os.path.basename(path)}: {failure}")
    if total:
        print(f"{total} translation problem(s)")
        return 1
    print("translations: terms in English, identifiers verbatim, placeholders intact")
    return 0


if __name__ == "__main__":
    args = sys.argv[1:] or ["translations"]
    files = []
    for arg in args:
        files.extend(glob.glob(os.path.join(arg, "*.ts")) if os.path.isdir(arg) else [arg])
    sys.exit(main(files))

# Changelog

## 1.0.0 — 2026-11-21

Première version publiable. Portage Qt 6 d'EtherApe (base 0.9.22 / 0.9.23).

### Fonctionnalités

- Capture live via libpcap (Npcap sous Windows), filtre BPF.
- Replay de fichiers pcap, vitesse réglable.
- Modes **Link** (MAC), **IP**, **TCP** (adresse:port).
- Décodage Ethernet, VLAN 802.1Q/QinQ, IPv4, IPv6 (+ en-têtes d'extension),
  ARP, TCP, UDP, ICMP ; **réassemblage des fragments** IPv4/IPv6.
- Dissection applicative : HTTP, TLS, DNS, SSH, SMB, RDP, MySQL, NTP, NBNS…
- Graphe animé (layout force-directed), zoom, épinglage des nœuds.
- Nuages de zones LAN / DMZ / VPN / Internet, avec préfixes des interfaces
  locales détectés automatiquement.
- Fusion des adresses résolvant vers le même nom d'hôte.
- Panneau statistiques (nœuds, liens, protocoles) + courbe de débit 5 min.
- Filtrer l'affichage (`proto:`, `host:`, `vlan:`, `zone:`, négation) sans
  toucher à la capture ; autocomplétion et aide.
- Recherche de nœud (`Ctrl+F`), conversations détaillées avec export CSV.
- Export XML et JSON ; disposition des nœuds en JSON.
- Résolution DNS inverse asynchrone, NetBIOS passif, `/etc/ethers`.
- 10 langues (anglais source, fr, es, pt_BR, ru, zh_CN, ar, hi, bn, ur).
- Élévation polkit sous Linux, UAC sous Windows.
- Installeur NSIS, recettes RPM/AppImage/Flatpak.

### Notes

- La fusion par MAC a été retirée : derrière un routeur, tous les hôtes
  portent la MAC de la passerelle.
- La capture live ne fonctionne pas dans un bac à sable Flatpak
  (pas de `CAP_NET_RAW`).

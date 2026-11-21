# Packaging

Trois familles de paquets sont fournies. Aucune n'est « officielle » : ce sont
des recettes prêtes à l'emploi, à adapter à ton dépôt.

## Linux

| Format | Fichier | Commande |
|---|---|---|
| Archive + `install.sh` | `scripts/package-linux.sh` | `./scripts/package-linux.sh build dist` |
| RPM | `packaging/rpm/etherape2026.spec` | `rpmbuild -bb packaging/rpm/etherape2026.spec` |
| AppImage | `scripts/build-appimage.sh` | `./scripts/build-appimage.sh` |
| Flatpak | `packaging/flatpak/org.etherape.EtherApe2026.yml` | `flatpak-builder --user --install build-flatpak …` |

L'archive produite par `package-linux.sh` sert de `Source0` au spec RPM (elle
contient un répertoire déjà installé, d'où `%cmake_install`).

### AppImage

Nécessite `linuxdeploy`, `linuxdeploy-plugin-qt` et `appimagetool` dans le
`PATH` (voir l'en-tête du script). Le script dépose l'icône, le `.desktop`, la
page de manuel, puis demande à `linuxdeploy` d'embarquer Qt.

### Flatpak

Le manifeste construit libpcap puis l'application avec le runtime
`org.kde.Platform` (Qt 6).

> **Limite assumée** : un Flatpak ne peut pas ouvrir de socket `AF_PACKET`
> avec `CAP_NET_RAW`. **La capture live ne fonctionne donc pas dans le bac à
> sable** ; le replay de fichiers, l'interface, le graphe et les exports
> fonctionnent normalement. Pour capturer, utilise l'AppImage, le paquet de la
> distribution, ou `setcap` sur un binaire installé hors Flatpak.

## Windows

| Élément | Fichier |
|---|---|
| Installeur NSIS | `packaging/windows/etherape2026.nsi` |
| Script de build | `scripts/build-installer-windows.sh` |

```bash
export MSYSTEM=UCRT64
export PATH=/ucrt64/bin:$PATH
pacman -S --needed mingw-w64-ucrt-x86_64-nsis
./scripts/build-installer-windows.sh
```

L'installeur crée les raccourcis (Bureau, menu Démarrer), enregistre
l'entrée « Applications et fonctionnalités » et fournit un désinstalleur.

**Npcap n'est pas embarqué** : son pilote signé exige une installation
interactive. L'installeur le rappelle à la fin ; l'application détecte son
absence (le binaire ne se charge pas sans `wpcap.dll`).

## Ce qui reste manuel

- **Signature** des paquets (GPG pour AppImage/RPM, Authenticode/NSIS pour
  Windows) : hors périmètre ici, à faire avec tes clés.
- **Mises à jour automatiques** : aucune n'est implémentée ; un paquet
  Flatpak/AppImage suit son propre canal, Windows doit être remplacé.

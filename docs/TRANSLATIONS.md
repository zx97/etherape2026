# Traductions

## Langues fournies

Les dix langues les plus parlées au monde, l'anglais étant la langue source
(intégrée au code, aucun fichier `.ts` nécessaire) :

| Langue | Code | Fichier | État |
|---|---|---|---|
| Français | `fr` | `etherape2026_fr.ts` | complet (85/85) |
| Español | `es` | `etherape2026_es.ts` | complet (85/85) |
| Português (BR) | `pt_BR` | `etherape2026_pt_BR.ts` | complet (85/85) |
| Русский | `ru` | `etherape2026_ru.ts` | complet (85/85) |
| 简体中文 | `zh_CN` | `etherape2026_zh_CN.ts` | complet (85/85) |
| العربية | `ar` | `etherape2026_ar.ts` | complet (85/85), interface RTL |
| हिन्दी | `hi` | `etherape2026_hi.ts` | noyau (76/85) |
| বাংলা | `bn` | `etherape2026_bn.ts` | noyau (76/85) |
| اردو | `ur` | `etherape2026_ur.ts` | noyau (76/85) |

Les chaînes non traduites retombent automatiquement en anglais : une interface
partielle reste parfaitement utilisable.

> **Relecture native nécessaire.** Les traductions `fr/es/pt_BR/ru` ont été
> écrites soigneusement ; `zh_CN/ar` demandent une relecture par un locuteur ;
> `hi/bn/ur` sont un premier jet à faire valider. Les fichiers `.ts` sont
> conçus pour cela (Qt Linguist).

## Termes volontairement laissés en anglais

Consigne de traduction : les termes techniques gardent leur forme d'origine
dans **toutes** les langues.

`VLAN`, `MAC`, `BPF`, `DNS`, `TLS`, `HTTP`, `TCP`, `UDP`, `ICMP`, `IP`,
`IPv4`/`IPv6`, `ARP`, `pcap`, `Npcap`, `pkexec`, `polkit`, `CAP_NET_RAW`,
`CIDR`, `LAN`, `DMZ`, `VPN`, `XML`, `JSON`, `Qt`, `EtherApe`.

Exemple : `&Merge IPv4/IPv6 Hosts` → *&Fusionner les hôtes IPv4/IPv6*.

## Comment ça fonctionne

* Les chaînes sources sont dans le code (`tr("...")`).
* `lupdate` extrait le catalogue : `translations/etherape2026.ts`.
* Un fichier `.ts` par langue, compilé en `.qm` par `lrelease`.
* Les `.qm` sont embarqués dans le binaire via `translations.qrc`.
* Au démarrage, `main.cpp` charge `:/translations/etherape2026_<locale>.qm`
  d'après la préférence `ui/language`, sinon `QLocale::system()` ; la direction
  du texte (RTL/LTR) est appliquée automatiquement.
* **Settings → Preferences → Language** permet de forcer une langue ; le
  changement prend effet au redémarrage.

## Compléter une traduction

Les fichiers `.ts` sont **la source de vérité** : on les édite directement.

```bash
# ouvrir le catalogue de la langue
linguist translations/etherape2026_fr.ts        # paquet qt6-linguist
# ou lister ce qui manque, sans interface graphique
grep -B2 -A2 'type="unfinished"' translations/etherape2026_fr.ts
```

Dans Qt Linguist, filtre sur « unfinished », saisis la traduction, puis
`File → Release`. En ligne de commande, cela revient à :

```bash
# remplacer <translation type="unfinished"></translation> par
#            <translation>votre texte</translation>
lrelease translations/etherape2026_fr.ts -qm translations/etherape2026_fr.qm
cmake --build build     # les .qm sont embarqués par translations.qrc
```

## Après ajout de chaînes dans le code

```bash
lupdate src -ts translations/etherape2026.ts -no-obsolete
# puis reporter les nouvelles entrées dans chaque fichier de langue
```

`scripts/update-translations.sh` enchaîne `lupdate`/`lrelease` et rappelle
l'état de chaque langue.

`scripts/update-translations.sh` enchaîne ces étapes et vérifie les manquants.

## Vérification

```bash
LANG=fr_FR.UTF-8 ./build/bin/etherape2026        # français
LANG=ar_SA.UTF-8 ./build/bin/etherape2026        # arabe, interface inversée
```

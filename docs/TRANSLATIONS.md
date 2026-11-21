# Traductions

## Langues fournies

Les dix langues les plus parlées au monde, l'anglais étant la langue source
(intégrée au code, aucun fichier `.ts` nécessaire) :

| Langue | Code | Fichier | Chaînes | État |
|---|---|---|---|---|
| Français | `fr` | `etherape2026_fr.ts` | 185/185 | complet |
| Español | `es` | `etherape2026_es.ts` | 185/185 | complet |
| Português (BR) | `pt_BR` | `etherape2026_pt_BR.ts` | 185/185 | complet |
| Русский | `ru` | `etherape2026_ru.ts` | 185/185 | complet |
| 简体中文 | `zh_CN` | `etherape2026_zh_CN.ts` | 185/185 | complet |
| العربية | `ar` | `etherape2026_ar.ts` | 185/185 | complet, interface RTL |
| हिन्दी | `hi` | `etherape2026_hi.ts` | 108/185 | noyau |
| বাংলা | `bn` | `etherape2026_bn.ts` | 108/185 | noyau |
| اردو | `ur` | `etherape2026_ur.ts` | 108/185 | noyau |

Les 77 chaînes qui manquent à `hi/bn/ur` sont uniquement des textes longs :
descriptions de `--help`, boîte **À propos**, aide HTML imbriquée et messages
d'erreur détaillés. Tout le libellé d'interface courant est traduit.

Les chaînes non traduites retombent automatiquement en anglais : une interface
partielle reste parfaitement utilisable.

> **Relecture native nécessaire.** Les six langues complètes ont été écrites
> avec soin et passent les contrôles automatiques, mais une relecture humaine
> reste souhaitable, en particulier pour `zh_CN` et `ar`. Les fichiers `.ts`
> sont conçus pour cela (Qt Linguist).

## Termes volontairement laissés en anglais

Consigne de traduction : les termes techniques gardent leur forme d'origine
dans **toutes** les langues.

`VLAN`, `MAC`, `BPF`, `DNS`, `TLS`, `HTTP`, `TCP`, `UDP`, `ICMP`, `IP`,
`IPv4`/`IPv6`, `ARP`, `pcap`, `Npcap`, `pkexec`, `polkit`, `CAP_NET_RAW`,
`CIDR`, `LAN`, `DMZ`, `VPN`, `XML`, `JSON`, `Qt`, `EtherApe`, `NetBIOS`.

### Noms et identifiants : jamais traduits

Les noms de mode et les identifiants restent **identiques** au texte source
dans toutes les langues, sinon l'interface devient incohérente :

`Link`, `IP`, `TCP`, `VLAN`, `VLAN %1`, `DNS`, `NetBIOS`, `/etc/ethers`,
`EtherApe 2026`, `ms`, ainsi que l'exemple de syntaxe
`proto:http host:10.0 -vlan:100 zone:dmz`.

> Le sélecteur de mode affiche donc `Link | IP | TCP` dans les dix langues :
> `Link` avait été traduit en *Lien* en français, ce qui laissait un menu
> mi-français mi-anglais.

Exemple de traduction correcte : `&Merge IPv4/IPv6 Hosts` →
*&Fusionner les hôtes IPv4/IPv6*.

### Espaces réservés

`<device>`, `<file>`, `<ms>`… sont traduits **en même temps que le nom de
l'argument** affiché par `--help` : en français `--interface <périphérique>`
s'explique par « Capturer sur <périphérique>. ». Les `%1`, `%2` et les balises
HTML restent intacts, sinon la chaîne perd des données ou son formatage.

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

## Vérification

```bash
python3 scripts/check-translations.py            # règles ci-dessus, code 1 si échec
LANG=fr_FR.UTF-8 ./build/bin/etherape2026 --help # rendu réel
```

> **Piège** : la préférence `ui/language` enregistrée dans
> `~/.config/etherape/etherape2026.conf` **prime** sur `LANG`. Pour tester une
> autre langue sans toucher à ta configuration :
>
> ```bash
> XDG_CONFIG_HOME=$(mktemp -d -p /dev/shm) LC_ALL=ar_SA.UTF-8 \
>     ./build/bin/etherape2026 --help
> ```

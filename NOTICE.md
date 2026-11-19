# Origine, licence et traçabilité

## Le programme original

**EtherApe** est un moniteur graphique de trafic réseau, créé en 2001 par
**Juan Toledo**, puis maintenu par **Riccardo Ghetta** et une communauté de
contributeurs.

| | |
|---|---|
| Dépôt officiel | <https://gitlab.com/rghetta/etherape> |
| Ancien hébergement | <https://sourceforge.net/projects/etherape/> |
| Site | <https://etherape.sourceforge.io/> |
| Licence | GNU GPL v2 **ou ultérieure** (`GPL-2.0-or-later`) |
| Base de ce portage | tag **`rel-0.9.22`** (commit `8753ed7`, 2026-04-12) |
| État amont au moment du portage | branche `main`, version 0.9.23 (commit `1edfbb8`, 2026-10-22) |

Le code source original (C, GTK 3, libglade, autotools, ~18 100 lignes) reste
la référence fonctionnelle : chaque module de ce portage en reprend le
comportement, parfois en le simplifiant — voir
[`docs/PORTING.md`](PORTING.md) pour le détail des décisions.

Ce dépôt est un **portage**, pas un fork : il n'a pas vocation à recevoir des
correctifs du code C historique. Les deux peuvent coexister sur une machine
(binaires `etherape` et `etherape2026`).

## Licence

* Ce portage : **GPL-2.0-or-later**, comme l'original (texte dans
  [`COPYING`](COPYING)).
* Qt 6 est distribué sous **LGPL v3** (ou GPL v3, ou licence commerciale).
  Un projet `GPL-2.0-or-later` peut être redistribué sous GPL v3, ce qui est
  compatible avec la LGPL v3 : le portage est donc licitement distribuable.
  Il est lié **dynamiquement** aux bibliothèques Qt.
* libpcap/Npcap : licence BSD à 3 clauses (compatible).
* L'icône (`data/etherape.png`) provient du projet original.

## Auteurs

* **EtherApe original** — © 2001 Juan Toledo, Riccardo Ghetta et les
  contributeurs listés dans l'historique du dépôt amont.
* **Portage Qt 6 (EtherApe 2026)** — voir l'historique Git de ce dépôt.

## Ce qui a été vérifié contre l'original

Les éléments suivants ont été relus dans les sources C avant d'être réécrits,
afin de conserver la sémantique :

* modes de fonctionnement (`link` / `ip` / `tcp`) et granularité des nœuds ;
* schéma d'export XML (`header` / `nodes` / `links` / `protocols`) ;
* résolution de noms : DNS inverse asynchrone, `/etc/ethers`, NetBIOS ;
* décroissance de l'intensité des liens et expiration des nœuds ;
* options de ligne de commande (`-i`, `-r`, `-f`, `-m`, `-n`, `-l`, `-P`,
  `--final-export`, `--signal-export`).

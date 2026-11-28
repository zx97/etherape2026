# Origin, licence and provenance

## The original program

**EtherApe** is a graphical network traffic monitor, created in 2001 by
**Juan Toledo**, then maintained by **Riccardo Ghetta** and a community of
contributors.

| | |
|---|---|
| Official repository | <https://gitlab.com/rghetta/etherape> |
| Former hosting | <https://sourceforge.net/projects/etherape/> |
| Website | <https://etherape.sourceforge.io/> |
| Licence | GNU GPL v2 **or later** (`GPL-2.0-or-later`) |
| Base of this port | tag **`rel-0.9.22`** (commit `8753ed7`, 2026-04-12) |
| Upstream state when porting | `main` branch, version 0.9.23 (commit `1edfbb8`, 2026-10-22) |

The original source code (C, GTK 3, libglade, autotools, ~18,100 lines) remains
the functional reference: every module of this port follows its behaviour,
sometimes simplifying it — see [`docs/PORTING.md`](PORTING.md) for the
decisions.

This repository is a **port**, not a fork: it is not meant to receive patches
from the historical C code. Both can coexist on one machine (binaries
`etherape` and `etherape2026`).

## Licence

* This port: **GPL-2.0-or-later**, like the original (text in
  [`COPYING`](COPYING)).
* Qt 6 is distributed under **LGPL v3** (or GPL v3, or a commercial licence).
  A `GPL-2.0-or-later` project may be redistributed under GPL v3, which is
  compatible with LGPL v3: the port can therefore be distributed lawfully. It
  is linked **dynamically** against the Qt libraries.
* libpcap/Npcap: 3-clause BSD licence (compatible).
* The icon (`data/etherape.png`) comes from the original project.

## Authors

* **Original EtherApe** — © 2001 Juan Toledo, Riccardo Ghetta and the
  contributors listed in the upstream repository history.
* **Qt 6 port (EtherApe 2026)** — see the Git history of this repository.

## What was checked against the original

The following were read in the C sources before being rewritten, to preserve the
semantics:

* operating modes (`link` / `ip` / `tcp`) and node granularity;
* XML export schema (`header` / `nodes` / `links` / `protocols`);
* name resolution: asynchronous reverse DNS, `/etc/ethers`, NetBIOS;
* link intensity decay and node expiration;
* command-line options (`-i`, `-r`, `-f`, `-m`, `-n`, `-l`, `-P`,
  `--final-export`, `--signal-export`).

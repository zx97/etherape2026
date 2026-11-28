# Translations

## Languages provided

The ten most spoken languages in the world, English being the source language
(built into the code, no `.ts` file needed):

| Language | Code | File | Strings | State |
|---|---|---|---|---|
| French | `fr` | `etherape2026_fr.ts` | 185/185 | complete |
| Spanish | `es` | `etherape2026_es.ts` | 185/185 | complete |
| Portuguese (BR) | `pt_BR` | `etherape2026_pt_BR.ts` | 185/185 | complete |
| Russian | `ru` | `etherape2026_ru.ts` | 185/185 | complete |
| Simplified Chinese | `zh_CN` | `etherape2026_zh_CN.ts` | 185/185 | complete |
| Arabic | `ar` | `etherape2026_ar.ts` | 185/185 | complete, RTL interface |
| Hindi | `hi` | `etherape2026_hi.ts` | 108/185 | core only |
| Bengali | `bn` | `etherape2026_bn.ts` | 108/185 | core only |
| Urdu | `ur` | `etherape2026_ur.ts` | 108/185 | core only |

The 77 strings missing from `hi/bn/ur` are only long texts: `--help`
descriptions, the **About** box, nested HTML help and detailed error messages.
Everyday interface text is translated.

Untranslated strings fall back to English automatically: a partial interface
remains perfectly usable.

> **Native review needed.** The six complete languages were written carefully
> and pass the automated checks, but a human review remains desirable,
> especially for `zh_CN` and `ar`. The `.ts` files are designed for that
> (Qt Linguist).

## Terms deliberately left in English

Translation policy: technical terms keep their original form in **every**
language.

`VLAN`, `MAC`, `BPF`, `DNS`, `TLS`, `HTTP`, `TCP`, `UDP`, `ICMP`, `IP`,
`IPv4`/`IPv6`, `ARP`, `pcap`, `Npcap`, `pkexec`, `polkit`, `CAP_NET_RAW`,
`CIDR`, `LAN`, `DMZ`, `VPN`, `XML`, `JSON`, `Qt`, `EtherApe`, `NetBIOS`.

### Names and identifiers: never translated

Mode names and identifiers stay **identical** to the source text in every
language, otherwise the interface becomes inconsistent:

`Link`, `IP`, `TCP`, `VLAN`, `VLAN %1`, `DNS`, `NetBIOS`, `/etc/ethers`,
`EtherApe 2026`, `ms`, and the syntax example
`proto:http host:10.0 -vlan:100 zone:dmz`.

> The mode selector therefore shows `Link | IP | TCP` in all ten languages:
> `Link` had been translated to *Lien* in French, leaving a half-French,
> half-English menu.

Example of a correct translation: `&Merge IPv4/IPv6 Hosts` →
*&Fusionner les hôtes IPv4/IPv6*.

### Placeholders

`<device>`, `<file>`, `<ms>`… are translated **together with the argument
name** shown by `--help`: in French `--interface <périphérique>` is explained as
"Capturer sur <périphérique>.". `%1`, `%2` and HTML tags stay intact,
otherwise the string loses data or formatting.

## How it works

* Source strings live in the code (`tr("...")`).
* `lupdate` extracts the catalogue: `translations/etherape2026.ts`.
* One `.ts` file per language, compiled to `.qm` by `lrelease`.
* The `.qm` files are embedded in the binary through `translations.qrc`.
* At start-up, `main.cpp` loads `:/translations/etherape2026_<locale>.qm`
  according to the `ui/language` preference, otherwise `QLocale::system()`;
  the text direction (RTL/LTR) is applied automatically.
* **Settings → Preferences → Language** forces a language; the change takes
  effect at the next start.

## Completing a translation

The `.ts` files are **the source of truth**: they are edited directly.

```bash
# open the language catalogue
linguist translations/etherape2026_fr.ts        # qt6-linguist package
# or list what is missing, without a GUI
grep -B2 -A2 'type="unfinished"' translations/etherape2026_fr.ts
```

In Qt Linguist, filter on "unfinished", type the translation, then
`File → Release`. On the command line this amounts to:

```bash
# replace <translation type="unfinished"></translation> with
#         <translation>your text</translation>
lrelease translations/etherape2026_fr.ts -qm translations/etherape2026_fr.qm
cmake --build build     # the .qm files are embedded by translations.qrc
```

## After adding strings in the code

```bash
lupdate src -ts translations/etherape2026.ts -no-obsolete
# then propagate the new entries to every language file
```

`scripts/update-translations.sh` runs `lupdate`/`lrelease` and reports the state
of every language.

## Verification

```bash
python3 scripts/check-translations.py            # rules above, exit code 1 on failure
LANG=fr_FR.UTF-8 ./build/bin/etherape2026 --help # actual output
```

> **Pitfall**: the `ui/language` preference stored in
> `~/.config/etherape/etherape2026.conf` **overrides** `LANG`. To test another
> language without touching your configuration:
>
> ```bash
> XDG_CONFIG_HOME=$(mktemp -d -p /dev/shm) LC_ALL=ar_SA.UTF-8 \
>     ./build/bin/etherape2026 --help
> ```

# Contributing

## Build

```bash
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build -j"$(nproc)"
ctest --test-dir build --output-on-failure
```

Linux needs Qt 6 (Core/Gui/Widgets/Network) and libpcap headers; Windows needs
MSYS2 UCRT64 plus the Npcap SDK (`-DNPCAP_SDK_DIR=...`). See `README.md`.

## Conventions

- C++20, Qt 6, no other dependency.
- C++ naming: `camelCase` members with an `m_` prefix, `PascalCase` types,
  anonymous namespaces for file-local helpers.
- Comments and identifiers in **English**; user-visible strings go through
  `tr()` and technical terms (VLAN, MAC, BPF, DNS, TCP/IP…) stay in English in
  every translation.
- No MAC-based identity: a MAC is not unique once a router is in the path.

## Tests

Every behaviour change needs a test in `tests/tst_core.cpp`; it runs headless
(no GUI). `src/` is split so that decoding, the model, zones and exports live
in `etherape_core`, independent of Qt Widgets.

## Translations

`translations/*.ts` are the source of truth; edit them with Qt Linguist, run
`scripts/update-translations.sh`, then rebuild. See `docs/TRANSLATIONS.md`.

## Reporting

Include the output of `ETHERAPE_DEBUG=1 etherape2026 2>&1` when the capture
behaves unexpectedly, plus the interface name, the link type and whether the
privileged helper was involved.

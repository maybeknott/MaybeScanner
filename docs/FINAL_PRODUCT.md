# MaybeScanner Final Product Notes

MaybeScanner is a scanner-first Android product with an optional Go sidecar. The final product model is:

- `Sources`: choose managed IP corpora, custom target additions, workflow stages, scan volume, timeout, threads, and performance posture.
- `Results`: inspect result cards, extracted host hints, quick-filter common views, sort, paginate, change visualization/density, copy, and export the visible result set.
- `Diagnostics`: inspect logs, enriched network state, Shizuku radio controls, support links, and project reference material.

## Product Scope

MaybeScanner is the IP-first product. It scans endpoint targets directly and does not maintain an IP/SNI route-pairing model. Hostnames discovered from TLS certificates, HTTP metadata, and result evidence are treated as extracted host hints in Results.

MaybeEdgeScanner is the route-pairing sibling for SNI-heavy edge tests. Keeping this split avoids confusing Scanner users with route controls that do not shape its core scan.

## Interaction Model

- Sticky top tabs keep `Sources`, `Results`, and `Diagnostics` visible.
- Horizontal swipes move between tabs.
- Managed source selection, sample presets, per-source steppers, and custom target additions are separated.
- Compact density is treated as a performance mode: it caps rendered cards and avoids heavyweight visual panels while keeping result cards readable.
- The source-health card summarizes managed tokens, manual tokens, endpoint expansion, cap behavior, and load posture.
- Results quick buttons jump to working endpoints, TLS/HTTP evidence, or best-per-IP ranking without changing the scan queue.

## Release Artifacts

The Android builder emits three release APK families:

- `MaybeScanner-universal-release.apk`
- `MaybeScanner-armv7-release.apk`
- `MaybeScanner-armv8-release.apk`

The universal APK is the safest public default. ABI-specific APKs are produced for release-channel clarity and future native-library readiness.

## Publication Notes

Public release text should describe MaybeScanner as an authorized IP endpoint scanner with optional Shizuku radio diagnostics. It should not market VPN behavior, SNI/IP route pairing, exploit verification, stealth scanning, or automatic radio switching.

Release tags are generated from version, versionCode, workflow run number, and commit SHA so new runs do not overwrite an old `v1.0.0` release.

## Shizuku Scope

Shizuku is implemented as an explicit diagnostics tool. It can read common `preferred_network_mode` keys and can write guarded LTE-only, 5G/LTE, Auto, or sanitized custom numeric values after confirmation.

It is intentionally not connected to scan start/stop, automatic retry, background work, widgets, or Quick Settings tiles. Radio control is device-specific and must remain user-directed.

## Cleanup Boundary

Generated APKs, `.signing`, local `signing.properties`, build outputs, Gradle state, and sidecar binaries are ignored. Private signing files are not garbage; they are operator state and must stay outside git. Production signing secrets belong in GitHub Actions secrets or another encrypted secret manager.

## Local Diagnostic Privacy Policy

MaybeScanner integrates a local search engine for runtime logs and a standalone automated Network Diagnostic Suite. These diagnostic procedures run fully client-side inside isolated user-initiated processes:
1. All log querying and string searches are executed in-memory. Log files are not persisted or cached on external media.
2. Latency checks, DNS hostname lookups, raw TCP port connects, and HTTPS protocol handshakes are performed directly from the local device to public servers (`one.one.one.one`, `dns.google`, `1.1.1.1`, `8.8.8.8`, `www.google.com`, `aparat.com`).
3. No telemetry reports, diagnostic logs, system details, or performance scores are transmitted to any remote servers or third-party analytic services.

## Verification

The canonical verification path is GitHub Actions. The workflow downloads Go and Gradle dependencies, runs sidecar tests, builds sidecars, builds all Android release flavors, verifies signatures, uploads artifacts, and publishes the dependency-warmed container when needed.

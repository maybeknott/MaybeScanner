# MaybeScanner

MaybeScanner is an Android edge-scanning application with an optional Go sidecar for higher-volume desktop or server scans. It helps users test owned or authorized target lists for TCP reachability, TLS metadata, HTTP response behavior, CDN classification, latency, ranking, filtering, and export.

This repository is focused only on scanner functionality. The active product surface is the scanner app and sidecar documented here.

## Capabilities

- Android scanner activity with foreground scanning, live progress, filtered result copy/export, home-screen widget, and Quick Settings tile.
- Three-part app model: `Sources` for scan inputs, `Results` for cards/filtering/export/visualizations, and `Diagnostics` for logs, enriched network/system context, support, and radio tools.
- Sticky full-width top navigation with swipe gestures between `Sources`, `Results`, and `Diagnostics`.
- Source-health summary that separates managed corpora from manual additions, estimates expanded endpoints, and explains phone-load posture before a scan starts.
- Checkbox-driven managed sources with compact exact sample counts and horizontal sample scrubbers. `0` means the complete source, so selected corpora stay out of the manual target field.
- Provider-separated target corpora for community edge IPs, community `/24` CIDRs, Akamai, AWS CloudFront, Fastly, Cloudflare, GitHub Pages, Azure Front Door, Google CDN, Bunny CDN, StackPath/Edgio, and conventional CDN/cloud ranges.
- Custom user targets: IPv4, IPv6, domains, CIDRs, and hyphen ranges.
- IP-first scan model: MaybeScanner scans endpoint targets directly and extracts host hints from TLS/HTTP evidence after results arrive.
- Scan profiles: Quick TCP, Standard TLS, Deep HTTP, and Verify CDN edge.
- Workflow modes: run one selected profile, run the automatic TCP to TLS to HTTP to Verify ladder, or run manually selected scanner stages.
- Result filters for working status, TLS/HTTP status, TLS 1.3, CDN text, extracted host-hint text, certificate text, max latency, and minimum score.
- Quick result buttons for working endpoints, TLS/HTTP evidence, and best-per-IP ranking.
- Sort modes for newest, latency, score, CDN, extracted host hint, TLS-first, and HTTP-first.
- Results include analytics, local stable observations, status heatmaps, latency distribution, CDN mix, and tap-to-copy result tiles.
- Export formats for JSON, CSV, line-separated IPs, comma-separated IPs, and IP host hints.
- Shizuku-backed radio diagnostics for explicit user-controlled network-mode reads and guarded LTE/5G/Auto writes on supported devices.
- Optional Go sidecar with streaming scan results, standards-based DNS probing, Prometheus-style metrics, Grafana dashboard JSON, Nmap XML export, ALPN capture, server/cache header capture, random scan order, optional pacing, and jitter controls.
- Safety mode with bundled do-not-scan CIDRs, strict CIDR expansion caps, reserved/special-use address skipping, pacing, jitter, and adaptive backoff when timeout/reset rates rise.
- GitHub Actions worker that downloads Go and Gradle dependencies, builds sidecar binaries, builds Android artifacts, uploads build outputs, and publishes a dependency-warmed GHCR container.

## Current Status

The Android UI is Java/programmatic-view based and organized around `Sources`, `Results`, and `Diagnostics`. Sources owns managed IP corpora, custom target additions, scan volume, workflow, performance, and the source-health panel. Results owns visual cards, quick filters, provider narrowing, extracted host hints from result metadata, sort, pagination, density, copy, and export. Diagnostics owns logs, enriched network status, Shizuku radio controls, support links, and project reference material.

The Go sidecar is a standalone HTTP service. It uses structured `slog` logging, graceful HTTP shutdown, IPv4/IPv6 target parsing, uTLS ClientHello rotation, ALPN negotiation for `h2` and `http/1.1`, Alt-Svc HTTP/3 hint capture, and `github.com/miekg/dns` for DNS queries.

The sidecar also uses pooled HTTP readers, bounded CIDR expansion, dynamic safety-prefix loading from `go-sidecar/assets/do_not_scan_cidrs.txt`, and adaptive scan backoff when recent results show a high timeout/reset ratio.

## Corpora And Sampling

Provider corpora live under `app/src/main/assets/scan-corpora`.

Each source is parsed independently so users can combine several provider families in one scan. Enable or disable each family with its checkbox, then either type an exact sample count or scrub horizontally for coarse adjustment. A value of `0` uses the complete source. Managed samples stay summarized as source state and are not pasted into the custom target text field; that field is reserved for manual additions such as one-off IPs, domains, CIDRs, or ranges. The source-health panel shows managed token count, custom token count, expanded endpoint estimate, final Total-cap count, and whether the current settings are light, balanced, or high-load for a phone. Compact density caps card rendering and skips heavy visualizations so mode changes stay responsive on slower devices.

## Scan Workflows

- `Single selected profile`: runs the chosen profile exactly as selected.
- `Auto multi-step ladder`: enables TCP, TLS, HTTP, and verification in order.
- `Manual selected steps`: uses the TCP/TLS/HTTP/Verify checkboxes. Dependencies are inferred, so TLS includes TCP and HTTP includes TLS/TCP.

Use balanced settings for normal phones, lower thread counts for battery-sensitive scans, and shorter target samples while tuning filters.

## Android Build

Use JDK 17.

```powershell
$env:JAVA_HOME='C:\Program Files\Eclipse Adoptium\jdk-17.0.19.10-hotspot'
.\gradlew.bat :app:assembleDebug :app:assembleRelease
```

Generated APKs:

- `app/build/outputs/apk/universal/debug/MaybeScanner-universal-debug.apk`
- `app/build/outputs/apk/universal/release/MaybeScanner-universal-release.apk`
- `app/build/outputs/apk/armv7/release/MaybeScanner-armv7-release.apk`
- `app/build/outputs/apk/armv8/release/MaybeScanner-armv8-release.apk`

The `universal` artifact is the default recommendation. `armv7` targets `armeabi-v7a`; `armv8` targets `arm64-v8a`. The app is mostly Java, so the split artifacts are primarily release-channel clarity and future native-library readiness rather than a runtime requirement.

## Shizuku Radio Diagnostics

Diagnostics includes a guarded Shizuku panel for users who explicitly want to inspect or change Android radio preference settings.

- Uses the official `dev.rikka.shizuku` API and provider.
- Requests Shizuku permission only after the user taps the action.
- Links directly to the official Shizuku GitHub release for APK install/update checks, while still linking the official setup guide.
- Shows binder state, server version, and backend identity so users can distinguish root (`UID 0`) from ADB shell (`UID 2000`).
- Includes a safe bridge probe that prints Android version, device identity, command reach, and current radio readback before any write is attempted.
- Reads common `preferred_network_mode` keys before/after changes.
- Provides guarded `LTE only`, `5G/LTE`, and `Auto` actions with confirmation dialogs.
- Provides a sanitized advanced key/value override for OEM and SIM-slot variants.
- Does not expose arbitrary shell commands.
- Does not run during scans or change radio state automatically.

### Modern Android Compatibility

Shizuku remains viable on newer phones, but the startup path depends on Android version and device policy:

- Android 11 and newer: users can usually start Shizuku fully on-device through Android's Wireless debugging flow. This is the best path for modern non-rooted phones because it does not require a computer after setup.
- Android 13 and newer: recent Shizuku releases include newer-platform startup improvements, including trusted-WLAN auto-start support on supported builds.
- Android 16-era devices: current Shizuku releases are still being updated for new platform behavior. Use the latest official GitHub release when testing brand-new Android builds.
- Android 10 and older: Shizuku can still be used, but non-rooted devices normally need computer ADB again after reboot.
- Rooted devices: Shizuku can run with root, or users can use Sui. The app detects `UID 0` vs `UID 2000` so the diagnostics are honest about the backend.

For our app, the direct GitHub Release link is preferable to making Google Play the main path because it is universal, version-visible, and works for users without Play access. The official Shizuku download page is still useful as a hub because it lists Play Store, GitHub, and F-Droid-style options.

### Architecture Notes

Shizuku does not magically grant every permission to this app. It supplies a privileged Binder bridge or a privileged process identity. ADB-backed Shizuku runs as shell (`UID 2000`), which has many Android shell permissions but is still constrained by SELinux, vendor policy, hidden API restrictions, modem/carrier behavior, and Android version changes. Root/Sui has broader reach (`UID 0`) but still deserves explicit user confirmation for risky actions.

This app currently keeps Shizuku usage narrow: status checks, a safe bridge probe, readback, and guarded `settings` writes for radio preference keys. The deeper future refinement would be a Shizuku UserService/AIDL module for richer privileged APIs without parsing shell text. That is the right direction for anything beyond these small, auditable radio commands.

Hidden API bypass libraries are intentionally not included right now. They are useful when calling restricted framework APIs directly from the app process, but this app currently uses Shizuku for narrow shell-backed diagnostics. Adding hidden API bypass before a real Binder/UserService need would add distribution risk without improving the current radio panel.

Android radio integers, shell permissions, and settings keys vary by OEM, carrier, Android version, modem, and SIM slot. ADB-backed Shizuku is powerful but not the same as root; it can use many shell-granted Android permissions, but it cannot bypass every platform, SELinux, or vendor restriction. If a device behaves unexpectedly, use `Auto`, the Android network settings button, or the Shizuku readback output to restore the intended mode.

## Install Identity

- Release package: `com.maybeknott.maybescanner`
- App label: `MaybeScanner`
- Launcher icon: `@mipmap/ic_launcher`
- Round launcher icon: `@mipmap/ic_launcher_round`

Versioning uses date-derived Android `versionCode` values so signed updates move forward cleanly.

## Go Sidecar

```powershell
cd go-sidecar
go test ./...
go build -trimpath -ldflags='-s -w' -o maybescanner-sidecar.exe .
.\maybescanner-sidecar.exe
```

Docker deployment:

```powershell
cd go-sidecar
docker compose up --build
```

Useful endpoints:

- `GET /`
- `GET /health`
- `GET /metrics`
- `GET /grafana-dashboard.json`
- `POST /api/scan`
- `POST /api/dns`
- `POST /api/stop`
- `POST /api/export/nmap`

The scan endpoint streams newline-delimited JSON so clients can process large scans incrementally. The DNS endpoint supports `A`, `AAAA`, `CNAME`, `MX`, `NS`, `TXT`, and `SOA` queries with EDNS and DNSSEC/AD signal capture where available.

## Observability

Prometheus can scrape:

```text
http://127.0.0.1:10808/metrics
```

Grafana can import `go-sidecar/grafana-dashboard.json`, or download the same dashboard from:

```text
http://127.0.0.1:10808/grafana-dashboard.json
```

The dashboard tracks scan throughput, pass rates, timeout/reset rates, goroutines, and heap usage.

## GitHub Worker

`.github/workflows/build.yml` is the canonical clean build path. It:

- Downloads Go modules with `go mod tidy` and `go mod download`.
- Uploads the resolved `go-sidecar/go.sum` so the GitHub worker can finish dependency lock updates when local networks block module downloads.
- Runs `go test ./...` for the sidecar.
- Builds Linux, Windows, and macOS sidecar binaries.
- Downloads Gradle dependencies before Android compilation.
- Builds universal, armv7, and armv8 Android APK artifacts.
- Verifies every signed release APK with `apksigner`.
- Uploads all APK and sidecar artifacts.
- Publishes `ghcr.io/<owner>/<repo>-deps:<sha>` and `ghcr.io/<owner>/<repo>-deps:latest`.
- Uses BuildKit `gha` and registry cache layers so the dependency image reuses prior Go/Gradle layers and only refreshes changed dependency inputs.
- Checks whether dependency manifests changed or the image is missing before publishing the dependency image, so app-only commits do not rebuild dependency layers from zero.

## Support

Project repository: [MaybeScanner](https://github.com/maybeknott/MaybeScanner/)

Optional support for ongoing development:

- BTC: `bc1qt2mxzmlcv3re4pjemshejzq0hj3c8dgp0e5tvx`
- EVM-compatible networks such as ETH/ERC20/BNB/BEP20: `0x8988ed09DA218799e99Fb1E94243cC1C1cB41A40`

Please verify the asset and network before sending funds. This section is informational and optional; MaybeScanner remains fully usable without donations.

## Signing

Release signing reads `signing.properties` when present. Keep production signing material outside public source control.

```properties
STORE_FILE=.signing/your-keystore.jks
STORE_PASSWORD=...
KEY_ALIAS=...
KEY_PASSWORD=...
```

For CI/CD, store signing values in GitHub Secrets or another encrypted secret manager and materialize them only during the worker run. Do not commit keystores, local signing files, or plaintext passwords.

## Safe Scope

MaybeScanner is for owned, authorized, and diagnostic scanning. It intentionally excludes exploit execution, destructive traffic generation, credential capture, stealth abuse workflows, DPI poisoning, decoy traffic generation, and automated vulnerability exploitation.

Large scans can stress phones, routers, and networks. The app provides warnings, validation, sampling controls, cancellation, and pacing options so users can choose responsible limits for their environment.

Safety mode skips private, reserved, documentation, multicast, link-local, loopback, and locally configured do-not-scan CIDRs. The bundled file is intentionally editable so operators can add organization-specific opt-out ranges without changing code.

## Roadmap

Planned safe improvements include Kotlin/Compose migration, MVVM state separation, coroutine-based scan orchestration, persistent scan history, foreground-service continuity, richer analytics, better accessibility semantics, optional GeoIP/ASN tagging from user-provided databases, expanded IPv6 testing, OpenAPI documentation, and deeper CI release automation.

### Shizuku Roadmap

These are high-ROI Shizuku-backed additions worth considering after the current Health Tile and guarded radio diagnostics:

- Network Snapshot: read active network, DNS, Private DNS mode, proxy state, airplane mode, Wi-Fi/mobile state, and radio preference keys before and after scans.
- Connectivity Repair Panel: guided, confirmation-based repair actions for Private DNS reset, proxy clearing, supported Wi-Fi subsystem recovery, and direct settings fallbacks.
- Private DNS and Proxy Widget: show current values and offer explicit presets such as Off, Automatic, and custom hostname where Android permissions allow it.
- SIM Slot Radio Matrix: expand the current readback into per-key/per-SIM display for `preferred_network_mode`, `preferred_network_mode1`, `preferred_network_mode2`, and OEM variants.
- Per-App Network Firewall Check: inspect whether this app or user-selected helper apps are blocked by platform networking controls, with unblock-first UX.
- Export Debug Bundle: copy/share scan config, Shizuku health, bridge probe output, network snapshot, Android version, and device model for support reports.
- UserService/AIDL Backend: replace shell-text parsing for deeper privileged features with a typed Shizuku service once there is a clear feature that needs it.

Lower-priority or avoid-for-now items include Wi-Fi password viewing, broad Hidden API bypass, deep modem hidden APIs, and automatic radio writes without device-specific validation.

Advanced evasion, offensive reconnaissance, exploit verification, destructive active-defense payloads, and stealth traffic generation are outside the supported product direction, MAYBE :)

## License

MaybeScanner is distributed under the GNU Affero General Public License v3.0. See `LICENSE`.

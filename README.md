# MaybeScanner

MaybeScanner is an Android edge-scanning application with an optional Go sidecar for higher-volume desktop or server scans. It helps users test owned or authorized target lists for TCP reachability, TLS metadata, HTTP response behavior, CDN classification, latency, ranking, filtering, and export.

This repository is focused only on scanner functionality. The active product surface is the scanner app and sidecar documented here.

## Capabilities

- Android scanner activity with foreground scanning, live progress, filtered result copy/export, home-screen widget, and Quick Settings tile.
- Provider-separated target corpora for community edge IPs, community `/24` CIDRs, Akamai, AWS CloudFront, Fastly, Cloudflare, GitHub Pages, Azure Front Door, Google CDN, Bunny CDN, StackPath/Edgio, and conventional CDN/cloud ranges.
- Custom user targets: IPv4, IPv6, domains, CIDRs, and hyphen ranges.
- Scan profiles: Quick TCP, Standard TLS, Deep HTTP + SNI, and Verify CDN edge.
- Workflow modes: run one selected profile, run the automatic TCP to TLS to HTTP to Verify ladder, or run manually selected scanner stages.
- Result filters for working status, SNI/TLS/HTTP status, TLS 1.3, CDN text, SNI text, certificate text, max latency, and minimum score.
- Sort modes for newest, latency, score, SNI, TLS-first, HTTP-first, and CDN grouping.
- Export formats for JSON, CSV, line-separated IPs, comma-separated IPs, and IP/SNI pairs.
- Optional Go sidecar with streaming scan results, standards-based DNS probing, Prometheus-style metrics, Grafana dashboard JSON, Nmap XML export, ALPN capture, server/cache header capture, random scan order, optional pacing, and jitter controls.
- Safety mode with bundled do-not-scan CIDRs, strict CIDR expansion caps, reserved/special-use address skipping, pacing, jitter, and adaptive backoff when timeout/reset rates rise.
- GitHub Actions worker that downloads Go and Gradle dependencies, builds sidecar binaries, builds Android artifacts, uploads build outputs, and publishes a dependency-warmed GHCR container.

## Current Status

The Android UI is Java/XML based and organized around guided scanner controls, provider sampling, workflow stages, result filters, visual density modes, high-contrast result semantics, haptic result copy, and beginner-readable parameter explanations.

The Go sidecar is a standalone HTTP service. It uses structured `slog` logging, graceful HTTP shutdown, IPv4/IPv6 target parsing, uTLS ClientHello rotation, ALPN negotiation for `h2` and `http/1.1`, Alt-Svc HTTP/3 hint capture, and `github.com/miekg/dns` for DNS queries.

The sidecar also uses pooled HTTP readers, bounded CIDR expansion, dynamic safety-prefix loading from `go-sidecar/assets/do_not_scan_cidrs.txt`, and adaptive scan backoff when recent results show a high timeout/reset ratio.

## Corpora And Sampling

Provider corpora live under `app/src/main/assets/scan-corpora`.

Each source is parsed independently so users can combine several provider families in one scan. Per-source controls decide how many entries to load from each source. `0` means all entries from that source. `Total sample` controls the final expanded target sample for a run. Large CIDRs are sampled to avoid expanding very large ranges into memory.

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

- `app/build/outputs/apk/debug/MaybeScanner-debug.apk`
- `app/build/outputs/apk/release/MaybeScanner-release.apk`

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
- Builds Android artifacts through the existing build pipeline.
- Uploads APK and sidecar artifacts.
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

Advanced evasion, offensive reconnaissance, exploit verification, destructive active-defense payloads, and stealth traffic generation are outside the supported product direction.

## License

MaybeScanner is distributed under the GNU Affero General Public License v3.0. See `LICENSE`.

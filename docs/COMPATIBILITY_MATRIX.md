# MaybeScanner Compatibility Matrix

Last updated: 2026-06-01

## Runtime and Build Surface

| Surface | Status | Notes |
| --- | --- | --- |
| Android app variant | `universalDebug` validated | JVM unit tests and Java compile pass in CI/local script gate. |
| Android min/target SDK | Defined in app Gradle | Must be re-verified per release cut. |
| Go sidecar | Supported | `go test ./...` and `go vet ./...` passing. |
| Sidecar API transport | Loopback HTTP + NDJSON | Current baseline; binary telemetry is deferred/ADR backlog. |
| Auth transport | Bearer + HttpOnly cookie | Query-token auth disabled. |

## Network and Feature Compatibility

| Feature | Current Compatibility | Notes |
| --- | --- | --- |
| IP-first scanning | Supported | Default MaybeScanner posture. |
| Route-pairing workflows | Limited/advanced | Core route-pairing belongs to MaybeEdgeScanner. |
| Provider-managed routes (Psiphon/Windscribe) | Not a default MaybeScanner surface | Only generic proxy diagnostics are expected in this app. |
| Shizuku-assisted diagnostics | Conditional | Requires user grant + runtime capability checks; no root assumptions. |
| VPN ownership claims | Not claimed | If external VPN is observed, it must be labeled observed, not owned. |

## Test Evidence Snapshot

| Evidence | Status |
| --- | --- |
| `gradlew testUniversalDebugUnitTest --offline` | Passing |
| `gradlew compileUniversalDebugJavaWithJavac --offline` | Passing |
| `go test ./...` (sidecar) | Passing |
| `go vet ./...` (sidecar) | Passing |
| `scripts/verify-release-readiness.ps1` | Passing |

## Open Compatibility Blockers Before Stable Release

- Real device/emulator screenshot matrix for release-critical UI states.
- Signed release APK verification.
- Formal SBOM output and release-packaged provenance bundle.
- Device-level lifecycle instrumentation for notification stop, heartbeat-loss, and export-after-recreate flows.

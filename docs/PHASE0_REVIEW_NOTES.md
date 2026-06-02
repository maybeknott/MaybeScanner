# Phase 0 documentation review (MaybeScanner)

Date: 2026-05-31

## README

- First paragraph describes target-first IP/domain/CIDR scanning, not CDN edge discovery.
- Empty-target behavior and no default public corpus are documented.
- Advanced managed sources are called out as optional/collapsed.

## Sidecar README (`go-sidecar/README.md`)

- Documents loopback HTTP/NDJSON scan and DNS APIs, structured public errors, `phase_results` on scan and DNS streams, and `init.expansion`.
- Empty scan requests reject with structured errors (no bundled target fallback).

## Architecture guide

- Lock-free/arena prefix claims removed; pointer trie + direct dialer baseline documented.

## Grep gate

- Retired overclaim strings are still tracked as a release-doc gate, but the legacy `scripts/verify-release-readiness.ps1` path is no longer present in the current repo tree and must not be cited as active evidence.

## Deferred (not Phase 0 doc blockers)

- Screenshot proof of default UI (B4 device matrix).

## 2026-06-02 final refactor closeout

- MainActivity has been reduced through app-owned extraction of diagnostics, result filtering/summary/export, preview input analysis, preview chips, local history, Shizuku process/radio handling, and runtime reporting.
- Final mirror audit removed the tiny SupportActions wrapper and specialized retained helpers where product copy differs.
- Verification: `./gradlew.bat :app:compileUniversalDebugJavaWithJavac` and `go test ./...` passed after the final closeout pass.

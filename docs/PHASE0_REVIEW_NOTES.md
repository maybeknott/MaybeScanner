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

- `scripts/verify-release-readiness.ps1` bans retired overclaim strings in release docs.

## Deferred (not Phase 0 doc blockers)

- Screenshot proof of default UI (B4 device matrix).

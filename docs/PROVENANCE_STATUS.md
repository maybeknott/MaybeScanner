# MaybeScanner Provenance and License Status

Last updated: 2026-06-01

## Project License

- Repository license: AGPLv3 (`/LICENSE`).

## Current Provenance Position

- Sidecar and Android code in this repository are first-party.
- External ecosystem material under `D:\GitHub\SCANNERS\tooling_inventory\external_refs` is treated as reference input and **not** direct runtime dependency by default.
- Route/provider concepts imported from external projects remain evidence-gated and must not be presented as active runtime capability without attachable-route proof.

## Release-Readiness Provenance Requirements (Open)

- Produce formal SBOM artifacts per release build (SPDX or CycloneDX).
- Attach dependency license inventory aligned to shipped binaries, not just repository references.
- Record commit/tag + retrieval date for any external source-derived behavior claims.
- Maintain claim registry entries for speculative/advanced transport features until implemented and benchmarked.

## Baseline Artifact Present

- Pre-release dependency baseline: [SBOM_BASELINE.md](./SBOM_BASELINE.md).

## Verified Security/Policy Baseline

- Local API query-token auth is removed.
- Fixed-length hashed token verification is in place.
- Read-auth regression coverage exists for `/metrics` and `/health` with Bearer + cookie acceptance.
- Diagnostics redaction is covered by JVM tests (IPv4/IPv6/token/cookie/public-IP masking pathways).

## Explicit Non-Claims

- No claim that device-level screenshot matrix is complete in this environment.
- No claim that signed release APK artifacts have been verified yet.
- No claim that production SBOM/provenance bundle is already generated.

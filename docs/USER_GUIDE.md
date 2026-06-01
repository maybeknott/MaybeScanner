# MaybeScanner User Guide

MaybeScanner is the target-first scanner. It starts from targets you provide, not from a public edge corpus. Use it to check TCP reachability, TLS certificate behavior, and HTTP status for IPs, domains, CIDR blocks, ranges, or imported target files.

---

## 1. Setup

### Android App

- Android 7.0/API 24 or newer.
- Notification permission is needed for long-running foreground scans on modern Android.
- Shizuku is optional and only enables advanced diagnostics when the user grants permission.

### Optional Go Sidecar

The sidecar can run on a workstation or server for higher-throughput local scan sessions:

```bash
./sidecar
```

Open `http://127.0.0.1:10808` for the local dashboard. Local sidecar API reads and mutations (including `/metrics` and `/health`) require sidecar auth credentials (Bearer header, `X-Sidecar-Token`, or the HttpOnly sidecar cookie).

---

## 2. Sources

The Sources tab is the scan setup surface:

- Paste IPs, domains, CIDR blocks, or ranges.
- Import a target file when available.
- Choose ports, timeout, worker count, and target cap.
- Review the target preview before starting.
- Use managed network corpora only from the collapsed advanced area, with explicit limits.

MaybeScanner does not silently scan a bundled public target set when the target box is empty. Start remains unavailable until at least one valid target exists.

Supported target formats:

| Input Example | Meaning |
| :--- | :--- |
| `1.1.1.1` | Single IPv4 address |
| `2606:4700:4700::1111` | Single IPv6 address |
| `example.com` | Hostname resolved to addresses |
| `192.168.1.0/24` | CIDR expansion, bounded by safety and target limits |
| `192.168.1.10-192.168.1.20` | Inclusive IP range |

Literal IP scans do not receive a default SNI. Hostname-derived TLS names are used only when the scan plan calls for hostname verification or an explicit manual override.

---

## 3. Scan Profiles

Recommended MaybeScanner profiles are:

1. **TCP Reachability**: connect checks and latency.
2. **TCP Ports**: repeated reachability checks across selected ports.
3. **TLS Certificate Check**: TLS handshake, protocol, cipher, certificate subject/issuer/SAN, and fingerprint observation.
4. **HTTP Status Check**: HTTP response status and selected headers when the negotiated protocol supports the probe.
5. **Full Scan**: TCP, TLS, certificate, and HTTP phases with stable per-phase result codes.

Advanced TLS ClientHello selection, manual SNI/Host override, HTTP/3 hints, and provider classification are optional diagnostics. They are not the default product flow.

---

## 4. Results

Results are shown as completed attempts with explicit phase status:

- IP and port.
- TCP/TLS/HTTP status.
- Latency and selected ALPN.
- Certificate names and fingerprint when available.
- Best-effort network classification when a bundled or refreshed corpus matches.

Classification is an annotation, not target identity. Use the advanced classification filter only to narrow visible result rows after a scan.

If all visible attempts time out, treat that as a failure condition rather than an empty result set. Try fewer workers, a longer timeout, Wi-Fi, a smaller target plan, or a different route.

---

## 5. Diagnostics

Diagnostics are separate from scan state:

- Network environment summary.
- DNS and TCP diagnostic probes.
- Sidecar heartbeat and local API status.
- Optional public-IP lookup, disabled by default.
- Optional Shizuku-assisted radio diagnostics when permission is granted.

Use **Copy redacted** for normal support/debugging. Full diagnostic copy should be confirmed explicitly because it can contain local network details.

Shizuku does not imply root, packet capture, raw socket privileges, or permission to bypass Android power policy. Privileged actions must be user-visible and readback-verified.

---

## 6. Safety

Default safety excludes private, loopback, multicast, link-local, documentation, and broadcast ranges unless explicitly enabled. Broad scans require an explicit visible plan with target count, checks, rate, worker budget, and user-selected limits. Current sidecar policy relies on explicit budgets rather than a separate server-side broad-scan confirmation block.

On mobile:

- Prefer 8-32 workers.
- Keep rates modest on metered networks.
- Avoid broad scans while unplugged.
- Stop or reduce workers when timeout rate remains extreme.

---

## 7. Export

Exports should preserve schema version, product mode, target identity, phase results, error codes, redaction state, app version, sidecar version, and corpus revision where available.

Default redaction covers local API tokens, proxy credentials, plugin secrets, sensitive diagnostics, and private network/device details when privacy mode is enabled.

---

## 8. Troubleshooting

| Symptom | Likely Cause | Action |
| :--- | :--- | :--- |
| No targets selected | The app starts empty by design. | Paste targets or import a file. |
| Broad scan is larger than intended | Target budget or source selection is too broad. | Review count, rate, route, safety policy, and target limits before starting. |
| All probes time out | Network path, firewall, route, timeout, or worker pressure. | Reduce workers, increase timeout, try Wi-Fi, or shrink target set. |
| TLS succeeds but HTTP is skipped | ALPN selected HTTP/2 and the HTTP/1.1 probe is not valid on that connection. | Use HTTP/2-capable probing when available or restrict HTTP/1.1 on a separate run. |
| Shizuku unavailable | Service missing, not running, or permission not granted. | Open Shizuku and grant MaybeScanner permission. |

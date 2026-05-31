package com.maybescanner;

import org.json.JSONObject;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Locale;

/** Contract-shaped TargetPlan v1 snapshot attached to probe results. */
final class TargetPlanRecord {
    private final JSONObject payload;
    private final String planId;
    private final String correlationId;
    private final String productMode;
    private final String sniMode;
    private final String dedupeKey;
    private final String originalHostname;
    private final String routeId;

    private TargetPlanRecord(JSONObject payload, String planId, String correlationId, String productMode,
                             String sniMode, String dedupeKey, String originalHostname, String routeId) {
        this.payload = payload;
        this.planId = planId;
        this.correlationId = correlationId;
        this.productMode = productMode;
        this.sniMode = sniMode;
        this.dedupeKey = dedupeKey;
        this.originalHostname = originalHostname;
        this.routeId = routeId;
    }

    static TargetPlanRecord forIpFirstProbe(String rawToken, String resolvedIp, int port, String sniHost, boolean sniPairingEnabled) {
        return build("ip_first", rawToken, resolvedIp, port, sniHost, sniPairingEnabled, "direct-default", "direct", "direct");
    }

    static TargetPlanRecord forRoutePairingProbe(String rawToken, String resolvedIp, int port, String sniHost,
                                                 boolean sniPairingEnabled, String routeId, String routeType, String networkPath) {
        return build("route_pairing", rawToken, resolvedIp, port, sniHost, sniPairingEnabled, routeId, routeType, networkPath);
    }

    private static TargetPlanRecord build(String productMode, String rawToken, String resolvedIp, int port, String sniHost,
                                          boolean sniPairingEnabled, String routeId, String routeType, String networkPath) {
        String token = clean(rawToken);
        String ip = clean(resolvedIp);
        String sni = clean(sniHost);
        String kind = normalizedKind(token);
        String sniMode = sniModeFor(kind, ip, sni, sniPairingEnabled);
        String hostname = hostnameFor(token, kind);
        String httpHost = httpHostFor(kind, sni, sniPairingEnabled);
        String dedupe = dedupeKey(productMode, ip, port, sniMode, sni, httpHost, routeId);
        String planId = stableId("plan", dedupe);
        String correlationId = stableId("corr", dedupe);

        JSONObject o = new JSONObject();
        try {
            o.put("schema_version", 1);
            o.put("plan_id", planId);
            o.put("product_mode", productMode);
            o.put("raw_token", token.isEmpty() ? ip : token);
            o.put("source_type", "manual");
            o.put("source_provider", "manual");
            o.put("corpus_revision", JSONObject.NULL);
            o.put("normalized_kind", kind);
            o.put("original_hostname", hostname == null ? JSONObject.NULL : hostname);
            o.put("resolved_ip", ip.isEmpty() ? JSONObject.NULL : ip);
            o.put("ip_family", ipFamily(ip));
            o.put("port", Math.max(0, port));
            o.put("sni_host", sniMode.equals("ip_only_no_sni") ? JSONObject.NULL : (sni.isEmpty() ? JSONObject.NULL : sni));
            o.put("sni_mode", sniMode);
            o.put("http_host", httpHost == null ? JSONObject.NULL : httpHost);
            o.put("verification_host", httpHost == null ? JSONObject.NULL : httpHost);
            o.put("dns_mode", ip.isEmpty() ? "system" : "pre_resolved");
            o.put("resolver_id", JSONObject.NULL);
            o.put("alpn_policy", "http1_http2");
            o.put("route_id", clean(routeId));
            o.put("route_type", clean(routeType));
            o.put("network_path", clean(networkPath));
            o.put("safety_status", "allowed");
            o.put("expansion_parent", JSONObject.NULL);
            o.put("expansion_index", JSONObject.NULL);
            o.put("expansion_total_theoretical", JSONObject.NULL);
            o.put("expansion_total_capped", JSONObject.NULL);
            o.put("expansion_skipped_count", JSONObject.NULL);
            o.put("sampling_seed", JSONObject.NULL);
            o.put("dedupe_key", dedupe);
            o.put("result_correlation_id", correlationId);
        } catch (Exception ignored) {
        }
        return new TargetPlanRecord(o, planId, correlationId, productMode, sniMode, dedupe,
                hostname == null ? "" : hostname, clean(routeId));
    }

    JSONObject toJson() {
        try {
            return new JSONObject(payload.toString());
        } catch (Exception e) {
            return payload;
        }
    }

    String planId() {
        return planId;
    }

    String correlationId() {
        return correlationId;
    }

    String productMode() {
        return productMode;
    }

    String sniMode() {
        return sniMode;
    }

    String dedupeKey() {
        return dedupeKey;
    }

    String originalHostname() {
        return originalHostname;
    }

    String routeId() {
        return routeId;
    }

    private static String clean(String value) {
        return value == null ? "" : value.trim();
    }

    private static String normalizedKind(String token) {
        if (token.isEmpty()) return "ip";
        if (ScanTargetPlanner.isIp(token)) return "ip";
        if (token.contains("/")) return "cidr";
        if (token.contains("-")) return "range";
        return "hostname";
    }

    private static String sniModeFor(String kind, String ip, String sni, boolean sniPairingEnabled) {
        if (!sniPairingEnabled || sni.isEmpty()) {
            return "ip_only_no_sni";
        }
        if ("hostname".equals(kind)) {
            return "domain_sni";
        }
        return "explicit_sni";
    }

    private static String hostnameFor(String token, String kind) {
        if ("hostname".equals(kind)) return token;
        return null;
    }

    private static String httpHostFor(String kind, String sni, boolean sniPairingEnabled) {
        if (!sniPairingEnabled) return null;
        if ("hostname".equals(kind)) return sni.isEmpty() ? null : sni;
        return sni.isEmpty() ? null : sni;
    }

    private static String ipFamily(String ip) {
        if (ip.isEmpty()) return "unknown";
        try {
            return InetAddress.getByName(ip) instanceof Inet6Address ? "ipv6" : "ipv4";
        } catch (Exception ignored) {
            return ip.contains(":") ? "ipv6" : "ipv4";
        }
    }

    private static String dedupeKey(String productMode, String ip, int port, String sniMode, String sni, String httpHost, String routeId) {
        if ("route_pairing".equals(productMode)) {
            return productMode + "|" + ip + "|" + port + "|sni=" + sni + "|host=" + (httpHost == null ? "" : httpHost) + "|route=" + routeId;
        }
        String sniPart = "ip_only_no_sni".equals(sniMode) ? "no_sni" : sni;
        return productMode + "|" + ip + "|" + port + "|" + sniPart + "|" + routeId;
    }

    private static String stableId(String prefix, String seed) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(seed.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder();
            for (int i = 0; i < 4; i++) {
                hex.append(String.format(Locale.US, "%02x", hash[i]));
            }
            return prefix + "-" + hex;
        } catch (Exception ignored) {
            return prefix + "-" + Math.abs(seed.hashCode());
        }
    }
}

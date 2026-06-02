package com.maybescanner;

import org.junit.Test;

import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class ResultFilterEngineTest {
    @Test
    public void providerPresetMatchesIpScannerClassifications() {
        assertTrue(ResultFilterEngine.providerMatches("Known network", "Cloudflare"));
        assertTrue(ResultFilterEngine.providerMatches("AWS CloudFront", "Amazon CloudFront"));
        assertTrue(ResultFilterEngine.providerMatches("Unknown", "UNKNOWN"));
        assertFalse(ResultFilterEngine.providerMatches("Cloudflare", "Fastly"));
    }

    @Test
    public void filtersWorkingTls13KnownProviderRows() {
        ResultFilterEngine.Spec spec = new ResultFilterEngine.Spec();
        spec.requireWorking = true;
        spec.requireKnownClassification = true;
        spec.requireTls13 = true;
        spec.networkPreset = "Cloudflare";

        List<Row> filtered = ResultFilterEngine.apply(Arrays.asList(
                new Row("slow-cloudflare", true, true, false, "TLS 1.2", 120, 60, "Cloudflare", "SAN=old.example", "old.example", "1.1.1.1:443"),
                new Row("good-cloudflare", true, true, true, "TLS 1.3", 40, 96, "Cloudflare", "SAN=edge.example", "edge.example", "1.1.1.1:443"),
                new Row("unknown", true, true, true, "TLS 1.3", 20, 99, "UNKNOWN", "SAN=unknown.example", "unknown.example", "8.8.8.8:443")
        ), spec, Row.ACCESSOR);

        assertEquals(1, filtered.size());
        assertEquals("good-cloudflare", filtered.get(0).id);
    }

    @Test
    public void bestPerEndpointKeepsHighestQualityObservation() {
        ResultFilterEngine.Spec spec = new ResultFilterEngine.Spec();
        spec.bestPerEndpoint = true;
        spec.sortMode = 2;

        List<Row> filtered = ResultFilterEngine.apply(Arrays.asList(
                new Row("first", true, true, false, "TLS 1.3", 30, 50, "Cloudflare", "SAN=a.example", "a.example", "1.1.1.1:443"),
                new Row("best", true, true, true, "TLS 1.3", 45, 91, "Cloudflare", "SAN=b.example", "b.example", "1.1.1.1:443"),
                new Row("other", true, false, true, "", 20, 75, "Fastly", "SAN=c.example", "c.example", "2.2.2.2:443")
        ), spec, Row.ACCESSOR);

        assertEquals(2, filtered.size());
        assertEquals("best", filtered.get(0).id);
        assertEquals("other", filtered.get(1).id);
    }

    private static final class Row {
        static final ResultFilterEngine.Accessor<Row> ACCESSOR = new ResultFilterEngine.Accessor<Row>() {
            @Override public boolean working(Row row) { return row.working; }
            @Override public boolean tlsPass(Row row) { return row.tls; }
            @Override public boolean httpPass(Row row) { return row.http; }
            @Override public String tlsVersion(Row row) { return row.tlsVersion; }
            @Override public long totalLatency(Row row) { return row.latency; }
            @Override public double quality(Row row) { return row.quality; }
            @Override public String networkClassification(Row row) { return row.network; }
            @Override public String certificateText(Row row) { return row.cert; }
            @Override public String hostHintText(Row row) { return row.host; }
            @Override public String endpointKey(Row row) { return row.endpoint; }
            @Override public String sortHostKey(Row row) { return row.host; }
        };

        final String id;
        final boolean working;
        final boolean tls;
        final boolean http;
        final String tlsVersion;
        final long latency;
        final double quality;
        final String network;
        final String cert;
        final String host;
        final String endpoint;

        Row(String id, boolean working, boolean tls, boolean http, String tlsVersion,
            long latency, double quality, String network, String cert, String host, String endpoint) {
            this.id = id;
            this.working = working;
            this.tls = tls;
            this.http = http;
            this.tlsVersion = tlsVersion;
            this.latency = latency;
            this.quality = quality;
            this.network = network;
            this.cert = cert;
            this.host = host;
            this.endpoint = endpoint;
        }
    }
}

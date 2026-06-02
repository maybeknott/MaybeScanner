package com.maybescanner;

import org.junit.Test;

import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class ScanInputAnalyzerTest {
    @Test
    public void emptyCustomTargetsReportNoSelection() {
        assertEquals("Custom IPs: none", ScanInputAnalyzer.customTargetStatsText(
                " \n\t",
                values -> 1,
                (value, cap) -> 0,
                (value, cap) -> 0));
    }

    @Test
    public void targetStatsPreserveIpFirstExpansionShape() {
        String raw = "8.8.8.8\nscanner-edge.invalid 8.8.8.8\nbad/host\n8.8.0.0/30\n8.8.8.1-8.8.8.3";

        String stats = ScanInputAnalyzer.customTargetStatsText(
                raw,
                values -> {
                    String value = values.get(0);
                    if (value.contains("/")) return 4;
                    if (ScanTargetPlanner.looksLikeIpv4Range(value)) return 3;
                    return 1;
                },
                (value, cap) -> value.contains("/") ? 4 : 0,
                (value, cap) -> ScanTargetPlanner.looksLikeIpv4Range(value) ? 3 : 0);

        assertTrue(stats.contains("6 items"));
        assertTrue(stats, stats.contains("5 valid"));
        assertTrue(stats, stats.contains("1 invalid"));
        assertTrue(stats.contains("1 duplicates"));
        assertTrue(stats.contains("about 10 IPs"));
        assertTrue(stats.contains("1 CIDR"));
        assertTrue(stats.contains("1 ranges"));
        assertTrue(stats.contains("1 hostnames"));
        assertTrue(stats.contains("Preview: 8.8.8.8, scanner-edge.invalid, 8.8.0.0/30, 8.8.8.1-8.8.8.3"));
    }

    @Test
    public void hasValidTargetsRejectsSniOnlyNoise() {
        assertFalse(ScanInputAnalyzer.hasValidTargets("bad_host"));
        assertTrue(ScanInputAnalyzer.hasValidTargets("1.1.1.1"));
        assertTrue(ScanInputAnalyzer.hasValidTargets("target.example.com"));
        assertTrue(ScanInputAnalyzer.hasValidTargets("target-edge.example.com"));
    }

    @Test
    public void previewExpandedTargetsSamplesOnlyExpandedForms() {
        List<String> preview = ScanInputAnalyzer.previewExpandedTargets(
                Arrays.asList("8.8.0.0/30", "8.8.8.1-8.8.8.3", "example.com", "target-edge.example.com"),
                4,
                (value, index) -> value + "#" + index);

        assertEquals(Arrays.asList("8.8.0.0/30#0", "8.8.8.1-8.8.8.3#1", "example.com", "target-edge.example.com"), preview);
    }

}

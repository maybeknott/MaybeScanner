package com.maybescanner;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;

public class TargetPlanRecordTest {
    @Test
    public void literalIpUsesIpOnlyNoSniMode() {
        TargetPlanRecord plan = TargetPlanRecord.forIpFirstProbe("203.0.113.10", "203.0.113.10", 443, "", false);
        assertEquals("ip_only_no_sni", plan.sniMode());
        assertEquals("ip_first", plan.productMode());
        assertEquals(true, plan.dedupeKey().contains("no_sni"));
    }

    @Test
    public void hostnameUsesDomainSniWhenPairingEnabled() {
        TargetPlanRecord plan = TargetPlanRecord.forIpFirstProbe("service.example", "198.51.100.10", 443, "service.example", true);
        assertEquals("domain_sni", plan.sniMode());
        assertEquals("service.example", plan.originalHostname());
    }

    @Test
    public void hyphenatedHostnameKeepsHostnameKind() {
        TargetPlanRecord plan = TargetPlanRecord.forIpFirstProbe(
                "target-edge.example.com", "198.51.100.10", 443, "target-edge.example.com", true);

        assertEquals("domain_sni", plan.sniMode());
        assertEquals("target-edge.example.com", plan.originalHostname());
        assertEquals("hostname", plan.normalizedKind());
    }

    @Test
    public void hostnamePassedAsResolvedIpIsSanitizedButStillDistinct() {
        TargetPlanRecord first = TargetPlanRecord.forIpFirstProbe(
                "alpha.example.com", "alpha.example.com", 443, "", false);
        TargetPlanRecord second = TargetPlanRecord.forIpFirstProbe(
                "beta.example.com", "beta.example.com", 443, "", false);

        assertEquals("", first.resolvedIp());
        assertEquals("unknown", first.ipFamily());
        assertTrue(first.dedupeKey().contains("raw=alpha.example.com"));
        assertNotEquals(first.planId(), second.planId());
    }

    @Test
    public void planAndCorrelationIdsAreStable() {
        TargetPlanRecord a = TargetPlanRecord.forIpFirstProbe("1.1.1.1", "1.1.1.1", 443, "", false);
        TargetPlanRecord b = TargetPlanRecord.forIpFirstProbe("1.1.1.1", "1.1.1.1", 443, "", false);
        assertEquals(a.planId(), b.planId());
        assertEquals(a.correlationId(), b.correlationId());
    }

    @Test
    public void cidrExpansionPreservesParentAndIndex() {
        TargetExpansionMeta expansion = TargetExpansionMeta.forExpandedMember("203.0.113.0/30", 1, 4, 2);
        TargetPlanRecord plan = TargetPlanRecord.forIpFirstProbe("203.0.113.2", "203.0.113.2", 443, "", false, expansion);
        assertTrue(plan.dedupeKey().contains("parent=203.0.113.0/30"));
        assertTrue(plan.dedupeKey().contains("idx=1"));
        assertNotEquals(
                TargetPlanRecord.forIpFirstProbe("203.0.113.2", "203.0.113.2", 443, "", false).planId(),
                plan.planId());
    }

    @Test
    public void expandedMembersHaveDistinctDedupeKeys() {
        TargetExpansionMeta first = TargetExpansionMeta.forExpandedMember("203.0.113.0/30", 0, 4, 4);
        TargetExpansionMeta second = TargetExpansionMeta.forExpandedMember("203.0.113.0/30", 1, 4, 4);
        TargetPlanRecord a = TargetPlanRecord.forIpFirstProbe("203.0.113.1", "203.0.113.1", 443, "", false, first);
        TargetPlanRecord b = TargetPlanRecord.forIpFirstProbe("203.0.113.2", "203.0.113.2", 443, "", false, second);
        assertNotEquals(a.dedupeKey(), b.dedupeKey());
        assertNotEquals(a.planId(), b.planId());
    }
}

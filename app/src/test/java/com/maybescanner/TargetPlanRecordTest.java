package com.maybescanner;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

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
    public void planAndCorrelationIdsAreStable() {
        TargetPlanRecord a = TargetPlanRecord.forIpFirstProbe("1.1.1.1", "1.1.1.1", 443, "", false);
        TargetPlanRecord b = TargetPlanRecord.forIpFirstProbe("1.1.1.1", "1.1.1.1", 443, "", false);
        assertEquals(a.planId(), b.planId());
        assertEquals(a.correlationId(), b.correlationId());
    }
}

package com.maybescanner;

import org.junit.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

public class ScanTargetPlannerExpansionTest {
    @Test
    public void expandTargetsDetailedAttachesMetaForCidrMembers() {
        List<ScanTargetPlanner.ExpandedTarget> expanded = ScanTargetPlanner.expandTargetsDetailed(
                Collections.singletonList("203.0.113.0/30"), 10);
        assertEquals(2, expanded.size());
        assertEquals("203.0.113.1", expanded.get(0).address);
        assertNotNull(expanded.get(0).expansion);
        assertEquals("203.0.113.0/30", expanded.get(0).expansion.parentToken);
        assertEquals(0, expanded.get(0).expansion.index);
    }

    @Test
    public void expandTargetsDetailedLeavesLiteralTargetsWithoutMeta() {
        List<ScanTargetPlanner.ExpandedTarget> expanded = ScanTargetPlanner.expandTargetsDetailed(
                Arrays.asList("203.0.113.10", "203.0.113.0/30"), 10);
        assertEquals(3, expanded.size());
        assertNull(expanded.get(0).expansion);
        assertNotNull(expanded.get(1).expansion);
    }
}

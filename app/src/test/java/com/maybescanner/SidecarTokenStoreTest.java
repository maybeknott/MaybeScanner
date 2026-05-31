package com.maybescanner;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class SidecarTokenStoreTest {
    @Test
    public void generatedTokenIsHexAndLongEnough() {
        String token = SidecarTokenStore.generateTokenHex(32);
        assertTrue(token.length() >= 64);
        assertTrue(token.matches("[0-9a-f]+"));
    }

    @Test
    public void envNameIsStable() {
        assertEquals("MAYBESCANNER_SIDECAR_TOKEN", SidecarTokenStore.ENV_NAME);
    }
}

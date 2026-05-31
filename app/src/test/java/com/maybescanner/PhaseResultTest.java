package com.maybescanner;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class PhaseResultTest {
    @Test
    public void statusFromCodeMapsTimeout() {
        assertEquals("timeout", PhaseResult.statusFromCode("TCP_CONNECT_TIMEOUT"));
    }

    @Test
    public void classifyCodeUsesPhasePrefix() {
        Exception timeout = new Exception("read timed out");
        assertEquals("TLS_HANDSHAKE_TIMEOUT", PhaseResult.classifyCode(timeout, "tls"));
    }

    @Test
    public void retryablePolicy() {
        assertTrue(PhaseResult.retryableFromCode("TCP_CONNECT_RESET"));
    }

    @Test
    public void displayLabelHumanizesCode() {
        PhaseResult phase = PhaseResult.failure("tcp", 10, null, "TCP_CONNECT_TIMEOUT");
        assertEquals("Tcp Connect Timeout", phase.displayLabel());
    }
}

package main

import (
	"errors"
	"testing"
)

func TestPhaseStatusFromCode(t *testing.T) {
	cases := []struct {
		code string
		want string
	}{
		{code: "TCP_CONNECT_TIMEOUT", want: "timeout"},
		{code: "TCP_CONNECT_REFUSED", want: "refused"},
		{code: "TLS_HANDSHAKE_RESET", want: "reset"},
		{code: "SAFETY_RESERVED_RANGE_EXCLUDED", want: "skipped"},
		{code: "HTTP2_UNSUPPORTED_IN_PROBE", want: "unsupported"},
		{code: "TLS_VERIFY_HOSTNAME_MISMATCH", want: "failed"},
		{code: "DNS_FAILED", want: "failed"},
	}
	for _, tc := range cases {
		if got := phaseStatusFromCode(tc.code, errors.New("x")); got != tc.want {
			t.Fatalf("phaseStatusFromCode(%q)=%q want %q", tc.code, got, tc.want)
		}
	}
}

func TestPhaseRetryablePolicy(t *testing.T) {
	if !phaseRetryable("TCP_CONNECT_TIMEOUT") {
		t.Fatal("timeout should be retryable")
	}
	if phaseRetryable("TCP_CONNECT_REFUSED") {
		t.Fatal("refused should not be retryable")
	}
}

func TestFinalizeFinalPhasePrefersStructuredPhases(t *testing.T) {
	res := result{HTTP: true, TLS: true, ALPN: "h2", PhaseResults: []PhaseResult{
		newPhaseSuccess("tcp", 10),
		newPhaseFailure("tls", errors.New("reset"), 20, "TLS_HANDSHAKE_RESET"),
	}}
	if got := finalizeFinalPhase(res, res.PhaseResults, ""); got != "http2" {
		t.Fatalf("finalizeFinalPhase()=%q want http2 when HTTP succeeded", got)
	}
	res = result{PhaseResults: []PhaseResult{newPhaseFailure("tcp", errors.New("timeout"), 5, "TCP_CONNECT_TIMEOUT")}}
	if got := finalizeFinalPhase(res, res.PhaseResults, "TCP_CONNECT_TIMEOUT"); got != "tcp" {
		t.Fatalf("finalizeFinalPhase()=%q want tcp", got)
	}
}

func TestResultIndicatesTimeoutUsesPhaseStatus(t *testing.T) {
	res := result{Error: "legacy timeout text", PhaseResults: []PhaseResult{
		{Phase: "tcp", Status: "timeout", ErrorCode: "TCP_CONNECT_TIMEOUT"},
	}}
	if !resultIndicatesTimeout(res) {
		t.Fatal("expected timeout from phase status")
	}
}

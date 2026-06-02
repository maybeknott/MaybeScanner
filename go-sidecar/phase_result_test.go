package main

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestAppendTLSOutcomePhasesHostnameMismatch(t *testing.T) {
	phases := appendTLSOutcomePhases(nil, "expected.example", false, 12)
	if len(phases) != 2 {
		t.Fatalf("len(phases)=%d want 2", len(phases))
	}
	if phases[1].ErrorCode != "TLS_VERIFY_HOSTNAME_MISMATCH" {
		t.Fatalf("ErrorCode=%q want TLS_VERIFY_HOSTNAME_MISMATCH", phases[1].ErrorCode)
	}
}

func TestDecodeSidecarScanRequestV1(t *testing.T) {
	body := []byte(`{"schema_version":1,"request_id":"req-1","product_mode":"ip_first","plans":[{"plan_id":"p1","raw_token":"198.51.100.1","resolved_ip":"198.51.100.1","port":443,"sni_host":null,"sni_mode":"ip_only_no_sni","result_correlation_id":"c1","dns_mode":"pre_resolved","safety_status":"allowed"}],"scan_options":{"timeout_ms":1000,"connect_timeout_ms":500,"tls_timeout_ms":500,"http_timeout_ms":500,"threads":1,"http_probe":false,"http_path":"/","http_protocol_policy":"alpn_select","body_limit_bytes":1024,"result_stream":"ndjson"},"safety_policy":{"respect_reserved_ranges":true,"max_plans":10,"max_cidr_hosts":0,"rate_per_second":0,"jitter_ms":0}}`)
	got, ok := decodeSidecarScanRequestV1(body)
	if !ok {
		t.Fatal("expected v1 decode")
	}
	if len(got.planWorkItems()) != 1 {
		t.Fatalf("planWorkItems()=%d want 1", len(got.planWorkItems()))
	}
	item := got.planWorkItems()[0]
	if item.planID != "p1" || item.port != 443 {
		t.Fatalf("unexpected plan item: %+v", item)
	}
}

func TestPlanWorkItemCarriesTargetPlanEvidence(t *testing.T) {
	body := []byte(`{"schema_version":1,"request_id":"req-2","product_mode":"ip_first","plans":[{"schema_version":1,"plan_id":"p2","raw_token":"example.com","source_type":"manual","normalized_kind":"hostname","original_hostname":"example.com","resolved_ip":"93.184.216.34","ip_family":"ipv4","port":8443,"sni_host":"example.com","sni_mode":"from_hostname","http_host":"example.com","verification_host":"example.com","dns_mode":"pre_resolved","resolver_id":"system","alpn_policy":"alpn_select","safety_status":"allowed","expansion_parent":"example.com","expansion_index":3,"expansion_total_theoretical":8,"expansion_total_capped":4,"expansion_skipped_count":1,"sampling_seed":"seed-1","dedupe_key":"dedupe-1","result_correlation_id":"corr-2"}],"scan_options":{"timeout_ms":1000,"threads":1,"http_probe":false,"http_path":"/"},"safety_policy":{"respect_reserved_ranges":true,"max_plans":10,"max_cidr_hosts":0,"rate_per_second":0,"jitter_ms":0}}`)
	req, ok := decodeSidecarScanRequestV1(body)
	if !ok {
		t.Fatal("expected v1 decode")
	}
	items := req.planWorkItems()
	if len(items) != 1 {
		t.Fatalf("planWorkItems()=%d want 1", len(items))
	}
	opts := items[0].probeOptions()
	if opts.TargetPlan == nil {
		t.Fatal("expected TargetPlan evidence")
	}
	plan := opts.TargetPlan
	if plan.RawToken != "example.com" || plan.OriginalHostname != "example.com" || plan.ResolvedIP != "93.184.216.34" {
		t.Fatalf("identity fields not preserved: %+v", plan)
	}
	if plan.ProductMode != "ip_first" || plan.Port != 8443 || plan.SNIHost != "example.com" || plan.SNIMode != "from_hostname" {
		t.Fatalf("execution fields not preserved: %+v", plan)
	}
	if plan.ExpansionIndex == nil || *plan.ExpansionIndex != 3 || plan.ExpansionTotalCapped == nil || *plan.ExpansionTotalCapped != 4 {
		t.Fatalf("expansion fields not preserved: %+v", plan)
	}
	if plan.DedupeKey != "dedupe-1" || plan.ResultCorrelationID != "corr-2" {
		t.Fatalf("correlation fields not preserved: %+v", plan)
	}
}

func TestResultJSONIncludesTargetPlanEvidence(t *testing.T) {
	res := result{
		Target:              "example.com",
		Port:                443,
		PlanID:              "p-json",
		ResultCorrelationID: "corr-json",
		TargetPlan: &TargetPlanEvidence{
			SchemaVersion:       1,
			PlanID:              "p-json",
			ProductMode:         "ip_first",
			RawToken:            "example.com",
			ResolvedIP:          "93.184.216.34",
			Port:                443,
			ResultCorrelationID: "corr-json",
		},
	}
	b, err := json.Marshal(res)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	out := string(b)
	if !strings.Contains(out, `"target_plan"`) || !strings.Contains(out, `"raw_token":"example.com"`) {
		t.Fatalf("target_plan evidence missing from json: %s", out)
	}
}

func TestPhaseStatusFromCode(t *testing.T) {
	cases := []struct {
		code string
		want string
	}{
		{code: "TCP_CONNECT_TIMEOUT", want: "timeout"},
		{code: "TCP_CONNECT_REFUSED", want: "refused"},
		{code: "TLS_HANDSHAKE_RESET", want: "reset"},
		{code: "PROXY_CONNECT_MALFORMED_RESPONSE", want: "malformed"},
		{code: "SAFETY_RESERVED_RANGE_EXCLUDED", want: "skipped"},
		{code: "HTTP2_UNSUPPORTED_IN_PROBE", want: "unsupported"},
		{code: "LOCAL_API_THROTTLED", want: "throttled"},
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
	res = result{HTTP: true, TLS: true, ALPN: "http/1.1", PhaseResults: []PhaseResult{
		newPhaseSuccess("tcp", 10),
		newPhaseSuccess("tls", 20),
		newPhaseFailure("route", errors.New("not observed"), 0, "ROUTE_REQUEST_NOT_OBSERVED"),
	}}
	if got := finalizeFinalPhase(res, res.PhaseResults, ""); got != "route" {
		t.Fatalf("finalizeFinalPhase()=%q want route when route evidence failed", got)
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

func TestResultErrorSignalsPreferStructuredPhases(t *testing.T) {
	res := result{Error: "legacy text", ErrorCode: "LEGACY_FAILED", PhaseResults: []PhaseResult{
		newPhaseSuccess("tcp", 1),
		newPhaseFailure("http1", errors.New("parse failed"), 2, "HTTP_PARSE_FAILED"),
		newPhaseFailure("tcp", errors.New("timeout"), 3, "TCP_CONNECT_TIMEOUT"),
	}}
	signals := resultErrorSignals(res)
	if len(signals) != 4 {
		t.Fatalf("signals=%#v", signals)
	}
	if signals[0] != "HTTP_PARSE_FAILED" || signals[1] != "TCP_CONNECT_TIMEOUT" {
		t.Fatalf("phase signals not first: %#v", signals)
	}
}

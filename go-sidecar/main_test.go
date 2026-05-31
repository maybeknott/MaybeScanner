package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestCandidateSNIsUsesOnlyResolvedHostHints(t *testing.T) {
	cases := []struct {
		name        string
		resolvedSNI string
		want        []string
	}{
		{name: "domain input uses resolved host for certificate observation", resolvedSNI: "target.example", want: []string{"target.example"}},
		{name: "ip input keeps direct ip probing", resolvedSNI: "", want: []string{""}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := candidateSNIs(tc.resolvedSNI); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("candidateSNIs()=%v, want %v", got, tc.want)
			}
		})
	}
}

func TestExpandTargetsExpandsIPv4RangesAndSmallCIDRs(t *testing.T) {
	got := expandTargets([]string{"203.0.113.7-203.0.113.9", "198.51.100.42/32"}, 10, 10, false)
	want := []string{"203.0.113.7", "203.0.113.8", "203.0.113.9", "198.51.100.42"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("expandTargets()=%v, want %v", got, want)
	}
}

func TestExpandRangeHonorsSafety(t *testing.T) {
	got := expandTargets([]string{"192.168.1.1-192.168.1.3"}, 10, 10, true)
	if len(got) != 0 {
		t.Fatalf("expandTargets()=%v, want private range skipped", got)
	}
}

func TestExpandTargetsDoesNotSpendRangeBudgetOnDuplicates(t *testing.T) {
	got := expandTargets([]string{"203.0.113.7", "203.0.113.7-203.0.113.9"}, 3, 3, false)
	want := []string{"203.0.113.7", "203.0.113.8", "203.0.113.9"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("expandTargets()=%v, want %v", got, want)
	}
}

func TestExpandTargetsDoesNotRejectBroadPublicCIDRWhenBudgetProvided(t *testing.T) {
	got := expandTargets([]string{"8.8.0.0/15"}, 3, 3, true)
	want := []string{"8.8.0.1", "8.8.0.2", "8.8.0.3"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("expandTargets()=%v, want %v", got, want)
	}
}

func TestScanRejectsExplicitTargetsFilteredToZero(t *testing.T) {
	body := bytes.NewBufferString(`{"targets":["192.168.0.0/24"],"ports":[443],"respect_safety":true}`)
	req := httptest.NewRequest(http.MethodPost, "/api/scan", body)
	rec := httptest.NewRecorder()
	scan(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("scan status=%d, want %d", rec.Code, http.StatusBadRequest)
	}
	if !strings.Contains(rec.Body.String(), `"error_code":"NO_USABLE_TARGETS"`) {
		t.Fatalf("missing NO_USABLE_TARGETS error envelope: %s", rec.Body.String())
	}
}

func TestScanRejectsMalformedBodyWithSanitizedError(t *testing.T) {
	body := bytes.NewBufferString(`{"targets":["198.51.100.1"],"ports":[`)
	req := httptest.NewRequest(http.MethodPost, "/api/scan", body)
	rec := httptest.NewRecorder()
	scan(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("scan status=%d, want %d", rec.Code, http.StatusBadRequest)
	}
	got := rec.Body.String()
	if !strings.Contains(got, "invalid scan request body") || strings.Contains(strings.ToLower(got), "unexpected") {
		t.Fatalf("scan decode error was not sanitized: %q", got)
	}
}

func TestGrafanaDashboardNotFoundReturnsStructuredError(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd() error: %v", err)
	}
	tmp := t.TempDir()
	if err := os.Chdir(tmp); err != nil {
		t.Fatalf("Chdir(%q) error: %v", tmp, err)
	}
	defer func() {
		_ = os.Chdir(wd)
	}()

	req := httptest.NewRequest(http.MethodGet, "/api/grafana-dashboard", nil)
	rec := httptest.NewRecorder()
	grafanaDashboard(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("dashboard status=%d, want %d", rec.Code, http.StatusNotFound)
	}
	if !strings.Contains(rec.Body.String(), `"error_code":"DASHBOARD_NOT_FOUND"`) {
		t.Fatalf("dashboard error was not structured: %q", rec.Body.String())
	}
}

func TestScanRejectsNonPostWithStructuredMethodError(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/scan", nil)
	rec := httptest.NewRecorder()
	scan(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("scan status=%d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
	got := rec.Body.String()
	if !strings.Contains(got, `"error_code":"METHOD_NOT_ALLOWED"`) || !strings.Contains(got, `"required_method":"POST"`) {
		t.Fatalf("scan method error was not structured: %q", got)
	}
}

func TestScanRejectsMissingTargetsWithoutFallback(t *testing.T) {
	body := bytes.NewBufferString(`{"targets":[],"ports":[443]}`)
	req := httptest.NewRequest(http.MethodPost, "/api/scan", body)
	rec := httptest.NewRecorder()
	scan(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("scan status=%d, want %d", rec.Code, http.StatusBadRequest)
	}
	if !strings.Contains(rec.Body.String(), `"error_code":"NO_TARGETS_SELECTED"`) || !strings.Contains(rec.Body.String(), "no targets selected") {
		t.Fatalf("unexpected error body: %q", rec.Body.String())
	}
}

func TestScanAcceptsLargeExplicitWorkloadRequest(t *testing.T) {
	body := bytes.NewBufferString(`{"targets":["198.51.100.1"],"ports":[443],"threads":999999}`)
	req := httptest.NewRequest(http.MethodPost, "/api/scan", body)
	rec := httptest.NewRecorder()
	scan(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("scan status=%d, want %d body=%q", rec.Code, http.StatusOK, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"type":"init"`) {
		t.Fatalf("expected init frame, got: %q", rec.Body.String())
	}
}

func TestScanSafeQuickDoesNotRequireBroadScanConfirmation(t *testing.T) {
	body := bytes.NewBufferString(`{
		"targets":["8.8.8.8","8.8.4.4","1.1.1.1"],
		"ports":[443],
		"safety_preset":"safe_quick",
		"broad_scan_confirmed":false,
		"max_targets":0,
		"max_cidr_hosts":0
	}`)
	req := httptest.NewRequest(http.MethodPost, "/api/scan", body)
	rec := httptest.NewRecorder()
	scan(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("scan status=%d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), `"error_code":"BROAD_SCAN_CONFIRMATION_REQUIRED"`) {
		t.Fatalf("broad scan confirmation gate should be removed: %s", rec.Body.String())
	}
}

func TestExportNmapRejectsMalformedBodyWithSanitizedError(t *testing.T) {
	body := bytes.NewBufferString(`[{"ip":"198.51.100.1","port":443}`)
	req := httptest.NewRequest(http.MethodPost, "/api/export/nmap", body)
	rec := httptest.NewRecorder()
	exportNmap(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("export status=%d, want %d", rec.Code, http.StatusBadRequest)
	}
	got := rec.Body.String()
	if !strings.Contains(got, "invalid export request body") || strings.Contains(strings.ToLower(got), "unexpected") {
		t.Fatalf("export decode error was not sanitized: %q", got)
	}
}

func TestExportNmapRejectsNonPostWithStructuredMethodError(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/export/nmap", nil)
	rec := httptest.NewRecorder()
	exportNmap(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("export status=%d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
	got := rec.Body.String()
	if !strings.Contains(got, `"error_code":"METHOD_NOT_ALLOWED"`) || !strings.Contains(got, `"required_method":"POST"`) {
		t.Fatalf("export method error was not structured: %q", got)
	}
}

func TestValidateRoutingPluginEndpointReturnsValidation(t *testing.T) {
	body := bytes.NewBufferString(`{
		"schema_version":1,
		"route_id":"route-proxy-test",
		"plugin_id":"generic-proxy",
		"enabled":true,
		"remote_dns":true,
		"endpoint":"socks5://127.0.0.1:1080",
		"credential_ref":"ref:proxy-creds",
		"fields":{"auth_mode":"none","dns_policy":"remote"}
	}`)
	req := httptest.NewRequest(http.MethodPost, "/api/plugins/validate", body)
	rec := httptest.NewRecorder()
	validateRoutingPlugin(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("validate status=%d body=%s", rec.Code, rec.Body.String())
	}
	var result RoutingPluginConfigValidation
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if !result.Valid || result.PluginID != "generic-proxy" || result.PluginType != "generic_proxy" {
		t.Fatalf("unexpected validation response: %#v", result)
	}
}

func TestValidateRoutingPluginEndpointReturnsStructuredSanitizedError(t *testing.T) {
	body := bytes.NewBufferString(`{
		"schema_version":1,
		"route_id":"route-bad",
		"plugin_id":"generic-proxy",
		"enabled":true,
		"fields":{"mode":"wireguard\r\nx-injected: true"}
	}`)
	req := httptest.NewRequest(http.MethodPost, "/api/plugins/validate", body)
	rec := httptest.NewRecorder()
	validateRoutingPlugin(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("validate status=%d body=%s", rec.Code, rec.Body.String())
	}
	var result map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result["valid"] != false || result["error_code"] != "PLUGIN_CONFIG_INVALID" || result["field"] != "config" {
		t.Fatalf("unexpected structured error payload: %#v", result)
	}
	if strings.Contains(rec.Body.String(), "wireguard") || strings.Contains(rec.Body.String(), "x-injected") || strings.Contains(rec.Body.String(), "route-bad") {
		t.Fatalf("public validation error leaked request detail: %s", rec.Body.String())
	}
}

func TestProbeHTTPOverNegotiatedALPNSkipsHTTP11ForH2(t *testing.T) {
	httpOK, status, server, cache, altSvc, http3, code := probeHTTPOverNegotiatedALPN(context.Background(), nil, "192.0.2.5", "", "/", 1000, "h2")
	if httpOK || status != 0 || server != "" || cache != "" || altSvc != "" || http3 {
		t.Fatalf("unexpected HTTP probe output for h2 skip: ok=%v status=%d server=%q cache=%q altSvc=%q http3=%v", httpOK, status, server, cache, altSvc, http3)
	}
	if code != "HTTP2_UNSUPPORTED_IN_PROBE" {
		t.Fatalf("unexpected probe code %q", code)
	}
}

func TestProbeHTTPOverNegotiatedALPNExecutesHTTP11WhenAllowed(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		reader := bufio.NewReader(server)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			if line == "\r\n" {
				break
			}
		}
		_, _ = io.WriteString(server, "HTTP/1.1 200 OK\r\nServer: unit-test\r\n\r\n")
	}()
	httpOK, status, serverHeader, _, _, _, code := probeHTTPOverNegotiatedALPN(context.Background(), client, "192.0.2.5", "", "/", 1000, "http/1.1")
	<-done
	if !httpOK || status != 200 || serverHeader != "unit-test" {
		t.Fatalf("unexpected HTTP probe output: ok=%v status=%d server=%q", httpOK, status, serverHeader)
	}
	if code != "" {
		t.Fatalf("unexpected probe code %q", code)
	}
}

func TestClassifyNetworkError(t *testing.T) {
	cases := []struct {
		name  string
		err   error
		phase string
		want  string
	}{
		{name: "timeout", err: errors.New("i/o timeout"), phase: "tcp", want: "TCP_CONNECT_TIMEOUT"},
		{name: "reset", err: errors.New("connection reset by peer"), phase: "tls", want: "TLS_HANDSHAKE_RESET"},
		{name: "refused", err: errors.New("connection refused"), phase: "tcp", want: "TCP_CONNECT_REFUSED"},
		{name: "default", err: errors.New("network unreachable"), phase: "tcp", want: "TCP_CONNECT_FAILED"},
		{name: "dns default", err: errors.New("no such host"), phase: "dns", want: "DNS_FAILED"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyNetworkError(tc.err, tc.phase); got != tc.want {
				t.Fatalf("classifyNetworkError()=%q, want %q", got, tc.want)
			}
		})
	}
}

func TestTrackAdaptiveBackoffControllerOwnsDelayAndReset(t *testing.T) {
	globalBackoffNS.Store(0)
	noisy := make([]string, 32)
	for i := range noisy {
		noisy[i] = "connection timeout"
	}
	trackAdaptiveBackoff(noisy, 250)
	if globalBackoffNS.Load() <= 0 {
		t.Fatalf("expected controller to set backoff delay, got %d", globalBackoffNS.Load())
	}
	trackAdaptiveBackoff([]string{"ok"}, 250)
	if globalBackoffNS.Load() != 0 {
		t.Fatalf("expected controller to clear backoff delay, got %d", globalBackoffNS.Load())
	}
}

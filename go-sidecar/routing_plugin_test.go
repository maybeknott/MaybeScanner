package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDefaultRoutingPluginRegistryContainsExpectedAdapters(t *testing.T) {
	registry, err := defaultRoutingPluginRegistry()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := registry.Get("generic-proxy"); !ok {
		t.Fatal("missing generic-proxy plugin")
	}
	for _, id := range []string{"psiphon", "windscribe"} {
		if _, ok := registry.Get(id); ok {
			t.Fatalf("generic scanner must not advertise provider plugin %s", id)
		}
	}
}

func TestRoutingPluginValidationRejectsProviderSpecificPluginTypes(t *testing.T) {
	descriptor := RoutingPluginDescriptor{
		SchemaVersion:     1,
		PluginID:          "bad-psiphon",
		PluginType:        "psiphon",
		DisplayName:       "Bad Psiphon",
		Version:           "v1",
		SourceURL:         "https://example.test",
		License:           "test",
		RouteType:         "plugin",
		CredentialMode:    "user_supplied",
		LocalAPIMode:      "authenticated_http",
		LocalAPIRequired:  true,
		SecretPolicy:      "credential_ref_only",
		Enabled:           false,
		EnabledByDefault:  false,
		SupportsIPv4:      true,
		SupportsIPv6:      false,
		SupportsRemoteDNS: true,
		DiagnosticLabel:   "bad",
	}
	if err := validateRoutingPluginDescriptor(descriptor); err == nil {
		t.Fatal("expected provider-specific plugin_type validation error")
	}
}

func TestRoutingPluginValidationRejectsUnsupportedEnums(t *testing.T) {
	descriptor := RoutingPluginDescriptor{
		SchemaVersion:     1,
		PluginID:          "bad-route",
		PluginType:        "generic_proxy",
		DisplayName:       "Bad Route",
		Version:           "v1",
		SourceURL:         "https://example.test",
		License:           "test",
		RouteType:         "raw_packet",
		CredentialMode:    "user_supplied",
		LocalAPIMode:      "none",
		LocalAPIRequired:  false,
		SecretPolicy:      "credential_ref_only",
		Enabled:           false,
		EnabledByDefault:  false,
		SupportsIPv4:      true,
		SupportsIPv6:      true,
		SupportsRemoteDNS: true,
		DiagnosticLabel:   "bad",
	}
	if err := validateRoutingPluginDescriptor(descriptor); err == nil {
		t.Fatal("expected unsupported route_type validation error")
	}
}

func TestRoutingPluginValidationRejectsImpossibleLocalAPIContract(t *testing.T) {
	descriptor := RoutingPluginDescriptor{
		SchemaVersion:     1,
		PluginID:          "bad-api",
		PluginType:        "generic_proxy",
		DisplayName:       "Bad API",
		Version:           "v1",
		SourceURL:         "https://example.test",
		License:           "test",
		RouteType:         "socks5",
		CredentialMode:    "user_supplied",
		LocalAPIMode:      "none",
		LocalAPIRequired:  true,
		SecretPolicy:      "credential_ref_only",
		Enabled:           false,
		EnabledByDefault:  false,
		SupportsIPv4:      true,
		SupportsIPv6:      true,
		SupportsRemoteDNS: true,
		DiagnosticLabel:   "bad",
	}
	if err := validateRoutingPluginDescriptor(descriptor); err == nil {
		t.Fatal("expected impossible local API contract validation error")
	}
}

func TestRoutingPluginRedactsKnownAndGenericSecrets(t *testing.T) {
	registry, err := defaultRoutingPluginRegistry()
	if err != nil {
		t.Fatal(err)
	}
	plugin, _ := registry.Get("generic-proxy")
	out := redactPluginDiagnostics(plugin, map[string]string{
		"username":            "alice",
		"proxy_authorization": "Basic secret",
		"api_token":           "token",
		"public_endpoint":     "example.test:443",
	})
	if out["username"] != "[REDACTED]" || out["proxy_authorization"] != "[REDACTED]" || out["api_token"] != "[REDACTED]" {
		t.Fatalf("secrets not redacted: %#v", out)
	}
	if out["public_endpoint"] != "example.test:443" {
		t.Fatalf("non-secret field redacted incorrectly: %#v", out)
	}
}

func TestRoutingPluginsJSONDoesNotLeakPlaceholderSecrets(t *testing.T) {
	body, err := routingPluginsJSON()
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatal(err)
	}
	lower := strings.ToLower(string(body))
	for _, forbidden := range []string{"clientsecret", "password=", "api_token="} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("plugin JSON leaked forbidden token %q: %s", forbidden, string(body))
		}
	}
}

func TestRoutingPluginsEndpointIsReadOnly(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/plugins", nil)
	routingPlugins(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status=%d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
}

func TestRoutingPluginConfigRejectsProviderIDs(t *testing.T) {
	registry, err := defaultRoutingPluginRegistry()
	if err != nil {
		t.Fatal(err)
	}
	_, err = validateRoutingPluginConfig(registry, RoutingPluginConfig{
		SchemaVersion: 1,
		RouteID:       "route-psiphon-lab",
		PluginID:      "psiphon",
		Enabled:       true,
		RemoteDNS:     true,
		LocalAPIURL:   "http://127.0.0.1:28080",
		ConfigRef:     "ref:psiphon-admin-config",
	})
	if err == nil {
		t.Fatal("expected provider plugin ID rejection")
	}
}

func TestRoutingPluginConfigRejectsUnsupportedGenericField(t *testing.T) {
	registry, err := defaultRoutingPluginRegistry()
	if err != nil {
		t.Fatal(err)
	}
	_, err = validateRoutingPluginConfig(registry, RoutingPluginConfig{
		SchemaVersion: 1,
		RouteID:       "route-proxy",
		PluginID:      "generic-proxy",
		Enabled:       true,
		Endpoint:      "socks5://127.0.0.1:1080",
		CredentialRef: "ref:proxy-creds",
		Fields: map[string]string{
			"provider_chain": "windscribe_over_psiphon",
		},
	})
	if err == nil {
		t.Fatal("expected provider-chain field rejection in MaybeScanner")
	}
}

func TestRoutingPluginConfigRejectsFieldCRLF(t *testing.T) {
	registry, err := defaultRoutingPluginRegistry()
	if err != nil {
		t.Fatal(err)
	}
	_, err = validateRoutingPluginConfig(registry, RoutingPluginConfig{
		SchemaVersion: 1,
		RouteID:       "route-proxy",
		PluginID:      "generic-proxy",
		Enabled:       true,
		Endpoint:      "socks5://127.0.0.1:1080",
		CredentialRef: "ref:proxy-creds",
		Fields: map[string]string{
			"dns_policy": "remote_dns\r\nbad: value",
		},
	})
	if err == nil {
		t.Fatal("expected CR/LF field value rejection")
	}
}

func TestRoutingPluginConfigRejectsTooManyFields(t *testing.T) {
	registry, err := defaultRoutingPluginRegistry()
	if err != nil {
		t.Fatal(err)
	}
	fields := map[string]string{
		"mode": "socks5",
	}
	for i := 0; i < 33; i++ {
		fields[fmt.Sprintf("k%d", i)] = "x"
	}
	_, err = validateRoutingPluginConfig(registry, RoutingPluginConfig{
		SchemaVersion: 1,
		RouteID:       "route-proxy",
		PluginID:      "generic-proxy",
		Enabled:       true,
		Endpoint:      "socks5://127.0.0.1:1080",
		CredentialRef: "ref:proxy-creds",
		Fields:        fields,
	})
	if err == nil {
		t.Fatal("expected too-many-fields rejection")
	}
}

func TestRoutingPluginConfigRejectsOversizedFieldValue(t *testing.T) {
	registry, err := defaultRoutingPluginRegistry()
	if err != nil {
		t.Fatal(err)
	}
	_, err = validateRoutingPluginConfig(registry, RoutingPluginConfig{
		SchemaVersion: 1,
		RouteID:       "route-proxy",
		PluginID:      "generic-proxy",
		Enabled:       true,
		Endpoint:      "socks5://127.0.0.1:1080",
		CredentialRef: "ref:proxy-creds",
		Fields: map[string]string{
			"dns_policy": strings.Repeat("a", 2049),
		},
	})
	if err == nil {
		t.Fatal("expected oversized field value rejection")
	}
}

func TestRoutingPluginConfigAcceptsGenericProxyEndpoint(t *testing.T) {
	registry, err := defaultRoutingPluginRegistry()
	if err != nil {
		t.Fatal(err)
	}
	result, err := validateRoutingPluginConfig(registry, RoutingPluginConfig{
		SchemaVersion: 1,
		RouteID:       "route-proxy",
		PluginID:      "generic-proxy",
		Enabled:       true,
		RemoteDNS:     true,
		Endpoint:      "socks5://127.0.0.1:1080",
		CredentialRef: "ref:proxy-creds",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Valid || result.PluginType != "generic_proxy" {
		t.Fatalf("unexpected validation result: %#v", result)
	}
}

func TestRoutingPluginConfigRejectsEndpointUserInfo(t *testing.T) {
	registry, err := defaultRoutingPluginRegistry()
	if err != nil {
		t.Fatal(err)
	}
	_, err = validateRoutingPluginConfig(registry, RoutingPluginConfig{
		SchemaVersion: 1,
		RouteID:       "route-proxy",
		PluginID:      "generic-proxy",
		Enabled:       true,
		RemoteDNS:     true,
		Endpoint:      "socks5://user:pass@127.0.0.1:1080",
		CredentialRef: "ref:proxy-creds",
	})
	if err == nil {
		t.Fatal("expected endpoint userinfo rejection")
	}
}

func TestRoutingPluginConfigRejectsMalformedGenericProxyEndpoint(t *testing.T) {
	registry, err := defaultRoutingPluginRegistry()
	if err != nil {
		t.Fatal(err)
	}
	for _, endpoint := range []string{
		"http://127.0.0.1:notaport",
		"socks5://127.0.0.1",
		"https://127.0.0.1:1080",
		"socks5://127.0.0.1:1080/path",
	} {
		_, err = validateRoutingPluginConfig(registry, RoutingPluginConfig{
			SchemaVersion: 1,
			RouteID:       "route-proxy",
			PluginID:      "generic-proxy",
			Enabled:       true,
			Endpoint:      endpoint,
			CredentialRef: "ref:proxy-creds",
		})
		if err == nil {
			t.Fatalf("expected endpoint rejection for %q", endpoint)
		}
	}
}

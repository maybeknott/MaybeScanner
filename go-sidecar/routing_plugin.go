package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

type RoutingPluginDescriptor struct {
	SchemaVersion     int      `json:"schema_version"`
	PluginID          string   `json:"plugin_id"`
	PluginType        string   `json:"plugin_type"`
	DisplayName       string   `json:"display_name"`
	Version           string   `json:"version"`
	SourceURL         string   `json:"source_url"`
	License           string   `json:"license"`
	RouteType         string   `json:"route_type"`
	CredentialMode    string   `json:"credential_mode"`
	LocalAPIMode      string   `json:"local_api_mode"`
	LocalAPIRequired  bool     `json:"local_api_required"`
	SecretPolicy      string   `json:"secret_policy"`
	Enabled           bool     `json:"enabled"`
	EnabledByDefault  bool     `json:"enabled_by_default"`
	SupportsIPv4      bool     `json:"supports_ipv4"`
	SupportsIPv6      bool     `json:"supports_ipv6"`
	SupportsRemoteDNS bool     `json:"supports_remote_dns"`
	DiagnosticLabel   string   `json:"diagnostic_label"`
	RedactedFields    []string `json:"redacted_fields,omitempty"`
	Notes             []string `json:"notes,omitempty"`
}

type RoutingPluginRegistry struct {
	descriptors map[string]RoutingPluginDescriptor
}

type RoutingPluginConfig struct {
	SchemaVersion int               `json:"schema_version"`
	RouteID       string            `json:"route_id"`
	PluginID      string            `json:"plugin_id"`
	Enabled       bool              `json:"enabled"`
	RemoteDNS     bool              `json:"remote_dns"`
	Endpoint      string            `json:"endpoint,omitempty"`
	LocalAPIURL   string            `json:"local_api_url,omitempty"`
	CredentialRef string            `json:"credential_ref,omitempty"`
	ConfigRef     string            `json:"config_ref,omitempty"`
	ProfileRef    string            `json:"profile_ref,omitempty"`
	Fields        map[string]string `json:"fields,omitempty"`
}

type RoutingPluginConfigValidation struct {
	Valid          bool                    `json:"valid"`
	RouteID        string                  `json:"route_id"`
	PluginID       string                  `json:"plugin_id"`
	PluginType     string                  `json:"plugin_type"`
	RouteType      string                  `json:"route_type"`
	RemoteDNS      bool                    `json:"remote_dns"`
	RedactedConfig map[string]string       `json:"redacted_config"`
	Warnings       []string                `json:"warnings,omitempty"`
	Descriptor     RoutingPluginDescriptor `json:"descriptor"`
}

var errPluginDescriptor = errors.New("invalid routing plugin descriptor")
var errPluginConfig = errors.New("invalid routing plugin config")

func defaultRoutingPluginRegistry() (*RoutingPluginRegistry, error) {
	descriptors := []RoutingPluginDescriptor{
		{
			SchemaVersion:    1,
			PluginID:         "generic-proxy",
			PluginType:       "generic_proxy",
			DisplayName:      "Generic proxy route",
			Version:          "adapter-v1",
			SourceURL:        "local://generic-proxy",
			License:          "app-native",
			RouteType:        "socks5",
			CredentialMode:   "user_supplied",
			LocalAPIMode:     "none",
			LocalAPIRequired: false,
			SecretPolicy:     "credential_ref_only",
			Enabled:          true,
			EnabledByDefault: true,
			SupportsIPv4:     true, SupportsIPv6: true, SupportsRemoteDNS: true,
			DiagnosticLabel: "Generic SOCKS/HTTP proxy",
			RedactedFields:  []string{"username", "password", "proxy_authorization"},
			Notes:           []string{"Credentials are references only and must not be logged"},
		},
	}
	return NewRoutingPluginRegistry(descriptors)
}

func NewRoutingPluginRegistry(descriptors []RoutingPluginDescriptor) (*RoutingPluginRegistry, error) {
	reg := &RoutingPluginRegistry{descriptors: map[string]RoutingPluginDescriptor{}}
	for _, descriptor := range descriptors {
		if err := validateRoutingPluginDescriptor(descriptor); err != nil {
			return nil, err
		}
		if _, exists := reg.descriptors[descriptor.PluginID]; exists {
			return nil, fmt.Errorf("%w: duplicate plugin_id %q", errPluginDescriptor, descriptor.PluginID)
		}
		reg.descriptors[descriptor.PluginID] = descriptor
	}
	return reg, nil
}

func validateRoutingPluginDescriptor(d RoutingPluginDescriptor) error {
	if d.SchemaVersion != 1 {
		return fmt.Errorf("%w: unsupported schema_version %d", errPluginDescriptor, d.SchemaVersion)
	}
	required := []string{d.PluginID, d.PluginType, d.DisplayName, d.Version, d.SourceURL, d.License, d.RouteType, d.CredentialMode, d.LocalAPIMode, d.SecretPolicy, d.DiagnosticLabel}
	if containsCRLF(required...) {
		return fmt.Errorf("%w: descriptor strings must not contain CR/LF", errPluginDescriptor)
	}
	for _, value := range required {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%w: required descriptor field is empty", errPluginDescriptor)
		}
	}
	if d.EnabledByDefault && !d.Enabled {
		return fmt.Errorf("%w: enabled_by_default requires enabled", errPluginDescriptor)
	}
	if !allowedValue(d.PluginType, "generic_proxy", "custom") {
		return fmt.Errorf("%w: unsupported plugin_type %q", errPluginDescriptor, d.PluginType)
	}
	if !allowedValue(d.RouteType, "socks5", "http_connect", "plugin", "vpn") {
		return fmt.Errorf("%w: unsupported route_type %q", errPluginDescriptor, d.RouteType)
	}
	if !allowedValue(d.CredentialMode, "none", "user_supplied", "credential_ref_only", "imported_config_ref", "external_app") {
		return fmt.Errorf("%w: unsupported credential_mode %q", errPluginDescriptor, d.CredentialMode)
	}
	if !allowedValue(d.LocalAPIMode, "none", "authenticated_http", "authenticated_unix_socket", "external_app") {
		return fmt.Errorf("%w: unsupported local_api_mode %q", errPluginDescriptor, d.LocalAPIMode)
	}
	if !allowedValue(d.SecretPolicy, "none", "credential_ref_only", "imported_config_ref", "external_app") {
		return fmt.Errorf("%w: unsupported secret_policy %q", errPluginDescriptor, d.SecretPolicy)
	}
	if d.LocalAPIRequired && d.LocalAPIMode == "none" {
		return fmt.Errorf("%w: local_api_required cannot use local_api_mode=none", errPluginDescriptor)
	}
	return nil
}

func allowedValue(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}

func (r *RoutingPluginRegistry) List() []RoutingPluginDescriptor {
	out := make([]RoutingPluginDescriptor, 0, len(r.descriptors))
	for _, descriptor := range r.descriptors {
		out = append(out, descriptor)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PluginID < out[j].PluginID })
	return out
}

func (r *RoutingPluginRegistry) Get(pluginID string) (RoutingPluginDescriptor, bool) {
	descriptor, ok := r.descriptors[pluginID]
	return descriptor, ok
}

func redactPluginDiagnostics(plugin RoutingPluginDescriptor, fields map[string]string) map[string]string {
	redacted := make(map[string]string, len(fields))
	secretNames := map[string]bool{}
	for _, field := range plugin.RedactedFields {
		secretNames[strings.ToLower(field)] = true
	}
	for key, value := range fields {
		lower := strings.ToLower(key)
		if secretNames[lower] || strings.Contains(lower, "secret") || strings.Contains(lower, "password") || strings.Contains(lower, "token") || strings.Contains(lower, "authorization") || strings.Contains(lower, "private_key") {
			redacted[key] = "[REDACTED]"
		} else {
			redacted[key] = value
		}
	}
	return redacted
}

func validateRoutingPluginConfig(registry *RoutingPluginRegistry, cfg RoutingPluginConfig) (RoutingPluginConfigValidation, error) {
	if cfg.SchemaVersion != 1 {
		return RoutingPluginConfigValidation{}, fmt.Errorf("%w: unsupported schema_version %d", errPluginConfig, cfg.SchemaVersion)
	}
	if containsCRLF(cfg.RouteID, cfg.PluginID, cfg.Endpoint, cfg.LocalAPIURL, cfg.CredentialRef, cfg.ConfigRef, cfg.ProfileRef) {
		return RoutingPluginConfigValidation{}, fmt.Errorf("%w: config strings must not contain CR/LF", errPluginConfig)
	}
	if err := validatePluginFieldMap(cfg.Fields); err != nil {
		return RoutingPluginConfigValidation{}, err
	}
	if strings.TrimSpace(cfg.RouteID) == "" || strings.TrimSpace(cfg.PluginID) == "" {
		return RoutingPluginConfigValidation{}, fmt.Errorf("%w: route_id and plugin_id are required", errPluginConfig)
	}
	plugin, ok := registry.Get(cfg.PluginID)
	if !ok {
		return RoutingPluginConfigValidation{}, fmt.Errorf("%w: unknown plugin_id %q", errPluginConfig, cfg.PluginID)
	}
	if !plugin.Enabled {
		return RoutingPluginConfigValidation{}, fmt.Errorf("%w: plugin %q is not available in this build", errPluginConfig, cfg.PluginID)
	}
	if cfg.RemoteDNS && !plugin.SupportsRemoteDNS {
		return RoutingPluginConfigValidation{}, fmt.Errorf("%w: plugin %q does not support remote DNS", errPluginConfig, cfg.PluginID)
	}
	if cfg.PluginID == "generic-proxy" {
		if err := validateProxyEndpoint(cfg.Endpoint); err != nil {
			return RoutingPluginConfigValidation{}, err
		}
	}
	if plugin.LocalAPIRequired && !isLocalPluginAPI(cfg.LocalAPIURL) {
		return RoutingPluginConfigValidation{}, fmt.Errorf("%w: plugin %q requires localhost local_api_url", errPluginConfig, cfg.PluginID)
	}
	if leaksInlineSecret(plugin, cfg) {
		return RoutingPluginConfigValidation{}, fmt.Errorf("%w: inline secret detected; use credential_ref/config_ref/profile_ref", errPluginConfig)
	}
	redacted := map[string]string{
		"route_id":       cfg.RouteID,
		"plugin_id":      cfg.PluginID,
		"endpoint":       cfg.Endpoint,
		"local_api_url":  cfg.LocalAPIURL,
		"credential_ref": cfg.CredentialRef,
		"config_ref":     cfg.ConfigRef,
		"profile_ref":    cfg.ProfileRef,
	}
	for key, value := range cfg.Fields {
		redacted[key] = value
	}
	redacted = redactPluginDiagnostics(plugin, redacted)
	warnings := []string{"generic scanner supports generic proxy/custom route validation only; provider adapters belong to MaybeEdgeScanner"}
	return RoutingPluginConfigValidation{
		Valid:          true,
		RouteID:        cfg.RouteID,
		PluginID:       cfg.PluginID,
		PluginType:     plugin.PluginType,
		RouteType:      plugin.RouteType,
		RemoteDNS:      cfg.RemoteDNS,
		RedactedConfig: redacted,
		Warnings:       warnings,
		Descriptor:     plugin,
	}, nil
}

func validatePluginFieldMap(fields map[string]string) error {
	const maxPluginFields = 32
	const maxPluginFieldKeyBytes = 96
	const maxPluginFieldValueBytes = 2048
	if len(fields) > maxPluginFields {
		return fmt.Errorf("%w: too many provider fields", errPluginConfig)
	}
	allowed := map[string]bool{
		"mode":                true,
		"auth_mode":           true,
		"dns_policy":          true,
		"remote_dns":          true,
		"proxy_gateway_scope": true,
		"upstream_mode":       true,
		"upstream_proxy_ref":  true,
	}
	for key, value := range fields {
		trimmedKey := strings.TrimSpace(key)
		if trimmedKey == "" {
			return fmt.Errorf("%w: provider field key is required", errPluginConfig)
		}
		if key != trimmedKey {
			return fmt.Errorf("%w: provider field keys must not have surrounding whitespace", errPluginConfig)
		}
		if key != strings.ToLower(key) {
			return fmt.Errorf("%w: provider field keys must be lowercase", errPluginConfig)
		}
		if len(key) > maxPluginFieldKeyBytes {
			return fmt.Errorf("%w: provider field key is too long", errPluginConfig)
		}
		if len(value) > maxPluginFieldValueBytes {
			return fmt.Errorf("%w: provider field value for %q is too long", errPluginConfig, key)
		}
		if containsCRLF(key, value) {
			return fmt.Errorf("%w: provider fields must not contain CR/LF", errPluginConfig)
		}
		if strings.ContainsAny(key, "\x00\t ") || !isPluginFieldKey(key) {
			return fmt.Errorf("%w: provider field key %q is invalid", errPluginConfig, key)
		}
		if !allowed[key] {
			return fmt.Errorf("%w: provider field %q is not supported by MaybeScanner", errPluginConfig, key)
		}
	}
	return nil
}

func isPluginFieldKey(key string) bool {
	for _, r := range key {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.' {
			continue
		}
		return false
	}
	return true
}

func leaksInlineSecret(plugin RoutingPluginDescriptor, cfg RoutingPluginConfig) bool {
	fields := map[string]string{}
	for key, value := range cfg.Fields {
		fields[key] = value
	}
	fields["credential_ref"] = cfg.CredentialRef
	fields["config_ref"] = cfg.ConfigRef
	fields["profile_ref"] = cfg.ProfileRef
	fields["endpoint"] = cfg.Endpoint
	for key, value := range fields {
		lower := strings.ToLower(key)
		if strings.Contains(lower, "ref") {
			continue
		}
		if value == "" {
			continue
		}
		if isSecretField(plugin, lower) && !strings.HasPrefix(value, "ref:") {
			return true
		}
	}
	return false
}

func isSecretField(plugin RoutingPluginDescriptor, lower string) bool {
	for _, field := range plugin.RedactedFields {
		if strings.ToLower(field) == lower {
			return true
		}
	}
	return strings.Contains(lower, "secret") ||
		strings.Contains(lower, "password") ||
		strings.Contains(lower, "token") ||
		strings.Contains(lower, "authorization") ||
		strings.Contains(lower, "private_key")
}

func isLocalPluginAPI(value string) bool {
	_, err := parseLocalPluginAPI(value)
	return err == nil
}

func parseLocalPluginAPI(value string) (*url.URL, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, fmt.Errorf("%w: local_api_url is required", errPluginConfig)
	}
	if containsCRLF(value) {
		return nil, fmt.Errorf("%w: local_api_url must not contain CR/LF", errPluginConfig)
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid local_api_url: %v", errPluginConfig, err)
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("%w: local_api_url must not contain credentials, query, or fragment", errPluginConfig)
	}
	switch parsed.Scheme {
	case "http":
		host := parsed.Hostname()
		port := parsed.Port()
		if !isLoopbackHost(host) || !validPort(port) {
			return nil, fmt.Errorf("%w: local_api_url must use loopback host and numeric port", errPluginConfig)
		}
	case "unix":
		if strings.TrimSpace(parsed.Path) == "" {
			return nil, fmt.Errorf("%w: unix local_api_url requires an app-private socket path", errPluginConfig)
		}
	default:
		return nil, fmt.Errorf("%w: local_api_url scheme must be http or unix", errPluginConfig)
	}
	return parsed, nil
}

func validateProxyEndpoint(endpoint string) error {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return fmt.Errorf("%w: generic proxy endpoint is required", errPluginConfig)
	}
	if containsCRLF(endpoint) {
		return fmt.Errorf("%w: endpoint must not contain CR/LF", errPluginConfig)
	}
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return fmt.Errorf("%w: invalid proxy endpoint: %v", errPluginConfig, err)
	}
	if parsed.User != nil {
		return fmt.Errorf("%w: endpoint must not contain inline credentials", errPluginConfig)
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return fmt.Errorf("%w: proxy endpoint must not contain path, query, or fragment", errPluginConfig)
	}
	if !allowedValue(parsed.Scheme, "socks5", "http", "http-connect") {
		return fmt.Errorf("%w: proxy endpoint scheme must be socks5, http, or http-connect", errPluginConfig)
	}
	if strings.TrimSpace(parsed.Hostname()) == "" || !validPort(parsed.Port()) {
		return fmt.Errorf("%w: proxy endpoint must include host and numeric port", errPluginConfig)
	}
	return nil
}

func isLoopbackHost(host string) bool {
	host = strings.Trim(strings.ToLower(host), "[]")
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func validPort(port string) bool {
	n, err := strconv.Atoi(port)
	return err == nil && n > 0 && n <= 65535
}

func routingPluginsJSON() ([]byte, error) {
	registry, err := defaultRoutingPluginRegistry()
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(map[string]any{
		"schema_version": 1,
		"plugins":        registry.List(),
	}, "", "  ")
}

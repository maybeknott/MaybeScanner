package main

import "testing"

func BenchmarkRoutingPluginValidationGenericProxy(b *testing.B) {
	registry, err := defaultRoutingPluginRegistry()
	if err != nil {
		b.Fatal(err)
	}
	cfg := RoutingPluginConfig{
		SchemaVersion: 1,
		RouteID:       "route-generic-bench",
		PluginID:      "generic-proxy",
		Enabled:       true,
		RemoteDNS:     true,
		Endpoint:      "socks5://127.0.0.1:1080",
		LocalAPIURL:   "http://127.0.0.1:19001",
		Fields: map[string]string{
			"auth_mode":  "none",
			"dns_policy": "remote",
		},
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := validateRoutingPluginConfig(registry, cfg); err != nil {
			b.Fatal(err)
		}
	}
}

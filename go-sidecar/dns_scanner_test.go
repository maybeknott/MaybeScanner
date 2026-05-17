package main

import "testing"

func TestBuildDNSQueryIncludesQuestionAndEDNS(t *testing.T) {
	msg, err := buildDNSQuery("example.com", dnsTypeCode("A"), true)
	if err != nil {
		t.Fatalf("buildDNSQuery failed: %v", err)
	}
	if len(msg) < 12 {
		t.Fatalf("query too short: %d", len(msg))
	}
	if got := int(msg[4])<<8 | int(msg[5]); got != 1 {
		t.Fatalf("QDCOUNT=%d, want 1", got)
	}
	if got := int(msg[10])<<8 | int(msg[11]); got != 1 {
		t.Fatalf("ARCOUNT=%d, want 1 EDNS OPT", got)
	}
}

func TestDNSTypeCode(t *testing.T) {
	cases := map[string]uint16{"A": 1, "AAAA": 28, "MX": 15, "NS": 2, "TXT": 16, "SOA": 6, "CNAME": 5}
	for name, want := range cases {
		if got := dnsTypeCode(name); got != want {
			t.Fatalf("dnsTypeCode(%s)=%d, want %d", name, got, want)
		}
	}
}

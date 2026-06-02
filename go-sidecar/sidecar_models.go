package main

import (
	"context"
	"sync"
	"sync/atomic"
)

type scanRequest struct {
	Targets                []string `json:"targets"`
	Ports                  []int    `json:"ports"`
	HTTPPath               string   `json:"http_path"`
	Threads                int      `json:"threads"`
	TimeoutMS              int      `json:"timeout_ms"`
	MaxTargets             int      `json:"max_targets"`
	MaxCIDRHosts           int      `json:"max_cidr_hosts"`
	BatchSize              int      `json:"batch_size"`
	HTTPProbe              bool     `json:"http_probe"`
	Randomize              bool     `json:"randomize"`
	RatePerSecond          int      `json:"rate_per_second"`
	JitterMS               int      `json:"jitter_ms"`
	RespectSafety          bool     `json:"respect_safety"`
	SafetyPreset           string   `json:"safety_preset,omitempty"`
	BroadScanConfirmed     bool     `json:"broad_scan_confirmed,omitempty"`
	TLSFingerprint         string   `json:"tls_fingerprint"`
	EnablePayloadSplitting bool     `json:"enable_payload_splitting"`
	SplitByteBoundary      int      `json:"split_byte_boundary"`
}

type result struct {
	Target                string        `json:"target"`
	IP                    string        `json:"ip"`
	Port                  int           `json:"port"`
	SNI                   string        `json:"sni"`
	TCP                   bool          `json:"tcp"`
	TLS                   bool          `json:"tls"`
	HTTP                  bool          `json:"http"`
	HTTPStatus            int           `json:"http_status"`
	TLSVersion            string        `json:"tls_version,omitempty"`
	TLSCipher             string        `json:"tls_cipher,omitempty"`
	CertVerified          bool          `json:"cert_verified"`
	ALPN                  string        `json:"alpn,omitempty"`
	TLSFingerprint        string        `json:"tls_fingerprint,omitempty"`
	CertSubject           string        `json:"cert_subject,omitempty"`
	ServerHeader          string        `json:"server_header,omitempty"`
	CacheHeader           string        `json:"cache_header,omitempty"`
	AltSvc                string        `json:"alt_svc,omitempty"`
	HTTP3Hint             bool          `json:"http3_hint,omitempty"`
	HTTPProbeCode         string        `json:"http_probe_code,omitempty"`
	NetworkClassification string        `json:"network_classification"`
	ProviderID            string        `json:"provider_id,omitempty"`
	ProviderName          string        `json:"provider_name,omitempty"`
	ProviderPrefix        string        `json:"provider_prefix,omitempty"`
	ProviderConfidence    string        `json:"provider_confidence,omitempty"`
	ProviderCorpusID      string        `json:"provider_corpus_id,omitempty"`
	ProviderSource        string        `json:"provider_source,omitempty"`
	LatencyMS             int64         `json:"latency_ms"`
	Score                 int           `json:"score"`
	ErrorCode             string        `json:"error_code,omitempty"`
	Error                 string        `json:"error,omitempty"`
	FinalPhase            string        `json:"final_phase,omitempty"`
	PhaseResults          []PhaseResult `json:"phase_results,omitempty"`
	PlanID                string        `json:"plan_id,omitempty"`
	ResultCorrelationID   string        `json:"result_correlation_id,omitempty"`
	BatchNumber           int           `json:"batch_number"`
}

type probeOptions struct {
	FixedIP             string
	FixedSNI            string
	SNIMode             string
	PlanID              string
	ResultCorrelationID string
}

type stats struct {
	Total       int `json:"total"`
	Checked     int `json:"checked"`
	Working     int `json:"working"`
	TLSWorking  int `json:"tls_working"`
	HTTPWorking int `json:"http_working"`
	Down        int `json:"down"`
	Batches     int `json:"batches"`
	Batch       int `json:"batch"`
}

var (
	activeCancelMu       sync.Mutex
	activeCancel         context.CancelFunc
	activeSerial         uint64
	metricScansStarted   atomic.Uint64
	metricScansCompleted atomic.Uint64
	metricScanResults    atomic.Uint64
	metricTCPPass        atomic.Uint64
	metricTLSPass        atomic.Uint64
	metricHTTPPass       atomic.Uint64
	metricTimeouts       atomic.Uint64
	metricResets         atomic.Uint64
	metricDNSRuns        atomic.Uint64
	metricSafetySkipped  atomic.Uint64
	metricBackoffEvents  atomic.Uint64
	globalBackoffNS      atomic.Int64
	safetyCIDRPrefixes   = loadSafetyPrefixes()
	activeControlPlane   *sidecarControlPlane
)

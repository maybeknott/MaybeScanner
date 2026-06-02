package main

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	tls "github.com/refraction-networking/utls"
)

func probe(ctx context.Context, target string, port int, req scanRequest, batchNo int, opts probeOptions) result {
	res := result{Target: target, Port: port, BatchNumber: batchNo, NetworkClassification: "unknown", PlanID: opts.PlanID, ResultCorrelationID: opts.ResultCorrelationID, TargetPlan: opts.TargetPlan}
	var phases []PhaseResult
	dnsStart := time.Now()
	var ips []string
	var sni string
	var err error
	if strings.TrimSpace(opts.FixedIP) != "" {
		ips = []string{strings.TrimSpace(opts.FixedIP)}
		sni = strings.TrimSpace(opts.FixedSNI)
		if opts.SNIMode == "ip_only_no_sni" {
			sni = ""
		}
	} else {
		ips, sni, err = resolveTargetCandidates(target)
	}
	if len(ips) > 0 {
		res.IP = ips[0]
	}
	res.SNI = sni
	if err != nil {
		dnsPhase := newPhaseFailure("dns", err, time.Since(dnsStart).Milliseconds(), "DNS_RESOLUTION_FAILED")
		res.PhaseResults = []PhaseResult{dnsPhase}
		res.FinalPhase = "dns"
		res.ErrorCode = dnsPhase.ErrorCode
		res.Error = err.Error()
		return res
	}
	snis := candidateSNIs(sni)
	var lastErr error
	var lastErrCode string

	for _, ip := range ips {
		if ctx.Err() != nil {
			break
		}
		res.IP = ip
		res.applyProviderObservation(observeProvider(ip))
		res.NetworkClassification = detectNetworkClassification(ip, sni, "")
		var tlsAttempted bool
		var anyTCPOK bool
		for _, candidateSNI := range snis {
			if ctx.Err() != nil {
				break
			}
			fingerprint := chooseTLSFingerprint(req.TLSFingerprint)
			tlsAttempted = true
			start := time.Now()
			conn, tcpOK, tlsInfo, tlsOK, tlsErr := tlsProbeOpen(ctx, ip, port, candidateSNI, req.TimeoutMS, fingerprint, DPIObfuscationOptions{EnablePayloadSplitting: req.EnablePayloadSplitting, SplitByteBoundary: req.SplitByteBoundary})
			if tcpOK {
				anyTCPOK = true
			}
			if tlsErr != nil {
				lastErr = tlsErr
				lastErrCode = classifyNetworkError(tlsErr, "tls")
				phases = append(phases, newPhaseFailure("tls", tlsErr, time.Since(start).Milliseconds(), lastErrCode))
			}
			if tlsOK {
				elapsed := time.Since(start).Milliseconds()
				res.TCP = true
				res.LatencyMS = elapsed
				res.TLS = true
				res.SNI = candidateSNI
				res.TLSVersion = tlsInfo.Version
				res.TLSCipher = tlsInfo.Cipher
				res.CertVerified = tlsInfo.Verified
				res.ALPN = tlsInfo.ALPN
				res.TLSFingerprint = fingerprint
				res.CertSubject = tlsInfo.Subject
				res.NetworkClassification = detectNetworkClassification(ip, candidateSNI, tlsInfo.Subject)
				phases = appendTLSOutcomePhases(phases, candidateSNI, tlsInfo.Verified, elapsed)
				if req.HTTPProbe {
					httpStart := time.Now()
					res.HTTP, res.HTTPStatus, res.ServerHeader, res.CacheHeader, res.AltSvc, res.HTTP3Hint, res.HTTPProbeCode = probeHTTPOverNegotiatedALPN(ctx, conn, ip, candidateSNI, req.HTTPPath, req.TimeoutMS, tlsInfo.ALPN)
					httpPhase := httpPhaseFromALPN(tlsInfo.ALPN)
					httpMs := time.Since(httpStart).Milliseconds()
					if res.HTTP {
						phases = append(phases, newPhaseSuccess(httpPhase, httpMs))
					} else if strings.TrimSpace(res.HTTPProbeCode) != "" {
						phases = append(phases, newPhaseFailure(httpPhase, fmt.Errorf("%s", res.HTTPProbeCode), httpMs, res.HTTPProbeCode))
					}
				}
				_ = conn.Close()
				break
			}
		}
		if anyTCPOK {
			res.TCP = true
		}
		if !res.TLS && tlsAttempted && !anyTCPOK {
			tcpStart := time.Now()
			res.TCP, err = tcpWithError(ctx, ip, port, req.TimeoutMS)
			tcpMs := time.Since(tcpStart).Milliseconds()
			res.LatencyMS = tcpMs
			if err != nil {
				lastErr = err
				lastErrCode = classifyNetworkError(err, "tcp")
				phases = append(phases, newPhaseFailure("tcp", err, tcpMs, lastErrCode))
			} else {
				phases = append(phases, newPhaseSuccess("tcp", tcpMs))
			}
		}
		if res.TLS || res.TCP {
			break
		}
	}
	if !res.TLS && !res.TCP && lastErr != nil {
		res.ErrorCode = lastErrCode
		res.Error = lastErr.Error()
	}
	res.PhaseResults = phases
	res.FinalPhase = finalizeFinalPhase(res, phases, lastErrCode)
	res.Score = score(res)
	return res
}

func resolveTarget(target string) (string, string, error) {
	ips, sni, err := resolveTargetCandidates(target)
	if err != nil {
		return "", sni, err
	}
	return ips[0], sni, nil
}

func resolveTargetCandidates(target string) ([]string, string, error) {
	if net.ParseIP(target) != nil {
		return []string{target}, "", nil
	}
	ips, err := net.LookupIP(target)
	if err != nil || len(ips) == 0 {
		return nil, "", errors.New("DNS failed")
	}
	var out []string
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			out = append(out, v4.String())
		}
	}
	for _, ip := range ips {
		if ip.To4() == nil && ip.To16() != nil {
			out = append(out, ip.String())
		}
	}
	if len(out) == 0 {
		return nil, "", errors.New("no IP address")
	}
	return uniqueInOrder(out), target, nil
}

func candidateSNIs(resolvedSNI string) []string {
	if strings.TrimSpace(resolvedSNI) != "" {
		return []string{resolvedSNI}
	}
	return []string{""}
}

func uniqueInOrder(xs []string) []string {
	set := make(map[string]bool)
	var out []string
	for _, x := range xs {
		for _, part := range strings.FieldsFunc(x, func(r rune) bool { return r == ',' || r == ';' || r == '\r' || r == '\n' || r == '\t' || r == ' ' }) {
			part = strings.TrimSpace(part)
			if part != "" && !set[part] {
				set[part] = true
				out = append(out, part)
			}
		}
	}
	return out
}

func tcp(ctx context.Context, ip string, port int, timeoutMS int) bool {
	ok, _ := tcpWithError(ctx, ip, port, timeoutMS)
	return ok
}

func tcpWithError(ctx context.Context, ip string, port int, timeoutMS int) (bool, error) {
	d := net.Dialer{Timeout: time.Duration(timeoutMS) * time.Millisecond}
	network := "tcp4"
	if strings.Contains(ip, ":") {
		network = "tcp6"
	}
	conn, err := d.DialContext(ctx, network, net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		return false, err
	}
	_ = conn.Close()
	return true, nil
}

type tlsInfo struct {
	Version  string
	Cipher   string
	ALPN     string
	Verified bool
	Subject  string
}

func tlsProbe(ctx context.Context, ip string, port int, sni string, timeoutMS int, fingerprint string, opts DPIObfuscationOptions) (tlsInfo, bool) {
	conn, _, info, ok, _ := tlsProbeOpen(ctx, ip, port, sni, timeoutMS, fingerprint, opts)
	if conn != nil {
		_ = conn.Close()
	}
	return info, ok
}

func tlsProbeOpen(ctx context.Context, ip string, port int, sni string, timeoutMS int, fingerprint string, opts DPIObfuscationOptions) (*tls.UConn, bool, tlsInfo, bool, error) {
	conn, tcpOK, err := dialUTLS(ctx, ip, port, sni, timeoutMS, fingerprint, opts)
	if err != nil {
		return nil, tcpOK, tlsInfo{}, false, err
	}
	state := conn.ConnectionState()
	info := tlsInfo{Version: tlsVersionName(state.Version), Cipher: cipherSuiteName(state.CipherSuite), ALPN: state.NegotiatedProtocol}
	if len(state.PeerCertificates) > 0 {
		verifyName := strings.TrimSpace(sni)
		if verifyName == "" {
			verifyName = conn.RemoteAddr().String()
			if host, _, err := net.SplitHostPort(verifyName); err == nil {
				verifyName = host
			}
		}
		optsVerify := x509.VerifyOptions{
			DNSName:       verifyName,
			Intermediates: x509.NewCertPool(),
		}
		for _, cert := range state.PeerCertificates[1:] {
			optsVerify.Intermediates.AddCert(cert)
		}
		_, verifyErr := state.PeerCertificates[0].Verify(optsVerify)
		info.Verified = verifyErr == nil
		info.Subject = state.PeerCertificates[0].Subject.String()
	}
	if ctx.Err() != nil {
		_ = conn.Close()
		return nil, true, info, false, ctx.Err()
	}
	return conn, true, info, true, nil
}

func httpProbe(ctx context.Context, ip string, port int, sni, path string, timeoutMS int, fingerprint string) (bool, int, string, string, string, bool) {
	conn, _, err := dialUTLSWithALPN(ctx, ip, port, sni, timeoutMS, fingerprint, []string{"http/1.1"}, DPIObfuscationOptions{})
	if err != nil {
		return false, 0, "", "", "", false
	}
	defer conn.Close()
	httpOK, status, server, cache, altSvc, http3, _ := httpProbeConn(ctx, conn, ip, sni, path, timeoutMS)
	return httpOK, status, server, cache, altSvc, http3
}

func httpProbeConn(ctx context.Context, conn net.Conn, ip string, sni, path string, timeoutMS int) (bool, int, string, string, string, bool, string) {
	rollingDeadline := time.Now().Add(time.Duration(timeoutMS) * time.Millisecond)
	_ = conn.SetDeadline(rollingDeadline)

	host := strings.TrimSpace(sni)
	if host == "" {
		host = ip
	}
	if _, err := fmt.Fprintf(conn, "HEAD %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: MaybeScanner/1.2\r\nCache-Control: no-cache, no-store, must-revalidate\r\nPragma: no-cache\r\nX-Maybe-Cachebuster: %d\r\nConnection: close\r\n\r\n", path, host, time.Now().UnixNano()); err != nil {
		return false, 0, "", "", "", false, classifyNetworkError(err, "http")
	}
	reader := pooledReader(io.LimitReader(conn, 64*1024))
	defer putReader(reader)

	_ = conn.SetReadDeadline(time.Now().Add(750 * time.Millisecond))
	line, err := readLimitedLine(reader, 4096)
	status := parseHTTPStatus(line)
	if err != nil && errors.Is(err, io.EOF) && status > 0 {
		// Accept short-lived but syntactically valid status-line responses that close immediately.
		err = nil
	}
	if status == 0 {
		if err != nil {
			return false, 0, "", "", "", false, classifyNetworkError(err, "http")
		}
		return false, 0, "", "", "", false, "HTTP_PARSE_FAILED"
	}
	server, cache, altSvc := "", "", ""
	if err == nil {
		for i := 0; i < 48; i++ {
			_ = conn.SetReadDeadline(time.Now().Add(750 * time.Millisecond))
			header, hErr := readLimitedLine(reader, 4096)
			if hErr != nil {
				if errors.Is(hErr, io.EOF) && strings.TrimSpace(header) == "" {
					break
				}
				return false, status, server, cache, altSvc, false, classifyNetworkError(hErr, "http")
			}
			header = strings.TrimRight(header, "\r\n")
			if strings.TrimSpace(header) == "" {
				break
			}
			lower := strings.ToLower(header)
			if strings.HasPrefix(lower, "server:") {
				server = strings.TrimSpace(header[len("server:"):])
			}
			if strings.HasPrefix(lower, "x-cache:") || strings.HasPrefix(lower, "cf-cache-status:") || strings.HasPrefix(lower, "age:") {
				if cache != "" {
					cache += "; "
				}
				cache += strings.TrimSpace(header)
			}
			if strings.HasPrefix(lower, "alt-svc:") {
				altSvc = strings.TrimSpace(header[len("alt-svc:"):])
			}
		}
	}
	return ctx.Err() == nil && status < 500, status, server, cache, altSvc, strings.Contains(strings.ToLower(altSvc), "h3"), ""
}

func probeHTTPOverNegotiatedALPN(ctx context.Context, conn net.Conn, ip string, sni string, path string, timeoutMS int, negotiatedALPN string) (bool, int, string, string, string, bool, string) {
	if strings.EqualFold(strings.TrimSpace(negotiatedALPN), "h2") {
		return false, 0, "", "", "", false, "HTTP2_UNSUPPORTED_IN_PROBE"
	}
	httpOK, status, server, cache, altSvc, http3, probeCode := httpProbeConn(ctx, conn, ip, sni, path, timeoutMS)
	return httpOK, status, server, cache, altSvc, http3, probeCode
}

func dialUTLS(ctx context.Context, ip string, port int, sni string, timeoutMS int, fingerprint string, opts DPIObfuscationOptions) (*tls.UConn, bool, error) {
	return dialUTLSWithALPN(ctx, ip, port, sni, timeoutMS, fingerprint, []string{"h2", "http/1.1"}, opts)
}

func dialUTLSWithALPN(ctx context.Context, ip string, port int, sni string, timeoutMS int, fingerprint string, nextProtos []string, opts DPIObfuscationOptions) (*tls.UConn, bool, error) {
	network := "tcp4"
	if strings.Contains(ip, ":") {
		network = "tcp6"
	}
	rawConn, err := DialObfuscatedSocket(ctx, network, net.JoinHostPort(ip, strconv.Itoa(port)), time.Duration(timeoutMS)*time.Millisecond, opts)
	if err != nil {
		return nil, false, err
	}
	deadline := time.Now().Add(time.Duration(timeoutMS) * time.Millisecond)
	_ = rawConn.SetDeadline(deadline)
	serverName := strings.TrimSpace(sni)
	conn := tls.UClient(rawConn, &tls.Config{
		ServerName: serverName, MinVersion: tls.VersionTLS12, NextProtos: nextProtos,
		// This is an IP scanner: continue handshakes so certificate metadata can be
		// measured and reported instead of hidden as TLS failures.
		InsecureSkipVerify: true,
	}, clientHelloID(fingerprint))
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = rawConn.Close()
		case <-done:
		}
	}()
	if err := conn.Handshake(); err != nil {
		close(done)
		_ = rawConn.Close()
		return nil, true, err
	}
	close(done)
	if err := ctx.Err(); err != nil {
		_ = conn.Close()
		return nil, true, err
	}
	_ = conn.SetDeadline(deadline)
	return conn, true, nil
}

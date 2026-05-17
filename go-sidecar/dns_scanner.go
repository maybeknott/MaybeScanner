package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

type dnsScanRequest struct {
	Resolvers []string `json:"resolvers"`
	Domains   []string `json:"domains"`
	QTypes    []string `json:"qtypes"`
	TimeoutMS int      `json:"timeout_ms"`
	Workers   int      `json:"workers"`
	Samples   int      `json:"samples"`
}

type dnsResult struct {
	Resolver      string   `json:"resolver"`
	Domain        string   `json:"domain"`
	QType         string   `json:"qtype"`
	Protocol      string   `json:"protocol"`
	Answers       []string `json:"answers"`
	LatencyMS     int64    `json:"latency_ms"`
	RCode         int      `json:"rcode"`
	Recursive     bool     `json:"recursive"`
	Authoritative bool     `json:"authoritative"`
	DNSSEC        bool     `json:"dnssec"`
	EDNS          bool     `json:"edns"`
	Vendor        string   `json:"vendor"`
	Health        int      `json:"health"`
	Error         string   `json:"error,omitempty"`
}

type dnsJob struct {
	resolver string
	domain   string
	qtype    string
}

func scanDNS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	var req dnsScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	metricDNSRuns.Add(1)
	req.normalize()
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	w.Header().Set("Content-Type", "application/x-ndjson")
	flusher, _ := w.(http.Flusher)
	enc := json.NewEncoder(w)
	total := len(req.Resolvers) * len(req.Domains) * len(req.QTypes) * req.Samples
	_ = enc.Encode(map[string]any{"type": "init", "total": total})
	flush(flusher)

	jobs := make(chan dnsJob)
	results := make(chan dnsResult)
	var done atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < req.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				if ctx.Err() != nil {
					return
				}
				results <- runDNSQuery(ctx, job, req.TimeoutMS)
			}
		}()
	}
	go func() {
		defer close(jobs)
		for sample := 0; sample < req.Samples; sample++ {
			for _, resolver := range req.Resolvers {
				for _, domain := range req.Domains {
					for _, qtype := range req.QTypes {
						select {
						case <-ctx.Done():
							return
						case jobs <- dnsJob{resolver: resolver, domain: domain, qtype: qtype}:
						}
					}
				}
			}
		}
	}()
	go func() { wg.Wait(); close(results) }()
	for res := range results {
		checked := done.Add(1)
		_ = enc.Encode(map[string]any{"type": "dns", "result": res, "checked": checked, "total": total})
		flush(flusher)
	}
	_ = enc.Encode(map[string]any{"type": "done", "stopped": ctx.Err() != nil})
	flush(flusher)
}

func (r *dnsScanRequest) normalize() {
	r.Resolvers = unique(r.Resolvers)
	if len(r.Resolvers) == 0 {
		r.Resolvers = []string{"1.1.1.1", "8.8.8.8", "9.9.9.9", "208.67.222.222"}
	}
	for i, resolver := range r.Resolvers {
		if !strings.Contains(resolver, ":") {
			r.Resolvers[i] = net.JoinHostPort(resolver, "53")
		}
	}
	r.Domains = unique(r.Domains)
	if len(r.Domains) == 0 {
		r.Domains = []string{"cloudflare.com", "google.com", randomNXDomain()}
	}
	if len(r.QTypes) == 0 {
		r.QTypes = []string{"A", "AAAA", "MX", "NS", "TXT", "SOA"}
	}
	var qtypes []string
	for _, qt := range r.QTypes {
		qt = strings.ToUpper(strings.TrimSpace(qt))
		if dnsTypeCode(qt) != 0 {
			qtypes = append(qtypes, qt)
		}
	}
	r.QTypes = unique(qtypes)
	if r.TimeoutMS < 200 || r.TimeoutMS > 10000 {
		r.TimeoutMS = 1500
	}
	if r.Workers <= 0 || r.Workers > 512 {
		r.Workers = max(4, runtime.NumCPU()*2)
	}
	if r.Samples <= 0 || r.Samples > 20 {
		r.Samples = 1
	}
}

func runDNSQuery(ctx context.Context, job dnsJob, timeoutMS int) dnsResult {
	res := dnsResult{Resolver: job.resolver, Domain: job.domain, QType: job.qtype, Protocol: "udp", Vendor: dnsVendor(job.resolver)}
	start := time.Now()
	qtype := dns.StringToType[strings.ToUpper(job.qtype)]
	if qtype == 0 {
		res.Error = "unsupported query type"
		return res
	}
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(job.domain), qtype)
	msg.RecursionDesired = true
	msg.SetEdns0(4096, true)
	client := &dns.Client{Net: "udp", Timeout: time.Duration(timeoutMS) * time.Millisecond}
	done := make(chan struct {
		msg *dns.Msg
		rtt time.Duration
		err error
	}, 1)
	go func() {
		in, rtt, err := client.Exchange(msg, job.resolver)
		done <- struct {
			msg *dns.Msg
			rtt time.Duration
			err error
		}{msg: in, rtt: rtt, err: err}
	}()
	select {
	case <-ctx.Done():
		res.Error = ctx.Err().Error()
		res.LatencyMS = time.Since(start).Milliseconds()
		res.Health = scoreDNS(res)
		return res
	case reply := <-done:
		res.LatencyMS = reply.rtt.Milliseconds()
		if reply.err != nil {
			res.Error = reply.err.Error()
			res.Health = scoreDNS(res)
			return res
		}
		parsed := parseDNSMessage(reply.msg)
		res.Answers = parsed.answers
		res.RCode = parsed.rcode
		res.Recursive = parsed.ra
		res.Authoritative = parsed.aa
		res.DNSSEC = parsed.ad
		res.EDNS = parsed.edns
		res.Health = scoreDNS(res)
		return res
	}
}

type parsedDNS struct {
	answers []string
	rcode   int
	ra      bool
	aa      bool
	ad      bool
	edns    bool
}

func parseDNSMessage(msg *dns.Msg) parsedDNS {
	var out parsedDNS
	if msg == nil {
		return out
	}
	out.rcode = msg.Rcode
	out.ra = msg.RecursionAvailable
	out.aa = msg.Authoritative
	out.ad = msg.AuthenticatedData
	for _, rr := range msg.Answer {
		switch v := rr.(type) {
		case *dns.A:
			out.answers = append(out.answers, v.A.String())
		case *dns.AAAA:
			out.answers = append(out.answers, v.AAAA.String())
		case *dns.CNAME:
			out.answers = append(out.answers, strings.TrimSuffix(v.Target, "."))
		case *dns.NS:
			out.answers = append(out.answers, strings.TrimSuffix(v.Ns, "."))
		case *dns.MX:
			out.answers = append(out.answers, fmt.Sprintf("%d %s", v.Preference, strings.TrimSuffix(v.Mx, ".")))
		case *dns.TXT:
			out.answers = append(out.answers, strings.Join(v.Txt, " "))
		case *dns.SOA:
			out.answers = append(out.answers, fmt.Sprintf("%s %s serial=%d", strings.TrimSuffix(v.Ns, "."), strings.TrimSuffix(v.Mbox, "."), v.Serial))
		default:
			out.answers = append(out.answers, rr.String())
		}
	}
	for _, rr := range msg.Extra {
		if _, ok := rr.(*dns.OPT); ok {
			out.edns = true
			break
		}
	}
	return out
}

func buildDNSQuery(domain string, qtype uint16, edns bool) ([]byte, error) {
	if domain == "" {
		return nil, errors.New("empty domain")
	}
	buf := make([]byte, 12, 512)
	binary.BigEndian.PutUint16(buf[0:2], uint16(rand.Intn(65535)))
	binary.BigEndian.PutUint16(buf[2:4], 0x0100)
	binary.BigEndian.PutUint16(buf[4:6], 1)
	if edns {
		binary.BigEndian.PutUint16(buf[10:12], 1)
	}
	for _, label := range strings.Split(strings.TrimSuffix(domain, "."), ".") {
		if len(label) > 63 {
			return nil, errors.New("label too long")
		}
		buf = append(buf, byte(len(label)))
		buf = append(buf, label...)
	}
	buf = append(buf, 0, byte(qtype>>8), byte(qtype), 0, 1)
	if edns {
		buf = append(buf, 0, 0, 41, 16, 0, 0, 0x80, 0, 0, 0)
	}
	return buf, nil
}

func parseDNSResponse(buf []byte) (parsedDNS, error) {
	var out parsedDNS
	if len(buf) < 12 {
		return out, errors.New("short dns response")
	}
	flags := binary.BigEndian.Uint16(buf[2:4])
	out.rcode = int(flags & 0x000f)
	out.aa = flags&0x0400 != 0
	out.ra = flags&0x0080 != 0
	out.ad = flags&0x0020 != 0
	qd := int(binary.BigEndian.Uint16(buf[4:6]))
	an := int(binary.BigEndian.Uint16(buf[6:8]))
	ar := int(binary.BigEndian.Uint16(buf[10:12]))
	off := 12
	for i := 0; i < qd; i++ {
		var err error
		off, _, err = readDNSName(buf, off)
		if err != nil || off+4 > len(buf) {
			return out, errors.New("bad question")
		}
		off += 4
	}
	for i := 0; i < an; i++ {
		next, text, err := readDNSRecord(buf, off)
		if err != nil {
			return out, err
		}
		off = next
		if text != "" {
			out.answers = append(out.answers, text)
		}
	}
	for i := 0; i < ar && off < len(buf); i++ {
		next, text, err := readDNSRecord(buf, off)
		if err != nil {
			break
		}
		if text == "OPT" {
			out.edns = true
		}
		off = next
	}
	return out, nil
}

func readDNSRecord(buf []byte, off int) (int, string, error) {
	var err error
	off, _, err = readDNSName(buf, off)
	if err != nil || off+10 > len(buf) {
		return off, "", errors.New("bad rr")
	}
	typ := binary.BigEndian.Uint16(buf[off : off+2])
	off += 8
	rdlen := int(binary.BigEndian.Uint16(buf[off : off+2]))
	off += 2
	if off+rdlen > len(buf) {
		return off, "", errors.New("bad rdata")
	}
	data := buf[off : off+rdlen]
	next := off + rdlen
	switch typ {
	case 1:
		if len(data) == 4 {
			return next, net.IP(data).String(), nil
		}
	case 28:
		if len(data) == 16 {
			return next, net.IP(data).String(), nil
		}
	case 2, 5, 6:
		_, name, e := readDNSName(buf, off)
		return next, name, e
	case 15:
		if len(data) > 2 {
			_, name, e := readDNSName(buf, off+2)
			return next, name, e
		}
	case 16:
		if len(data) > 1 {
			return next, string(data[1:]), nil
		}
	case 41:
		return next, "OPT", nil
	}
	return next, "", nil
}

func readDNSName(buf []byte, off int) (int, string, error) {
	var labels []string
	original := off
	jumped := false
	for depth := 0; depth < 20; depth++ {
		if off >= len(buf) {
			return off, "", errors.New("name overflow")
		}
		l := int(buf[off])
		if l == 0 {
			off++
			if jumped {
				return original + 2, strings.Join(labels, "."), nil
			}
			return off, strings.Join(labels, "."), nil
		}
		if l&0xc0 == 0xc0 {
			if off+1 >= len(buf) {
				return off, "", errors.New("bad pointer")
			}
			ptr := int(binary.BigEndian.Uint16(buf[off:off+2]) & 0x3fff)
			if !jumped {
				original = off
			}
			off = ptr
			jumped = true
			continue
		}
		off++
		if off+l > len(buf) {
			return off, "", errors.New("bad label")
		}
		labels = append(labels, string(buf[off:off+l]))
		off += l
	}
	return off, "", errors.New("pointer loop")
}

func dnsTypeCode(qtype string) uint16 {
	switch strings.ToUpper(qtype) {
	case "A":
		return 1
	case "NS":
		return 2
	case "CNAME":
		return 5
	case "SOA":
		return 6
	case "MX":
		return 15
	case "TXT":
		return 16
	case "AAAA":
		return 28
	default:
		return 0
	}
}

func scoreDNS(r dnsResult) int {
	score := 0
	if r.Error == "" {
		score += 40
	}
	if r.Recursive {
		score += 15
	}
	if r.EDNS {
		score += 15
	}
	if r.DNSSEC {
		score += 10
	}
	if len(r.Answers) > 0 || r.RCode == 3 {
		score += 10
	}
	if r.LatencyMS > 0 {
		score += max(0, 30-int(r.LatencyMS/20))
	}
	return score
}

func dnsVendor(resolver string) string {
	host, _, _ := net.SplitHostPort(resolver)
	switch host {
	case "1.1.1.1", "1.0.0.1":
		return "Cloudflare"
	case "8.8.8.8", "8.8.4.4":
		return "Google"
	case "9.9.9.9", "149.112.112.112":
		return "Quad9"
	case "208.67.222.222", "208.67.220.220":
		return "OpenDNS"
	default:
		return "Unknown"
	}
}

func randomNXDomain() string {
	return "nx-" + strconv.FormatInt(time.Now().UnixNano(), 36) + ".invalid"
}

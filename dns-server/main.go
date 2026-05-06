package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Config holds DNS server configuration from environment variables.
type Config struct {
	Domain          string
	PublicIP        string
	HTTPServerURL   string
	InternalAPIKey  string
	Port            string
}

// DNSServer handles all incoming DNS queries.
type DNSServer struct {
	config  Config
	rb      *Rebinder
	httpCli *http.Client
}

// Interaction represents an OOB interaction to be forwarded to the HTTP server.
type Interaction struct {
	UUID        string    `json:"uuid"`
	Type        string    `json:"type"`
	SourceIP    string    `json:"source_ip"`
	QueryName   string    `json:"query_name"`
	QueryType   string    `json:"query_type"`
	RawData     string    `json:"raw_data"`
	DecodedData string    `json:"decoded_data"`
	Timestamp   time.Time `json:"timestamp"`
}

// ServeDNS is called for every incoming DNS query (implements dns.Handler).
func (s *DNSServer) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	// Strip port from remote address
	remoteAddr := w.RemoteAddr().String()
	sourceIP := remoteAddr
	if idx := strings.LastIndex(remoteAddr, ":"); idx != -1 {
		sourceIP = remoteAddr[:idx]
	}
	sourceIP = strings.TrimPrefix(sourceIP, "[") // strip brackets from IPv6

	for _, q := range r.Question {
		qname := q.Name
		qtype := dns.TypeToString[q.Qtype]

		log.Printf("[DNS] %s %s from %s", qtype, qname, sourceIP)

		uuid, exfilData, isRebind := s.parseSubdomain(qname)

		interaction := Interaction{
			UUID:        uuid,
			Type:        "dns",
			SourceIP:    sourceIP,
			QueryName:   strings.TrimSuffix(qname, "."),
			QueryType:   qtype,
			RawData:     fmt.Sprintf("%s %s", qtype, qname),
			DecodedData: exfilData,
			Timestamp:   time.Now(),
		}
		go s.reportInteraction(interaction)

		switch q.Qtype {
		case dns.TypeA:
			ip := s.config.PublicIP
			if isRebind && uuid != "" {
				if rebindIP := s.rb.GetIP(uuid, s.config.PublicIP); rebindIP != "" {
					ip = rebindIP
				}
			}
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 1},
				A:   net.ParseIP(ip),
			})

		case dns.TypeAAAA:
			// Return NXDOMAIN for IPv6 to avoid unexpected IPv6 resolution
			m.Rcode = dns.RcodeNameError

		case dns.TypeNS:
			domain := strings.ToLower(s.config.Domain)
			if strings.ToLower(strings.TrimSuffix(qname, ".")) == domain {
				m.Answer = append(m.Answer, &dns.NS{
					Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300},
					Ns:  "ns1." + domain + ".",
				})
			}

		case dns.TypeMX:
			m.Answer = append(m.Answer, &dns.MX{
				Hdr:        dns.RR_Header{Name: qname, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 300},
				Preference: 10,
				Mx:         "mail." + s.config.Domain + ".",
			})

		case dns.TypeTXT:
			m.Answer = append(m.Answer, &dns.TXT{
				Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 1},
				Txt: []string{"ssrf-box interaction logged: " + time.Now().Format(time.RFC3339)},
			})
		}
	}

	if err := w.WriteMsg(m); err != nil {
		log.Printf("[WARN] WriteMsg error: %v", err)
	}
}

// parseSubdomain extracts UUID, exfiltrated data, and rebind flag from a query name.
//
// Expected formats (relative to base domain oob.example.com):
//   <uuid>.oob.example.com                 → plain callback
//   <b64data>.<uuid>.oob.example.com       → DNS exfiltration
//   rebind-<uuid>.oob.example.com          → DNS rebinding
func (s *DNSServer) parseSubdomain(qname string) (uuid, exfilData string, isRebind bool) {
	fqdn := strings.ToLower(strings.TrimSuffix(qname, "."))
	baseDomain := strings.ToLower(s.config.Domain)

	if !strings.HasSuffix(fqdn, baseDomain) {
		return "", "", false
	}

	sub := strings.TrimSuffix(fqdn, baseDomain)
	sub = strings.TrimSuffix(sub, ".")

	if sub == "" {
		return "", "", false
	}

	parts := strings.Split(sub, ".")

	// Rebind pattern: rebind-<uuid>
	last := parts[len(parts)-1]
	if strings.HasPrefix(last, "rebind-") {
		return strings.TrimPrefix(last, "rebind-"), "", true
	}

	if len(parts) == 1 {
		return parts[0], "", false
	}

	// Exfil pattern: <data_chunk1>.<data_chunk2>...<uuid>
	uuid = last
	rawChunks := strings.Join(parts[:len(parts)-1], "")
	exfilData = decodeExfilData(rawChunks)
	return uuid, exfilData, false
}

// decodeExfilData attempts to decode base64 or hex encoded exfiltrated data.
func decodeExfilData(raw string) string {
	// Try URL-safe base64 (no padding)
	if decoded, err := base64.RawURLEncoding.DecodeString(raw); err == nil && isPrintable(decoded) {
		return string(decoded)
	}
	// Try standard base64
	if decoded, err := base64.StdEncoding.DecodeString(raw); err == nil && isPrintable(decoded) {
		return string(decoded)
	}
	// Try hex
	if decoded, err := hex.DecodeString(raw); err == nil && isPrintable(decoded) {
		return string(decoded)
	}
	return raw
}

func isPrintable(b []byte) bool {
	for _, c := range b {
		if c < 0x09 || (c > 0x0d && c < 0x20) {
			return false
		}
	}
	return true
}

// reportInteraction sends an interaction to the HTTP server's internal API.
func (s *DNSServer) reportInteraction(i Interaction) {
	body, err := json.Marshal(i)
	if err != nil {
		log.Printf("[ERROR] Marshal interaction: %v", err)
		return
	}

	req, err := http.NewRequest(http.MethodPost, s.config.HTTPServerURL+"/internal/interaction", bytes.NewReader(body))
	if err != nil {
		log.Printf("[ERROR] Create request: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Internal-Key", s.config.InternalAPIKey)

	resp, err := s.httpCli.Do(req)
	if err != nil {
		log.Printf("[WARN] Report interaction: %v", err)
		return
	}
	resp.Body.Close()
}

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	cfg := Config{
		Domain:         getEnv("SSRF_DOMAIN", "oob.example.com"),
		PublicIP:       getEnv("VPS_IP", "1.2.3.4"),
		HTTPServerURL:  getEnv("HTTP_SERVER_URL", "http://http-server:8080"),
		InternalAPIKey: getEnv("INTERNAL_API_KEY", "changeme-internal"),
		Port:           getEnv("DNS_PORT", "53"),
	}

	rb := NewRebinder(cfg.HTTPServerURL, cfg.InternalAPIKey)

	srv := &DNSServer{
		config:  cfg,
		rb:      rb,
		httpCli: &http.Client{Timeout: 3 * time.Second},
	}

	log.Printf("[INFO] DNS server starting | domain=%s public_ip=%s port=%s", cfg.Domain, cfg.PublicIP, cfg.Port)

	udpSrv := &dns.Server{Addr: ":" + cfg.Port, Net: "udp", Handler: srv}
	tcpSrv := &dns.Server{Addr: ":" + cfg.Port, Net: "tcp", Handler: srv}

	errc := make(chan error, 2)
	go func() { errc <- udpSrv.ListenAndServe() }()
	go func() { errc <- tcpSrv.ListenAndServe() }()

	if err := <-errc; err != nil {
		log.Fatalf("[FATAL] DNS server: %v", err)
	}
}

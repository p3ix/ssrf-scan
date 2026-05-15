// smtp-ldap-listener: Passive TCP listeners for non-HTTP SSRF detection.
// Listens on SMTP, LDAP, FTP, Redis, MySQL, PostgreSQL, MongoDB, Memcached, Elasticsearch.
// Reports all connections to the HTTP server's internal API.
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

// mysqlGreeting is a minimal MySQL 5.7 server greeting (Protocol 10).
// Payload = 78 bytes → header length field = 0x4e.
var mysqlGreeting = []byte{
	// Packet header: payload length = 78 (LE), sequence = 0
	0x4e, 0x00, 0x00, 0x00,
	// Protocol version 10
	0x0a,
	// Server version "5.7.0-ssrf\0"
	'5', '.', '7', '.', '0', '-', 's', 's', 'r', 'f', 0x00,
	// Connection ID = 1 (LE)
	0x01, 0x00, 0x00, 0x00,
	// Auth-plugin-data-part-1 (8 bytes)
	0x3a, 0x27, 0x6e, 0x29, 0x56, 0x67, 0x37, 0x42,
	// Filler
	0x00,
	// Capability flags lower
	0x0d, 0xa2,
	// Character set utf8 (0x21)
	0x21,
	// Status flags: SERVER_STATUS_AUTOCOMMIT
	0x02, 0x00,
	// Capability flags upper
	0xff, 0xdf,
	// Length of auth-plugin-data (21)
	0x15,
	// Reserved (10 zero bytes)
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	// Auth-plugin-data-part-2 (13 bytes)
	0x43, 0x5b, 0x56, 0x39, 0x3a, 0x2e, 0x22, 0x5b, 0x24, 0x4c, 0x3c, 0x21, 0x00,
	// Auth plugin name "mysql_native_password\0"
	'm', 'y', 's', 'q', 'l', '_', 'n', 'a', 't', 'i', 'v', 'e', '_',
	'p', 'a', 's', 's', 'w', 'o', 'r', 'd', 0x00,
}

// uuidRe matches the 8-hex-char UUID format used by SSRF-BOX payload generator.
var uuidRe = regexp.MustCompile(`[0-9a-f]{8}`)

func extractUUID(s string) string {
	return uuidRe.FindString(strings.ToLower(s))
}

type Interaction struct {
	UUID        string    `json:"uuid"`
	Type        string    `json:"type"`
	SourceIP    string    `json:"source_ip"`
	RawData     string    `json:"raw_data"`
	DecodedData string    `json:"decoded_data"`
	Timestamp   time.Time `json:"timestamp"`
}

// ParseFn extracts a correlation UUID and human-readable summary from raw captured bytes.
type ParseFn func(raw string) (uuid, decoded string)

type PortListener struct {
	Port         string
	Protocol     string
	Banner       string  // text banner (sent with trailing newline)
	BannerBytes  []byte  // binary banner (sent as-is); takes precedence over Banner
	MaxReadBytes int
	ParseFn      ParseFn // nil → generic fallback

	httpServerURL  string
	internalAPIKey string
	httpCli        *http.Client
}

func (p *PortListener) ListenAndLog() {
	ln, err := net.Listen("tcp", ":"+p.Port)
	if err != nil {
		log.Printf("[WARN] Cannot listen on %s/%s: %v", p.Protocol, p.Port, err)
		return
	}
	log.Printf("[INFO] Listening on %s port %s", p.Protocol, p.Port)
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("[ERROR] Accept %s: %v", p.Protocol, err)
			continue
		}
		go p.handleConn(conn)
	}
}

func (p *PortListener) handleConn(conn net.Conn) {
	defer conn.Close()

	remoteAddr := conn.RemoteAddr().String()
	sourceIP := remoteAddr
	if idx := strings.LastIndex(remoteAddr, ":"); idx >= 0 {
		sourceIP = remoteAddr[:idx]
	}
	// Strip IPv6 brackets
	sourceIP = strings.Trim(sourceIP, "[]")

	log.Printf("[%s/%s] Connection from %s", p.Protocol, p.Port, sourceIP)

	// Send banner
	if len(p.BannerBytes) > 0 {
		conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		conn.Write(p.BannerBytes)
	} else if p.Banner != "" {
		conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		fmt.Fprintln(conn, p.Banner)
	}

	// Read initial client data
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, p.MaxReadBytes)
	n, _ := io.ReadAtLeast(conn, buf, 1)
	rawData := ""
	if n > 0 {
		rawData = string(buf[:n])
	}

	uuid := ""
	decoded := ""
	if p.ParseFn != nil {
		uuid, decoded = p.ParseFn(rawData)
	}
	if decoded == "" {
		decoded = fmt.Sprintf("SSRF detected via %s on port %s from %s", p.Protocol, p.Port, sourceIP)
	}

	interaction := Interaction{
		UUID:        uuid,
		Type:        p.Protocol,
		SourceIP:    sourceIP,
		RawData:     fmt.Sprintf("[%s port %s] %s", p.Protocol, p.Port, rawData),
		DecodedData: decoded,
		Timestamp:   time.Now(),
	}
	p.report(interaction)
}

func (p *PortListener) report(i Interaction) {
	body, err := json.Marshal(i)
	if err != nil {
		log.Printf("[ERROR] Marshal: %v", err)
		return
	}
	req, err := http.NewRequest(http.MethodPost, p.httpServerURL+"/internal/interaction", bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Internal-Key", p.internalAPIKey)
	resp, err := p.httpCli.Do(req)
	if err != nil {
		log.Printf("[WARN] Report: %v", err)
		return
	}
	resp.Body.Close()
}

// parseSMTP extracts UUID from EHLO/HELO hostname and logs MAIL FROM / RCPT TO.
func parseSMTP(ssrfDomain string) ParseFn {
	return func(raw string) (uuid, decoded string) {
		var parts []string
		for _, line := range strings.Split(raw, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			upper := strings.ToUpper(line)
			if strings.HasPrefix(upper, "EHLO ") || strings.HasPrefix(upper, "HELO ") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					host := fields[1]
					// Try to extract UUID from subdomain prefix
					if ssrfDomain != "" && strings.HasSuffix(strings.ToLower(host), "."+ssrfDomain) {
						sub := strings.ToLower(host[:len(host)-len(ssrfDomain)-1])
						uuid = strings.SplitN(sub, ".", 2)[0]
					} else if u := extractUUID(host); u != "" {
						uuid = u
					}
					parts = append(parts, "EHLO:"+host)
				}
			} else if strings.HasPrefix(upper, "MAIL FROM:") || strings.HasPrefix(upper, "RCPT TO:") {
				if u := extractUUID(line); u != "" && uuid == "" {
					uuid = u
				}
				parts = append(parts, line)
			}
		}
		decoded = strings.Join(parts, " | ")
		return
	}
}

// parseFTP extracts USER and PASS commands.
func parseFTP(raw string) (uuid, decoded string) {
	var parts []string
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		upper := strings.ToUpper(line)
		if strings.HasPrefix(upper, "USER ") || strings.HasPrefix(upper, "PASS ") {
			if u := extractUUID(line); u != "" && uuid == "" {
				uuid = u
			}
			parts = append(parts, line)
		}
	}
	decoded = strings.Join(parts, " | ")
	return
}

// parseLDAP hex-dumps the BER-encoded binary bind request.
func parseLDAP(raw string) (uuid, decoded string) {
	decoded = "ldap-bind hex: " + hex.EncodeToString([]byte(raw))
	return "", decoded
}

// parseSMB detects NTLM negotiation messages or raw SMB traffic and hex-dumps them.
// Port 445 is Windows file sharing — an SSRF hitting it often triggers an NTLM negotiation
// that leaks NTLMv2 challenge/response hashes useful for cracking or relay attacks.
func parseSMB(raw string) (uuid, decoded string) {
	b := []byte(raw)
	prefix := b
	if len(prefix) > 64 {
		prefix = prefix[:64]
	}
	// NTLM messages start with the signature "NTLMSSP\x00"
	if len(b) >= 7 && string(b[:7]) == "NTLMSSP" {
		decoded = "NTLM negotiation detected — relay/crack candidate | hex: " + hex.EncodeToString(b)
	} else {
		decoded = "SMB connection (no NTLM header) | hex: " + hex.EncodeToString(prefix)
	}
	return "", decoded
}

// parseGeneric looks for the first 8-hex-char SSRF-BOX UUID token in any text data.
func parseGeneric(raw string) (uuid, decoded string) {
	uuid = extractUUID(raw)
	decoded = strings.TrimSpace(raw)
	return
}

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	httpServerURL := getEnv("HTTP_SERVER_URL", "http://http-server:8080")
	internalAPIKey := getEnv("INTERNAL_API_KEY", "changeme-internal")
	ssrfDomain := getEnv("SSRF_DOMAIN", "")

	httpCli := &http.Client{Timeout: 5 * time.Second}

	smtpParse := parseSMTP(ssrfDomain)

	// HTTP-style banner for Elasticsearch (clients speak HTTP to port 9200)
	esBanner := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" +
		`{"name":"ssrf-box","cluster_name":"elasticsearch","version":{"number":"7.17.0"},"tagline":"You Know, for Search"}` + "\n"

	listeners := []PortListener{
		// ── Original protocols ────────────────────────────────────────────────
		{Port: "25", Protocol: "smtp", Banner: "220 mail.ssrf-box.local ESMTP Postfix", MaxReadBytes: 512, ParseFn: smtpParse},
		{Port: "587", Protocol: "smtp", Banner: "220 mail.ssrf-box.local ESMTP Postfix (submission)", MaxReadBytes: 512, ParseFn: smtpParse},
		{Port: "389", Protocol: "ldap", Banner: "", MaxReadBytes: 512, ParseFn: parseLDAP},
		{Port: "636", Protocol: "ldaps", Banner: "", MaxReadBytes: 512, ParseFn: parseLDAP},
		{Port: "21", Protocol: "ftp", Banner: "220 FTP Server ready", MaxReadBytes: 256, ParseFn: parseFTP},
		// ── New database / service ports ──────────────────────────────────────
		{Port: "6379", Protocol: "redis", Banner: "-ERR unknown command 'SSRF'\r\n", MaxReadBytes: 256, ParseFn: parseGeneric},
		{Port: "3306", Protocol: "mysql", BannerBytes: mysqlGreeting, MaxReadBytes: 256, ParseFn: parseGeneric},
		{Port: "5432", Protocol: "postgresql", Banner: "", MaxReadBytes: 256, ParseFn: parseGeneric},
		{Port: "27017", Protocol: "mongodb", Banner: "", MaxReadBytes: 256, ParseFn: parseGeneric},
		{Port: "11211", Protocol: "memcached", Banner: "", MaxReadBytes: 256, ParseFn: parseGeneric},
		{Port: "9200", Protocol: "elasticsearch", Banner: esBanner, MaxReadBytes: 512, ParseFn: parseGeneric},
		// SMB/NTLM — Windows file sharing port; SSRF here may leak NTLMv2 hashes
		{Port: "445", Protocol: "smb", Banner: "", MaxReadBytes: 512, ParseFn: parseSMB},
	}

	for i := range listeners {
		listeners[i].httpServerURL = httpServerURL
		listeners[i].internalAPIKey = internalAPIKey
		listeners[i].httpCli = httpCli
		go listeners[i].ListenAndLog()
	}

	log.Printf("[INFO] Listeners started (%d ports) | reporting to %s", len(listeners), httpServerURL)
	select {}
}

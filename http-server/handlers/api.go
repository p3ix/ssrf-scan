package handlers

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/ssrf-box/http-server/db"
)

// APIHandler groups all admin API endpoints.
type APIHandler struct {
	DB  *db.DB
	Hub *Hub
}

// ListInteractions handles GET /api/interactions?uuid=&type=&tag=&limit=&offset=
func (h *APIHandler) ListInteractions(c *gin.Context) {
	uuid := c.Query("uuid")
	itype := c.Query("type")
	tag := c.Query("tag")
	limit, _ := strconv.Atoi(c.Query("limit"))
	offset, _ := strconv.Atoi(c.Query("offset"))

	interactions, err := h.DB.ListInteractions(uuid, itype, tag, limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"count":        len(interactions),
		"interactions": interactions,
	})
}

// GetInteraction handles GET /api/interactions/:uuid
func (h *APIHandler) GetInteraction(c *gin.Context) {
	uuid := c.Param("uuid")
	interactions, err := h.DB.ListInteractions(uuid, "", "", 0, 0)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"uuid":         uuid,
		"count":        len(interactions),
		"interactions": interactions,
	})
}

// DeleteInteraction handles DELETE /api/interactions/:uuid
func (h *APIHandler) DeleteInteraction(c *gin.Context) {
	uuid := c.Param("uuid")
	n, err := h.DB.DeleteInteractionsByUUID(uuid)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"deleted": n})
}

// ExportCSV handles GET /api/export?uuid=...&type=...
func (h *APIHandler) ExportCSV(c *gin.Context) {
	uuid := c.Query("uuid")
	itype := c.Query("type")
	interactions, err := h.DB.ListInteractions(uuid, itype, "", 10000, 0)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.Header("Content-Type", "text/csv")
	c.Header("Content-Disposition", "attachment; filename=interactions.csv")
	w := csv.NewWriter(c.Writer)
	_ = w.Write([]string{"id", "uuid", "type", "timestamp", "source_ip", "query_name", "query_type", "method", "path", "user_agent", "decoded_data", "raw_data"})
	for _, i := range interactions {
		_ = w.Write([]string{
			strconv.FormatInt(i.ID, 10), i.UUID, i.Type, i.Timestamp.Format(time.RFC3339),
			i.SourceIP, i.QueryName, i.QueryType, i.Method, i.Path, i.UserAgent,
			i.DecodedData, i.RawData,
		})
	}
	w.Flush()
}

// CreateRebind handles POST /api/rebind
// Supports count-based (switch_after) and time-based (switch_delay_seconds) modes.
func (h *APIHandler) CreateRebind(c *gin.Context) {
	var req struct {
		UUID               string `json:"uuid" binding:"required"`
		PublicIP           string `json:"public_ip" binding:"required"`
		PrivateIP          string `json:"private_ip" binding:"required"`
		SwitchAfter        int    `json:"switch_after"`
		SwitchDelaySeconds int    `json:"switch_delay_seconds"` // convenience: set switch_at_time = now+delay
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.SwitchAfter <= 0 {
		req.SwitchAfter = 1
	}
	cfg := &db.RebindConfig{
		UUID:        req.UUID,
		PublicIP:    req.PublicIP,
		PrivateIP:   req.PrivateIP,
		SwitchAfter: req.SwitchAfter,
	}
	if req.SwitchDelaySeconds > 0 {
		t := time.Now().Add(time.Duration(req.SwitchDelaySeconds) * time.Second)
		cfg.SwitchAtTime = &t
	}
	if err := h.DB.UpsertRebindConfig(cfg); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, cfg)
}

// GetRebind handles GET /internal/rebind/:uuid (called by DNS server)
func (h *APIHandler) GetRebind(c *gin.Context) {
	uuid := c.Param("uuid")
	cfg, err := h.DB.GetRebindConfig(uuid)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if cfg == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	c.JSON(http.StatusOK, cfg)
}

// UpdateRebindCount handles PATCH /internal/rebind/:uuid/count (called by DNS server)
func (h *APIHandler) UpdateRebindCount(c *gin.Context) {
	uuid := c.Param("uuid")
	var body struct {
		RequestCount int `json:"request_count"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := h.DB.UpdateRebindCount(uuid, body.RequestCount); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"updated": true})
}

// Stats handles GET /api/stats — uses SQL aggregation, never loads rows into memory.
func (h *APIHandler) Stats(c *gin.Context) {
	stats, err := h.DB.GetStats()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"total":        stats.Total,
		"by_type":      stats.ByType,
		"unique_uuids": stats.UniqueUUIDs,
	})
}

// QuickPayloads handles GET /api/payloads — returns ready-to-use payload set for the configured domain.
func (h *APIHandler) QuickPayloads(domain string) gin.HandlerFunc {
	return func(c *gin.Context) {
		params, _ := json.Marshal(map[string]string{"domain": domain})
		result, err := GeneratePayloads("all", params)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, result)
	}
}

// Search handles GET /api/search?q=...&limit=...&offset=...
// Searches across all text fields (path, headers, body, query_name, etc.).
func (h *APIHandler) Search(c *gin.Context) {
	q := c.Query("q")
	if q == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "q parameter required"})
		return
	}
	limit, _ := strconv.Atoi(c.Query("limit"))
	offset, _ := strconv.Atoi(c.Query("offset"))
	interactions, err := h.DB.SearchInteractions(q, limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"query":        q,
		"count":        len(interactions),
		"interactions": interactions,
	})
}

// ListPayloadHistory handles GET /api/payload-history?limit=
func (h *APIHandler) ListPayloadHistory(c *gin.Context) {
	limit, _ := strconv.Atoi(c.Query("limit"))
	entries, err := h.DB.ListPayloadHistory(limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"history": entries})
}

// DeletePayloadHistory handles DELETE /api/payload-history/:id
func (h *APIHandler) DeletePayloadHistory(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	if err := h.DB.DeletePayloadHistoryEntry(id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"deleted": true})
}

// CheckUUID handles GET /api/check/:uuid — CLI-friendly hit check.
// Returns {"uuid":"...", "hit":true/false, "count":N}
func (h *APIHandler) CheckUUID(c *gin.Context) {
	uuid := c.Param("uuid")
	n, err := h.DB.CountInteractionsByUUID(uuid)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"uuid": uuid, "hit": n > 0, "count": n})
}

// SelfTest handles POST /api/selftest — fires a real HTTP probe to the local
// public receiver so the user can verify the full pipeline without leaving the UI.
func (h *APIHandler) SelfTest(c *gin.Context) {
	probe := fmt.Sprintf("selftest-%d", time.Now().UnixMilli()%100000)
	client := &http.Client{Timeout: 5 * time.Second}
	for _, port := range []string{"80", "3000", "8443", "8888"} {
		url := fmt.Sprintf("http://127.0.0.1:%s/%s", port, probe)
		resp, err := client.Get(url)
		if err != nil {
			continue
		}
		resp.Body.Close()
		c.JSON(http.StatusOK, gin.H{"ok": true, "uuid": probe, "port": port, "http_status": resp.StatusCode})
		return
	}
	c.JSON(http.StatusBadGateway, gin.H{"ok": false, "error": "receiver not responding on any port (80/3000/8443/8888)"})
}

// GeneratePayload handles POST /api/generate
// Body: {"type":"ssrf|rebind|cloud|bypass","params":{...}}
// Auto-records the generation in payload_history.
func (h *APIHandler) GeneratePayload(c *gin.Context) {
	var req struct {
		Type   string          `json:"type"`
		Params json.RawMessage `json:"params"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	result, err := GeneratePayloads(req.Type, req.Params)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// Record in history async (extract domain from params)
	{
		var p map[string]string
		domain := ""
		if len(req.Params) > 0 {
			if json.Unmarshal(req.Params, &p) == nil && p != nil {
				domain = p["domain"]
			}
		}
		u, t := result.UUID, req.Type
		go func() { _ = h.DB.InsertPayloadHistory(u, t, domain) }()
	}
	c.JSON(http.StatusOK, result)
}

// DeleteInteractionByID handles DELETE /api/interaction/:id (single record).
func (h *APIHandler) DeleteInteractionByID(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	if err := h.DB.DeleteInteractionByID(id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"deleted": id})
}

// AddTag handles POST /api/interactions/:id/tags.
func (h *APIHandler) AddTag(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	var req struct {
		Tag string `json:"tag"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	req.Tag = strings.TrimSpace(req.Tag)
	if req.Tag == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tag cannot be empty"})
		return
	}
	if len(req.Tag) > 120 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tag too long (max 120 chars)"})
		return
	}
	tags, err := h.DB.AddInteractionTag(id, req.Tag)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"tags": tags})
}

// RemoveTag handles DELETE /api/interactions/:id/tags.
func (h *APIHandler) RemoveTag(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	var req struct {
		Tag string `json:"tag"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	tags, err := h.DB.RemoveInteractionTag(id, req.Tag)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"tags": tags})
}

// ReplayInteraction handles POST /api/interactions/:id/replay.
// Re-fires the same HTTP request to our own receiver (port 80) to verify reproducibility.
func (h *APIHandler) ReplayInteraction(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	interaction, err := h.DB.GetInteractionByID(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if interaction == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	if interaction.Type != "http" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "replay only supported for HTTP interactions"})
		return
	}

	method := interaction.Method
	if method == "" {
		method = http.MethodGet
	}
	path := interaction.Path
	if path == "" {
		path = "/"
	}

	req, err := http.NewRequest(method, "http://127.0.0.1:80"+path, nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	skipHeaders := map[string]bool{
		"Host": true, "Content-Length": true,
		"Connection": true, "Transfer-Encoding": true,
	}
	var origHeaders map[string][]string
	if interaction.Headers != "" {
		if jsonErr := json.Unmarshal([]byte(interaction.Headers), &origHeaders); jsonErr == nil {
			for k, vs := range origHeaders {
				if skipHeaders[k] {
					continue
				}
				for _, v := range vs {
					req.Header.Add(k, v)
				}
			}
		}
	}
	req.Header.Set("X-SSRF-BOX-Replay", "true")

	client := &http.Client{Timeout: 5 * time.Second}
	start := time.Now()
	resp, err := client.Do(req)
	ms := time.Since(start).Milliseconds()
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"ok": false, "error": err.Error(), "ms": ms})
		return
	}
	defer resp.Body.Close()
	c.JSON(http.StatusOK, gin.H{"ok": true, "status": resp.StatusCode, "ms": ms})
}

// IMDSv2Step1 handles POST /api/chain/imdsv2/step1.
// Makes a PUT request to the target metadata endpoint and returns the token.
func (h *APIHandler) IMDSv2Step1(c *gin.Context) {
	var req struct {
		Target string `json:"target"`
		TTL    int    `json:"ttl"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Target == "" {
		req.Target = "127.0.0.1"
	}
	if req.TTL <= 0 {
		req.TTL = 21600
	}

	url := fmt.Sprintf("http://%s/latest/api/token", req.Target)
	httpReq, err := http.NewRequest(http.MethodPut, url, nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	httpReq.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", strconv.Itoa(req.TTL))

	client := &http.Client{Timeout: 5 * time.Second}
	start := time.Now()
	resp, err := client.Do(httpReq)
	ms := time.Since(start).Milliseconds()
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"ok": false, "error": err.Error(), "ms": ms})
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	token := strings.TrimSpace(string(body))
	c.JSON(http.StatusOK, gin.H{"ok": true, "token": token, "status": resp.StatusCode, "ms": ms})
}

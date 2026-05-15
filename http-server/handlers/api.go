package handlers

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/ssrf-box/http-server/db"
)

// APIHandler groups all admin API endpoints.
type APIHandler struct {
	DB  *db.DB
	Hub *Hub
}

// ListInteractions handles GET /api/interactions?uuid=&type=&limit=&offset=
func (h *APIHandler) ListInteractions(c *gin.Context) {
	uuid := c.Query("uuid")
	itype := c.Query("type")
	limit, _ := strconv.Atoi(c.Query("limit"))
	offset, _ := strconv.Atoi(c.Query("offset"))

	interactions, err := h.DB.ListInteractions(uuid, itype, limit, offset)
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
	interactions, err := h.DB.ListInteractions(uuid, "", 0, 0)
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
	interactions, err := h.DB.ListInteractions(uuid, itype, 10000, 0)
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

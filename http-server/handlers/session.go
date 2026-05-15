package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/ssrf-box/http-server/db"
)

// SessionHandler manages Bug Bounty session CRUD (program/target context per UUID).
type SessionHandler struct {
	DB *db.DB
}

// Create handles POST /api/sessions
// Accepts uuid (optional), program, parameter, endpoint, notes.
// If uuid is empty, generates one server-side.
func (h *SessionHandler) Create(c *gin.Context) {
	var req struct {
		UUID      string `json:"uuid"`
		Program   string `json:"program"`
		Parameter string `json:"parameter"`
		Endpoint  string `json:"endpoint"`
		Notes     string `json:"notes"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.UUID == "" {
		req.UUID = uuid.New().String()[:8]
	}
	s := &db.UUIDSession{
		UUID:      req.UUID,
		Program:   req.Program,
		Parameter: req.Parameter,
		Endpoint:  req.Endpoint,
		Notes:     req.Notes,
	}
	if err := h.DB.UpsertSession(s); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, s)
}

// List handles GET /api/sessions?program=
func (h *SessionHandler) List(c *gin.Context) {
	sessions, err := h.DB.ListSessions(c.Query("program"))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"sessions": sessions})
}

// Get handles GET /api/sessions/:uuid
func (h *SessionHandler) Get(c *gin.Context) {
	s, err := h.DB.GetSession(c.Param("uuid"))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if s == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	c.JSON(http.StatusOK, s)
}

// Update handles PATCH /api/sessions/:uuid
func (h *SessionHandler) Update(c *gin.Context) {
	var req struct {
		Program   string `json:"program"`
		Parameter string `json:"parameter"`
		Endpoint  string `json:"endpoint"`
		Notes     string `json:"notes"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	s := &db.UUIDSession{
		UUID:      c.Param("uuid"),
		Program:   req.Program,
		Parameter: req.Parameter,
		Endpoint:  req.Endpoint,
		Notes:     req.Notes,
	}
	if err := h.DB.UpsertSession(s); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, s)
}

// Delete handles DELETE /api/sessions/:uuid
func (h *SessionHandler) Delete(c *gin.Context) {
	if err := h.DB.DeleteSession(c.Param("uuid")); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"deleted": true})
}

// PatchStatus handles PATCH /api/sessions/:uuid/status
// Allowed values: "", "confirmed", "false_positive", "investigate"
func (h *SessionHandler) PatchStatus(c *gin.Context) {
	var req struct {
		Status string `json:"status"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	allowed := map[string]bool{"": true, "confirmed": true, "false_positive": true, "investigate": true}
	if !allowed[req.Status] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid status value"})
		return
	}
	if err := h.DB.UpdateSessionStatus(c.Param("uuid"), req.Status); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": req.Status})
}

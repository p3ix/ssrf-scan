package handlers

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/ssrf-box/http-server/db"
)

// InteractionHandler logs every incoming HTTP request as an SSRF interaction.
// It is registered as a catch-all on the public port (80/443).
type InteractionHandler struct {
	DB       *db.DB
	Hub      *Hub
	Notifier *Notifier
}

// Handle is the Gin handler for the interaction receiver.
func (h *InteractionHandler) Handle(c *gin.Context) {
	sourceIP := realIP(c)
	uuid := extractUUIDFromRequest(c)

	// Read body (cap at 1 MB to avoid abuse)
	bodyBytes, _ := io.ReadAll(io.LimitReader(c.Request.Body, 1<<20))

	// Marshal headers to JSON
	headerMap := make(map[string]string, len(c.Request.Header))
	for k, v := range c.Request.Header {
		headerMap[k] = strings.Join(v, ", ")
	}
	headersJSON, _ := json.Marshal(headerMap)

	i := &db.Interaction{
		UUID:      uuid,
		Type:      "http",
		Timestamp: time.Now(),
		SourceIP:  sourceIP,
		Method:    c.Request.Method,
		Path:      c.Request.RequestURI,
		Headers:   string(headersJSON),
		Body:      string(bodyBytes),
		UserAgent: c.GetHeader("User-Agent"),
		RawData:   c.Request.Method + " " + c.Request.RequestURI,
	}

	id, err := h.DB.InsertInteraction(i)
	if err != nil {
		log.Printf("[ERROR] InsertInteraction: %v", err)
	} else {
		i.ID = id
		log.Printf("[HTTP] id=%d uuid=%s method=%s path=%s from=%s", id, uuid, i.Method, i.Path, sourceIP)
		h.broadcastInteraction(i)
		if h.Notifier != nil {
			h.Notifier.Notify(i)
		}
	}

	// Return a benign 200 so the SSRF target doesn't retry
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (h *InteractionHandler) broadcastInteraction(i *db.Interaction) {
	payload := map[string]any{
		"event":       "new_interaction",
		"interaction": i,
	}
	data, err := json.Marshal(payload)
	if err == nil {
		h.Hub.Broadcast(data)
	}
}

// InternalReceive handles POST /internal/interaction sent by the DNS and SMTP/LDAP servers.
func InternalReceive(database *db.DB, hub *Hub, notifier *Notifier, internalKey string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.GetHeader("X-Internal-Key") != internalKey {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "forbidden"})
			return
		}

		var i db.Interaction
		if err := c.ShouldBindJSON(&i); err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if i.Timestamp.IsZero() {
			i.Timestamp = time.Now()
		}

		id, err := database.InsertInteraction(&i)
		if err != nil {
			log.Printf("[ERROR] InsertInteraction (internal): %v", err)
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		i.ID = id
		log.Printf("[%s] id=%d uuid=%s from=%s", strings.ToUpper(i.Type), id, i.UUID, i.SourceIP)

		payload := map[string]any{"event": "new_interaction", "interaction": i}
		if data, err := json.Marshal(payload); err == nil {
			hub.Broadcast(data)
		}
		if notifier != nil {
			notifier.Notify(&i)
		}

		c.JSON(http.StatusCreated, gin.H{"id": id})
	}
}

// extractUUIDFromRequest tries to find a UUID in: path prefix, Host subdomain, query param.
func extractUUIDFromRequest(c *gin.Context) string {
	// 1. First path segment often is the UUID
	path := strings.TrimPrefix(c.Request.URL.Path, "/")
	if seg := strings.SplitN(path, "/", 2)[0]; len(seg) >= 8 && len(seg) <= 36 {
		return seg
	}
	// 2. Subdomain prefix: <uuid>.oob.example.com
	host := c.Request.Host
	if idx := strings.Index(host, "."); idx != -1 {
		sub := host[:idx]
		if len(sub) >= 8 {
			return sub
		}
	}
	// 3. Query param
	if u := c.Query("uuid"); u != "" {
		return u
	}
	return ""
}

func realIP(c *gin.Context) string {
	if xff := c.GetHeader("X-Forwarded-For"); xff != "" {
		return strings.SplitN(xff, ",", 2)[0]
	}
	if xri := c.GetHeader("X-Real-IP"); xri != "" {
		return xri
	}
	return c.RemoteIP()
}

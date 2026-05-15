package main

import (
	"crypto/tls"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/ssrf-box/http-server/db"
	"github.com/ssrf-box/http-server/handlers"
)

func main() {
	dbPath := getEnv("DB_PATH", "/data/ssrf-box.db")
	domain := getEnv("SSRF_DOMAIN", "oob.example.com")
	apiKey := os.Getenv("API_KEY")
	if apiKey == "" {
		log.Fatal("[FATAL] API_KEY environment variable is required — set a strong random key in .env")
	}
	internalKey := getEnv("INTERNAL_API_KEY", "changeme-internal")
	tlsCert := getEnv("TLS_CERT_PATH", "")
	tlsKey := getEnv("TLS_KEY_PATH", "")

	database, err := db.Open(dbPath)
	if err != nil {
		log.Fatalf("[FATAL] Cannot open database: %v", err)
	}
	defer database.Close()

	// Seed default API key if table is empty
	var count int
	database.QueryRow("SELECT COUNT(*) FROM api_keys").Scan(&count)
	if count == 0 {
		database.Exec("INSERT INTO api_keys (key_value, description) VALUES (?,?)", apiKey, "default")
		log.Printf("[INFO] Default API key seeded: %s", apiKey)
	}

	hub := handlers.NewHub()
	notifier := handlers.NewNotifier()

	// ── Public interaction receiver (port 80 / 443) ────────────────────────
	gin.SetMode(gin.ReleaseMode)
	public := gin.New()
	public.Use(gin.Recovery())
	public.Use(requestLogger())

	// Health check (no auth)
	public.GET("/ping", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"status": "ok"}) })

	// Cloud metadata simulation (accessible without auth so SSRF targets can hit it)
	metaHandler := &handlers.MetadataHandler{DB: database, Hub: hub}
	metaGroup := public.Group("/metadata")
	metaHandler.RegisterRoutes(metaGroup)
	// Also simulate direct 169.254.169.254 paths
	public.Any("/latest/*path", metaHandler.Handle169)
	public.Any("/computeMetadata/*path", metaHandler.Handle169)

	// Catch-all SSRF interaction logger
	ihHandler := &handlers.InteractionHandler{DB: database, Hub: hub, Notifier: notifier}
	public.NoRoute(ihHandler.Handle)

	// ── Admin API (port 8080) ──────────────────────────────────────────────
	api := gin.New()
	api.Use(gin.Recovery())
	api.Use(requestLogger())

	// Serve static dashboard
	api.Static("/static", "/app/static")
	api.StaticFile("/", "/app/static/index.html")
	api.StaticFile("/dashboard", "/app/static/index.html")

	// WebSocket (auth via Sec-WebSocket-Protocol for browser compatibility — JS WS API has no custom headers)
	api.GET("/ws", func(c *gin.Context) {
		if !isAuthorizedWS(c, database, apiKey) {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
		hub.ServeWS(c.Writer, c.Request)
	})

	// Internal endpoints (called by DNS/SMTP services, no admin auth but internal key)
	internal := api.Group("/internal")
	{
		internal.POST("/interaction", handlers.InternalReceive(database, hub, notifier, internalKey))
		apiHandler := &handlers.APIHandler{DB: database, Hub: hub}
		internal.GET("/rebind/:uuid", apiHandler.GetRebind)
		internal.PATCH("/rebind/:uuid/count", apiHandler.UpdateRebindCount)
	}

	// Public REST API (admin auth required)
	apiGroup := api.Group("/api", authMiddleware(database, apiKey))
	{
		apiHandler := &handlers.APIHandler{DB: database, Hub: hub}
		apiGroup.GET("/interactions", apiHandler.ListInteractions)
		apiGroup.GET("/interactions/:uuid", apiHandler.GetInteraction)
		apiGroup.DELETE("/interactions/:uuid", apiHandler.DeleteInteraction)
		apiGroup.GET("/export", apiHandler.ExportCSV)
		apiGroup.POST("/rebind", apiHandler.CreateRebind)
		apiGroup.GET("/stats", apiHandler.Stats)
		apiGroup.POST("/generate", apiHandler.GeneratePayload)
		apiGroup.GET("/payloads", apiHandler.QuickPayloads(domain))
	}

	// ── Start both servers ─────────────────────────────────────────────────
	errc := make(chan error, 3)

	// Admin API on 8080
	go func() {
		log.Printf("[INFO] Admin API listening on :8080")
		errc <- api.Run(":8080")
	}()

	// Public receiver on 80
	go func() {
		log.Printf("[INFO] Interaction receiver listening on :80")
		errc <- public.Run(":80")
	}()

	// HTTPS on 443 (if certs configured)
	if tlsCert != "" && tlsKey != "" {
		go func() {
			log.Printf("[INFO] HTTPS receiver listening on :443")
			srv := &http.Server{
				Addr:    ":443",
				Handler: public,
				TLSConfig: &tls.Config{
					MinVersion: tls.VersionTLS12,
				},
				ReadHeaderTimeout: 10 * time.Second,
			}
			errc <- srv.ListenAndServeTLS(tlsCert, tlsKey)
		}()
	}

	log.Fatalf("[FATAL] Server stopped: %v", <-errc)
}

func authMiddleware(database *db.DB, fallbackKey string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !isAuthorized(c, database, fallbackKey) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "invalid or missing API key"})
			return
		}
		c.Next()
	}
}

func isAuthorized(c *gin.Context, database *db.DB, fallback string) bool {
	key := c.GetHeader("X-API-Key")
	if key == "" {
		return false
	}
	if key == fallback {
		return true
	}
	return database.ValidateAPIKey(key)
}

// isAuthorizedWS also accepts the API key via Sec-WebSocket-Protocol,
// which is the standard workaround for browser WebSocket auth (JS WS API has no custom headers).
func isAuthorizedWS(c *gin.Context, database *db.DB, fallback string) bool {
	key := c.GetHeader("X-API-Key")
	if key == "" {
		key = c.GetHeader("Sec-WebSocket-Protocol")
	}
	if key == "" {
		return false
	}
	if key == fallback {
		return true
	}
	return database.ValidateAPIKey(key)
}

func requestLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		log.Printf("[REQ] %d %s %s %s %v",
			c.Writer.Status(), c.Request.Method, c.Request.Host, c.Request.RequestURI,
			time.Since(start))
	}
}

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

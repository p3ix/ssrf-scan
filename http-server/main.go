package main

import (
	"crypto/tls"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/ssrf-box/http-server/db"
	"github.com/ssrf-box/http-server/handlers"
	"golang.org/x/crypto/acme/autocert"
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
	autoTLSDomain := os.Getenv("AUTO_TLS_DOMAIN")

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
	public.Use(rateLimitMiddleware(newIPRateLimiter(), 50, time.Minute))

	public.GET("/ping", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"status": "ok"}) })

	metaHandler := &handlers.MetadataHandler{DB: database, Hub: hub}
	metaGroup := public.Group("/metadata")
	metaHandler.RegisterRoutes(metaGroup)
	public.Any("/latest/*path", metaHandler.Handle169)
	public.Any("/computeMetadata/*path", metaHandler.Handle169)

	ihHandler := &handlers.InteractionHandler{DB: database, Hub: hub, Notifier: notifier}
	public.NoRoute(ihHandler.Handle)

	// ── Admin API (port 8080) ──────────────────────────────────────────────
	api := gin.New()
	api.Use(gin.Recovery())
	api.Use(requestLogger())

	api.Static("/static", "/app/static")
	api.StaticFile("/", "/app/static/index.html")
	api.StaticFile("/dashboard", "/app/static/index.html")

	api.GET("/ws", func(c *gin.Context) {
		if !isAuthorizedWS(c, database, apiKey) {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
		hub.ServeWS(c.Writer, c.Request)
	})

	internal := api.Group("/internal")
	{
		internal.POST("/interaction", handlers.InternalReceive(database, hub, notifier, internalKey))
		apiHandler := &handlers.APIHandler{DB: database, Hub: hub}
		internal.GET("/rebind/:uuid", apiHandler.GetRebind)
		internal.PATCH("/rebind/:uuid/count", apiHandler.UpdateRebindCount)
	}

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
		apiGroup.GET("/search", apiHandler.Search)
		apiGroup.GET("/payload-history", apiHandler.ListPayloadHistory)
		apiGroup.DELETE("/payload-history/:id", apiHandler.DeletePayloadHistory)
		apiGroup.GET("/check/:uuid", apiHandler.CheckUUID)
		apiGroup.POST("/selftest", apiHandler.SelfTest)

		sessionHandler := &handlers.SessionHandler{DB: database}
		apiGroup.POST("/sessions", sessionHandler.Create)
		apiGroup.GET("/sessions", sessionHandler.List)
		apiGroup.GET("/sessions/:uuid", sessionHandler.Get)
		apiGroup.PATCH("/sessions/:uuid", sessionHandler.Update)
		apiGroup.DELETE("/sessions/:uuid", sessionHandler.Delete)
		apiGroup.PATCH("/sessions/:uuid/status", sessionHandler.PatchStatus)
	}

	// ── Start servers ──────────────────────────────────────────────────────
	// errc is sized for critical servers only (admin + public receiver).
	// Extra ports are best-effort: failure is logged but doesn't stop the process.
	errc := make(chan error, 2)

	go func() {
		log.Printf("[INFO] Admin API on :8080")
		errc <- api.Run(":8080")
	}()

	// ── Public receiver: HTTP-01 ACME / manual TLS / plain HTTP ───────────
	switch {
	case autoTLSDomain != "":
		// Let's Encrypt via HTTP-01 challenge.
		// NOTE: issues a cert for the exact domain only (not wildcard subdomains).
		// Subdomain payloads still generate DNS callbacks; path-based HTTPS payloads work fully.
		certDir := getEnv("CERT_CACHE_DIR", "/certs")
		m := &autocert.Manager{
			Cache:      autocert.DirCache(certDir),
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(autoTLSDomain),
		}
		// Port 80: SSRF receiver + ACME challenge handler (/.well-known/acme-challenge/)
		go func() {
			log.Printf("[INFO] HTTP receiver + ACME challenge on :80 (domain=%s)", autoTLSDomain)
			srv := &http.Server{Addr: ":80", Handler: m.HTTPHandler(public), ReadHeaderTimeout: 10 * time.Second}
			errc <- srv.ListenAndServe()
		}()
		// Port 443: auto-TLS
		go func() {
			log.Printf("[INFO] HTTPS receiver (auto-TLS) on :443 (domain=%s)", autoTLSDomain)
			srv := &http.Server{
				Addr: ":443", Handler: public,
				TLSConfig: m.TLSConfig(), ReadHeaderTimeout: 10 * time.Second,
			}
			errc <- srv.ListenAndServeTLS("", "")
		}()

	case tlsCert != "" && tlsKey != "":
		// Manual certificate paths
		go func() {
			log.Printf("[INFO] HTTP receiver on :80")
			errc <- public.Run(":80")
		}()
		go func() {
			log.Printf("[INFO] HTTPS receiver (manual cert) on :443")
			srv := &http.Server{
				Addr: ":443", Handler: public,
				TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12},
				ReadHeaderTimeout: 10 * time.Second,
			}
			errc <- srv.ListenAndServeTLS(tlsCert, tlsKey)
		}()

	default:
		go func() {
			log.Printf("[INFO] HTTP receiver on :80")
			errc <- public.Run(":80")
		}()
	}

	// ── Extra HTTP SSRF listener ports (best-effort) ───────────────────────
	// These use the same interaction handler as port 80.
	// Port 8080 is already the admin API — skipped intentionally.
	for _, port := range []string{"3000", "8443", "8888"} {
		go func(p string) {
			log.Printf("[INFO] Extra HTTP listener on :%s", p)
			srv := &http.Server{Addr: ":" + p, Handler: public, ReadHeaderTimeout: 10 * time.Second}
			if err := srv.ListenAndServe(); err != nil {
				log.Printf("[WARN] Extra HTTP listener :%s stopped: %v", p, err)
			}
		}(port)
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

// ── Per-IP fixed-window rate limiter ──────────────────────────────────────

type ipRateLimiter struct {
	mu      sync.Mutex
	windows map[string]*rlWindow
}

type rlWindow struct {
	count   int
	resetAt time.Time
}

func newIPRateLimiter() *ipRateLimiter {
	rl := &ipRateLimiter{windows: make(map[string]*rlWindow)}
	go func() {
		for range time.Tick(time.Minute) {
			rl.mu.Lock()
			now := time.Now()
			for ip, w := range rl.windows {
				if now.After(w.resetAt) {
					delete(rl.windows, ip)
				}
			}
			rl.mu.Unlock()
		}
	}()
	return rl
}

func (rl *ipRateLimiter) allow(ip string, maxReqs int, window time.Duration) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	w, ok := rl.windows[ip]
	if !ok || now.After(w.resetAt) {
		rl.windows[ip] = &rlWindow{count: 1, resetAt: now.Add(window)}
		return true
	}
	w.count++
	return w.count <= maxReqs
}

func rateLimitMiddleware(rl *ipRateLimiter, maxReqs int, window time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !rl.allow(c.ClientIP(), maxReqs, window) {
			c.Header("Retry-After", "60")
			c.AbortWithStatus(http.StatusTooManyRequests)
			return
		}
		c.Next()
	}
}

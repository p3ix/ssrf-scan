package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/ssrf-box/http-server/db"
)

// MetadataHandler simulates cloud metadata endpoints.
// If an SSRF-vulnerable server reaches these endpoints it proves internal network access.
type MetadataHandler struct {
	DB  *db.DB
	Hub *Hub
}

// RegisterRoutes mounts all metadata simulation routes on the given router group.
//
// NOTE: do NOT add a /*path catch-all here. Gin's radix tree panics if a
// wildcard catch-all shares a prefix with already-registered named segments
// (e.g. "/*path" conflicts with "/latest/..." already in the tree).
// Unknown paths under this group fall through to the public router's NoRoute
// handler (the SSRF interaction logger), which records them correctly.
func (h *MetadataHandler) RegisterRoutes(rg *gin.RouterGroup) {
	// AWS IMDSv1
	rg.Any("/latest/meta-data/*path", h.awsMetadata)
	rg.Any("/latest/user-data", h.awsUserData)
	rg.Any("/latest/api/token", h.awsIMDSv2Token)
	// GCP
	rg.Any("/computeMetadata/v1/*path", h.gcpMetadata)
	// Azure
	rg.Any("/metadata/*path", h.azureMetadata)
	// Alibaba Cloud (ECS metadata service at 100.100.100.200)
	rg.Any("/2016-01-01/*path", h.alibabaMetadata)
}

func (h *MetadataHandler) logAndNotify(c *gin.Context, cloud, detail string) {
	sourceIP := realIP(c)
	log.Printf("[METADATA] cloud=%s path=%s from=%s", cloud, c.Request.RequestURI, sourceIP)

	headers, _ := json.Marshal(c.Request.Header)
	i := &db.Interaction{
		UUID:        "metadata-" + cloud,
		Type:        "http",
		Timestamp:   time.Now(),
		SourceIP:    sourceIP,
		Method:      c.Request.Method,
		Path:        c.Request.RequestURI,
		Headers:     string(headers),
		UserAgent:   c.GetHeader("User-Agent"),
		RawData:     c.Request.Method + " " + c.Request.RequestURI,
		DecodedData: "CLOUD METADATA ACCESS DETECTED: " + cloud + " — " + detail,
	}
	id, err := h.DB.InsertInteraction(i)
	if err == nil {
		i.ID = id
		payload := map[string]any{"event": "new_interaction", "interaction": i}
		if data, err := json.Marshal(payload); err == nil {
			h.Hub.Broadcast(data)
		}
	}
}

func (h *MetadataHandler) awsMetadata(c *gin.Context) {
	path := c.Param("path")
	h.logAndNotify(c, "AWS", path)

	switch path {
	case "/iam/security-credentials/", "/iam/security-credentials":
		c.String(http.StatusOK, "ssrf-box-role")
	case "/iam/security-credentials/ssrf-box-role":
		c.JSON(http.StatusOK, gin.H{
			"Code":            "Success",
			"LastUpdated":     time.Now().Format(time.RFC3339),
			"Type":            "AWS-HMAC",
			"AccessKeyId":     "AKIAIOSFODNN7EXAMPLE",
			"SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			"Token":           "SSRF-BOX-SIMULATED-TOKEN-" + time.Now().Format("20060102"),
			"Expiration":      time.Now().Add(6 * time.Hour).Format(time.RFC3339),
		})
	case "/hostname":
		c.String(http.StatusOK, "ip-10-0-0-1.ec2.internal")
	case "/local-ipv4":
		c.String(http.StatusOK, "10.0.0.1")
	case "/public-ipv4":
		c.String(http.StatusOK, "1.2.3.4")
	case "/instance-id":
		c.String(http.StatusOK, "i-0123456789abcdef0")
	case "/ami-id":
		c.String(http.StatusOK, "ami-0123456789abcdef0")
	case "/instance-type":
		c.String(http.StatusOK, "t3.micro")
	default:
		c.String(http.StatusOK, awsMetadataRoot)
	}
}

func (h *MetadataHandler) awsUserData(c *gin.Context) {
	h.logAndNotify(c, "AWS", "user-data")
	c.String(http.StatusOK, `#!/bin/bash
# SSRF-BOX: user-data simulado — en targets reales puede contener credenciales
DB_PASSWORD=SSRF_SIMULATED_SECRET
API_KEY=SSRF_SIMULATED_APIKEY
`)
}

func (h *MetadataHandler) awsIMDSv2Token(c *gin.Context) {
	h.logAndNotify(c, "AWS-IMDSv2", "token-request")
	if c.Request.Method != http.MethodPut {
		c.Status(http.StatusMethodNotAllowed)
		return
	}
	c.String(http.StatusOK, "SSRF-BOX-SIMULATED-IMDSV2-TOKEN-"+time.Now().Format("20060102150405"))
}

func (h *MetadataHandler) gcpMetadata(c *gin.Context) {
	path := c.Param("path")
	// Real GCP rejects requests without this header (403). We log even the rejected ones.
	if c.GetHeader("Metadata-Flavor") != "Google" {
		h.logAndNotify(c, "GCP-NO-HEADER", path)
		c.JSON(http.StatusForbidden, gin.H{
			"ssrf-box": "GCP metadata requires 'Metadata-Flavor: Google' header",
			"hint":     "Add header: Metadata-Flavor: Google",
		})
		return
	}
	h.logAndNotify(c, "GCP", path)

	switch path {
	case "/instance/service-accounts/default/token":
		c.JSON(http.StatusOK, gin.H{
			"access_token": "ya29.SSRF-BOX-SIMULATED-GCP-TOKEN",
			"expires_in":   3600,
			"token_type":   "Bearer",
		})
	case "/instance/service-accounts/default/email":
		c.String(http.StatusOK, "ssrf-box@ssrf-box.iam.gserviceaccount.com")
	case "/project/project-id":
		c.String(http.StatusOK, "ssrf-box-project")
	default:
		c.JSON(http.StatusOK, gin.H{
			"note":       "SSRF-BOX: GCP metadata simulado",
			"path":       path,
			"project_id": "ssrf-box-project",
			"zone":       "us-central1-a",
		})
	}
}

func (h *MetadataHandler) azureMetadata(c *gin.Context) {
	path := c.Param("path")
	// Real Azure IMDS rejects requests without Metadata: true header (400).
	if c.GetHeader("Metadata") != "true" {
		h.logAndNotify(c, "Azure-NO-HEADER", path)
		c.JSON(http.StatusBadRequest, gin.H{
			"ssrf-box": "Azure IMDS requires 'Metadata: true' header",
			"hint":     "Add header: Metadata: true",
		})
		return
	}
	h.logAndNotify(c, "Azure", path)

	if path == "/identity/oauth2/token" {
		c.JSON(http.StatusOK, gin.H{
			"access_token": "SSRF-BOX-SIMULATED-AZURE-TOKEN",
			"client_id":    "00000000-0000-0000-0000-000000000001",
			"expires_in":   "3599",
			"token_type":   "Bearer",
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"note":      "SSRF-BOX: Azure IMDS simulado",
		"compute":   gin.H{"vmId": "00000000-0000-0000-0000-000000000002", "location": "eastus"},
		"network":   gin.H{"interface": []gin.H{{"ipv4": gin.H{"ipAddress": []gin.H{{"privateIpAddress": "10.0.0.1"}}}}}},
	})
}

// alibabaMetadata simulates Alibaba Cloud ECS metadata (100.100.100.200, path prefix /2016-01-01/).
func (h *MetadataHandler) alibabaMetadata(c *gin.Context) {
	path := c.Param("path")
	h.logAndNotify(c, "Alibaba", path)
	c.JSON(http.StatusOK, gin.H{
		"ssrf-box":    "SSRF-BOX: Alibaba Cloud ECS metadata simulado",
		"path":        path,
		"instance-id": "i-ssrfbox0000000001",
		"region-id":   "cn-hangzhou",
		"role-name":   "ssrf-box-role",
		"owner-account-id": "123456789012",
		"security-credentials": gin.H{
			"AccessKeyId":     "STS.SSRF-BOX-SIMULATED-ALIBABA",
			"AccessKeySecret": "SSRF-BOX-SIMULATED-SECRET",
			"SecurityToken":   "SSRF-BOX-SIMULATED-TOKEN",
			"Expiration":      time.Now().Add(6 * time.Hour).Format(time.RFC3339),
		},
	})
}

// Handle169 handles direct paths under /latest/ and /computeMetadata/ (AWS/GCP IMDSv1 paths).
func (h *MetadataHandler) Handle169(c *gin.Context) {
	fullPath := c.Request.RequestURI
	cloud := "AWS"
	if strings.Contains(fullPath, "computeMetadata") {
		cloud = "GCP"
	}
	h.logAndNotify(c, cloud, fullPath)
	c.JSON(http.StatusOK, gin.H{
		"ssrf-box":  "Cloud metadata access detected via /latest or /computeMetadata",
		"cloud":     cloud,
		"path":      fullPath,
		"source_ip": realIP(c),
	})
}

func (h *MetadataHandler) genericMetadata(c *gin.Context) {
	path := c.Param("path")
	h.logAndNotify(c, "GENERIC", path)
	c.JSON(http.StatusOK, gin.H{
		"ssrf-box":    "Metadata access detected",
		"path":        path,
		"source_ip":   realIP(c),
		"timestamp":   time.Now().Format(time.RFC3339),
	})
}

const awsMetadataRoot = `ami-id
ami-launch-index
ami-manifest-path
block-device-mapping/
events/
hostname
iam/
instance-action
instance-id
instance-life-cycle
instance-type
local-hostname
local-ipv4
mac
metrics/
network/
placement/
profile
public-hostname
public-ipv4
public-keys/
reservation-id
security-groups
services/
`

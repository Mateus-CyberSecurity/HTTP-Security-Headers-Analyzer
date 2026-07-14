#!/usr/bin/env python3
"""
HTTP Security Headers Analyzer
================================
Ferramenta de auditoria de segurança que analisa os HTTP Response Headers
de um ou mais sites/aplicações web, verificando a presença e a configuração
de headers de segurança recomendados por OWASP, Mozilla Observatory e CIS
Benchmarks.

Uso comum em:
- AppSec / Blue Team (validação de hardening antes de deploy)
- Pentest / auditorias externas
- Compliance (ISO 27001, PCI-DSS, LGPD - proteção de dados em trânsito)

Autor: Mateus
"""

import argparse
import json
import socket
import ssl
import sys
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

# ---------------------------------------------------------------------------
# Definição dos headers de segurança avaliados
# ---------------------------------------------------------------------------
# Cada header tem: peso (impacto na nota final), descrição e recomendação
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "weight": 15,
        "description": "Força o uso de HTTPS (protege contra downgrade e SSL stripping).",
        "recommendation": "max-age=31536000; includeSubDomains; preload",
    },
    "Content-Security-Policy": {
        "weight": 20,
        "description": "Mitiga XSS e injeção de conteúdo malicioso restringindo fontes de scripts/estilos.",
        "recommendation": "default-src 'self'",
    },
    "X-Content-Type-Options": {
        "weight": 10,
        "description": "Evita que o navegador faça MIME-sniffing de arquivos.",
        "recommendation": "nosniff",
    },
    "X-Frame-Options": {
        "weight": 10,
        "description": "Protege contra ataques de Clickjacking.",
        "recommendation": "DENY ou SAMEORIGIN",
    },
    "Referrer-Policy": {
        "weight": 10,
        "description": "Controla quais informações de referência são enviadas entre origens.",
        "recommendation": "no-referrer-when-downgrade ou strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "weight": 10,
        "description": "Restringe o uso de APIs sensíveis do navegador (câmera, microfone, geolocalização).",
        "recommendation": "geolocation=(), microphone=(), camera=()",
    },
    "X-XSS-Protection": {
        "weight": 5,
        "description": "Header legado de proteção contra XSS refletido (obsoleto, mas ainda cobrado em checklists).",
        "recommendation": "1; mode=block",
    },
    "Cross-Origin-Opener-Policy": {
        "weight": 10,
        "description": "Isola o contexto de navegação, mitigando ataques do tipo Spectre e vazamento entre abas.",
        "recommendation": "same-origin",
    },
    "Cross-Origin-Resource-Policy": {
        "weight": 10,
        "description": "Impede que outros domínios carreguem recursos do seu site sem permissão.",
        "recommendation": "same-origin",
    },
}

# Headers que podem vazar informação sensível sobre a stack tecnológica
INFO_LEAK_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"]


@dataclass
class HeaderFinding:
    header: str
    present: bool
    value: str = ""
    weight: int = 0
    description: str = ""
    recommendation: str = ""


@dataclass
class ScanResult:
    url: str
    status_code: int = 0
    score: int = 0
    max_score: int = 0
    grade: str = ""
    findings: list = field(default_factory=list)
    info_leaks: list = field(default_factory=list)
    tls_info: dict = field(default_factory=dict)
    error: str = ""


def grade_from_score(pct: float) -> str:
    if pct >= 90:
        return "A"
    if pct >= 75:
        return "B"
    if pct >= 60:
        return "C"
    if pct >= 40:
        return "D"
    return "F"


def get_tls_info(hostname: str, port: int = 443, timeout: int = 5) -> dict:
    """Coleta informações básicas do certificado TLS (validade, emissor)."""
    info = {}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                info["tls_version"] = ssock.version()
                info["issuer"] = dict(x[0] for x in cert.get("issuer", []))
                info["not_after"] = cert.get("notAfter")
                not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                days_left = (not_after - datetime.now()).days
                info["days_until_expiry"] = days_left
                info["expired"] = days_left < 0
    except Exception as e:
        info["error"] = f"Não foi possível validar o TLS: {e}"
    return info


def analyze_url(url: str, timeout: int = 8) -> ScanResult:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)
    result = ScanResult(url=url)

    req = Request(url, headers={"User-Agent": "SecurityHeadersAnalyzer/1.0"})
    try:
        with urlopen(req, timeout=timeout) as resp:
            result.status_code = resp.status
            headers = {k: v for k, v in resp.getheaders()}
    except HTTPError as e:
        result.status_code = e.code
        headers = dict(e.headers) if e.headers else {}
    except URLError as e:
        result.error = f"Falha ao conectar: {e.reason}"
        return result
    except Exception as e:
        result.error = f"Erro inesperado: {e}"
        return result

    score = 0
    max_score = 0
    findings = []

    for header, meta in SECURITY_HEADERS.items():
        present = header in headers
        max_score += meta["weight"]
        if present:
            score += meta["weight"]
        findings.append(HeaderFinding(
            header=header,
            present=present,
            value=headers.get(header, ""),
            weight=meta["weight"],
            description=meta["description"],
            recommendation=meta["recommendation"],
        ))

    result.findings = findings
    result.max_score = max_score
    result.score = score
    pct = (score / max_score) * 100 if max_score else 0
    result.grade = grade_from_score(pct)

    # Checagem de vazamento de informação de stack
    for leak_header in INFO_LEAK_HEADERS:
        if leak_header in headers:
            result.info_leaks.append(f"{leak_header}: {headers[leak_header]}")

    # Info de TLS, apenas se HTTPS
    if parsed.scheme == "https":
        result.tls_info = get_tls_info(parsed.hostname, parsed.port or 443)

    return result


def print_report(result: ScanResult):
    print("\n" + "=" * 70)
    print(f" Alvo: {result.url}")
    print("=" * 70)

    if result.error:
        print(f"[ERRO] {result.error}")
        return

    print(f"Status HTTP: {result.status_code}")
    pct = (result.score / result.max_score) * 100 if result.max_score else 0
    print(f"Pontuação: {result.score}/{result.max_score} ({pct:.1f}%) -> Nota: {result.grade}\n")

    print("--- Headers de Segurança ---")
    for f in result.findings:
        status = "✅ PRESENTE" if f.present else "❌ AUSENTE "
        print(f"[{status}] {f.header}")
        if f.present:
            print(f"    Valor atual : {f.value}")
        else:
            print(f"    Recomendado : {f.recommendation}")
        print(f"    Descrição   : {f.description}")

    if result.info_leaks:
        print("\n--- Possível Vazamento de Informação (Fingerprinting) ---")
        for leak in result.info_leaks:
            print(f"⚠️  {leak}")

    if result.tls_info:
        print("\n--- Certificado TLS ---")
        if "error" in result.tls_info:
            print(f"⚠️  {result.tls_info['error']}")
        else:
            print(f"Versão TLS       : {result.tls_info.get('tls_version')}")
            print(f"Emissor          : {result.tls_info.get('issuer', {}).get('organizationName', 'N/A')}")
            print(f"Expira em        : {result.tls_info.get('not_after')}")
            days = result.tls_info.get("days_until_expiry")
            if days is not None:
                if result.tls_info.get("expired"):
                    print("Status           : ❌ CERTIFICADO EXPIRADO")
                elif days < 30:
                    print(f"Status           : ⚠️  Expira em {days} dias (renovar em breve)")
                else:
                    print(f"Status           : ✅ Válido ({days} dias restantes)")


def export_json(results: list, path: str):
    data = []
    for r in results:
        data.append({
            "url": r.url,
            "status_code": r.status_code,
            "score": r.score,
            "max_score": r.max_score,
            "grade": r.grade,
            "error": r.error,
            "headers": [
                {
                    "header": f.header,
                    "present": f.present,
                    "value": f.value,
                    "recommendation": f.recommendation,
                }
                for f in r.findings
            ],
            "info_leaks": r.info_leaks,
            "tls_info": r.tls_info,
        })
    with open(path, "w", encoding="utf-8") as fp:
        json.dump(data, fp, indent=2, ensure_ascii=False)
    print(f"\n📄 Relatório JSON salvo em: {path}")


def main():
    parser = argparse.ArgumentParser(
        description="HTTP Security Headers Analyzer - Auditoria de headers de segurança em aplicações web."
    )
    parser.add_argument("targets", nargs="+", help="Uma ou mais URLs/domínios para analisar")
    parser.add_argument("-o", "--output", help="Caminho para salvar relatório em JSON")
    parser.add_argument("-t", "--timeout", type=int, default=8, help="Timeout da requisição em segundos (padrão: 8)")

    args = parser.parse_args()

    results = []
    for target in args.targets:
        result = analyze_url(target, timeout=args.timeout)
        print_report(result)
        results.append(result)

    if args.output:
        export_json(results, args.output)

    sys.exit(0)


if __name__ == "__main__":
    main()
    
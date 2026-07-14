# 🛡️ HTTP Security Headers Analyzer

Ferramenta desenvolvida em **Python** para auditoria de aplicações web através da análise dos principais **HTTP Security Headers**, seguindo recomendações da **OWASP**, **Mozilla Observatory** e **CIS Benchmarks**.

O objetivo do projeto é auxiliar na identificação de configurações de segurança ausentes ou incorretas, fornecendo uma avaliação da postura de segurança de aplicações web de forma simples e automatizada.

---

## 📖 Sobre o projeto

Os HTTP Response Headers desempenham um papel fundamental na proteção de aplicações web contra diversos ataques, como:

- Cross-Site Scripting (XSS)
- Clickjacking
- MIME Sniffing
- SSL Stripping
- Information Disclosure
- Ataques relacionados à política de origem (Origin Policy)

Esta ferramenta realiza uma auditoria automatizada desses headers, calcula uma pontuação de segurança e apresenta recomendações de acordo com boas práticas reconhecidas pela indústria.

---

# ✨ Funcionalidades

✔ Verificação dos principais HTTP Security Headers

✔ Sistema de pontuação baseado em peso dos headers

✔ Classificação da segurança (A, B, C, D ou F)

✔ Detecção de possíveis vazamentos de informações da infraestrutura (Fingerprinting)

✔ Coleta de informações do certificado TLS

✔ Verificação da validade do certificado

✔ Identificação da versão TLS utilizada

✔ Exportação dos resultados em formato JSON

✔ Suporte para análise de múltiplos domínios

---

# 🔒 Headers analisados

A ferramenta verifica diversos headers importantes, incluindo:

- Strict-Transport-Security (HSTS)
- Content-Security-Policy (CSP)
- X-Content-Type-Options
- X-Frame-Options
- Referrer-Policy
- Permissions-Policy
- X-XSS-Protection
- Cross-Origin-Opener-Policy
- Cross-Origin-Resource-Policy

Também identifica possíveis vazamentos através de:

- Server
- X-Powered-By
- X-AspNet-Version
- X-AspNetMvc-Version

---

# 🔐 Análise TLS

Além dos HTTP Headers, a ferramenta realiza uma verificação do certificado TLS, coletando informações como:

- Versão do protocolo TLS
- Emissor do certificado
- Data de expiração
- Dias restantes até o vencimento
- Certificado expirado ou válido

---

# 🖥️ Tecnologias utilizadas

- Python 3
- urllib
- ssl
- socket
- json
- argparse
- dataclasses

---

# 🚀 Como executar

Clone o repositório:

```bash
git clone https://github.com/Mateus-CyberSecurity/HTTP-Security-Headers-Analyzer.git
```

Entre na pasta:

```bash
cd HTTP-Security-Headers-Analyzer
```

Execute a ferramenta:

```bash
python analisador_security_headers.py google.com
```

Analisando múltiplos domínios:

```bash
python analisador_security_headers.py google.com github.com microsoft.com
```

Exportando para JSON:

```bash
python analisador_security_headers.py google.com -o relatorio.json
```

---

# 🎯 Objetivo do projeto

Este projeto foi desenvolvido com foco em estudos práticos de:

- Segurança da Informação
- Application Security (AppSec)
- Blue Team
- HTTP Security
- TLS
- Desenvolvimento em Python

Além de reforçar conceitos técnicos, o projeto demonstra como a programação pode ser utilizada para automatizar tarefas de auditoria de segurança.

---

# 📚 Referências

- OWASP
- Mozilla Observatory
- CIS Benchmarks

---

# 👨‍💻 Autor

**Mateus Trentin**

Estudante de Segurança da Informação | Python | Cybersecurity | Automação | AppSec

LinkedIn:

(https://www.linkedin.com/in/mateus-trentin-a570b133b/)

GitHub:

https://github.com/Mateus-CyberSecurity

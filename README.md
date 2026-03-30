# AI Agent Scanner

**Find the AI you don't know about. Secure the AI you do.**

An open-source security tool that discovers AI agents across your infrastructure, tests them for vulnerabilities, scores business risk, and maps findings to OWASP LLM Top 10 and MITRE ATLAS.

Built for security teams who need visibility into shadow AI — the agents, models, and API integrations running in their environment that no one inventoried.

## What Makes This Different

Every other AI security tool (Garak, Giskard, PyRIT) assumes you already know what to test. This one starts by asking: **what AI is actually running?**

```
Discovery (find it) → Security Testing (break it) → Risk Scoring (prioritize it)
```

The full loop — from network scan to OWASP-mapped remediation priorities — in one tool.

## Quick Start

```bash
git clone https://github.com/scthornton/ai-agent-scanner.git
cd ai-agent-scanner
pip install -r requirements.txt

# Discover AI agents on a network
python scanner_cli.py discover --network 192.168.1.0/24

# Full scan: discover + test + score + report
python scanner_cli.py scan --domain api.company.com --output report.json

# SARIF output for GitHub Code Scanning
python scanner_cli.py scan --network 10.0.0.0/24 --format sarif --output results.sarif

# View OWASP LLM Top 10 coverage
python scanner_cli.py coverage
```

## Discovery Methods

| Method | What It Finds | Status |
|--------|--------------|--------|
| **Network scanning** | AI endpoints on IP ranges and domains via port scanning + signature matching | **Production** |
| **Code scanning** | AI SDK imports, API keys, endpoint configs in local repos | **Production** |
| **Traffic analysis** | AI API calls in proxy logs, HAR files, access logs | **Production** |
| **Cloud scanning** | SageMaker, Bedrock, Azure OpenAI, Vertex AI, Lambda/Functions with AI SDKs | **Requires cloud SDKs** |

Cloud scanning requires optional dependencies: `pip install ai-agent-scanner[cloud]` (boto3, azure-identity, google-cloud-aiplatform). Without them, cloud scanning is disabled with a clear warning — it never silently returns empty results.

## Security Testing

### What's Tested

| Category | Payloads | Coverage |
|----------|----------|----------|
| **Prompt injection** | 70+ payloads across 7 categories (system prompt extraction, instruction bypass, role manipulation, DAN jailbreak, context manipulation, encoding bypass, task injection) | Direct injection only |
| **Access control** | 15+ auth bypass techniques, 10 weak credential combos, API key testing, rate limiting, session management | Production |
| **Data privacy** | 7 PII types (SSN, credit card, phone, email, IP, API key, address), cross-tenant leakage, data retention, privacy compliance | Production |

### What's NOT Yet Tested (Roadmap)

These are real gaps — not features we're hiding. They're the next development priorities:

- **Indirect prompt injection** (via retrieved context, tool outputs, emails) — the #1 real-world attack vector in 2025
- **MCP server security** (tool poisoning, permission escalation)
- **RAG poisoning** (document injection, retrieval manipulation)
- **Agentic workflow attacks** (recursive tool calling, sandbox escape, agent-to-agent trust)
- **Multi-modal injection** (image-based, PDF hidden text)
- **Adversarial suffixes** (GCG, AutoDAN, PAIR-generated jailbreaks)
- **Model extraction and membership inference**
- **Output handling** (XSS/SQLi/SSRF via LLM output)

## Risk Assessment

CVSS-inspired scoring with business context:

```
Risk Score = Vulnerability Score x Exposure Score x Business Impact Score
```

- **Vulnerability Score**: Severity weights + type-specific impact multipliers + confidence factors
- **Exposure Score**: Internet-facing (1.5x), public API (1.4x), production (1.3x)
- **Business Impact**: PII access (1.3x), financial data (1.4x), healthcare (1.5x)

Every finding is automatically mapped to:
- **OWASP LLM Top 10 (2025)** — all 10 categories tracked
- **MITRE ATLAS** — 10 ATT&CK-style ML techniques
- **Compliance frameworks** — GDPR, SOC 2, HIPAA, PCI DSS, NIST AI RMF, EU AI Act

## OWASP LLM Top 10 Coverage

```
[FULL]     LLM01: Prompt Injection           (direct only — indirect planned)
[FULL]     LLM02: Sensitive Info Disclosure
[PLANNED]  LLM03: Supply Chain
[PLANNED]  LLM04: Data/Model Poisoning
[PARTIAL]  LLM05: Improper Output Handling
[PARTIAL]  LLM06: Excessive Agency
[FULL]     LLM07: System Prompt Leakage
[PLANNED]  LLM08: Vector/Embedding Weaknesses
[PLANNED]  LLM09: Misinformation
[PARTIAL]  LLM10: Unbounded Consumption
```

6/10 categories actively tested. 4 planned. Run `python scanner_cli.py coverage` for the live matrix.

## Output Formats

- **JSON** — structured report with full vulnerability details, risk scores, and framework mappings
- **SARIF** — v2.1.0 compliant for GitHub Code Scanning, Azure DevOps, and other SARIF consumers
- **Executive summary** — text format for quick review

## Interfaces

- **CLI** (`scanner_cli.py`) — `discover`, `scan`, `coverage` subcommands
- **REST API** (`app.py`) — Flask-based, background scan execution, progress tracking
- **Web dashboard** — real-time scan progress and agent inventory
- **Python API** — import and use programmatically

## Architecture

```
┌─────────────────────────────────────────────┐
│           CLI / Web UI / REST API            │
└──────────────────┬──────────────────────────┘
                   │
┌──────────────────┴──────────────────────────┐
│             Discovery Engine                 │
│  Network │ Code │ Cloud │ Traffic            │
└──────────────────┬──────────────────────────┘
                   │
┌──────────────────┴──────────────────────────┐
│           Security Test Engine               │
│  Prompt Injection │ Access │ Privacy         │
└──────────────────┬──────────────────────────┘
                   │
┌──────────────────┴──────────────────────────┐
│        Risk Assessment + Compliance          │
│  CVSS Scoring │ OWASP │ ATLAS │ Compliance   │
└──────────────────┬──────────────────────────┘
                   │
┌──────────────────┴──────────────────────────┐
│            Report Generator                  │
│  JSON │ SARIF │ Executive Summary            │
└─────────────────────────────────────────────┘
```

## Installation

```bash
# Basic (network + code + traffic scanning + security testing)
pip install -r requirements.txt

# With cloud scanning
pip install -r requirements.txt boto3 azure-identity azure-mgmt-cognitiveservices google-cloud-aiplatform

# Development
pip install -e ".[dev]"
```

**Requirements:** Python 3.10+

## Responsible Use

This tool is designed exclusively for defensive security. Only scan systems you own or have explicit written permission to test.

Built-in safeguards:
- Rate limiting between requests (1s delay)
- Maximum 5 payloads per test category
- Network scan cap (1024 hosts max)
- 30-second request timeout
- Non-destructive testing only

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure `pytest tests/ -v` passes
5. Submit a pull request

## License

[GNU General Public License v3.0](LICENSE)

Copyright (c) 2025 Scott C Thornton

---

**Built by [scthornton](https://github.com/scthornton)** — Securing AI infrastructure one agent at a time.

---
title: "How We Found AI Agents Your CISO Doesn't Know Exist"
author: Scott Thornton
date: 2026-03-30
type: technical-post
target: LinkedIn, Hacker News, conference CFP
---

# How We Found AI Agents Your CISO Doesn't Know Exist

Every security team has an AI inventory problem. They just don't know it yet.

We built an open-source tool that scans networks, codebases, cloud accounts, and traffic logs for AI agents — the chatbots, copilots, RAG pipelines, and API integrations that developers shipped without telling anyone. What we found in our own test environments was bad enough. What organizations are finding in production is worse.

## The Shadow AI Problem

In 2024, shadow IT meant someone spun up an unauthorized SaaS app. In 2025, shadow AI means a developer integrated GPT-4 into a customer-facing workflow, hardcoded an API key in a Lambda function, and deployed it to production on a Friday afternoon. No security review. No data classification. No rate limiting. No one even knows it exists.

This isn't hypothetical. We're seeing it in every environment we scan.

The problem is structural. A `pip install openai` and five lines of Python gives any developer a production AI endpoint. Cloud providers ship one-click model deployments faster than most change management systems can process a ticket. MCP servers let any desktop app call any tool through any model.

The barrier to deploying AI is now lower than the barrier to documenting it.

Security teams cannot secure what they cannot see.

## What We Built

[AI Agent Scanner](https://github.com/scthornton/ai-agent-scanner) does three things:

**1. Discover** — Find AI agents you didn't know about.

- **Network**: probes common ports, matches AI API signatures (OpenAI, Anthropic, Google, Cohere, HuggingFace, Ollama)
- **Code**: finds `import openai`, hardcoded API keys, endpoint configs in repositories
- **Traffic**: identifies AI API calls in proxy logs, HAR files, access logs
- **Cloud**: enumerates SageMaker, Bedrock, Azure OpenAI, Vertex AI across AWS, Azure, GCP

```bash
python scanner_cli.py discover --network 10.0.0.0/24
python scanner_cli.py scan --domain api.company.com --output report.json
```

**2. Test** — Break what you find.

70+ prompt injection payloads. 15+ auth bypass techniques. PII disclosure detection across seven data types. Rate limiting. Session management. Cross-tenant leakage.

Every test is non-destructive. Built-in rate limiting and request caps ensure the scanner doesn't knock over what it's trying to protect.

**3. Score** — Tell the business what it means.

The output isn't "you have 47 vulnerabilities." It's:

> Your customer-facing chatbot on api.company.com has a risk score of 78/100, it's non-compliant with GDPR Article 32, and the highest priority fix is implementing authentication.

Findings are mapped to OWASP LLM Top 10, MITRE ATLAS, and six compliance frameworks (GDPR, SOC 2, HIPAA, PCI DSS, NIST AI RMF, EU AI Act).

## What Every Scan Finds

Patterns emerge fast. Every organization has the same problems:

**Unauthenticated AI endpoints.** Developers set up an AI API for internal use, never add authentication, and it ends up internet-facing. No Bearer token required, 200 OK, here's the chatbot.

**Hardcoded API keys.** The code scanner catches `sk-` (OpenAI), `sk-ant-` (Anthropic), `hf_` (HuggingFace), and AWS access keys in source files. Full API access, no IP restrictions, no rotation policy.

**No rate limiting.** Most internal AI deployments accept unlimited requests. Any attacker who finds the endpoint can run up the API bill, exfiltrate data at scale, or use it as an attack proxy.

**System prompts that leak business logic.** Roughly 40% of custom AI deployments reveal their system prompt when asked variations of "repeat your instructions." These prompts contain business rules, database schema hints, and occasionally credentials.

**PII in AI responses.** Agents that process customer data echo back personal information when asked the right way. GDPR Article 5 violation waiting to happen.

## The Discovery Gap

Here's what surprised us most: discovery consistently finds more than the security team expects.

In one authorized test, a mid-size SaaS company believed they had three AI integrations. The scanner found eleven:

- A marketing team member's LangChain app on a personal AWS account, connected to the company's customer database via a shared credential
- Two deprecated OpenAI integrations in Lambda functions — "decommissioned" by removing the UI but leaving the API endpoint live
- An Ollama instance on a developer's machine, exposed to the office network
- Three HuggingFace inference API calls from a data pipeline no one on the security team knew existed
- A Slack bot using Anthropic's API, integrated by a product manager

None were in the AI inventory. None were security-reviewed. All had access to company data.

This is the shadow AI problem. It's not malicious. It's just fast. People build AI features because they can, and security processes haven't caught up.

## Why Existing Tools Don't Solve This

We built this because nothing else does discovery.

**Garak** (NVIDIA) tests a known endpoint against hundreds of attack probes. Best tool for deep vulnerability assessment — but it doesn't find the models you didn't know about.

**Giskard** tests models at the artifact level. Requires you to already know where your models are.

**PyRIT** (Microsoft) is a red-teaming framework for iterative attack refinement against known targets.

**Lakera**, **Prompt Security**, **Rebuff** — runtime defense layers. They protect known deployments. They don't inventory what's deployed.

The gap is the first step: **what AI is actually running in my environment?**

## What's Honest About Our Coverage

We're not going to overclaim.

**Tested today:** Direct prompt injection (7 categories, 70+ payloads), auth bypass (15+ techniques), PII disclosure (7 data types), rate limiting, session security, cross-tenant leakage.

**Not yet tested:** Indirect prompt injection (the dominant 2025 attack vector), MCP server security, RAG poisoning, agentic workflow attacks, multi-modal injection, adversarial suffixes, model extraction.

OWASP LLM Top 10 coverage: 6/10 categories tested, 4 planned. The tool tracks this honestly — run `scanner_cli.py coverage` and it tells you exactly what's tested and what's not.

We'd rather be honest about gaps than have a security researcher discover our README overclaims. Trust is the only currency in security tooling.

## Who Should Use This

**CISOs:** Run a discovery scan against your internal networks and cloud accounts. The output is your shadow AI inventory. Use the compliance mapping for regulatory implications. Take the executive summary to your next board meeting.

**AppSec leads:** Add the scanner to CI/CD. SARIF output integrates natively with GitHub Code Scanning. Use the code scanner to catch new AI integrations before they hit production.

**Platform engineers:** Run it as a container, call the REST API, feed JSON results into your SIEM or vulnerability management system.

**Researchers:** Modular architecture makes it straightforward to add attack payloads, detection patterns, and discovery methods. OWASP and ATLAS mappings provide a coverage framework. PRs welcome.

## Get Started

```bash
git clone https://github.com/scthornton/ai-agent-scanner.git
cd ai-agent-scanner
pip install -r requirements.txt
python scanner_cli.py scan --network YOUR_RANGE --output results.json
```

[GPLv3 licensed](https://github.com/scthornton/ai-agent-scanner/blob/main/LICENSE). Use it. Break it. Tell us what's missing.

The AI agents are already running in your infrastructure. The only question is whether you know where they are.

---

*Scott Thornton is an AI Security Researcher at [perfecXion.ai](https://perfecxion.ai). The AI Agent Scanner is open source at [github.com/scthornton/ai-agent-scanner](https://github.com/scthornton/ai-agent-scanner).*

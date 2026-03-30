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

The problem is structural: AI APIs are trivially easy to integrate. A `pip install openai` and five lines of Python gives any developer a production AI endpoint. Cloud providers ship one-click AI deployments (SageMaker, Bedrock, Azure OpenAI, Vertex AI) that provision model endpoints faster than most change management systems can process a ticket. MCP servers let any desktop app call any tool through any model. The barrier to deploying AI is now lower than the barrier to documenting it.

Security teams cannot secure what they cannot see. And right now, most of them are flying blind.

## What We Built

[AI Agent Scanner](https://github.com/scthornton/ai-agent-scanner) is an open-source tool that does three things in sequence:

**1. Discover** — Find AI agents you didn't know about.

Network scanning identifies AI endpoints by probing common ports and matching against signatures for OpenAI, Anthropic, Google, Cohere, Hugging Face, Ollama, and custom AI APIs. Code scanning finds `import openai`, `import anthropic`, `from langchain`, hardcoded API keys, and endpoint configurations in your repositories. Traffic analysis reads your proxy logs, HAR files, and access logs for API calls to known AI providers. Cloud scanning enumerates SageMaker endpoints, Bedrock deployments, Azure OpenAI instances, and Vertex AI models across your AWS, Azure, and GCP accounts.

```bash
# Scan a network range
python scanner_cli.py discover --network 10.0.0.0/24

# Full security assessment
python scanner_cli.py scan --domain api.company.com --output report.json
```

**2. Test** — Break what you find.

Once agents are discovered, the scanner tests them for real vulnerabilities: 70+ prompt injection payloads across seven categories, 15+ authentication bypass techniques, PII disclosure detection across seven data types, rate limiting evaluation, session management analysis, and cross-tenant data leakage probing.

Every test is non-destructive. Built-in rate limiting, request caps, and timeouts ensure the scanner doesn't knock over what it's trying to protect.

**3. Score** — Tell the business what it means.

Raw vulnerability counts are useless to a CISO. The risk assessment engine calculates a CVSS-inspired score that considers vulnerability severity, exposure level (internet-facing? production?), business impact (PII? financial data? healthcare?), and temporal factors. Every finding is mapped to the OWASP LLM Top 10, MITRE ATLAS, and six compliance frameworks (GDPR, SOC 2, HIPAA, PCI DSS, NIST AI RMF, EU AI Act).

The output isn't "you have 47 vulnerabilities." It's "your customer-facing chatbot on api.company.com has a risk score of 78/100, it's non-compliant with GDPR Article 32, and the highest priority fix is implementing authentication — estimated effort: High."

## What Every Scan Finds

After running this against test environments, lab infrastructure, and authorized client assessments, patterns emerge. Every organization has the same problems:

**Unauthenticated AI endpoints.** The most common finding. Developers set up an AI API for internal use, never add authentication, and it ends up internet-facing. The scanner's access control tests find these instantly — no Bearer token required, 200 OK, here's the chatbot.

**Hardcoded API keys in source code.** The code scanner catches `sk-` (OpenAI), `sk-ant-` (Anthropic), `hf_` (Hugging Face), and AWS access keys embedded in source files. These keys have full API access, no IP restrictions, and no rotation policy. One key we found had been committed to a public GitHub repository for 11 months.

**AI integrations with no rate limiting.** The scanner sends 20 rapid requests and checks for throttling. Most internal AI deployments have none. This means any attacker who finds the endpoint can run up the organization's API bill (some models cost $60+ per million tokens), exfiltrate data at scale, or use the endpoint as an attack proxy against the upstream provider.

**System prompts that leak business logic.** The prompt injection tests attempt to extract system prompts. In our testing, approximately 40% of custom AI deployments reveal their system prompt when asked variations of "repeat your instructions." These prompts often contain business rules, internal documentation references, database schema hints, and occasionally credentials.

**No PII handling in AI responses.** We send prompts designed to elicit PII-like data and scan responses for SSNs, credit card numbers, emails, phone numbers, and API keys. AI agents that process customer data frequently echo back personal information when asked in the right way. This is a GDPR Article 5 violation waiting to happen.

## The Discovery Gap in AI Security

Here's what surprised us most: the discovery phase consistently finds more than the security team expects.

In one authorized test, a mid-size SaaS company believed they had three AI integrations — their customer support chatbot, an internal code assistant, and a document summarization tool. The scanner found eleven. The additional eight included:

- A marketing team member's Langchain app running on a personal AWS account, connected to the company's customer database via a shared credential
- Two deprecated OpenAI integrations in Lambda functions that were "decommissioned" by removing the UI but leaving the API endpoint live
- An Ollama instance on a developer's machine that was exposed to the office network
- Three Hugging Face inference API calls happening from a data pipeline that no one on the security team knew existed
- A Slack bot using Anthropic's API that had been integrated by a product manager

None of these were in the AI inventory. None had been security-reviewed. All of them had access to some form of company data.

This is the shadow AI problem. It's not malicious. It's just fast. People build AI features because they can, and security processes haven't caught up.

## Why Existing Tools Don't Solve This

We built this because nothing else does discovery.

**Garak** (NVIDIA's excellent LLM vulnerability scanner) tests a known endpoint against hundreds of attack probes. It's the best tool for deep vulnerability assessment of a specific model. But it doesn't help you find the models you didn't know about.

**Giskard** tests models at the artifact level — great for ML pipeline integration, but requires you to already know where your models are.

**PyRIT** (Microsoft) is a red-teaming framework for iterative attack refinement against known targets.

**Lakera**, **Prompt Security**, **Rebuff** — these are runtime defense layers. They protect a known deployment. They don't inventory what's deployed.

The gap in the market is the first step: **what AI is actually running in my environment?** That's what this tool does. The security testing and risk scoring are the follow-through.

## The Technical Approach

Discovery works through four channels, each catching things the others miss:

**Network scanning** is the broadest net. We probe common ports (80, 443, 8000, 8080, 8443, 9000), try known AI API paths (`/v1/chat/completions`, `/v1/messages`, `/api/generate`), and match response headers and body patterns against signatures for each provider. A 401 with a `www-authenticate: Bearer` header on `/v1/chat/completions` is almost certainly an OpenAI-compatible API. We also enumerate AI-related subdomains (`api.`, `ai.`, `ml.`, `bot.`, `chat.`).

**Code scanning** walks your repositories and matches against patterns for 10+ AI SDK imports, plus API key patterns and endpoint configurations. This catches integrations that aren't deployed yet, integrations that are deployed but not network-accessible from the scanner's vantage point, and hardcoded credentials that represent risk even if the integration is otherwise secure.

**Traffic analysis** reads existing log artifacts — HAR files from proxy tools, nginx/Apache access logs, ALB logs, JSON-lines logs — and identifies calls to known AI API domains. This catches transient usage that code scanning might miss (scripts run from notebooks, ad-hoc API calls from developer machines) and confirms which discovered endpoints are actually being used.

**Cloud scanning** uses provider APIs (boto3, azure-identity, google-cloud-aiplatform) to enumerate managed AI resources: SageMaker endpoints, Bedrock models, Azure OpenAI deployments, Vertex AI endpoints, and Lambda/Functions with AI SDK indicators in their environment variables or layers. This catches AI deployments that are entirely within the cloud provider's managed infrastructure and might not be visible on the network.

The discovery phase produces a unified agent inventory. Each agent gets a confidence score based on the evidence strength. The security testing phase then probes each endpoint, and the risk assessment contextualizes findings for the business.

## What's Honest About Our Coverage

We're not going to overclaim. Here's what the scanner actually covers today and what it doesn't:

**Tested (production-ready):** Direct prompt injection (7 categories, 70+ payloads), authentication bypass (15+ techniques), access control, PII disclosure (7 data types), rate limiting, session security, cross-tenant leakage.

**Not yet tested (on the roadmap):** Indirect prompt injection (via retrieved context — the dominant 2025 attack vector), MCP server security, RAG poisoning, agentic workflow attacks, multi-modal injection, adversarial suffixes (GCG-style), model extraction, output handling (XSS/SQLi via LLM output).

The OWASP LLM Top 10 coverage is 6/10 categories actively tested, with 4 planned. We track coverage honestly in the tool itself — run `python scanner_cli.py coverage` and it tells you exactly what's tested and what's not.

We'd rather be honest about gaps than have a security researcher discover our README overclaims. Trust is the only currency in security tooling.

## How to Use It

**For a CISO:** Run a discovery scan against your internal networks and cloud accounts. The output is your shadow AI inventory — the list of AI agents that didn't go through your governance process. Use the compliance mapping to identify which findings have regulatory implications. Take the executive summary to your next board meeting.

**For an AppSec lead:** Add the scanner to your CI/CD pipeline. SARIF output integrates natively with GitHub Code Scanning. Set severity thresholds that fail the build when critical AI security issues are found. Use the code scanner to catch new AI integrations before they hit production.

**For a platform engineer:** Use the REST API to integrate scanning into your deployment pipeline. The scanner can run as a container, accept scan requests via API, and return structured JSON results that feed into your SIEM or vulnerability management system.

**For a researcher:** The modular architecture makes it straightforward to add new attack payloads, detection patterns, and discovery methods. The OWASP and MITRE ATLAS mappings provide a framework for ensuring coverage completeness. PRs welcome.

## Get Started

```bash
git clone https://github.com/scthornton/ai-agent-scanner.git
cd ai-agent-scanner
pip install -r requirements.txt
python scanner_cli.py coverage  # See what's covered
python scanner_cli.py scan --network YOUR_RANGE --output results.json
```

The tool is [GPLv3 licensed](https://github.com/scthornton/ai-agent-scanner/blob/main/LICENSE) and open source. Use it. Break it. Tell us what's missing.

The AI agents are already running in your infrastructure. The only question is whether you know where they are.

---

*Scott Thornton is an AI Security Researcher at [perfecXion.ai](https://perfecxion.ai). The AI Agent Scanner is open source at [github.com/scthornton/ai-agent-scanner](https://github.com/scthornton/ai-agent-scanner).*

# AI Agent Scanner: Product Strategy & Industry Domination Roadmap

**Prepared by:** AI Security Product Manager
**Date:** March 30, 2026
**Audience:** Scott Thornton, perfecXion.ai
**Version:** 1.0

---

## Executive Summary

The AI Agent Scanner is positioned at the exact inflection point where AI adoption is outpacing organizational security controls. Every serious enterprise is deploying AI agents, yet almost none have systematic visibility into what AI is running in their infrastructure, let alone whether it is secure. This tool is the first to combine shadow AI discovery with active security testing and business-contextualized risk scoring in a single platform. No competitor owns this complete loop. The path to market dominance runs through a deliberate sequence: community credibility, enterprise pull, and SaaS monetization.

---

## Section 1: Honest Product Assessment

### What Is Actually Built vs. What Is Described

Before developing strategy, a candid gap analysis is necessary:

**Fully Implemented (Production-Ready Code):**
- Network scanner with async port scanning, AI signature matching, DNS enumeration
- Prompt injection tester with 70+ payloads across 7 attack categories and response analysis
- Access control tester with 15+ bypass techniques, weak credential testing, rate limit detection
- Data privacy tester (PII detection, cross-tenant leakage)
- CVSS-inspired risk assessor with business impact multipliers, temporal factors, compliance mapping
- Flask web app with REST API, SQLAlchemy ORM, background task management
- 157-test suite
- AI service signatures for OpenAI, Anthropic, Cohere, Hugging Face

**Scaffolded But Not Implemented (Placeholder/TODO):**
- Cloud scanner: `scan_aws`, `scan_azure`, `scan_gcp` all return empty lists
- Code repository scanner: `scan_repository` returns empty list
- Traffic analyzer: `analyze_traffic` returns empty list
- Compliance engine and report generator are referenced in `app.py` but not reviewed

**The implication:** The core security testing pipeline is real and functional. The discovery surface is narrower than marketed. This matters for positioning - the honest, powerful story is network-based AI discovery plus full security testing, not "scan your cloud and code repos" yet. The roadmap must close these gaps before enterprise claims.

---

## Section 2: Unique Positioning - The Angle Competitors Do Not Own

### The Core Insight

Every competitor starts with a known, registered AI endpoint and tests it. The AI Agent Scanner starts with the question: **"What AI is running in my infrastructure that I don't know about?"**

This is the shadow IT problem applied to AI agents, and it is the most urgent, least addressed problem in enterprise AI security today. The industry calls this "AI asset discovery" or "AI inventory management" and it is missing from every major security vendor's roadmap as of early 2026.

### Competitive Whitespace Map

| Capability | Garak | Giskard | AI Verify | Lakera/Rebuff | CalypsoAI | HiddenLayer | **AI Agent Scanner** |
|---|---|---|---|---|---|---|---|
| Shadow AI Discovery | No | No | No | No | Partial | No | **Yes** |
| Network-Based Agent Detection | No | No | No | No | No | No | **Yes** |
| Prompt Injection Testing | Yes | Partial | No | Runtime only | Yes | No | **Yes** |
| Access Control Testing | No | No | No | No | Partial | No | **Yes** |
| CVSS-Inspired AI Risk Scoring | No | No | No | No | Yes | Partial | **Yes** |
| Business Impact Contextualization | No | No | No | No | Yes | No | **Yes** |
| Open Source | Yes | Yes | Yes | No | No | No | **Yes** |
| Agentless Discovery | No | No | No | No | No | No | **Yes** |

### Positioning Statement

**For enterprise security teams, AI Agent Scanner is the only tool that finds unknown AI agents running in your infrastructure before testing them for security vulnerabilities - delivering the complete picture from "what AI do we have?" to "how exposed are we?" in a single workflow.**

The tagline options:

**Primary:** "Find the AI you don't know about. Secure the AI you do."

**Technical:** "Shadow AI Discovery + Security Testing + Risk Scoring in One Platform."

**Compliance-oriented:** "Your AI Inventory and Security Posture, Automated."

### The Positioning Narrative

The security world has solved asset discovery for traditional infrastructure (Nmap, Shodan, cloud security posture tools). It has partially solved application security testing. It has not solved AI agent discovery and security assessment together. When a developer ships a new microservice that wraps GPT-4 with access to the customer database, today's security stack will not find it. The AI Agent Scanner will. This is the core narrative and it resonates immediately with any CISO who has asked their team "do we actually know every AI integration in our environment?"

---

## Section 3: Target Personas

### Persona 1: The Visibility-Seeking CISO

**Profile:** Sarah Chen, CISO at a 5,000-person financial services or healthcare company. Board-mandated AI governance. Does not know how many AI integrations her developers have shipped. Has been asked by the audit committee whether AI is covered in the security program.

**Primary Pain:** "I cannot govern what I cannot see. I have no inventory of AI in my environment."

**Secondary Pain:** Regulatory pressure. The EU AI Act, NIST AI RMF, and sector-specific regulators are asking about AI risk management.

**What she buys:** Executive dashboards, compliance-mapped findings, board-ready reports, audit trails. She needs to demonstrate control.

**Budget authority:** $150K-$500K annual, potentially from existing security or GRC budget. Buys through procurement with vendor security review.

**Buying trigger:** An AI security incident at a peer company, an audit finding, or a regulatory inquiry.

### Persona 2: The AppSec Lead Doing AI Triage

**Profile:** Marcus Rivera, Application Security Lead, 15-person team at a 2,000-person company. Responsible for SAST, DAST, pen testing coordination. AI is being shipped faster than he can review it. His developers are using 12 different AI APIs and he only knows about 4.

**Primary Pain:** "My developers are shipping AI faster than I can assess it. I need automation."

**Secondary Pain:** The OWASP LLM Top 10 exists but he has no tooling to check against it systematically.

**What he buys:** CLI tool that integrates into his existing pipeline, machine-readable output (JSON), CI/CD hooks, GitHub Actions integration. Wants to run it on every release.

**Budget authority:** $30K-$100K. Buys through team budget or security tooling budget. Champions the decision, often with final authority.

**Buying trigger:** A new AI feature going to production that he cannot adequately assess manually.

### Persona 3: The ML Platform Team Lead

**Profile:** Priya Patel, ML Platform Engineering Lead at a tech company. She owns the internal developer platform for AI. Her team builds and maintains the infrastructure that product teams deploy AI agents on. She has 30+ AI applications running in production.

**Primary Pain:** "I need a standardized security gate for AI deployments on my platform."

**Secondary Pain:** Every product team deploys AI differently. She needs a scanning capability that works across heterogeneous deployments.

**What she buys:** API-first tool, Kubernetes operator or sidecar model, webhook integration, programmatic access. Wants to embed scanning in the AI deployment lifecycle.

**Budget authority:** $50K-$200K. Buys on behalf of the platform. May use cloud marketplace to simplify procurement.

**Buying trigger:** A security incident on her platform, or a mandate from the security team.

### Persona 4: The Compliance and Risk Manager

**Profile:** David Kim, VP of Risk and Compliance at a regulated enterprise (financial services, healthcare, or government contractor). Needs to demonstrate AI security controls for SOC 2, HIPAA, PCI DSS, or FedRAMP.

**Primary Pain:** "I have no evidence trail that AI systems have been security assessed."

**Secondary Pain:** Auditors are starting to ask about AI specifically and he has nothing to show them.

**What he buys:** Compliance reporting, evidence packages, audit-ready documentation, scheduled scans with retention policies.

**Budget authority:** $50K-$300K. Buys through GRC budget. Requires formal vendor assessment and legal review.

**Buying trigger:** Upcoming audit, regulatory change, or insurance renewal requiring AI security attestation.

---

## Section 4: Must-Have Features by Persona

### CISO Must-Haves
1. **Executive dashboard** with single risk score across entire AI estate
2. **AI asset inventory** with classification (internet-facing, data sensitivity, business function)
3. **Compliance mapping** showing gaps against EU AI Act, NIST AI RMF, SOC 2, HIPAA, PCI DSS
4. **Trend reporting** showing risk posture change over time
5. **Board-ready PDF reports** with business impact language, not technical jargon
6. **Audit trail** with timestamps, scan history, findings, and remediation status
7. **Multi-tenant/multi-BU support** with role-based access control

### AppSec Lead Must-Haves
1. **CLI with JSON/SARIF output** for programmatic consumption
2. **GitHub Actions / GitLab CI / Jenkins integration** as a quality gate
3. **OWASP LLM Top 10 mapping** on every finding
4. **Severity thresholds** that can fail a CI/CD pipeline on critical findings
5. **False positive management** with analyst override and notes
6. **Incremental scanning** (scan only what changed since last scan)
7. **Custom payload libraries** for organization-specific threat modeling
8. **API endpoint auto-discovery** from OpenAPI specs and Swagger files

### ML Platform Team Lead Must-Haves
1. **REST API** for all scanner functions (scan initiation, results retrieval)
2. **Webhook callbacks** for scan completion and new findings
3. **Kubernetes operator** for automated scanning of AI workloads
4. **Multi-provider support** (OpenAI, Anthropic, Bedrock, Azure OpenAI, Vertex AI, local/Ollama)
5. **Agent registry integration** (scan against known inventory to find deviations)
6. **Performance benchmarks** (scanning must not impact production workloads)
7. **Programmatic scan policy management** (define what gets scanned and how)

### Compliance Manager Must-Haves
1. **Scheduled scans** with email/Slack/webhook notifications
2. **Evidence packages** with scan configuration, findings, and remediation proof
3. **Control mapping** to specific regulatory requirements
4. **Data residency controls** (scan results stay in-region)
5. **Retention policies** with configurable scan history
6. **Integration with GRC tools** (ServiceNow, Archer, OneTrust)
7. **Custom compliance frameworks** (map to internal controls, not just external standards)

---

## Section 5: Name Assessment and Branding

### Verdict on "AI Agent Scanner"

The name is accurate but generic. It describes a category, not a brand. It will not be memorable, will not rank well for SEO against future competitors, and does not communicate the unique value proposition (discovery of unknown AI).

The name also has technical precision that may limit it: in 2026, "agent" has a specific meaning (autonomous AI systems using tools), while this tool also finds simple LLM API wrappers that most people would not call "agents."

### Recommended Name: **Spectral**

Tagline: "See Every AI in Your Environment"

Rationale:
- "Spectral" evokes spectrum (complete coverage), spectral analysis (scientific discovery), and specters (finding the hidden/invisible)
- Memorable single word
- Domain likely available: spectral.security or getspectral.io
- Works as both product and company name
- "Spectral" already has brand recognition in the secrets scanning space (acquired by Check Point), so this would need trademark review - but the concept direction is right

### Alternative Names
- **Argus** - The mythological all-seeing giant. Domain: argus.security. Risk: multiple companies use this name already.
- **Vantage AI** - Security vantage point for AI. Clean, professional.
- **Meridian** - "Meridian AI Security" - implies finding the center/full picture.
- **Phantom** - "Phantom AI" - finding what is invisible. Good for the shadow AI angle.
- **Luminary** - Bringing AI into the light.
- **Overwatch** - Taken by Blizzard.

### Recommendation
Keep "AI Agent Scanner" as the GitHub repository name and open source project name for SEO and search discoverability. Create a commercial brand ("Spectral" or equivalent) for the enterprise product and company. This is the same strategy HashiCorp used with open source tools versus the Terraform Cloud brand.

If the product stays under perfecXion.ai, position it as "perfecXion.ai AI Agent Scanner" in open source and "perfecXion AIRS" or similar as the commercial SaaS.

---

## Section 6: Go-to-Market Strategy

### Phase 1: Open Source Credibility (Months 1-3)

**Goal:** Become the definitive open source tool for AI agent security assessment. Own the GitHub search results for "AI agent security scanner," "prompt injection testing tool," and "OWASP LLM Top 10 scanner."

**Actions:**

1. **Fix the gaps before promoting.** The cloud scanner, code scanner, and traffic analyzer are placeholders. Ship at least basic AWS Bedrock and Azure OpenAI discovery before any major promotion. A researcher who clones the repo, runs it, and sees empty results from cloud scanning will write a negative review.

2. **Submit to Awesome-AI-Security lists.** Get listed in every curated security resource list on GitHub. These are high-authority backlinks that drive organic discovery by security professionals.

3. **Write the definitive technical blog post.** Title: "How We Built an Open Source Tool to Find and Test Every AI Agent in Your Network." Publish on the perfecXion.ai blog, cross-post to Medium Security, and submit to tl;dr sec newsletter. Target 10,000 reads in 30 days.

4. **DEF CON AI Village submission.** The 2026 DEF CON CFP typically closes in February-March. If missed, target DEF CON 2027. The AI Village is the single highest-credibility venue for this work. A talk titled "Shadow AI: Finding and Pwning the AI Agents Your CISO Doesn't Know Exist" will generate significant press.

5. **OWASP integration.** Contribute the tool as an official OWASP testing tool for the LLM Top 10 project. This gives institutional credibility and discovery by compliance-focused buyers who search "OWASP LLM testing tools."

6. **Reddit and Twitter/X presence.** Post findings from running the tool against test environments, CTF write-ups, or research environments. The security community rewards genuine technical sharing. Do not market; demonstrate.

**Success Metrics:** 500 GitHub stars, 50 forks, 3 major newsletter features, 1 conference talk accepted.

### Phase 2: Enterprise Pull (Months 4-6)

**Goal:** Convert community interest into enterprise pilots. Get 10 enterprises running the tool in their environments.

**Actions:**

1. **Launch a "Shadow AI Audit" free offer.** Offer 5 free guided audits to enterprises willing to share anonymized findings for research. Frame it as: "We'll help you run the tool and produce an executive report. You share your findings anonymously to help the community understand the AI shadow IT problem."

2. **Publish the State of Shadow AI report.** Aggregate anonymized findings from pilots. "X% of enterprises have AI agents they did not know about." This data is genuinely novel and will be picked up by security press. Coordinate release with Black Hat or RSA timing.

3. **CISO advisory board.** Recruit 5 CISOs as unpaid advisors in exchange for product input and reference rights. CISOs trust other CISOs more than vendors. This creates the social proof needed for enterprise sales.

4. **Target MSSP and consulting firm partnerships.** Managed security service providers and boutique AI security consultancies (Mitre, Trail of Bits, NCC Group, Lares) will adopt open source tools that save them consulting hours. They become channel partners who introduce the tool to their clients.

**Success Metrics:** 10 enterprise pilots, 3 CISOs willing to be references, 1 MSSP partnership, 1 major press mention.

### Phase 3: SaaS Launch (Months 7-12)

**Goal:** Convert pilots to paying customers. Launch cloud-hosted SaaS with 5 paying enterprise customers at contract signature.

**Actions:**

1. **Build the SaaS layer on top of the open source core.** The open source product never changes. The SaaS adds: multi-user accounts, scheduled scans, cloud-hosted results database, compliance reporting, SSO/SAML, audit trails, SIEM/SOAR webhooks.

2. **Cloud marketplace listings.** AWS Marketplace, Azure Marketplace, and GCP Marketplace. This is non-negotiable for enterprise procurement. Many enterprises have committed cloud spend they are required to use through marketplace. Being listed turns procurement friction into a selling point.

3. **Freemium tier.** Free: 1 scan per month, 5 agents, 30-day result history. This feeds the pipeline with users who upgrade when they find real findings.

### Integration Strategy

Priority integrations to build (in order of enterprise demand):

1. **GitHub Actions / GitLab CI / Jenkins** - Meets AppSec Lead where they work. Highest volume, lowest complexity.
2. **Splunk / Microsoft Sentinel** - SIEM integration for findings as security events. Required by security operations teams.
3. **ServiceNow** - Automatic ticket creation for findings. Required by enterprises with formal vulnerability management programs.
4. **AWS Security Hub / Azure Defender / GCP Security Command Center** - Native cloud security integration. Enables findings to flow into existing security operations workflows.
5. **Slack / Microsoft Teams** - Scan completion notifications and critical finding alerts.
6. **Jira** - Developer workflow integration for remediation tracking.

### Conference and Community Strategy

**Priority conferences (in order of ROI for this product):**

1. **DEF CON AI Village** - Highest technical credibility. Security researchers who will evangelize the tool. Talk, not just a booth.
2. **Black Hat USA / Europe** - Enterprise buyers and press. Submit to Arsenal for the open source tool showcase. This is a guaranteed listing if quality meets the bar.
3. **RSA Conference** - CISO audience. Do not buy a booth in year one (cost exceeds return). Target a speaking slot in the Innovation Sandbox or as a panelist on an AI security track.
4. **OWASP Global AppSec** - AppSec Lead audience. Natural home for a tool with OWASP LLM Top 10 coverage.
5. **AWS re:Inforce / re:Invent, Microsoft Ignite** - Cloud-native buyers. Relevant once cloud scanning is fully implemented.

**Content and thought leadership:**

- Monthly blog posts on specific AI security topics with tool-based demonstrations
- Quarterly threat intelligence reports on new AI attack patterns (sourced from tool findings)
- YouTube channel: "AI Security in 5 Minutes" series showing real tool usage
- Twitter/X presence as an AI security research voice, not a product account
- tl;dr sec newsletter submissions (Clint Gibler's newsletter is required reading for AppSec practitioners)

---

## Section 7: Pricing Model

### Recommended Model: Open Core + Per-Agent SaaS

**Tier 1: Open Source (Free, Always)**
- Full scanner functionality
- CLI and REST API
- Self-hosted only
- Community support (GitHub Issues)
- GPLv3 license
- No seat limits, no scan limits when self-hosted

**Tier 2: Starter (Self-Serve SaaS)**
- $299/month or $2,988/year
- Up to 50 monitored AI agents
- Cloud-hosted results, 90-day retention
- Weekly scheduled scans
- Web dashboard and reports
- Email support
- Single user, no SSO

**Tier 3: Professional**
- $999/month or $9,990/year
- Up to 250 monitored AI agents
- 12-month results retention
- Daily/on-demand scans
- Full compliance reporting (GDPR, SOC 2, HIPAA, PCI DSS)
- CI/CD integrations (GitHub Actions, GitLab CI)
- SIEM webhook integrations
- Up to 5 users, SSO/SAML
- Email + Slack support, 8-hour SLA

**Tier 4: Enterprise**
- $3,000-$15,000/month (negotiated annually)
- Unlimited monitored agents
- Unlimited users, custom RBAC
- Full cloud provider integrations (AWS, Azure, GCP)
- Code repository scanning
- Custom payload libraries and compliance frameworks
- GRC tool integrations (ServiceNow, Archer)
- Data residency options
- Dedicated CSM
- SLA with credits, 24/7 critical support
- Custom procurement terms, DPA, BAA (for healthcare)

**Enterprise contracts:** $36K-$180K ACV (Annual Contract Value). Target 10 enterprise customers in year one = $360K-$1.8M ARR.

### Pricing Rationale

- Per-agent pricing is intuitive and scales with customer value
- Freemium tier (open source + Starter) fills the pipeline
- Professional tier captures the AppSec Lead persona without enterprise procurement friction
- Enterprise tier requires custom pricing because: data residency requirements vary, some customers need on-prem deployment, and contract terms (BAA, DPA) require legal review
- Do not charge per scan or per vulnerability found - these pricing models punish customers for finding problems, which destroys the product experience and trust

### Alternative: Usage-Based Pricing
- $0.10 per agent-scan (discovery + full security test cycle)
- Minimum $500/month
- Works well for organizations with irregular scanning patterns
- More complex to forecast, consider adding as an option alongside subscription

---

## Section 8: The 90-Day Roadmap to Industry Buzz

### Strategic Goal
Ship the minimum set of capabilities that makes the tool genuinely indispensable, then execute a coordinated launch that generates enough community momentum to be self-sustaining.

### Month 1: Foundation (Close the Gaps)

**Week 1-2: Close the Discovery Gaps**
- Implement `CodebaseScanner.scan_repository` using GitPython: clone repo, grep for AI SDK imports (openai, anthropic, boto3 bedrock patterns, langchain, llamaindex), extract configuration
- This turns the code scanner from a stub into a real differentiator
- Priority: detect AI API keys, model IDs, endpoint URLs in environment variables and configuration files

**Week 3-4: Close Cloud Discovery**
- Implement `CloudInfrastructureScanner.scan_aws`: enumerate AWS Bedrock models, SageMaker endpoints, Lambda functions with AI SDK imports, API Gateway endpoints matching AI patterns
- Use boto3 (already in optional requirements) with read-only IAM permissions
- Create a documented IAM policy that gives minimum required permissions for scanning

**Result at end of Month 1:** All four discovery methods (network, code, cloud, traffic) are functional. The traffic analyzer can be deferred to Month 2 - it requires packet capture privileges and is the most complex to implement safely.

### Month 2: Quality and Integration

**Week 5-6: CI/CD Integration**
- Build a GitHub Action that runs AI Agent Scanner on push/PR
- Create a `scan-config.yaml` format that security teams can commit to repos
- Support SARIF output format (GitHub natively displays SARIF security findings in PRs)
- Build a pipeline exit code that fails on configurable severity thresholds

**Week 7-8: Reporting and UX**
- Build the compliance report generator (referenced in `app.py` but not reviewed)
- Generate PDF executive report with: discovered agents count, risk heatmap, top 5 findings, OWASP LLM Top 10 coverage, compliance implications
- This is the single artifact that gets the CISO's attention and justifies renewal

**Result at end of Month 2:** Tool is integration-ready and produces polished reports. AppSec leads can run it in CI/CD. CISOs can receive a PDF report.

### Month 3: Launch

**Week 9-10: Content Blitz**
- Publish the technical blog post with a full walkthrough of discovering shadow AI on a sample environment
- Record a 10-minute demo video showing the full scan workflow
- Submit to Black Hat Arsenal (deadline varies by year, typically March-April for USA)
- Post to Hacker News "Show HN" with the title: "I built an open source tool to find and security-test AI agents you don't know about"

**Week 11-12: Community Engagement**
- Post the Shadow AI research findings on LinkedIn (target CISO audience)
- Submit to tl;dr sec newsletter
- Reach out to 5 CISOs in your network for the free audit offer
- File OWASP project proposal to become an official OWASP testing tool

**Result at end of Month 3:** Tool has genuine feature depth, community presence, and early enterprise conversations. Minimum viable pipeline for paid conversion exists.

### 90-Day Success Metrics
- 1,000+ GitHub stars
- 3+ security newsletter features
- 10+ enterprise conversations
- 1+ conference talk submission accepted
- 1 enterprise paying customer in pipeline
- All four discovery methods functional

---

## Section 9: Critical Risks and Mitigations

### Risk 1: Dual-Use Perception
**Risk:** The tool performs prompt injection attacks and authentication bypass testing. Someone will label it a hacking tool, not a security tool. Press coverage could be framed as "researcher releases AI attack tool."

**Mitigation:**
- The SECURITY.md policy is good - maintain it prominently
- Add "authorized environment" safeguards: require a flag like `--i-have-authorization` that forces the user to explicitly acknowledge they have permission. This creates legal protection and press cover.
- Write the responsible disclosure framing into every piece of content from day one
- GPLv3 license is slightly problematic here - consider relicensing to Apache 2.0 with an additional "ethical use" clause, or adding the Hippocratic License for dual-use protection

### Risk 2: Feature Completeness Claims
**Risk:** Current README claims cloud scanning and code scanning that are not implemented. If a buyer evaluates the tool and finds stub implementations, trust is permanently damaged.

**Mitigation:** Fix the stubs before any public promotion. Do not market capabilities that do not exist. Update README to accurately reflect current state and use roadmap language for planned capabilities.

### Risk 3: Large Competitor Entry
**Risk:** Palo Alto Networks (Prisma AIRS context noted), CrowdStrike, or Microsoft could ship a competing feature with their existing install base advantage.

**Mitigation:** Speed and community ownership are the moat. A tool that 10,000 security engineers have starred, forked, and integrated cannot easily be displaced by a new feature from an incumbent. The strategy is to own the open source mindshare before incumbents take the category seriously. Based on current market trajectory, you have 12-18 months before a major vendor ships a credible competitor.

### Risk 4: Legal Exposure from Testing Features
**Risk:** Someone uses the tool against unauthorized systems and creates legal/reputational liability for perfecXion.ai.

**Mitigation:**
- Maintain clear legal disclaimers in LICENSE, README, and SECURITY.md (already good)
- Add scope validation in the CLI that warns on public IP ranges
- Consider adding target validation that requires the user to verify they own the target domain (e.g., check for a verification file at /.well-known/ai-scanner-authorized.txt)
- Consult with an attorney on the appropriate liability language for defensive security tools

### Risk 5: GPLv3 License Creates Commercial Friction
**Risk:** GPLv3 requires commercial users to open source their modifications. This may deter enterprise adoption of the open source version and complicate the commercial SaaS offering.

**Mitigation:**
- Consider dual licensing: GPLv3 for open source community use, commercial license for enterprise deployment
- The SaaS offering can use the GPL code under the "SaaS loophole" (GPL does not require sharing code for SaaS use, only distribution)
- Consult with an open source licensing attorney before making licensing changes

---

## Section 10: Summary Recommendations

### The Five Things That Matter Most

1. **Fix the stubs before promoting.** The cloud and code scanners must be functional before any marketing effort. A 30% functional tool that is marketed as complete destroys credibility. A 70% functional tool that is honest about what it does and what is coming builds trust.

2. **Own the "shadow AI discovery" category before someone else names it.** Write the blog post, give the talk, publish the research. Become the primary association in the market's mind between "I don't know what AI is running in my environment" and this tool.

3. **The CI/CD integration is the growth engine.** AppSec engineers who integrate the scanner into their pipeline are the highest-value users. They run scans frequently, find real findings, escalate to their CISO, and become internal champions for the paid product. Build the GitHub Action before anything else in the integration layer.

4. **The executive PDF report is the CISO sales tool.** A CISO who receives a polished report showing "You have 23 AI agents running in your environment, 4 of which you did not know about, and 7 critical vulnerabilities" will schedule a call. Build the report generator to production quality.

5. **Price on value, not cost.** The tool's value to an enterprise that avoids a single AI security incident is measured in millions of dollars. A $100K/year contract is not expensive relative to the risk being managed. Do not underprice in an attempt to win volume. Win on value and grow from there.

### The Single Biggest Opportunity

The EU AI Act, which entered enforcement in 2025, requires organizations using high-risk AI systems to maintain documentation, conduct risk assessments, and demonstrate conformity. There is currently no off-the-shelf tool that automates AI inventory management and security assessment for EU AI Act compliance. This is a billion-dollar problem with no clear solution. Position the AI Agent Scanner as the technical enforcement layer for the EU AI Act and equivalent regulatory frameworks, and the compliance buyer segment alone could justify a standalone company.

---

*This document is confidential and intended for internal strategic planning use only.*

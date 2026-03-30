"""
OWASP LLM Top 10 (2025) Mapping Framework

Maps AI Agent Scanner vulnerability findings to the OWASP Top 10 for LLM
Applications, providing standardized risk categorization and compliance
reporting.

Reference: https://genai.owasp.org/llm-top-10/
"""

from typing import Dict, List, Any
from dataclasses import dataclass, field


@dataclass
class OWASPCategory:
    """Represents an OWASP LLM Top 10 category."""
    id: str
    name: str
    description: str
    risk_level: str
    vulnerability_types: List[str]
    test_coverage: str  # 'full', 'partial', 'planned', 'none'
    mitigations: List[str]
    references: List[str] = field(default_factory=list)


# OWASP LLM Top 10 (2025 edition)
OWASP_LLM_TOP_10: Dict[str, OWASPCategory] = {
    "LLM01": OWASPCategory(
        id="LLM01",
        name="Prompt Injection",
        description=(
            "Crafted inputs manipulate the LLM into executing unintended actions, "
            "bypassing safety measures, or revealing sensitive information. "
            "Includes direct injection (user input) and indirect injection "
            "(via retrieved context from external sources)."
        ),
        risk_level="critical",
        vulnerability_types=[
            "prompt_injection",
            "system_prompt_extraction",
            "instruction_bypass",
            "role_manipulation",
            "dan_jailbreak",
            "context_manipulation",
            "injection_via_encoding",
            "payload_injection",
            "indirect_prompt_injection",
        ],
        test_coverage="full",
        mitigations=[
            "Implement input sanitization and validation",
            "Use structured output formats to constrain responses",
            "Apply least-privilege access for LLM tool integrations",
            "Implement output filtering and content safety layers",
            "Separate instruction context from user-supplied data",
            "Use adversarial testing with diverse prompt injection payloads",
        ],
        references=[
            "https://genai.owasp.org/llmrisk/llm01-prompt-injection/",
        ],
    ),

    "LLM02": OWASPCategory(
        id="LLM02",
        name="Sensitive Information Disclosure",
        description=(
            "LLMs may reveal confidential data including PII, proprietary "
            "information, credentials, or system architecture details through "
            "their responses, training data memorization, or error messages."
        ),
        risk_level="high",
        vulnerability_types=[
            "pii_disclosure",
            "information_disclosure_in_errors",
            "system_prompt_exposure",
            "credential_leakage",
            "training_data_extraction",
        ],
        test_coverage="full",
        mitigations=[
            "Implement PII detection and redaction in outputs",
            "Sanitize error messages to prevent information disclosure",
            "Apply data loss prevention (DLP) filters on LLM outputs",
            "Use differential privacy techniques during training",
            "Restrict access to sensitive data in retrieval pipelines",
        ],
        references=[
            "https://genai.owasp.org/llmrisk/llm02-sensitive-information-disclosure/",
        ],
    ),

    "LLM03": OWASPCategory(
        id="LLM03",
        name="Supply Chain Vulnerabilities",
        description=(
            "Risks from third-party components: poisoned training data, "
            "compromised model weights, malicious plugins/tools, and "
            "vulnerable dependencies in the AI pipeline."
        ),
        risk_level="high",
        vulnerability_types=[
            "model_supply_chain",
            "poisoned_training_data",
            "malicious_plugin",
            "compromised_model_weights",
        ],
        test_coverage="planned",
        mitigations=[
            "Verify model provenance and integrity (checksums, signatures)",
            "Audit third-party plugins and tools before integration",
            "Implement SBOM (Software Bill of Materials) for AI components",
            "Use trusted model registries with access controls",
            "Scan dependencies for known vulnerabilities",
        ],
        references=[
            "https://genai.owasp.org/llmrisk/llm03-supply-chain-vulnerabilities/",
        ],
    ),

    "LLM04": OWASPCategory(
        id="LLM04",
        name="Data and Model Poisoning",
        description=(
            "Manipulation of training data, fine-tuning data, or embeddings "
            "to introduce backdoors, bias, or compromised behavior in the model."
        ),
        risk_level="high",
        vulnerability_types=[
            "training_data_poisoning",
            "fine_tuning_attack",
            "embedding_poisoning",
            "rag_poisoning",
        ],
        test_coverage="planned",
        mitigations=[
            "Validate and sanitize training data sources",
            "Implement anomaly detection on training data pipelines",
            "Use adversarial training to improve robustness",
            "Monitor model behavior for drift and unexpected changes",
            "Maintain data lineage and provenance tracking",
        ],
        references=[
            "https://genai.owasp.org/llmrisk/llm04-data-and-model-poisoning/",
        ],
    ),

    "LLM05": OWASPCategory(
        id="LLM05",
        name="Improper Output Handling",
        description=(
            "Failure to validate and sanitize LLM outputs before passing them "
            "to downstream systems, enabling XSS, SSRF, code injection, or "
            "privilege escalation through LLM-generated content."
        ),
        risk_level="high",
        vulnerability_types=[
            "output_injection",
            "xss_via_llm",
            "code_injection_via_llm",
            "ssrf_via_llm",
        ],
        test_coverage="partial",
        mitigations=[
            "Treat LLM output as untrusted — validate before use",
            "Apply output encoding appropriate to the consumption context",
            "Implement content security policies for LLM-generated content",
            "Sandbox code execution from LLM outputs",
            "Limit LLM output to expected formats using structured output",
        ],
        references=[
            "https://genai.owasp.org/llmrisk/llm05-improper-output-handling/",
        ],
    ),

    "LLM06": OWASPCategory(
        id="LLM06",
        name="Excessive Agency",
        description=(
            "LLM-based agents granted too many permissions, capabilities, or "
            "autonomy — allowing unintended actions on external systems via "
            "tool calling, function execution, or API access."
        ),
        risk_level="critical",
        vulnerability_types=[
            "excessive_tool_permissions",
            "unauthorized_api_access",
            "sandbox_escape",
            "recursive_tool_calling",
            "agent_privilege_escalation",
        ],
        test_coverage="partial",
        mitigations=[
            "Apply least-privilege to all LLM tool integrations",
            "Require human-in-the-loop for destructive or sensitive actions",
            "Implement rate limiting and action budgets for agents",
            "Log and audit all tool invocations and side effects",
            "Define explicit permission boundaries for agent capabilities",
        ],
        references=[
            "https://genai.owasp.org/llmrisk/llm06-excessive-agency/",
        ],
    ),

    "LLM07": OWASPCategory(
        id="LLM07",
        name="System Prompt Leakage",
        description=(
            "Exposure of system prompts, instructions, or configuration that "
            "reveal internal logic, security controls, or sensitive business "
            "rules embedded in the AI system."
        ),
        risk_level="medium",
        vulnerability_types=[
            "system_prompt_extraction",
            "instruction_leakage",
            "configuration_exposure",
        ],
        test_coverage="full",
        mitigations=[
            "Avoid embedding secrets or sensitive logic in system prompts",
            "Implement prompt extraction detection and response filtering",
            "Use defensive prompting techniques (meta-instructions)",
            "Monitor for system prompt content in outputs",
        ],
        references=[
            "https://genai.owasp.org/llmrisk/llm07-system-prompt-leakage/",
        ],
    ),

    "LLM08": OWASPCategory(
        id="LLM08",
        name="Vector and Embedding Weaknesses",
        description=(
            "Vulnerabilities in RAG pipelines and vector databases: poisoned "
            "embeddings, retrieval manipulation, unauthorized access to "
            "vector stores, and embedding inversion attacks."
        ),
        risk_level="medium",
        vulnerability_types=[
            "rag_poisoning",
            "embedding_inversion",
            "vector_db_unauthorized_access",
            "retrieval_manipulation",
        ],
        test_coverage="planned",
        mitigations=[
            "Validate and sanitize documents before embedding",
            "Implement access controls on vector database queries",
            "Monitor retrieval results for anomalous patterns",
            "Use embedding watermarking for provenance tracking",
            "Apply relevance scoring thresholds on retrieved context",
        ],
        references=[
            "https://genai.owasp.org/llmrisk/llm08-vector-and-embedding-weaknesses/",
        ],
    ),

    "LLM09": OWASPCategory(
        id="LLM09",
        name="Misinformation",
        description=(
            "LLMs generating false, misleading, or fabricated information "
            "(hallucinations) that appears authoritative. Risks include "
            "reputational damage, legal liability, and security implications."
        ),
        risk_level="medium",
        vulnerability_types=[
            "hallucination",
            "fabricated_citations",
            "misleading_output",
        ],
        test_coverage="planned",
        mitigations=[
            "Implement retrieval-augmented generation for factual grounding",
            "Add confidence scores and source attribution to outputs",
            "Use fact-checking pipelines for critical applications",
            "Implement human review for high-stakes outputs",
            "Train users to verify AI-generated information",
        ],
        references=[
            "https://genai.owasp.org/llmrisk/llm09-misinformation/",
        ],
    ),

    "LLM10": OWASPCategory(
        id="LLM10",
        name="Unbounded Consumption",
        description=(
            "LLM applications consuming excessive resources through denial "
            "of service, resource exhaustion, or cost manipulation attacks "
            "including prompt flooding, context window abuse, and recursive "
            "agent loops."
        ),
        risk_level="medium",
        vulnerability_types=[
            "no_rate_limiting",
            "resource_exhaustion",
            "cost_manipulation",
            "context_window_abuse",
            "recursive_agent_loop",
        ],
        test_coverage="partial",
        mitigations=[
            "Implement rate limiting and request throttling",
            "Set token and cost budgets per user/session",
            "Monitor for abnormal usage patterns",
            "Implement circuit breakers for agent loops",
            "Set maximum context window utilization limits",
        ],
        references=[
            "https://genai.owasp.org/llmrisk/llm10-unbounded-consumption/",
        ],
    ),
}


def map_vulnerability_to_owasp(vulnerability: Dict[str, Any]) -> List[str]:
    """
    Map a vulnerability finding to applicable OWASP LLM Top 10 categories.

    Args:
        vulnerability: A vulnerability dict with 'vulnerability_type' and
                       optionally 'category' keys.

    Returns:
        List of OWASP category IDs (e.g., ['LLM01', 'LLM07']).
    """
    vuln_type = vulnerability.get('vulnerability_type', '')
    category = vulnerability.get('category', '')

    matched = []
    for owasp_id, owasp_cat in OWASP_LLM_TOP_10.items():
        if vuln_type in owasp_cat.vulnerability_types:
            matched.append(owasp_id)
        elif category in owasp_cat.vulnerability_types:
            matched.append(owasp_id)

    return matched


def generate_owasp_coverage_report(vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Generate a coverage report showing which OWASP categories were tested
    and which had findings.

    Args:
        vulnerabilities: List of vulnerability dicts from security testing.

    Returns:
        Report dict with coverage matrix and findings per category.
    """
    report = {
        'framework': 'OWASP LLM Top 10 (2025)',
        'categories': {},
        'summary': {
            'total_categories': len(OWASP_LLM_TOP_10),
            'categories_with_findings': 0,
            'categories_tested': 0,
            'categories_planned': 0,
        }
    }

    for owasp_id, owasp_cat in OWASP_LLM_TOP_10.items():
        # Find vulnerabilities matching this category
        category_vulns = [
            v for v in vulnerabilities
            if owasp_id in map_vulnerability_to_owasp(v)
        ]

        report['categories'][owasp_id] = {
            'name': owasp_cat.name,
            'risk_level': owasp_cat.risk_level,
            'test_coverage': owasp_cat.test_coverage,
            'findings_count': len(category_vulns),
            'findings': category_vulns,
            'mitigations': owasp_cat.mitigations,
            'references': owasp_cat.references,
        }

        if owasp_cat.test_coverage in ('full', 'partial'):
            report['summary']['categories_tested'] += 1
        else:
            report['summary']['categories_planned'] += 1

        if category_vulns:
            report['summary']['categories_with_findings'] += 1

    return report


def get_coverage_summary() -> Dict[str, Any]:
    """
    Get a quick summary of OWASP LLM Top 10 test coverage.

    Returns:
        Dict mapping category IDs to their coverage status.
    """
    return {
        owasp_id: {
            'name': cat.name,
            'coverage': cat.test_coverage,
            'risk_level': cat.risk_level,
        }
        for owasp_id, cat in OWASP_LLM_TOP_10.items()
    }

"""
MITRE ATLAS (Adversarial Threat Landscape for AI Systems) Mapping

Maps AI Agent Scanner findings to the MITRE ATLAS knowledge base,
providing ATT&CK-style technique IDs for AI/ML-specific threats.

Reference: https://atlas.mitre.org/
"""

from typing import Dict, List, Any
from dataclasses import dataclass, field


@dataclass
class ATLASTechnique:
    """Represents a MITRE ATLAS technique."""
    id: str
    name: str
    tactic: str
    description: str
    vulnerability_types: List[str]
    test_coverage: str  # 'full', 'partial', 'planned', 'none'
    references: List[str] = field(default_factory=list)


# Key MITRE ATLAS techniques relevant to AI agent security
ATLAS_TECHNIQUES: Dict[str, ATLASTechnique] = {
    "AML.T0051": ATLASTechnique(
        id="AML.T0051",
        name="LLM Prompt Injection",
        tactic="Initial Access",
        description="Adversary crafts input to manipulate LLM behavior.",
        vulnerability_types=[
            "prompt_injection", "instruction_bypass", "role_manipulation",
            "dan_jailbreak", "context_manipulation", "payload_injection",
        ],
        test_coverage="full",
        references=["https://atlas.mitre.org/techniques/AML.T0051"],
    ),

    "AML.T0054": ATLASTechnique(
        id="AML.T0054",
        name="LLM Jailbreak",
        tactic="Defense Evasion",
        description="Adversary bypasses LLM safety alignment and content filters.",
        vulnerability_types=[
            "dan_jailbreak", "role_manipulation", "injection_via_encoding",
        ],
        test_coverage="full",
        references=["https://atlas.mitre.org/techniques/AML.T0054"],
    ),

    "AML.T0056": ATLASTechnique(
        id="AML.T0056",
        name="LLM Meta Prompt Extraction",
        tactic="Collection",
        description="Adversary extracts system prompts, instructions, or configuration.",
        vulnerability_types=[
            "system_prompt_extraction", "instruction_leakage", "configuration_exposure",
        ],
        test_coverage="full",
        references=["https://atlas.mitre.org/techniques/AML.T0056"],
    ),

    "AML.T0025": ATLASTechnique(
        id="AML.T0025",
        name="Exfiltration via ML Inference API",
        tactic="Exfiltration",
        description="Adversary extracts training data or model details via API queries.",
        vulnerability_types=[
            "training_data_extraction", "model_extraction", "pii_disclosure",
        ],
        test_coverage="partial",
        references=["https://atlas.mitre.org/techniques/AML.T0025"],
    ),

    "AML.T0024": ATLASTechnique(
        id="AML.T0024",
        name="Exfiltration via Cyber Means",
        tactic="Exfiltration",
        description="Adversary steals model weights, configs, or data through infrastructure.",
        vulnerability_types=[
            "authentication_bypass", "authorization_bypass", "information_disclosure_in_errors",
        ],
        test_coverage="full",
        references=["https://atlas.mitre.org/techniques/AML.T0024"],
    ),

    "AML.T0020": ATLASTechnique(
        id="AML.T0020",
        name="Poison Training Data",
        tactic="Persistence",
        description="Adversary contaminates training or fine-tuning data.",
        vulnerability_types=[
            "training_data_poisoning", "fine_tuning_attack", "rag_poisoning",
        ],
        test_coverage="planned",
        references=["https://atlas.mitre.org/techniques/AML.T0020"],
    ),

    "AML.T0043": ATLASTechnique(
        id="AML.T0043",
        name="Craft Adversarial Data",
        tactic="ML Attack Staging",
        description="Adversary creates inputs designed to cause misclassification or misbehavior.",
        vulnerability_types=[
            "adversarial_suffix", "multimodal_injection", "encoding_bypass",
        ],
        test_coverage="partial",
        references=["https://atlas.mitre.org/techniques/AML.T0043"],
    ),

    "AML.T0040": ATLASTechnique(
        id="AML.T0040",
        name="ML Model Inference API Access",
        tactic="Initial Access",
        description="Adversary gains access to ML model inference APIs.",
        vulnerability_types=[
            "weak_credentials", "weak_api_key", "no_rate_limiting",
        ],
        test_coverage="full",
        references=["https://atlas.mitre.org/techniques/AML.T0040"],
    ),

    "AML.T0044": ATLASTechnique(
        id="AML.T0044",
        name="Full ML Model Access",
        tactic="Collection",
        description="Adversary obtains full access to ML model internals.",
        vulnerability_types=[
            "model_extraction", "authorization_bypass", "authentication_bypass",
        ],
        test_coverage="partial",
        references=["https://atlas.mitre.org/techniques/AML.T0044"],
    ),

    "AML.T0048": ATLASTechnique(
        id="AML.T0048",
        name="Denial of ML Service",
        tactic="Impact",
        description="Adversary disrupts ML service availability.",
        vulnerability_types=[
            "no_rate_limiting", "resource_exhaustion", "cost_manipulation",
        ],
        test_coverage="partial",
        references=["https://atlas.mitre.org/techniques/AML.T0048"],
    ),
}


def map_vulnerability_to_atlas(vulnerability: Dict[str, Any]) -> List[str]:
    """Map a vulnerability finding to MITRE ATLAS technique IDs."""
    vuln_type = vulnerability.get('vulnerability_type', '')
    category = vulnerability.get('category', '')

    matched = []
    for tech_id, technique in ATLAS_TECHNIQUES.items():
        if vuln_type in technique.vulnerability_types or category in technique.vulnerability_types:
            matched.append(tech_id)

    return matched


def generate_atlas_coverage_report(vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Generate a MITRE ATLAS coverage and findings report."""
    report = {
        'framework': 'MITRE ATLAS',
        'techniques': {},
        'summary': {
            'total_techniques': len(ATLAS_TECHNIQUES),
            'techniques_with_findings': 0,
            'techniques_tested': 0,
        }
    }

    for tech_id, technique in ATLAS_TECHNIQUES.items():
        tech_vulns = [
            v for v in vulnerabilities
            if tech_id in map_vulnerability_to_atlas(v)
        ]

        report['techniques'][tech_id] = {
            'name': technique.name,
            'tactic': technique.tactic,
            'test_coverage': technique.test_coverage,
            'findings_count': len(tech_vulns),
        }

        if technique.test_coverage in ('full', 'partial'):
            report['summary']['techniques_tested'] += 1
        if tech_vulns:
            report['summary']['techniques_with_findings'] += 1

    return report

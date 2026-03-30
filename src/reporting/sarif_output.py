"""
SARIF (Static Analysis Results Interchange Format) Output Generator

Generates SARIF v2.1.0 compliant output for integration with GitHub
Code Scanning, Azure DevOps, and other SARIF-consuming tools.

Reference: https://sarifweb.azurewebsites.net/
"""

import json
from typing import Dict, List, Any
from datetime import datetime, timezone

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"

TOOL_NAME = "ai-agent-scanner"
TOOL_VERSION = "1.0.0"
TOOL_URI = "https://github.com/scthornton/ai-agent-scanner"


def _severity_to_sarif_level(severity: str) -> str:
    """Map internal severity to SARIF level."""
    return {
        'critical': 'error',
        'high': 'error',
        'medium': 'warning',
        'low': 'note',
        'info': 'note',
    }.get(severity, 'warning')


def _build_rule(vuln_type: str, category: str = '') -> Dict[str, Any]:
    """Build a SARIF rule definition from a vulnerability type."""
    rule_id = f"AIS-{vuln_type.upper().replace('_', '-')}"
    if category:
        rule_id += f"-{category.upper().replace('_', '-')}"

    return {
        'id': rule_id,
        'shortDescription': {
            'text': vuln_type.replace('_', ' ').title(),
        },
        'helpUri': f"{TOOL_URI}#vulnerability-{vuln_type}",
        'properties': {
            'tags': ['security', 'ai-security', vuln_type],
        },
    }


def generate_sarif(
    vulnerabilities: List[Dict[str, Any]],
    scan_metadata: Dict[str, Any] = None,
) -> Dict[str, Any]:
    """
    Generate a SARIF v2.1.0 document from vulnerability findings.

    Args:
        vulnerabilities: List of vulnerability dicts from security testing.
        scan_metadata: Optional metadata about the scan (targets, timestamps).

    Returns:
        SARIF document as a dict (serialize with json.dumps).
    """
    # Collect unique rules
    rules_map = {}
    results = []

    for vuln in vulnerabilities:
        vuln_type = vuln.get('vulnerability_type', 'unknown')
        category = vuln.get('category', '')
        rule = _build_rule(vuln_type, category)
        rules_map[rule['id']] = rule

        result = {
            'ruleId': rule['id'],
            'level': _severity_to_sarif_level(vuln.get('severity', 'medium')),
            'message': {
                'text': vuln.get('description', vuln.get('title', 'Vulnerability detected')),
            },
            'properties': {
                'confidence': vuln.get('confidence', 0.5),
                'agent_id': vuln.get('agent_id', ''),
                'vulnerability_id': vuln.get('id', ''),
                'remediation': vuln.get('remediation', ''),
            },
        }

        # Add endpoint as a logical location
        endpoint = vuln.get('endpoint') or vuln.get('full_url', '')
        if endpoint:
            result['locations'] = [{
                'logicalLocations': [{
                    'name': endpoint,
                    'kind': 'endpoint',
                }]
            }]

        results.append(result)

    sarif = {
        '$schema': SARIF_SCHEMA,
        'version': SARIF_VERSION,
        'runs': [{
            'tool': {
                'driver': {
                    'name': TOOL_NAME,
                    'version': TOOL_VERSION,
                    'informationUri': TOOL_URI,
                    'rules': list(rules_map.values()),
                }
            },
            'results': results,
            'invocations': [{
                'executionSuccessful': True,
                'startTimeUtc': (
                    scan_metadata.get('started_at', datetime.now(timezone.utc).isoformat())
                    if scan_metadata else datetime.now(timezone.utc).isoformat()
                ),
            }],
        }],
    }

    return sarif


def write_sarif(
    vulnerabilities: List[Dict[str, Any]],
    output_path: str,
    scan_metadata: Dict[str, Any] = None,
) -> str:
    """Generate SARIF and write to file. Returns the output path."""
    sarif = generate_sarif(vulnerabilities, scan_metadata)
    with open(output_path, 'w') as f:
        json.dump(sarif, f, indent=2)
    return output_path

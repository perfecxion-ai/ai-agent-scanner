"""Inspect local JSON only. Never start servers, resolve hosts, or call tools."""

import hashlib
import ipaddress
import json
import re
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

from src.reporting.sarif_output import generate_sarif


RULESET_VERSION = '1.0.0'
MAX_INPUT_BYTES = 2 * 1024 * 1024
SECRET_KEY = re.compile(r'(?:api[_-]?key|token|secret|password|authorization|credential)', re.IGNORECASE)
PLACEHOLDER = re.compile(r'^(?:\$\{[^}]+\}|\$[A-Za-z_][A-Za-z0-9_]*|%[A-Za-z_][A-Za-z0-9_]*%)$')
# Values to flag in untrusted configuration, never listener bind addresses.
WILDCARDS = {'0.0.0.0', '::', '[::]', '*'}  # nosec B104
RULES = {
    'MCP001': ('Wildcard network address', 'medium', 'configuration',
               'Configuration specifies a wildcard network address. Runtime exposure is not verified.',
               'Bind local servers to loopback and review network access controls.'),
    'MCP002': ('Remote plaintext transport', 'medium', 'configuration',
               'A non-loopback HTTP endpoint is configured without TLS.',
               'Use HTTPS for remote MCP transport.'),
    'MCP003': ('Embedded credential', 'high', 'configuration',
               'A credential-shaped field contains a literal value. The value is omitted from this report.',
               'Use a secret reference and rotate the credential if this file was shared.'),
    'MCP004': ('Shell launch configuration', 'info', 'heuristic',
               'The configured command invokes a shell interpreter. This is not proof of command injection.',
               'Prefer a direct executable and review shell code and trust boundaries.'),
    'MCP005': ('Automatic confirmation flag', 'info', 'heuristic',
               'A launch argument may bypass an interactive confirmation; interpretation depends on the executable.',
               'Review package provenance and the executable-specific meaning of this flag.'),
    'MCP006': ('Open command, path, or URL parameter', 'info', 'heuristic',
               'A sensitive input parameter accepts strings without an explicit value allowlist. Runtime authorization is unknown.',
               'Validate allowed operations, filesystem roots, and destinations in the tool implementation.'),
}


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate JSON object key')
        result[key] = value
    return result


def load_json(path):
    """Read bounded JSON, rejecting duplicate keys and nonfinite numbers."""
    with Path(path).open('rb') as stream:
        data = stream.read(MAX_INPUT_BYTES + 1)
    if len(data) > MAX_INPUT_BYTES:
        raise ValueError('Input exceeds 2 MiB')
    try:
        return json.loads(data, object_pairs_hook=_unique_object,
                          parse_constant=lambda value: (_ for _ in ()).throw(ValueError('Nonfinite JSON number')))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError('Invalid JSON input') from exc


def _pointer(*parts):
    return '/' + '/'.join(str(part).replace('~', '~0').replace('/', '~1') for part in parts)


def _literal(value):
    return isinstance(value, str) and bool(value.strip()) and not PLACEHOLDER.fullmatch(value.strip())


def _loopback(host):
    if host and host.rstrip('.').lower() == 'localhost':
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _finding(rule_id, source, pointer):
    title, severity, status, description, remediation = RULES[rule_id]
    identity = hashlib.sha256(f'{rule_id}:{source}:{pointer}'.encode()).hexdigest()[:20]
    return {'id': identity, 'rule_id': rule_id, 'ruleset_version': RULESET_VERSION,
            'vulnerability_type': f'mcp_{rule_id.lower()}', 'title': title,
            'severity': severity, 'evidence_status': status, 'description': description,
            'confidence': 1.0 if status == 'configuration' else 0.3,
            'remediation': remediation, 'source': source, 'json_pointer': pointer}


def _config_findings(config):
    if not isinstance(config, dict):
        raise ValueError('Config must be a JSON object')
    roots = [key for key in ('mcpServers', 'servers') if key in config]
    if len(roots) != 1 or not isinstance(config[roots[0]], dict):
        raise ValueError('Config must contain exactly one mcpServers or servers object')
    root = roots[0]
    findings = []
    for name, server in config[root].items():
        if not isinstance(server, dict):
            raise ValueError('Server entries must be objects')
        if not any(key in server for key in ('command', 'url')):
            raise ValueError('Each server requires command or url')
        for key in ('command', 'url', 'host', 'bind', 'listen'):
            if key in server and (not isinstance(server[key], str) or not server[key].strip()):
                raise ValueError('Server command, url and binding fields must be nonempty strings')
        args = server.get('args', [])
        if not isinstance(args, list) or not all(isinstance(arg, str) for arg in args):
            raise ValueError('Server args must be an array of strings')
        for section in ('env', 'headers'):
            values = server.get(section, {})
            if not isinstance(values, dict) or not all(isinstance(value, str) for value in values.values()):
                raise ValueError('Server env and headers must map names to strings')
            for key, value in values.items():
                # Header values can be opaque credentials; key names identify candidates.
                candidate = value.removeprefix('Bearer ').removeprefix('Basic ')
                if SECRET_KEY.search(key) and _literal(candidate):
                    findings.append(_finding('MCP003', 'config', _pointer(root, name, section, key)))
        for key in ('host', 'bind', 'listen'):
            if server.get(key) in WILDCARDS:
                findings.append(_finding('MCP001', 'config', _pointer(root, name, key)))
        if 'url' in server:
            try:
                url = urlsplit(server['url'])
                host = url.hostname
                _ = url.port
            except ValueError as exc:
                raise ValueError('Invalid server URL') from exc
            if url.scheme not in ('http', 'https') or not host or any(char.isspace() for char in server['url']):
                raise ValueError('Server URL must use http or https with a hostname')
            pointer = _pointer(root, name, 'url')
            if host in WILDCARDS:
                findings.append(_finding('MCP001', 'config', pointer))
            if url.scheme == 'http' and not _loopback(host):
                findings.append(_finding('MCP002', 'config', pointer))
            if url.username or url.password or any(SECRET_KEY.search(key) and _literal(value) for key, value in parse_qsl(url.query)):
                findings.append(_finding('MCP003', 'config', pointer))
        command = server.get('command', '').replace('\\', '/').rsplit('/', 1)[-1].lower()
        if command in ('sh', 'bash', 'zsh', 'fish', 'cmd', 'cmd.exe', 'powershell', 'powershell.exe', 'pwsh'):
            findings.append(_finding('MCP004', 'config', _pointer(root, name, 'command')))
        for index, arg in enumerate(args):
            flag, _, inline = arg.partition('=')
            value = inline if '=' in arg else (args[index + 1] if index + 1 < len(args) else '')
            pointer = _pointer(root, name, 'args', index)
            if flag in ('--host', '--bind', '--listen', '--listen-address') and value in WILDCARDS:
                findings.append(_finding('MCP001', 'config', pointer))
            if flag in ('-y', '--yes', '--auto-approve', '--dangerously-skip-permissions', '--no-confirm') and inline.lower() not in ('false', '0', 'no'):
                findings.append(_finding('MCP005', 'config', pointer))
            if flag.startswith('-') and SECRET_KEY.search(flag) and _literal(value):
                findings.append(_finding('MCP003', 'config', pointer))
    return findings, len(config[root])


def _tool_findings(inventory):
    if not isinstance(inventory, dict):
        raise ValueError('Tool inventory must be an object containing tools')
    body = inventory.get('result', inventory)
    if not isinstance(body, dict) or not isinstance(body.get('tools'), list):
        raise ValueError('Tool inventory requires a tools array')
    findings = []
    sensitive = {'command', 'cmd', 'shell', 'script', 'path', 'filepath', 'file_path',
                 'directory', 'url', 'uri', 'endpoint', 'target_url'}

    def inspect(schema, pointer, depth=0):
        if depth > 32:
            raise ValueError('Tool schema nesting exceeds 32 levels')
        if not isinstance(schema, (dict, bool)):
            raise ValueError('Schema nodes must be objects or booleans')
        if not isinstance(schema, dict):
            return
        properties = schema.get('properties', {})
        if not isinstance(properties, dict):
            raise ValueError('Schema properties must be an object')
        for key, child in properties.items():
            child_pointer = pointer + _pointer('properties', key)
            if not isinstance(child, (dict, bool)):
                raise ValueError('Property schemas must be objects or booleans')
            accepts_string = child is True or (isinstance(child, dict) and (
                'type' not in child or child['type'] == 'string' or isinstance(child['type'], list) and 'string' in child['type']))
            allowlisted = isinstance(child, dict) and ('enum' in child or 'const' in child)
            if key.lower() in sensitive and accepts_string and not allowlisted:
                findings.append(_finding('MCP006', 'tools', child_pointer))
            inspect(child, child_pointer, depth + 1)
        if 'items' in schema:
            inspect(schema['items'], pointer + '/items', depth + 1)
        for keyword in ('anyOf', 'oneOf', 'allOf', 'prefixItems'):
            if keyword in schema:
                if not isinstance(schema[keyword], list):
                    raise ValueError('Schema composition must be an array')
                for index, child in enumerate(schema[keyword]):
                    inspect(child, pointer + _pointer(keyword, index), depth + 1)

    for index, tool in enumerate(body['tools']):
        if not isinstance(tool, dict) or not isinstance(tool.get('name'), str) or not tool['name']:
            raise ValueError('Tools require nonempty string names')
        schema = tool.get('inputSchema')
        if not isinstance(schema, dict) or schema.get('type') != 'object':
            raise ValueError('Tool inputSchema must declare object type')
        prefix = '/result' if 'result' in inventory else ''
        inspect(schema, prefix + _pointer('tools', index, 'inputSchema'))
    return findings, len(body['tools'])


def assess(config=None, tools=None):
    """Return configuration findings and separate tool/launch observations."""
    if config is None and tools is None:
        raise ValueError('Provide a configuration or tool inventory')
    findings, server_count = _config_findings(config) if config is not None else ([], 0)
    tool_findings, tool_count = _tool_findings(tools) if tools is not None else ([], 0)
    findings.extend(tool_findings)
    return {'ruleset_version': RULESET_VERSION, 'mode': 'passive', 'servers_assessed': server_count,
            'tools_assessed': tool_count,
            'findings': [finding for finding in findings if finding['evidence_status'] == 'configuration'],
            'observations': [finding for finding in findings if finding['evidence_status'] == 'heuristic'],
            'limitations': ['No server processes started or network requests made.',
                            'Runtime authorization, Origin checks, sandboxing and exploitability are not verified.',
                            'Tool descriptions are untrusted data; schema references are not resolved.',
                            'Configuration formats vary by client; only documented fields are assessed.']}


def to_sarif(report):
    """Use the shared SARIF envelope, retaining passive evidence and rule versions."""
    findings = report['findings'] + report['observations']
    document = generate_sarif(findings)
    run = document['runs'][0]
    if report.get('mode') == 'live_inventory':
        run['invocations'][0]['executionSuccessful'] = report.get('status') == 'completed'
    run['properties'] = {'mode': report.get('mode', 'passive'), 'ruleset_version': RULESET_VERSION, 'limitations': report['limitations']}
    for key in ('protocol_version', 'status', 'check_schema_version', 'checks', 'risk_assessment_status'):
        if key in report:
            run['properties'][key] = report[key]
    for result, finding in zip(run['results'], findings):
        result['properties'].update({key: finding[key] for key in ('rule_id', 'ruleset_version', 'evidence_status', 'source', 'json_pointer')})
    return document

"""
Traffic Analyzer for AI Service Usage

Analyzes proxy logs, HAR files, and access logs to identify AI API
calls in network traffic. Works without packet capture — analyzes
already-captured log artifacts.

Supports:
    - HAR files (browser/proxy exports)
    - Access logs (nginx, Apache, cloud ALB)
    - JSON-lines log files
    - mitmproxy dump files (text format)
"""

import asyncio
import json
import logging
import re
from pathlib import Path
from typing import List, Dict, Any, Optional
import uuid
from collections import defaultdict


# Known AI API domains and path patterns
AI_API_SIGNATURES = {
    'openai': {
        'domains': ['api.openai.com'],
        'paths': ['/v1/chat/completions', '/v1/completions', '/v1/embeddings', '/v1/images'],
        'provider': 'openai',
    },
    'anthropic': {
        'domains': ['api.anthropic.com'],
        'paths': ['/v1/messages', '/v1/complete'],
        'provider': 'anthropic',
    },
    'google_ai': {
        'domains': ['generativelanguage.googleapis.com', 'aiplatform.googleapis.com'],
        'paths': ['/v1/models/', '/v1beta/models/', ':generateContent', ':predict'],
        'provider': 'google_ai',
    },
    'azure_openai': {
        'domains': ['.openai.azure.com'],
        'paths': ['/openai/deployments/'],
        'provider': 'azure_openai',
    },
    'cohere': {
        'domains': ['api.cohere.ai', 'api.cohere.com'],
        'paths': ['/v1/generate', '/v1/chat', '/v1/embed', '/v2/chat'],
        'provider': 'cohere',
    },
    'huggingface': {
        'domains': ['api-inference.huggingface.co'],
        'paths': ['/models/'],
        'provider': 'huggingface',
    },
    'replicate': {
        'domains': ['api.replicate.com'],
        'paths': ['/v1/predictions'],
        'provider': 'replicate',
    },
    'ollama': {
        'domains': ['localhost:11434', '127.0.0.1:11434'],
        'paths': ['/api/generate', '/api/chat', '/api/embeddings'],
        'provider': 'ollama',
    },
    'mistral': {
        'domains': ['api.mistral.ai'],
        'paths': ['/v1/chat/completions'],
        'provider': 'mistral',
    },
}

# Regex for extracting URLs from various log formats
URL_PATTERNS = [
    # Standard access log: GET /path HTTP/1.1 or POST https://host/path
    r'(?:GET|POST|PUT|PATCH)\s+(https?://[^\s"]+)',
    # Host + path from access logs
    r'(?:GET|POST|PUT|PATCH)\s+(/[^\s"]+)\s+HTTP.*?"?\s*\d+.*?(?:host[=:]\s*"?([^\s"]+))?',
    # Full URLs in JSON logs
    r'"(?:url|uri|request_url|target)":\s*"(https?://[^"]+)"',
    # HAR format
    r'"url":\s*"(https?://[^"]+)"',
]


class TrafficAnalyzer:
    """Analyze network traffic logs for AI service usage."""

    def __init__(self):
        self.logger = logging.getLogger(__name__)

    async def analyze_traffic(self, source: str, ai_signatures: Dict = None) -> List[Dict[str, Any]]:
        """
        Analyze a traffic source for AI API calls.

        Args:
            source: Path to a log file, HAR file, or directory of logs.
            ai_signatures: Optional additional signatures (unused, for interface compat).

        Returns:
            List of discovered agent dicts.
        """
        source_path = Path(source)

        if not source_path.exists():
            self.logger.error(f"Traffic source does not exist: {source}")
            return []

        # Collect all log files
        if source_path.is_dir():
            log_files = self._find_log_files(source_path)
        else:
            log_files = [source_path]

        if not log_files:
            self.logger.warning(f"No analyzable log files found in {source}")
            return []

        self.logger.info(f"Analyzing {len(log_files)} log file(s) from {source}")

        # Aggregate findings across all files
        api_calls: Dict[str, Dict] = defaultdict(lambda: {
            'count': 0,
            'endpoints': set(),
            'methods': set(),
            'source_files': set(),
            'first_seen': None,
            'last_seen': None,
        })

        for log_file in log_files:
            await self._analyze_file(log_file, api_calls)

        # Convert to agent dicts
        agents = []
        for provider_key, data in api_calls.items():
            sig = AI_API_SIGNATURES.get(provider_key, {})
            agents.append({
                'id': str(uuid.uuid4()),
                'name': f"Traffic AI: {sig.get('provider', provider_key)}",
                'provider': sig.get('provider', provider_key),
                'endpoint': next(iter(data['endpoints']), None),
                'discovery_method': 'traffic_analysis',
                'confidence': min(0.6 + data['count'] * 0.05, 0.95),
                'metadata': {
                    'total_api_calls': data['count'],
                    'unique_endpoints': list(data['endpoints'])[:20],
                    'methods': list(data['methods']),
                    'source_files': list(data['source_files'])[:10],
                    'internet_facing': True,
                }
            })

        self.logger.info(f"Traffic analysis complete: {len(agents)} AI services detected")
        return agents

    async def _analyze_file(self, file_path: Path, api_calls: Dict):
        """Analyze a single log file."""
        suffix = file_path.suffix.lower()

        try:
            if suffix == '.har':
                await self._analyze_har(file_path, api_calls)
            elif suffix in ('.json', '.jsonl', '.ndjson'):
                await self._analyze_jsonl(file_path, api_calls)
            else:
                await self._analyze_text_log(file_path, api_calls)
        except Exception as e:
            self.logger.debug(f"Error analyzing {file_path}: {e}")

    async def _analyze_har(self, file_path: Path, api_calls: Dict):
        """Analyze a HAR (HTTP Archive) file."""
        try:
            content = file_path.read_text(errors='ignore')
            har = json.loads(content)

            for entry in har.get('log', {}).get('entries', []):
                request = entry.get('request', {})
                url = request.get('url', '')
                method = request.get('method', '')

                provider = self._match_url_to_provider(url)
                if provider:
                    api_calls[provider]['count'] += 1
                    api_calls[provider]['endpoints'].add(url.split('?')[0])
                    api_calls[provider]['methods'].add(method)
                    api_calls[provider]['source_files'].add(str(file_path))

        except json.JSONDecodeError:
            self.logger.debug(f"Invalid JSON in HAR file: {file_path}")

    async def _analyze_jsonl(self, file_path: Path, api_calls: Dict):
        """Analyze JSON-lines log files."""
        try:
            with open(file_path, 'r', errors='ignore') as f:
                for line_num, line in enumerate(f):
                    if line_num > 100_000:  # Safety limit
                        break
                    line = line.strip()
                    if not line:
                        continue

                    # Extract URLs from JSON
                    for pattern in URL_PATTERNS:
                        for match in re.finditer(pattern, line):
                            url = match.group(1) if match.lastindex else match.group(0)
                            provider = self._match_url_to_provider(url)
                            if provider:
                                api_calls[provider]['count'] += 1
                                api_calls[provider]['endpoints'].add(url.split('?')[0])
                                api_calls[provider]['source_files'].add(str(file_path))
        except Exception as e:
            self.logger.debug(f"Error reading {file_path}: {e}")

    async def _analyze_text_log(self, file_path: Path, api_calls: Dict):
        """Analyze plain-text access logs (nginx, Apache, ALB, etc.)."""
        try:
            with open(file_path, 'r', errors='ignore') as f:
                for line_num, line in enumerate(f):
                    if line_num > 100_000:
                        break

                    for pattern in URL_PATTERNS:
                        for match in re.finditer(pattern, line):
                            url = match.group(1) if match.lastindex else match.group(0)
                            provider = self._match_url_to_provider(url)
                            if provider:
                                api_calls[provider]['count'] += 1
                                api_calls[provider]['endpoints'].add(url.split('?')[0])
                                api_calls[provider]['source_files'].add(str(file_path))

                    # Also check for AI domains mentioned in any context
                    for sig_name, sig in AI_API_SIGNATURES.items():
                        for domain in sig['domains']:
                            if domain in line:
                                api_calls[sig_name]['count'] += 1
                                api_calls[sig_name]['source_files'].add(str(file_path))
                                break

        except Exception as e:
            self.logger.debug(f"Error reading {file_path}: {e}")

    def _match_url_to_provider(self, url: str) -> Optional[str]:
        """Match a URL to a known AI API provider."""
        url_lower = url.lower()
        for sig_name, sig in AI_API_SIGNATURES.items():
            for domain in sig['domains']:
                if domain in url_lower:
                    return sig_name
            for path in sig['paths']:
                if path in url_lower:
                    return sig_name
        return None

    def _find_log_files(self, directory: Path) -> List[Path]:
        """Find analyzable log files in a directory."""
        extensions = {'.log', '.har', '.json', '.jsonl', '.ndjson', '.txt', '.gz'}
        files = []
        for f in directory.rglob('*'):
            if f.is_file() and f.suffix.lower() in extensions and f.stat().st_size <= 500_000_000:
                files.append(f)
        return sorted(files, key=lambda f: f.stat().st_mtime, reverse=True)[:50]

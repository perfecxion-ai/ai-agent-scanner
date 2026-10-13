"""Extract AI service observations from bounded, already captured traffic records."""

import asyncio
import json
import logging
import re
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit, urlunsplit

from src.core.transport import current_budget


AI_API_SIGNATURES = {
    'openai': {'domains': ['api.openai.com']},
    'anthropic': {'domains': ['api.anthropic.com']},
    'google_ai': {'domains': ['generativelanguage.googleapis.com', 'aiplatform.googleapis.com', '.aiplatform.googleapis.com', '-aiplatform.googleapis.com']},
    'azure_openai': {'domains': ['.openai.azure.com']},
    'cohere': {'domains': ['api.cohere.ai', 'api.cohere.com']},
    'huggingface': {'domains': ['api-inference.huggingface.co']},
    'replicate': {'domains': ['api.replicate.com']},
    'ollama': {'domains': ['localhost:11434', '127.0.0.1:11434', '[::1]:11434']},
    'mistral': {'domains': ['api.mistral.ai']},
}

MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024
MAX_FILES = 50
MAX_RECORDS = 100_000
SUPPORTED_SUFFIXES = {'.log', '.har', '.json', '.jsonl', '.ndjson', '.txt'}
REQUEST = re.compile(r'\b(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(https?://[^\s"<>]+)\s+HTTP/\d(?:\.\d)?\b')


class TrafficAnalyzer:
    """Analyze explicit request records without issuing network requests."""

    async def analyze_traffic(self, source: str, ai_signatures: Dict = None) -> List[Dict[str, Any]]:
        # Provider identity comes from authority, not ambiguous shared API paths.
        try:
            return await asyncio.to_thread(self._analyze, Path(source))
        except (OSError, ValueError, UnicodeError):
            self._failure('source')
            return []

    @staticmethod
    def _failure(operation):
        logging.getLogger(__name__).warning('Traffic discovery incomplete: %s', operation)
        budget = current_budget()
        if budget is None:
            raise ValueError('Traffic discovery incomplete') from None
        budget.failures += 1

    def _analyze(self, source: Path) -> List[Dict[str, Any]]:
        if not source.exists() or source.is_symlink():
            raise ValueError('Traffic source must be an existing regular file or directory')
        files = self._find_log_files(source) if source.is_dir() else [source]
        if not files:
            raise ValueError('No supported traffic records found')
        observations = {}
        total_bytes = 0
        for file_path in files:
            if file_path.is_symlink() or not file_path.is_file():
                raise ValueError('Traffic input must be a regular file without symlinks')
            if file_path.suffix.lower() not in SUPPORTED_SUFFIXES:
                raise ValueError('Unsupported traffic format')
            try:
                with file_path.open('rb') as stream:
                    raw = stream.read(MAX_FILE_BYTES + 1)
                total_bytes += len(raw)
                if len(raw) > MAX_FILE_BYTES or total_bytes > MAX_TOTAL_BYTES:
                    self._failure('byte limit')
                    if total_bytes > MAX_TOTAL_BYTES:
                        break
                    continue
                records = self._bounded_records(raw.decode('utf-8'), file_path.suffix.lower())
            except (OSError, UnicodeError):
                self._failure('read')
                continue
            for url, method in records:
                provider = self._match_url_to_provider(url)
                endpoint = self._clean_endpoint(url)
                if provider is None or endpoint is None:
                    continue
                key = (provider, endpoint)
                item = observations.setdefault(key, {
                    'id': str(uuid.uuid5(uuid.NAMESPACE_URL, f'traffic:{provider}:{endpoint}')),
                    'name': f'Traffic AI: {provider}', 'provider': provider,
                    'endpoint': endpoint, 'discovery_method': 'traffic_analysis',
                    'confidence': 0.85,
                    'metadata': {'total_api_calls': 0, 'methods': set(), 'source_files': set(),
                                 'evidence_status': 'observed_request'},
                })
                item['metadata']['total_api_calls'] += 1
                parsed = urlsplit(url)
                if parsed.username is not None or parsed.password is not None or parsed.query:
                    item['metadata']['endpoint_redacted'] = True
                if method:
                    item['metadata']['methods'].add(method.upper())
                item['metadata']['source_files'].add(str(file_path))
        result = []
        for key in sorted(observations):
            item = observations[key]
            item['metadata']['methods'] = sorted(item['metadata']['methods'])
            item['metadata']['source_files'] = sorted(item['metadata']['source_files'])
            result.append(item)
        return result

    def _bounded_records(self, text, suffix):
        try:
            for index, record in enumerate(self._records(text, suffix)):
                if index >= MAX_RECORDS:
                    self._failure('record limit')
                    return
                yield record
        except (ValueError, TypeError, RecursionError):
            self._failure('record format')

    def _records(self, text, suffix):
        if suffix in {'.har', '.json'}:
            document = json.loads(text)
            if suffix == '.har':
                if not isinstance(document, dict) or not isinstance(document.get('log'), dict):
                    raise ValueError('HAR must contain a log object')
                records = document['log'].get('entries')
                if not isinstance(records, list):
                    raise ValueError('HAR entries must be a list')
            else:
                records = document if isinstance(document, list) else [document]
            for record in records:
                yield self._json_request(record)
        elif suffix in {'.jsonl', '.ndjson'}:
            for line in text.splitlines():
                if line.strip():
                    yield self._json_request(json.loads(line))
        else:
            for line in text.splitlines():
                match = REQUEST.search(line)
                yield (match.group(2), match.group(1)) if match else ('', '')

    @staticmethod
    def _json_request(record):
        if not isinstance(record, dict):
            raise ValueError('Traffic request must be a JSON object')
        request = record.get('request', record)
        if not isinstance(request, dict):
            raise ValueError('Traffic request field must be an object')
        url = next((request[key] for key in ('url', 'uri', 'request_url', 'target')
                    if isinstance(request.get(key), str)), '')
        method = request.get('method', '')
        return url, method if isinstance(method, str) else ''

    @staticmethod
    def _clean_endpoint(url):
        try:
            parsed = urlsplit(url)
            if parsed.scheme not in {'http', 'https'} or not parsed.hostname:
                return None
            host = parsed.hostname.lower()
            authority = f'[{host}]' if ':' in host else host
            port = parsed.port
            if port is not None and port != (443 if parsed.scheme == 'https' else 80):
                authority += f':{port}'
            return urlunsplit((parsed.scheme, authority, parsed.path or '/', '', ''))
        except (ValueError, TypeError):
            return None

    def _match_url_to_provider(self, url: str) -> Optional[str]:
        endpoint = self._clean_endpoint(url)
        if endpoint is None:
            return None
        parsed = urlsplit(endpoint)
        for provider, signature in AI_API_SIGNATURES.items():
            for domain in signature['domains']:
                if ':' in domain:
                    matches = parsed.netloc == domain
                elif domain.startswith('.'):
                    matches = parsed.hostname.endswith(domain)
                elif domain.startswith('-'):
                    matches = bool(re.fullmatch(r'[a-z0-9-]+' + re.escape(domain), parsed.hostname))
                else:
                    matches = parsed.hostname == domain
                if matches:
                    return provider
        return None

    def _find_log_files(self, directory: Path) -> List[Path]:
        files = []
        for index, path in enumerate(directory.rglob('*')):
            if index >= 10_000:
                raise ValueError('Traffic input exceeds directory entry limit')
            if path.is_symlink():
                raise ValueError('Traffic directories must not contain symlinks')
            if path.is_file() and path.suffix.lower() in SUPPORTED_SUFFIXES:
                files.append(path)
                if len(files) > MAX_FILES:
                    raise ValueError('Traffic input exceeds file limit')
        return sorted(files)

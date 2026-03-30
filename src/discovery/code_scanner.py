"""
Code Repository Scanner for AI Integrations

Scans local directories and git repositories for AI SDK imports,
API keys, endpoint configurations, and AI framework usage patterns.
Works without any optional dependencies — uses only stdlib.
"""

import logging
import os
import re
from pathlib import Path
from typing import List, Dict, Any
import uuid


# Patterns that indicate AI/ML SDK usage
AI_IMPORT_PATTERNS = {
    'openai': {
        'patterns': [
            r'(?:from\s+|import\s+)openai',
            r'OpenAI\s*\(',
            r'openai\.ChatCompletion',
            r'openai\.Client',
        ],
        'provider': 'openai',
        'confidence': 0.90,
    },
    'anthropic': {
        'patterns': [
            r'(?:from\s+|import\s+)anthropic',
            r'Anthropic\s*\(',
            r'anthropic\.Client',
            r'claude',
        ],
        'provider': 'anthropic',
        'confidence': 0.90,
    },
    'langchain': {
        'patterns': [
            r'(?:from\s+|import\s+)langchain',
            r'LangChain',
            r'ChatOpenAI\s*\(',
            r'ConversationChain',
            r'RetrievalQA',
        ],
        'provider': 'langchain',
        'confidence': 0.85,
    },
    'llamaindex': {
        'patterns': [
            r'(?:from\s+|import\s+)llama_index',
            r'(?:from\s+|import\s+)llamaindex',
            r'VectorStoreIndex',
            r'GPTIndex',
        ],
        'provider': 'llamaindex',
        'confidence': 0.85,
    },
    'huggingface': {
        'patterns': [
            r'(?:from\s+|import\s+)transformers',
            r'(?:from\s+|import\s+)huggingface_hub',
            r'AutoModelFor',
            r'pipeline\s*\(\s*["\']text-generation',
            r'InferenceClient',
        ],
        'provider': 'huggingface',
        'confidence': 0.80,
    },
    'cohere': {
        'patterns': [
            r'(?:from\s+|import\s+)cohere',
            r'cohere\.Client',
        ],
        'provider': 'cohere',
        'confidence': 0.85,
    },
    'aws_bedrock': {
        'patterns': [
            r'bedrock-runtime',
            r'invoke_model',
            r'bedrock\.Client',
            r'BedrockRuntime',
        ],
        'provider': 'aws_bedrock',
        'confidence': 0.85,
    },
    'azure_openai': {
        'patterns': [
            r'AzureOpenAI\s*\(',
            r'azure\.ai\.openai',
            r'openai\.azure',
            r'AZURE_OPENAI',
        ],
        'provider': 'azure_openai',
        'confidence': 0.90,
    },
    'google_ai': {
        'patterns': [
            r'(?:from\s+|import\s+)google\.generativeai',
            r'(?:from\s+|import\s+)vertexai',
            r'GenerativeModel',
            r'gemini',
        ],
        'provider': 'google_ai',
        'confidence': 0.85,
    },
    'ollama': {
        'patterns': [
            r'(?:from\s+|import\s+)ollama',
            r'ollama\.chat',
            r'localhost:11434',
        ],
        'provider': 'ollama',
        'confidence': 0.80,
    },
}

# Patterns that indicate AI-related secrets/config
SECRET_PATTERNS = {
    'openai_key': r'sk-[a-zA-Z0-9]{20,}',
    'anthropic_key': r'sk-ant-[a-zA-Z0-9\-]{20,}',
    'hf_token': r'hf_[a-zA-Z0-9]{20,}',
    'aws_key': r'AKIA[0-9A-Z]{16}',
    'azure_key': r'[a-f0-9]{32}',
    'cohere_key': r'[a-zA-Z0-9]{40}',
}

# Endpoint configuration patterns
ENDPOINT_PATTERNS = [
    r'(?:OPENAI_API_BASE|OPENAI_BASE_URL)\s*=\s*["\']([^"\']+)',
    r'(?:api_base|base_url)\s*=\s*["\']([^"\']+)',
    r'(?:ANTHROPIC_BASE_URL)\s*=\s*["\']([^"\']+)',
    r'(?:AZURE_OPENAI_ENDPOINT)\s*=\s*["\']([^"\']+)',
    r'https?://[^\s"\']+/v1/(?:chat/completions|messages|completions)',
    r'https?://[^\s"\']+/api/(?:generate|chat|embeddings)',
]

# File extensions to scan
SCANNABLE_EXTENSIONS = {
    '.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.go', '.rs',
    '.rb', '.php', '.cs', '.yaml', '.yml', '.json', '.toml', '.cfg',
    '.env', '.ini', '.conf', '.sh', '.bash',
}

# Directories to skip
SKIP_DIRS = {
    'node_modules', '.git', '__pycache__', '.venv', 'venv',
    'env', '.env', 'dist', 'build', '.tox', '.mypy_cache',
    '.pytest_cache', 'egg-info', '.eggs', 'site-packages',
}


class CodebaseScanner:
    """Scan code repositories for AI integrations."""

    def __init__(self):
        self.logger = logging.getLogger(__name__)

    async def scan_repository(self, repo_path: str, ai_signatures: Dict = None) -> List[Dict[str, Any]]:
        """
        Scan a local directory or git repository for AI agent implementations.

        Args:
            repo_path: Local filesystem path to scan. Supports:
                       - Local directory path
                       - Git URL (will warn that cloning is not yet supported)
            ai_signatures: Optional additional signatures (unused, for interface compat).

        Returns:
            List of discovered agent dicts.
        """
        # Handle git URLs — we only support local paths for now
        if repo_path.startswith(('http://', 'https://', 'git@', 'git://')):
            self.logger.warning(
                f"Git URL cloning not yet supported: {repo_path}. "
                "Please provide a local path."
            )
            return []

        path = Path(repo_path).resolve()
        if not path.exists():
            self.logger.error(f"Path does not exist: {repo_path}")
            return []

        if not path.is_dir():
            self.logger.error(f"Path is not a directory: {repo_path}")
            return []

        self.logger.info(f"Scanning codebase at {path}")

        # Collect all findings
        findings: Dict[str, Dict] = {}  # keyed by provider to aggregate

        files_scanned = 0
        for file_path in self._walk_files(path):
            files_scanned += 1
            try:
                content = file_path.read_text(errors='ignore')
            except Exception:
                continue

            # Check for AI SDK imports
            for sdk_name, sdk_info in AI_IMPORT_PATTERNS.items():
                for pattern in sdk_info['patterns']:
                    if re.search(pattern, content, re.IGNORECASE):
                        provider = sdk_info['provider']
                        if provider not in findings:
                            findings[provider] = {
                                'files': [],
                                'endpoints': set(),
                                'has_secrets': False,
                                'secret_types': set(),
                                'confidence': sdk_info['confidence'],
                            }
                        rel_path = str(file_path.relative_to(path))
                        if rel_path not in findings[provider]['files']:
                            findings[provider]['files'].append(rel_path)
                        break  # One match per SDK per file is enough

            # Check for endpoints
            for ep_pattern in ENDPOINT_PATTERNS:
                for match in re.finditer(ep_pattern, content):
                    endpoint = match.group(1) if match.lastindex else match.group(0)
                    # Try to attribute to a provider
                    for provider_key in findings:
                        findings[provider_key]['endpoints'].add(endpoint)

            # Check for secrets (flag but don't extract)
            for secret_name, secret_pattern in SECRET_PATTERNS.items():
                if re.search(secret_pattern, content):
                    provider_guess = secret_name.split('_')[0]
                    for provider_key in findings:
                        if provider_guess in provider_key:
                            findings[provider_key]['has_secrets'] = True
                            findings[provider_key]['secret_types'].add(secret_name)

        # Convert findings to agent dicts
        agents = []
        for provider, data in findings.items():
            endpoint = next(iter(data['endpoints']), None)
            agents.append({
                'id': str(uuid.uuid4()),
                'name': f"Code AI Integration: {provider}",
                'provider': provider,
                'endpoint': endpoint,
                'discovery_method': 'code_scan',
                'confidence': data['confidence'],
                'metadata': {
                    'repo_path': str(path),
                    'files_with_usage': data['files'][:20],  # Cap for report size
                    'total_files_with_usage': len(data['files']),
                    'endpoints_found': list(data['endpoints'])[:10],
                    'has_hardcoded_secrets': data['has_secrets'],
                    'secret_types': list(data['secret_types']),
                    'files_scanned': files_scanned,
                }
            })

        self.logger.info(
            f"Code scan complete: {len(agents)} AI integrations found "
            f"across {files_scanned} files"
        )
        return agents

    def _walk_files(self, root: Path):
        """Yield scannable files, skipping known non-relevant directories."""
        for dirpath, dirnames, filenames in os.walk(root):
            # Prune skipped directories in-place
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]

            for fname in filenames:
                fpath = Path(dirpath) / fname
                # Check extension or known dotfiles
                if fpath.suffix in SCANNABLE_EXTENSIONS or fpath.name in ('.env', '.env.local', '.env.production'):
                    # Skip very large files (>1MB)
                    try:
                        if fpath.stat().st_size <= 1_048_576:
                            yield fpath
                    except OSError:
                        continue

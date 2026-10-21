"""Bounded, read-only network observations with conservative protocol identity."""

import asyncio
import errno
import ipaddress
import json
import logging
import math
import re
import uuid
from contextvars import ContextVar
from datetime import datetime
from typing import Any, Dict, List

import aiohttp
import dns.asyncresolver
import dns.exception
import dns.resolver

from src.core.transport import SafeSession, ScanBudget, TransportPolicyError, current_budget
from src.core.scope import local_host_addresses


MAX_BODY_BYTES = 10_000
MAX_JSON_DEPTH = 32
MAX_DNS_ADDRESSES = 32
MAX_TCP_CONNECTIONS = 50
_tcp_slots = ContextVar('network_tcp_slots', default=None)


def _text(value):
    return isinstance(value, str) and bool(value.strip())


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate JSON key')
        result[key] = value
    return result


def _reject_constant(value):
    raise ValueError('Non-finite JSON value')


def _finite_float(value):
    number = float(value)
    if not math.isfinite(number):
        raise ValueError('Non-finite JSON value')
    return number


def _bounded_json_depth(document):
    # Container depth is explicit, not dependent on a Python parser's recursion.
    pending = [(document, 1)]
    while pending:
        value, depth = pending.pop()
        if not isinstance(value, (dict, list)):
            continue
        if depth > MAX_JSON_DEPTH:
            return False
        children = value.values() if isinstance(value, dict) else value
        pending.extend((child, depth + 1) for child in children if isinstance(child, (dict, list)))
    return True


class NetworkScanner:
    """Observe advertised protocols, not vendor ownership or exploitability."""

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.common_ai_ports = [80, 443, 8000, 8080, 8443, 9000, 11434, 3000, 5000, 8888]
        self.timeout = 10

    def _failure(self, operation):
        # Exceptions and response content can contain secrets.
        self.logger.warning('Network discovery incomplete: %s', operation)
        budget = current_budget()
        if budget is not None:
            budget.failures += 1

    async def scan_range(self, network_range: str, ai_signatures: Dict) -> List[Dict[str, Any]]:
        network = ipaddress.ip_network(network_range, strict=False)
        if network.num_addresses > 1024:
            raise ValueError('Network range exceeds maximum of 1024 addresses')
        semaphore = asyncio.Semaphore(50)
        token = _tcp_slots.set(asyncio.Semaphore(MAX_TCP_CONNECTIONS))
        try:
            results = await asyncio.gather(*(
                self._scan_host(str(host), ai_signatures, semaphore) for host in network.hosts()
            ), return_exceptions=True)
        finally:
            _tcp_slots.reset(token)
        agents = []
        for result in results:
            if isinstance(result, asyncio.CancelledError):
                raise result
            if isinstance(result, list):
                agents.extend(result)
            else:
                self._failure('host scan')
        return agents

    async def scan_domain(self, domain: str, ai_signatures: Dict) -> List[Dict[str, Any]]:
        # Only the explicitly requested name is scanned. HTTP Host/SNI keeps it.
        try:
            domain = self._hostname(domain)
        except (ValueError, UnicodeError):
            self._failure('invalid domain')
            return []
        ips = await self._resolve_domain(domain)
        if not ips:
            return []
        agents = []
        semaphore = asyncio.Semaphore(MAX_TCP_CONNECTIONS)

        async def probe(ip, port):
            async with semaphore:
                return port, await self._is_port_open(ip, port)

        observations = await asyncio.gather(*(probe(ip, port) for ip in ips for port in self.common_ai_ports))
        open_ports = {port for port, opened in observations if opened}
        for port in self.common_ai_ports:
            if port in open_ports:
                agents.extend(await self._identify_ai_service(domain, port, ai_signatures))
        for agent in agents:
            agent['domain'] = domain
        return agents

    async def _scan_host(self, host: str, ai_signatures: Dict,
                         semaphore: asyncio.Semaphore = None) -> List[Dict[str, Any]]:
        if semaphore:
            async with semaphore:
                return await self._do_scan_host(host, ai_signatures)
        return await self._do_scan_host(host, ai_signatures)

    async def _do_scan_host(self, host: str, ai_signatures: Dict,
                            authority=None) -> List[Dict[str, Any]]:
        agents = []
        semaphore = _tcp_slots.get() or asyncio.Semaphore(MAX_TCP_CONNECTIONS)

        async def probe(port):
            async with semaphore:
                return await self._is_port_open(host, port)

        open_ports = await asyncio.gather(*(probe(port) for port in self.common_ai_ports))
        for port, is_open in zip(self.common_ai_ports, open_ports):
            if is_open:
                agents.extend(await self._identify_ai_service(authority or host, port, ai_signatures))
        return agents

    async def _is_port_open(self, host: str, port: int) -> bool:
        budget = current_budget() or ScanBudget()
        if budget:
            try:
                address = ipaddress.ip_address(host)
                budget.check_address(address)
                authority = f'[{host}]' if address.version == 6 else host
                budget.reserve(f'http://{authority}:{port}')
            except (ValueError, TransportPolicyError):
                budget.rejections += 1
                self.logger.warning('Network discovery policy rejected TCP probe')
                return False
        writer = None
        try:
            _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), self.timeout)
            return True
        except ConnectionRefusedError:
            return False
        except (TimeoutError, asyncio.TimeoutError):
            # Filtered ports and unused addresses are expected during discovery.
            self.logger.debug('Discovery TCP port did not respond')
            return False
        except OSError as error:
            if error.errno not in {errno.ECONNREFUSED, errno.EHOSTUNREACH, errno.ENETUNREACH}:
                self._failure('TCP probe')
            return False
        except Exception:
            self._failure('TCP probe')
            return False
        finally:
            if writer is not None:
                writer.close()
                try:
                    await asyncio.wait_for(writer.wait_closed(), self.timeout)
                except (OSError, TimeoutError, asyncio.TimeoutError):
                    pass

    async def _identify_ai_service(self, host: str, port: int,
                                    ai_signatures: Dict) -> List[Dict[str, Any]]:
        # Defaults probe TLS on TLS ports and HTTP elsewhere. Do not double-probe
        # with an intentionally wrong protocol or mask failures through fallback.
        scheme = 'https' if port in (443, 8443) else 'http'
        authority = f'[{host}]' if ':' in host else host
        base_url = f'{scheme}://{authority}:{port}'
        routes = {}
        for provider, signature in ai_signatures.items():
            if not self._supported_signature(signature):
                continue
            for path in signature.get('paths', []):
                if (not isinstance(path, str) or not path.startswith('/') or path.startswith('//')
                        or any(character in path for character in ('?', '#', '@', '\\'))):
                    self._failure('invalid discovery path')
                    continue
                routes.setdefault(path, []).append((provider, signature))
        agents = []
        model_sets = {}
        async with SafeSession(timeout=aiohttp.ClientTimeout(total=self.timeout)) as session:
            for path, signatures in routes.items():
                try:
                    async with session.get(base_url + path, discovery=not agents) as response:
                        document = await self._read_document(response, [signature for _, signature in signatures],
                                                             established=bool(agents))
                        if document is None:
                            continue
                        for provider, signature in signatures:
                            if self._matches_document(document, signature):
                                detected = ('openai-compatible' if provider in
                                            {'openai', 'vllm', 'openai-compatible'} else provider)
                                endpoint = base_url + path
                                asset = self._asset(host, port, scheme, endpoint, detected, response.status)
                                agents.append(asset)
                                models = (model['name'] for model in document['models']) if detected == 'ollama' else (
                                    model['id'] for model in document['data']) if detected == 'openai-compatible' else ()
                                model_sets[asset['id']] = frozenset(models)
                                break
                except TransportPolicyError:
                    # SafeSession already records policy rejections.
                    break
                except (aiohttp.ClientError, TimeoutError, asyncio.TimeoutError):
                    # SafeSession already records failed I/O. Keep earlier assets.
                    continue
        # Native Ollama also advertises an OpenAI-compatible inventory. Collapse
        # only identical nonempty model sets on this same authority, never a
        # colocated gateway exposing different models or a different provider.
        native = {model_sets[asset['id']] for asset in agents if asset['provider'] == 'ollama'}
        return [asset for asset in agents if not (
            asset['provider'] == 'openai-compatible' and model_sets[asset['id']] in native)]

    def _asset(self, host, port, scheme, endpoint, provider, status):
        metadata = {'host': host, 'port': port, 'scheme': scheme,
                    'response_status': status, 'evidence_status': 'protocol_observation'}
        exposure = self._is_internet_facing(host)
        if exposure is not None:
            metadata['internet_facing'] = exposure
        return {'id': str(uuid.uuid5(uuid.NAMESPACE_URL, 'network:' + endpoint + ':' + provider)),
                'name': f'{provider} service on {host}:{port}', 'provider': provider,
                'endpoint': endpoint, 'discovery_method': 'network_scan', 'confidence': 0.8,
                'metadata': metadata}

    async def _read_document(self, response, signatures=(), established=False):
        if response.status != 200:
            if response.status >= 500 or response.status in (408, 429):
                self._failure('HTTP service error')
            return None
        body = bytearray()
        async for chunk in response.content.iter_chunked(4096):
            if len(body) + len(chunk) > MAX_BODY_BYTES:
                # A bounded HTML/text landing page is not an incomplete AI
                # inventory. Keep indeterminate/JSON truncation conservative.
                prefix = (body + chunk).lstrip()[:1]
                content_type = response.headers.get('Content-Type', '').split(';')[0].lower()
                if established or (prefix != b'<' and content_type not in ('text/html', 'text/plain')):
                    self._failure('inventory body limit')
                return None
            body.extend(chunk)
        try:
            document = json.loads(body, object_pairs_hook=_unique_object,
                                  parse_constant=_reject_constant, parse_float=_finite_float)
        except (ValueError, UnicodeDecodeError, RecursionError):
            # HTML/prose is a normal non-AI service; truncated JSON is incomplete.
            if body.lstrip().startswith((b'{', b'[')):
                self._failure('malformed inventory JSON')
            return None
        if not _bounded_json_depth(document):
            self._failure('inventory JSON depth limit')
            return None
        if isinstance(document, dict) and 'error' in document:
            if established:
                self._failure('inventory error document')
            return None
        if isinstance(document, dict) and self._invalid_inventory(document, signatures):
            # Generic object:list APIs (for example payment APIs) are not AI
            # evidence. A native discriminator or prior inventory is required.
            native_claim = document.get('router') == 'text-generation-router' or (
                isinstance(document.get('models'), list) and any(
                    isinstance(model, dict) and 'modified_at' in model for model in document['models']))
            if established or native_claim:
                self._failure('invalid inventory schema')
            return None
        return document if isinstance(document, dict) else None

    async def _is_ai_service(self, response: aiohttp.ClientResponse, signature: Dict) -> bool:
        document = await self._read_document(response, [signature])
        return document is not None and self._matches_document(document, signature)

    @staticmethod
    def _supported_signature(signature):
        return bool({'modified_at', 'choices', 'model_id'} & set(signature.get('response_patterns', [])))

    @staticmethod
    def _matches_document(document, signature):
        patterns = set(signature.get('response_patterns', []))
        if 'modified_at' in patterns:
            models = document.get('models')
            return isinstance(models, list) and bool(models) and all(
                isinstance(model, dict) and _text(model.get('name')) and NetworkScanner._timestamp(model.get('modified_at'))
                for model in models)
        if 'choices' in patterns:
            models = document.get('data')
            if document.get('object') == 'list' and isinstance(models, list) and models:
                return all(isinstance(model, dict) and model.get('object') == 'model'
                           and _text(model.get('id')) for model in models)
            return False
        if 'model_id' in patterns:
            # Current TGI renamed this field; retain the documented older schema
            # only when the current field is absent. Self-reported router identity
            # is protocol evidence, not proof of vendor ownership.
            limit = document.get('max_input_tokens') if 'max_input_tokens' in document else document.get('max_input_length')
            return (document.get('router') == 'text-generation-router' and _text(document.get('version'))
                    and _text(document.get('model_id')) and type(limit) is int and limit > 0)
        return False

    @staticmethod
    def _timestamp(value):
        if not _text(value) or not re.fullmatch(
                r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})', value):
            return False
        try:
            datetime.fromisoformat(value.replace('Z', '+00:00'))
        except ValueError:
            return False
        return True

    @staticmethod
    def _invalid_inventory(document, signatures):
        # Empty typed inventories are clean negatives, not identifying evidence.
        if any(NetworkScanner._matches_document(document, signature) for signature in signatures):
            return False
        for signature in signatures:
            patterns = set(signature.get('response_patterns', []))
            if 'modified_at' in patterns and 'models' in document:
                models = document['models']
                if not isinstance(models, list) or models:
                    return True
            if 'choices' in patterns and document.get('object') == 'list':
                models = document.get('data')
                if not isinstance(models, list) or models:
                    return True
            if 'model_id' in patterns and document.get('router') == 'text-generation-router':
                return True
        return False

    async def _resolve_domain(self, domain: str) -> List[str]:
        ips = []
        try:
            domain = self._hostname(domain)
            resolver = dns.asyncresolver.Resolver()
            budget = current_budget() or ScanBudget()
            local = local_host_addresses(domain)
            if local:
                for address in local:
                    if budget:
                        budget.check_address(address)
                return local
            for record_type in ('A', 'AAAA'):
                if budget:
                    budget.reserve('http://' + domain)
                try:
                    answers = await asyncio.wait_for(
                        resolver.resolve(domain, record_type, lifetime=self.timeout), self.timeout)
                except dns.resolver.NoAnswer:
                    continue
                for answer in answers:
                    address = ipaddress.ip_address(str(answer))
                    if budget:
                        budget.check_address(address)
                    if str(address) not in ips:
                        if len(ips) >= MAX_DNS_ADDRESSES:
                            self._failure('DNS address limit')
                            return []
                        ips.append(str(address))
            if not ips:
                self._failure('DNS has no address')
        except TransportPolicyError:
            if current_budget():
                current_budget().rejections += 1
            return []
        except (dns.exception.DNSException, TimeoutError, asyncio.TimeoutError, ValueError, UnicodeError):
            self._failure('DNS resolution')
            return []
        return ips

    @staticmethod
    def _hostname(domain):
        if not isinstance(domain, str) or not domain or len(domain) > 253:
            raise ValueError('Invalid hostname')
        name = domain.encode('idna').decode('ascii').lower().rstrip('.')
        if not name or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label)
                           for label in name.split('.')):
            raise ValueError('Invalid hostname')
        return name

    def _is_internet_facing(self, host: str) -> bool:
        try:
            return ipaddress.ip_address(host).is_global
        except ValueError:
            # A DNS name is not proof of global exposure. HTTP resolves separately
            # from TCP eligibility, so do not invent peer-specific exposure.
            return None

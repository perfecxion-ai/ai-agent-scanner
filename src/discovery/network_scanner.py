"""Bounded, read-only network observations with conservative protocol identity."""

import asyncio
import errno
import ipaddress
import json
import logging
import re
import uuid
from contextvars import ContextVar
from datetime import datetime
from typing import Any, Dict, List

import aiohttp
import dns.asyncresolver
import dns.exception
import dns.resolver

from src.core.transport import SafeSession, TransportPolicyError, current_budget


MAX_BODY_BYTES = 10_000
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
        budget = current_budget()
        if budget:
            try:
                address = ipaddress.ip_address(host)
                budget.check_address(address)
                authority = f'[{host}]' if address.version == 6 else host
                budget.reserve(f'http://{authority}:{port}')
            except (ValueError, TransportPolicyError):
                budget.rejections += 1
                return False
        writer = None
        try:
            _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), self.timeout)
            return True
        except ConnectionRefusedError:
            return False
        except (TimeoutError, asyncio.TimeoutError):
            self._failure('TCP timeout')
            return False
        except OSError as error:
            if error.errno not in {errno.ECONNREFUSED}:
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
        async with SafeSession(timeout=aiohttp.ClientTimeout(total=self.timeout)) as session:
            for path, signatures in routes.items():
                try:
                    async with session.get(base_url + path) as response:
                        document = await self._read_document(response)
                        if document is None:
                            continue
                        for provider, signature in signatures:
                            if self._matches_document(document, signature):
                                detected = ('openai-compatible' if provider in
                                            {'openai', 'vllm', 'openai-compatible'} else provider)
                                endpoint = base_url + path
                                agents.append(self._asset(host, port, scheme, endpoint, detected, response.status))
                                break
                except TransportPolicyError:
                    # SafeSession already records policy rejections.
                    break
                except (aiohttp.ClientError, TimeoutError, asyncio.TimeoutError):
                    # SafeSession already records failed I/O. Keep earlier assets.
                    continue
        return agents

    def _asset(self, host, port, scheme, endpoint, provider, status):
        return {'id': str(uuid.uuid5(uuid.NAMESPACE_URL, 'network:' + endpoint + ':' + provider)),
                'name': f'{provider} service on {host}:{port}', 'provider': provider,
                'endpoint': endpoint, 'discovery_method': 'network_scan', 'confidence': 0.8,
                'metadata': {'host': host, 'port': port, 'scheme': scheme,
                             'response_status': status, 'internet_facing': self._is_internet_facing(host),
                             'evidence_status': 'protocol_observation'}}

    async def _read_document(self, response):
        if response.status != 200:
            if response.status >= 500 or response.status in (408, 429):
                self._failure('HTTP service error')
            return None
        body = bytearray()
        async for chunk in response.content.iter_chunked(4096):
            if len(body) + len(chunk) > MAX_BODY_BYTES:
                self._failure('inventory body limit')
                return None
            body.extend(chunk)
        try:
            document = json.loads(body, object_pairs_hook=_unique_object, parse_constant=_reject_constant)
        except (ValueError, UnicodeDecodeError, RecursionError):
            # HTML/prose is a normal non-AI service; truncated JSON is incomplete.
            if body.lstrip().startswith((b'{', b'[')):
                self._failure('malformed inventory JSON')
            return None
        if isinstance(document, dict) and 'error' in document:
            self._failure('inventory error document')
            return None
        if isinstance(document, dict) and self._invalid_inventory(document):
            self._failure('invalid inventory schema')
            return None
        return document if isinstance(document, dict) else None

    async def _is_ai_service(self, response: aiohttp.ClientResponse, signature: Dict) -> bool:
        document = await self._read_document(response)
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
            return (_text(document.get('model_id')) and type(document.get('max_input_length')) is int
                    and document['max_input_length'] > 0)
        return False

    @staticmethod
    def _timestamp(value):
        if not _text(value):
            return False
        try:
            datetime.fromisoformat(value.replace('Z', '+00:00'))
        except ValueError:
            return False
        return True

    @staticmethod
    def _invalid_inventory(document):
        # Empty typed inventories are clean negatives, not identifying evidence.
        if 'models' in document:
            models = document['models']
            return not isinstance(models, list) or bool(models) and not NetworkScanner._matches_document(
                document, {'response_patterns': ['modified_at']})
        if document.get('object') == 'list':
            models = document.get('data')
            return not isinstance(models, list) or bool(models) and not NetworkScanner._matches_document(
                document, {'response_patterns': ['choices']})
        if 'model_id' in document:
            return not NetworkScanner._matches_document(document, {'response_patterns': ['model_id']})
        return False

    async def _resolve_domain(self, domain: str) -> List[str]:
        ips = []
        try:
            domain = self._hostname(domain)
            resolver = dns.asyncresolver.Resolver()
            budget = current_budget()
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
            return True

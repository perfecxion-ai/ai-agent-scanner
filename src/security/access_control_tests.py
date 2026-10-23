#!/usr/bin/env python3
"""
Access Control and Authentication Security Testing Module

This module implements comprehensive testing for access control vulnerabilities
in AI agents and their supporting infrastructure. It tests for authentication
bypass, weak credentials, authorization flaws, and session management issues.

Author: Scott Thornton
Created: 2024
License: Private - All rights reserved

Security Focus: DEFENSIVE ONLY
This tool helps organizations identify authentication and authorization
vulnerabilities in their AI systems for remediation purposes.
"""

import asyncio
from src.core.transport import SafeSession, model_request_timeout
import logging
import base64
import json
import re
from http.cookies import SimpleCookie, CookieError
from typing import List, Dict, Any, Optional
from urllib.parse import urljoin, urlsplit
import uuid
from datetime import datetime, timezone
from src.core.contracts import checked, has_canary, record_interaction, usable_model_response
from src.core.access_probe_policy import (
    ACCESS_CONTROL_STATUS, DEFAULT_SENSITIVE_PATHS, DEFAULT_TEST_API_KEYS,
    DEFAULT_WEAK_CREDENTIALS, PROTECTED_ACCESS_PATHS, PROTECTED_CONTROL_VERSION, PUBLIC_ACCESS_FIELDS,
    access_probe_definition,
)
from src.core.redaction import contains_literal
from src.utils.request_builder import construct_agent_request, resolve_api_key
from yarl import URL


_CONTROL_MARKER = re.compile(r'[A-Za-z0-9_.~-]{16,128}\Z')


def _valid_access_marker(marker):
    return (isinstance(marker, str) and _CONTROL_MARKER.fullmatch(marker) is not None
            and not any(marker.casefold() in descriptor
                        for descriptor in PUBLIC_ACCESS_FIELDS))


def _issued_credential_prerequisite(agent):
    if not agent.get('api_key_env') or not resolve_api_key(agent):
        return "An explicit environment reference to an issued credential is required"
    return None


def _authentication_prerequisite(agent):
    if agent.get('authentication_required') is not True or not has_canary(agent, 'protected_response_marker'):
        return "A protected response marker and explicit authentication requirement are required"
    if not _valid_access_marker(agent['protected_response_marker']):
        return "Protected access markers require 16 to 128 opaque ASCII characters distinct from public descriptors"
    return _issued_credential_prerequisite(agent)


def _authorization_prerequisite(agent):
    markers = agent.get('protected_path_markers', {})
    paths = PROTECTED_ACCESS_PATHS
    if not isinstance(markers, dict) or not any(has_canary(markers, path) for path in paths):
        return "Protected admin-path markers are required"
    if any(path in markers and not _valid_access_marker(markers[path]) for path in paths):
        return "Protected access markers require 16 to 128 opaque ASCII characters distinct from public descriptors"
    return _issued_credential_prerequisite(agent)


def _protected_headers(headers):
    """Make automatic client header material explicit for reflection checks."""
    return {'User-Agent': 'ai-agent-scanner', 'Accept': '*/*',
            'Accept-Encoding': 'identity', **headers}


def _request_material(url, headers):
    """Include wire and common reflected forms, including the automatic Host."""
    host = url.raw_host
    if ':' in host:
        host = '[' + host + ']'
    hosts = [host, f'{host}:{url.port}'] if url.port is not None else [host]
    material = []
    for authority in hosts:
        complete = {'Host': authority, **headers}
        material.extend([complete, json.dumps(complete), str(complete),
                         'GET ' + url.raw_path_qs + ' HTTP/1.1\r\n'
                         + '\r\n'.join(f'{name}: {value}' for name, value in complete.items())])
    return material

class AccessControlTester:
    """
    Comprehensive access control and authentication security testing for AI agents.
    
    This class tests for various authentication and authorization vulnerabilities:
    - Authentication bypass techniques
    - Weak credential testing
    - API key security assessment
    - Authorization boundary testing
    - Rate limiting evaluation
    - Session management security
    
    The tester uses respectful testing practices with built-in delays and
    limits to avoid overwhelming target systems.
    """
    
    def __init__(self):
        """
        Initialize the access control tester.
        
        Sets up logging, HTTP client configuration, and test data including
        common weak credentials, test API keys, and rate limiting parameters.
        """
        # Set up logging for audit trails and debugging
        self.logger = logging.getLogger(__name__)
        
        # Common weak credentials used in credential stuffing attacks
        # These are typical default/weak combinations found in real systems
        self.weak_credentials = list(DEFAULT_WEAK_CREDENTIALS)
        
        # Common API key patterns for testing
        self.test_api_keys = list(DEFAULT_TEST_API_KEYS)
        
        # Rate limiting test patterns
        self.rate_limit_requests = 50  # Number of requests to test rate limiting
        self.sensitive_paths = list(DEFAULT_SENSITIVE_PATHS)
        
    async def test_agent(self, agent: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test agent for access control vulnerabilities"""
        vulnerabilities = []
        
        endpoint = agent.get('endpoint')
        if not endpoint:
            return []
        
        self.logger.info(f"Testing agent {agent.get('name', 'unknown')} for access control vulnerabilities")

        vulnerabilities.extend(await self._test_unauthenticated_inference(agent))
        
        # Test 1: Authentication bypass
        auth_vulns = await self._test_authentication_bypass(agent)
        vulnerabilities.extend(auth_vulns)
        
        # Test 2: Weak credentials
        cred_vulns = await self._test_weak_credentials(agent)
        vulnerabilities.extend(cred_vulns)
        
        # Test 3: API key security
        api_vulns = await self._test_api_key_security(agent)
        vulnerabilities.extend(api_vulns)
        
        # Test 4: Authorization bypass
        authz_vulns = await self._test_authorization_bypass(agent)
        vulnerabilities.extend(authz_vulns)
        
        # Test 5: Rate limiting
        rate_vulns = await self._test_rate_limiting(agent)
        vulnerabilities.extend(rate_vulns)
        
        # Test 6: Session management
        session_vulns = await self._test_session_management(agent)
        vulnerabilities.extend(session_vulns)
        
        return vulnerabilities

    @checked("unauthenticated_inference", "anonymous-model-call-v1",
             prerequisite=lambda agent: "Anonymous inference requires a query-free endpoint"
             if urlsplit(agent.get('endpoint', '')).query else None,
             absence_reason="No anonymous inference response observed; authorization policy is not established")
    async def _test_unauthenticated_inference(self, agent: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Observe open inference separately from proven access to protected data."""
        request = construct_agent_request(agent, "Reply with the word hello.")
        if request is None:
            return []
        # Explicitly omit every credential-bearing header, including auto-resolved keys.
        try:
            async with SafeSession(timeout=model_request_timeout()) as session:
                async with session.request(request['method'], request['url'],
                                           headers={'Content-Type': 'application/json'},
                                           json=request['json'], allow_redirects=False) as response:
                    text = await response.text()
                    if response.status in (401, 403):
                        record_interaction(True)
                        return []
                    usable = 200 <= response.status < 300 and usable_model_response(text)
                    record_interaction(usable)
                    if not usable:
                        return []
                    return [{
                        'id': str(uuid.uuid4()), 'agent_id': agent.get('id'),
                        'vulnerability_type': 'unauthenticated_inference', 'severity': 'info',
                        'evidence_status': 'heuristic', 'title': 'Anonymous Inference Observed',
                        'description': 'A model response was returned without scanner credentials. '
                                       'Review intended access policy; protected-resource access is not proven.',
                        'authentication_requirement_declared': agent.get('authentication_required') is True,
                        'status_code': response.status, 'confidence': 1.0,
                        'timestamp': datetime.now(timezone.utc).isoformat(),
                        'remediation': 'Review network exposure, authentication, and inference quotas.'
                    }]
        except Exception:
            record_interaction(False)
            self.logger.debug('Anonymous inference request failed')
            return []
    
    @checked("authentication_bypass", access_probe_definition('authentication_bypass'),
             prerequisite=_authentication_prerequisite, oracle=lambda agent: True)
    async def _test_authentication_bypass(self, agent: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for authentication bypass vulnerabilities"""
        vulnerabilities = []
        
        bypass_tests = [
            # No authentication
            {'headers': {}, 'name': 'No Authentication'},
            
            # Empty/malformed tokens
            {'headers': {'Authorization': ''}, 'name': 'Empty Authorization Header'},
            {'headers': {'Authorization': 'Bearer '}, 'name': 'Empty Bearer Token'},
            {'headers': {'Authorization': 'Bearer null'}, 'name': 'Null Bearer Token'},
            {'headers': {'Authorization': 'Bearer undefined'}, 'name': 'Undefined Bearer Token'},
            
            # Malformed authorization headers
            {'headers': {'Authorization': 'Basic '}, 'name': 'Empty Basic Auth'},
            {'headers': {'Authorization': 'Basic invalid'}, 'name': 'Invalid Basic Auth'},
            {'headers': {'Authorization': 'InvalidScheme token'}, 'name': 'Invalid Auth Scheme'},
            
            # SQL injection in auth headers
            {'headers': {'Authorization': "Bearer ' OR '1'='1"}, 'name': 'SQL Injection in Bearer Token'},
            {'headers': {'Authorization': "Basic ' OR '1'='1"}, 'name': 'SQL Injection in Basic Auth'},
            
            # API key bypass attempts
            {'headers': {'x-api-key': ''}, 'name': 'Empty API Key'},
            {'headers': {'x-api-key': 'null'}, 'name': 'Null API Key'},
            {'headers': {'api-key': ''}, 'name': 'Empty api-key Header'},
            
            # Common header injections
            {'headers': {'X-Forwarded-For': '127.0.0.1'}, 'name': 'X-Forwarded-For Bypass'},
            {'headers': {'X-Real-IP': '127.0.0.1'}, 'name': 'X-Real-IP Bypass'},
            {'headers': {'X-Originating-IP': '127.0.0.1'}, 'name': 'X-Originating-IP Bypass'},
            {'headers': {'X-Admin': 'true'}, 'name': 'X-Admin Header Injection'},
            {'headers': {'X-User-Role': 'admin'}, 'name': 'X-User-Role Header Injection'},
        ]

        if not await self._has_access_controls(
                agent, agent['endpoint'], agent['protected_response_marker'],
                [_protected_headers(test['headers']) for test in bypass_tests]):
            return []
        
        for test in bypass_tests:
            try:
                vuln = await self._test_auth_bypass_method(agent, test)
                if vuln:
                    vulnerabilities.append(vuln)
                
                await asyncio.sleep(0.5)  # Rate limiting
                
            except Exception:
                record_interaction(False)
                self.logger.debug("Auth bypass test failed")
                continue
        
        return vulnerabilities
    
    async def _test_auth_bypass_method(self, agent: Dict[str, Any], 
                                     test: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Probe one method after the group's fresh protected-resource controls."""
        
        async with SafeSession(timeout=model_request_timeout()) as session:
            endpoint = agent.get('endpoint')
            
            # Try the bypass method
            try:
                async with session.get(
                    endpoint,
                    headers=_protected_headers(test['headers']), allow_redirects=False
                ) as response:
                    
                    response_text = await response.text()
                    record_interaction(response.status in (401, 403) or 200 <= response.status < 300,
                                       response.status in (401, 403)
                                       and agent['protected_response_marker'] not in response_text)
                    
                    # Check if bypass was successful
                    if self._is_successful_bypass(response.status, response_text, agent.get('protected_response_marker')):
                        return {
                            'id': str(uuid.uuid4()),
                            'agent_id': agent.get('id'),
                            'vulnerability_type': 'authentication_bypass',
                            'severity': 'high',
                            'evidence_status': 'confirmed',
                            'control_status': ACCESS_CONTROL_STATUS,
                            'protected_control_version': PROTECTED_CONTROL_VERSION,
                            'title': f"Authentication Bypass - {test['name']}",
                            'description': f"Agent allows access without proper authentication using {test['name']}.",
                            'method': test['name'],
                            'headers_used': test['headers'],
                            'status_code': response.status,
                            'response_excerpt': '[RESPONSE_TEXT_OMITTED]',
                            'timestamp': datetime.now(timezone.utc).isoformat(),
                            'confidence': 0.9,
                            'remediation': "Implement proper authentication checks and validate all authorization headers."
                        }
                        
            except Exception:
                record_interaction(False)
                self.logger.debug("Bypass test failed")
                return None
        
        return None
    
    @checked("weak_credentials", lambda self: access_probe_definition('weak_credentials', sample=self.weak_credentials[:5]),
             prerequisite=_authentication_prerequisite, oracle=lambda agent: True)
    async def _test_weak_credentials(self, agent: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for weak or default credentials"""
        vulnerabilities = []
        endpoint = agent.get('endpoint')
        samples = self.weak_credentials[:5]
        if not samples:
            return []
        candidate_headers = [_protected_headers({'Authorization': 'Basic ' + base64.b64encode(
            f'{username}:{password}'.encode()).decode()}) for username, password in samples]
        if not await self._has_access_controls(
                agent, endpoint, agent['protected_response_marker'],
                candidate_headers + [f'{username}:{password}' for username, password in samples]):
            return []
        
        # Test basic authentication with common credentials
        for username, password in samples:
            try:
                credentials = base64.b64encode(f"{username}:{password}".encode()).decode()
                
                async with SafeSession(timeout=model_request_timeout()) as session:
                    async with session.get(
                        endpoint,
                        headers=_protected_headers({'Authorization': f'Basic {credentials}'}), allow_redirects=False
                    ) as response:
                        
                        text = await response.text()
                        record_interaction(response.status in (401, 403) or 200 <= response.status < 300,
                                           response.status in (401, 403)
                                           and agent['protected_response_marker'] not in text)
                        if self._is_successful_bypass(response.status, text, agent.get('protected_response_marker')):
                            vulnerabilities.append({
                                'id': str(uuid.uuid4()),
                                'agent_id': agent.get('id'),
                                'vulnerability_type': 'weak_credentials',
                                'severity': 'critical',
                                'evidence_status': 'confirmed',
                                'control_status': ACCESS_CONTROL_STATUS,
                                'protected_control_version': PROTECTED_CONTROL_VERSION,
                                'title': f"Weak Credentials - {username}:{password}",
                                'description': f"Agent accepts weak credentials: {username}:{password}",
                                'username': username,
                                'password': password,
                                'status_code': response.status,
                                'timestamp': datetime.now(timezone.utc).isoformat(),
                                'confidence': 0.95,
                                'remediation': "Change default credentials and enforce strong password policies."
                            })
                
                await asyncio.sleep(1)  # Rate limiting
                
            except Exception:
                record_interaction(False)
                self.logger.debug("Credential test failed")
                continue
        
        return vulnerabilities
    
    @checked("weak_api_key", lambda self: access_probe_definition('weak_api_key', sample=self.test_api_keys[:5]),
             prerequisite=_authentication_prerequisite, oracle=lambda agent: True)
    async def _test_api_key_security(self, agent: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test API key security implementation"""
        vulnerabilities = []
        endpoint = agent.get('endpoint')
        candidates = [_protected_headers(headers) for key in self.test_api_keys[:5]
                      for headers in self._api_key_headers(key)]
        if not candidates:
            return []
        if not await self._has_access_controls(
                agent, endpoint, agent['protected_response_marker'], candidates):
            return []
        
        # Test various API key weaknesses
        for api_key in self.test_api_keys[:5]:  # Test first 5
            try:
                # Test different API key header formats
                header_variations = self._api_key_headers(api_key)
                
                for headers in header_variations:
                    async with SafeSession(timeout=model_request_timeout()) as session:
                        async with session.get(endpoint, headers=_protected_headers(headers), allow_redirects=False) as response:
                            
                            text = await response.text()
                            record_interaction(response.status in (401, 403) or 200 <= response.status < 300,
                                               response.status in (401, 403)
                                               and agent['protected_response_marker'] not in text)
                            if self._is_successful_bypass(response.status, text, agent.get('protected_response_marker')):
                                vulnerabilities.append({
                                    'id': str(uuid.uuid4()),
                                    'agent_id': agent.get('id'),
                                    'vulnerability_type': 'weak_api_key',
                                    'severity': 'high',
                                    'evidence_status': 'confirmed',
                                    'control_status': ACCESS_CONTROL_STATUS,
                                    'protected_control_version': PROTECTED_CONTROL_VERSION,
                                    'title': f"Weak API Key Accepted - {api_key}",
                                    'description': f"Agent accepts weak/test API key: {api_key}",
                                    'api_key': api_key,
                                    'headers_used': headers,
                                    'status_code': response.status,
                                    'timestamp': datetime.now(timezone.utc).isoformat(),
                                    'confidence': 0.8,
                                    'remediation': "Implement strong API key validation and rotate default/test keys."
                                })
                                break  # Found working key, no need to test other header formats
                    
                    await asyncio.sleep(0.3)
                
            except Exception:
                record_interaction(False)
                self.logger.debug("API key test failed")
                continue
        
        return vulnerabilities

    @staticmethod
    def _api_key_headers(api_key):
        return [{'x-api-key': api_key}, {'api-key': api_key}, {'apikey': api_key},
                {'X-API-KEY': api_key}, {'Authorization': f'Bearer {api_key}'},
                {'Authorization': f'ApiKey {api_key}'}]
    
    @checked("authorization_bypass", lambda self: access_probe_definition('authorization_bypass', sample=self.sensitive_paths[:8]),
             prerequisite=_authorization_prerequisite,
             oracle=lambda agent: True,
             coverage=lambda self, agent: [path for path in self.sensitive_paths[:8]
                                           if has_canary(agent.get('protected_path_markers', {}), path)])
    async def _test_authorization_bypass(self, agent: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for authorization bypass vulnerabilities"""
        vulnerabilities = []
        endpoint = agent.get('endpoint')
        
        # Test path traversal and privilege escalation
        for path in self.sensitive_paths[:8]:
            marker = agent.get('protected_path_markers', {}).get(path)
            if not isinstance(marker, str) or len(marker) < 16:
                continue
            try:
                test_url = urljoin(endpoint.rstrip('/'), path)
                if not await self._has_access_controls(agent, test_url, marker, []):
                    continue
                
                async with SafeSession(timeout=model_request_timeout()) as session:
                    async with session.get(test_url, headers=_protected_headers({}), allow_redirects=False) as response:
                        
                        response_text = await response.text()
                        record_interaction(response.status in (401, 403) or 200 <= response.status < 300,
                                           response.status in (401, 403) and marker not in response_text)
                        
                        # Check for successful access to restricted areas
                        if self._is_admin_access(response.status, response_text, marker):
                            vulnerabilities.append({
                                'id': str(uuid.uuid4()),
                                'agent_id': agent.get('id'),
                                'vulnerability_type': 'authorization_bypass',
                                'severity': 'high',
                                'evidence_status': 'confirmed',
                                'control_status': ACCESS_CONTROL_STATUS,
                                'protected_control_version': PROTECTED_CONTROL_VERSION,
                                'title': "Authorization Bypass - Admin Access",
                                'description': f"Agent allows unauthorized access to admin functionality via {path}",
                                'path': path,
                                **({'protected_path_index': PROTECTED_ACCESS_PATHS.index(path)}
                                   if path in PROTECTED_ACCESS_PATHS else {}),
                                'full_url': test_url,
                                'status_code': response.status,
                                'response_excerpt': '[RESPONSE_TEXT_OMITTED]',
                                'timestamp': datetime.now(timezone.utc).isoformat(),
                                'confidence': 0.7,
                                'remediation': "Implement proper authorization checks for all admin endpoints."
                            })
                
                await asyncio.sleep(0.5)
                
            except Exception:
                record_interaction(False)
                self.logger.debug("Authorization bypass test failed")
                continue
        
        return vulnerabilities
    
    @checked("no_rate_limiting", lambda self: ["sample-only-v1", min(20, self.rate_limit_requests)])
    async def _test_rate_limiting(self, agent: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for rate limiting implementation"""
        vulnerabilities = []
        endpoint = agent.get('endpoint')
        
        try:
            # Send rapid requests to test rate limiting
            request_times = []
            status_codes = []
            
            async with SafeSession(timeout=model_request_timeout()) as session:
                for i in range(min(20, self.rate_limit_requests)):  # Test with 20 requests
                    start_time = datetime.now(timezone.utc)
                    
                    try:
                        async with session.get(endpoint) as response:
                            record_interaction(response.status in (401, 403, 429) or 200 <= response.status < 300)
                            status_codes.append(response.status)
                            request_times.append((datetime.now(timezone.utc) - start_time).total_seconds())
                    except Exception:
                        record_interaction(False)
                        break
                    
                    # Small delay to avoid connection limits
                    await asyncio.sleep(0.1)
            
            # Analyze results for rate limiting
            if len(status_codes) >= 10:
                # Check if any rate limiting occurred (429, 503, etc.)
                rate_limited = any(code in [429, 503, 502] for code in status_codes[-5:])
                
                if not rate_limited:
                    vulnerabilities.append({
                        'id': str(uuid.uuid4()),
                        'agent_id': agent.get('id'),
                        'vulnerability_type': 'no_rate_limiting',
                        'severity': 'info',
                        'evidence_status': 'heuristic',
                        'title': "Rate Limit Not Observed in Sample",
                        'description': f"No rate-limit response in {len(status_codes)} requests; policy and thresholds are unknown.",
                        'requests_sent': len(status_codes),
                        'successful_requests': sum(1 for code in status_codes if code == 200),
                        'avg_response_time': sum(request_times) / len(request_times) if request_times else 0,
                        'timestamp': datetime.now(timezone.utc).isoformat(),
                        'confidence': 0.6,
                        'remediation': "Implement rate limiting to prevent abuse and DoS attacks."
                    })
        
        except Exception:
            record_interaction(False)
            self.logger.debug("Rate limiting test failed")
        
        return vulnerabilities
    
    @checked("insecure_session_management", "cookie-attribute-observations-v1")
    async def _test_session_management(self, agent: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test session management security"""
        vulnerabilities = []
        endpoint = agent.get('endpoint')
        
        try:
            # Test session fixation and cookie security
            async with SafeSession(timeout=model_request_timeout()) as session:
                async with session.get(endpoint) as response:
                    record_interaction(response.status in (401, 403) or 200 <= response.status < 300)
                    
                    # Check cookie security attributes
                    if 'set-cookie' in response.headers:
                        cookies = response.headers.getall('set-cookie')
                        
                        for cookie in cookies:
                            parsed = SimpleCookie()
                            try:
                                parsed.load(cookie)
                            except CookieError:
                                continue
                            for name, morsel in parsed.items():
                                insecure_issues = []
                                if not morsel['secure']:
                                    insecure_issues.append('Missing Secure flag')
                                if not morsel['httponly']:
                                    insecure_issues.append('Missing HttpOnly flag')
                                if morsel['samesite'].lower() not in ('strict', 'lax', 'none'):
                                    insecure_issues.append('Missing or invalid SameSite attribute')
                                if not insecure_issues:
                                    continue
                                vulnerabilities.append({
                                    'id': str(uuid.uuid4()),
                                    'agent_id': agent.get('id'),
                                    'vulnerability_type': 'insecure_session_management',
                                    'severity': 'info',
                                    'evidence_status': 'heuristic',
                                    'title': "Cookie Attributes Require Review",
                                    'description': f"Cookie attributes require review; cookie purpose is unverified: {', '.join(insecure_issues)}",
                                    'cookie_name': name,
                                    'issues': insecure_issues,
                                    'timestamp': datetime.now(timezone.utc).isoformat(),
                                    'confidence': 0.5,
                                    'remediation': "Set Secure, HttpOnly, and SameSite attributes on session cookies."
                                })
        
        except Exception:
            record_interaction(False)
            self.logger.debug("Session management test failed")
        
        return vulnerabilities
    
    async def _has_access_controls(self, agent, endpoint, marker, probe_values) -> bool:
        """Verify the exact resource with issued and invalid credentials, without reuse."""
        try:
            # Only explicit credential references authorize a baseline. Provider
            # defaults must not silently send an operator credential to this GET.
            key = resolve_api_key(agent) if agent.get('api_key_env') else None
            url = URL(endpoint)
            if (not key or '\r' in key or '\n' in key
                    or not _valid_access_marker(marker)
                    or url.scheme not in ('http', 'https') or not url.host
                    or url.user is not None or url.query_string or url.fragment
                    or '%' in endpoint):
                record_interaction(False)
                return False
            provider = str(agent.get('provider', '')).lower()
            header = ('x-api-key' if provider == 'anthropic' else
                      'x-goog-api-key' if provider in ('google', 'gemini') else 'Authorization')
            headers = _protected_headers({header: 'Bearer ' + key if header == 'Authorization' else key})
            invalid_headers = _protected_headers({header: ('Bearer ' if header == 'Authorization' else '')
                                                 + 'scanner-invalid-' + str(uuid.uuid4())})
            public_agent = {name: value for name, value in agent.items()
                            if name not in ('protected_response_marker', 'protected_path_markers',
                                            'system_prompt_canary', 'cross_tenant_canary')}
            probe_material = [material for value in probe_values if isinstance(value, dict)
                              for material in _request_material(url, value)]
            material = [endpoint, str(url), public_agent, _request_material(url, headers),
                        _request_material(url, invalid_headers), probe_values, probe_material]
            if (contains_literal(material, marker)
                    or marker.casefold() in json.dumps(material).casefold()):
                record_interaction(False)
                return False

            async with SafeSession(timeout=model_request_timeout()) as session:
                async with session.get(endpoint, headers=headers, allow_redirects=False) as response:
                    text = await response.text()
                    authorized = self._is_successful_bypass(response.status, text, marker)
                    record_interaction(authorized, authorized)
                    if not authorized:
                        return False

            # A separate session prevents an issued cookie from authorizing the
            # denied control or subsequent anonymous/invalid-credential probes.
            async with SafeSession(timeout=model_request_timeout()) as session:
                async with session.get(endpoint, headers=invalid_headers, allow_redirects=False) as response:
                    text = await response.text()
                    denied = response.status in (401, 403) and marker not in text
                    record_interaction(denied, denied)
                    return denied
        except Exception:
            record_interaction(False)
            return False

    def _is_successful_bypass(self, status_code: int, response_text: str, marker: Optional[str] = None) -> bool:
        """A successful status alone cannot establish access to protected data."""
        return bool(200 <= status_code < 300 and isinstance(marker, str) and len(marker) >= 16 and marker in response_text)
    
    def _is_admin_access(self, status_code: int, response_text: str, marker: Optional[str] = None) -> bool:
        """Require configured evidence of protected admin data."""
        return self._is_successful_bypass(status_code, response_text, marker)

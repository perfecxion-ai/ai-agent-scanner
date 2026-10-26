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
from contextlib import asynccontextmanager
from functools import wraps
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
from src.core.contracts import (
    AccessObservation, CheckpointError, begin_access_controls, checked, ensure_evidence_active,
    has_canary, observe_access_response, record_interaction, usable_model_response,
)
from src.core.access_probe_policy import (
    ACCESS_CONTROL_STATUS, DEFAULT_SENSITIVE_PATHS, DEFAULT_TEST_API_KEYS,
    DEFAULT_WEAK_CREDENTIALS, PROTECTED_ACCESS_PATHS, PROTECTED_CONTROL_VERSION, PUBLIC_ACCESS_FIELDS,
    access_probe_definition,
)
from src.core.redaction import contains_literal
from src.core.access_evidence import (
    access_evidence_context, access_evidence_usable, get_access_evidence, verify_access_response,
)
from src.core.request_provenance import MAX_HEADER_COUNT, MAX_REQUEST_HEADERS, _strings
from src.utils.request_builder import construct_agent_request
from yarl import URL


_CONTROL_MARKER = re.compile(r'[A-Za-z0-9_.~-]{16,128}\Z')
_JSON_MARKS = re.compile(r'["\\\[\]{}]')


def _valid_access_marker(marker):
    return (isinstance(marker, str) and _CONTROL_MARKER.fullmatch(marker) is not None
            and not any(marker.casefold() in descriptor
                        for descriptor in PUBLIC_ACCESS_FIELDS))


def _issued_credential_prerequisite(agent):
    context = get_access_evidence(agent)
    if not agent.get('api_key_env') or context is None or not context.issued_key:
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


def _with_access_evidence(method):
    @wraps(method)
    async def wrapped(self, agent, *args, **kwargs):
        with access_evidence_context([agent]):
            return await method(self, agent, *args, **kwargs)
    return wrapped


def _denied_without_marker(response, text, marker):
    """A denial cannot prove absence when its bounded material discloses a marker."""
    if response.status not in (401, 403):
        return False
    try:
        if not isinstance(response.body, bytes):
            return False
        text = response.body.decode('utf-8-sig')
        if '\x00' in text or '\ufeff' in text or marker.casefold() in text.casefold():
            return False
        headers = tuple(response.headers.items())
        if (len(headers) > MAX_HEADER_COUNT
                or any(not isinstance(value, str) for pair in headers for value in pair)
                or sum(len(value.encode()) for pair in headers for value in pair) > MAX_REQUEST_HEADERS
                or any(marker.casefold() in value.casefold() for pair in headers for value in pair)):
            return False
        if text.lstrip().startswith(('{', '[', '"')):
            depth, quoted, escaped_at = 0, False, -1
            for match in _JSON_MARKS.finditer(text):
                position, mark = match.start(), match.group()
                if quoted:
                    if position == escaped_at:
                        escaped_at = -1
                        continue
                    escaped_at = position + 1 if mark == '\\' else -1
                    if mark == '"':
                        quoted = False
                elif mark == '"':
                    quoted = True
                elif mark in '[{':
                    depth += 1
                    if depth > 16:
                        return False
                elif mark in ']}':
                    depth -= 1
                    if depth < 0:
                        return False
                else:
                    return False
            if depth or quoted:
                return False
            def unique(pairs):
                value = {}
                for key, item in pairs:
                    if key in value:
                        raise ValueError('Ambiguous denial response')
                    value[key] = item
                return value
            def constant(value):
                raise ValueError('Invalid denial response')
            decoded = json.loads(text, object_pairs_hook=unique, parse_constant=constant)
            if any('\x00' in value or '\ufeff' in value or marker.casefold() in value.casefold()
                   for value in _strings(decoded)):
                return False
        return True
    except (TypeError, ValueError, KeyError, AttributeError, UnicodeError, OverflowError, RecursionError):
        return False


@asynccontextmanager
async def _protected_response(endpoint, headers):
    """Secondary cleanup errors cannot replace fatal evidence delivery failures."""
    interrupted = None
    try:
        ensure_evidence_active()
        async with SafeSession(timeout=model_request_timeout()) as session:
            try:
                async with session.get(endpoint, headers=headers, allow_redirects=False) as response:
                    try:
                        ensure_evidence_active()
                        yield response
                        ensure_evidence_active()
                    except (asyncio.CancelledError, CheckpointError) as error:
                        interrupted = error
                        raise
            except (asyncio.CancelledError, CheckpointError) as error:
                interrupted = error
                raise
        ensure_evidence_active()
    except BaseException:
        if interrupted is not None:
            raise interrupted
        ensure_evidence_active()
        raise


async def _access_observation(response, agent, *, modern, phase='probe', **indices):
    observed = await observe_access_response(response, agent=agent, phase=phase, **indices)
    ensure_evidence_active()
    if observed is None and not modern:
        return None
    if not isinstance(observed, AccessObservation) or not modern:
        raise CheckpointError()
    return observed


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
        
        self.logger.info('Testing access controls')

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
    
    @_with_access_evidence
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

        controls = await self._has_access_controls(
                agent, agent['endpoint'], agent['protected_response_marker'],
                [_protected_headers(test['headers']) for test in bypass_tests])
        if not controls:
            return []
        modern = isinstance(controls, AccessObservation)
        
        for sample_index, test in enumerate(bypass_tests):
            ensure_evidence_active()
            if not access_evidence_usable(agent):
                break
            try:
                vuln = await self._test_auth_bypass_method(agent, test, sample_index=sample_index, modern=modern)
                if vuln:
                    vulnerabilities.append(vuln)
                
                await asyncio.sleep(0.5)  # Rate limiting
                
            except CheckpointError:
                raise
            except Exception:
                ensure_evidence_active()
                record_interaction(False)
                self.logger.debug("Auth bypass test failed")
                continue
            ensure_evidence_active()
        
        return vulnerabilities
    
    async def _test_auth_bypass_method(self, agent: Dict[str, Any], 
                                     test: Dict[str, Any], *, sample_index=None, modern=False) -> Optional[Dict[str, Any]]:
        """Probe one method after the group's fresh protected-resource controls."""
        
        endpoint = agent.get('endpoint')
        retained = None
        try:
            headers = _protected_headers(test['headers'])
            async with _protected_response(endpoint, headers) as response:
                response_text = await response.text()
                observed = await _access_observation(response, agent, modern=modern, sample_index=sample_index)
                if isinstance(observed, AccessObservation):
                    retained = observed.findings[0] if observed.findings else None
                    return retained
                proven = verify_access_response(response, agent=agent, endpoint=endpoint, headers=headers)
                record_interaction(proven and (response.status in (401, 403) or 200 <= response.status < 300),
                                   proven and _denied_without_marker(response, response_text, agent['protected_response_marker']))
                if proven and self._is_successful_bypass(response.status, response_text, agent.get('protected_response_marker')):
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
                        
        except CheckpointError:
            raise
        except Exception:
            ensure_evidence_active()
            record_interaction(False)
            self.logger.debug("Bypass test failed")
            return retained
        
        return None
    
    @_with_access_evidence
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
        controls = await self._has_access_controls(
                agent, endpoint, agent['protected_response_marker'],
                candidate_headers + [f'{username}:{password}' for username, password in samples])
        if not controls:
            return []
        modern = isinstance(controls, AccessObservation)
        
        # Test basic authentication with common credentials
        for sample_index, (username, password) in enumerate(samples):
            ensure_evidence_active()
            if not access_evidence_usable(agent):
                break
            try:
                credentials = base64.b64encode(f"{username}:{password}".encode()).decode()
                
                headers = _protected_headers({'Authorization': f'Basic {credentials}'})
                async with _protected_response(endpoint, headers) as response:
                        
                        text = await response.text()
                        observed = await _access_observation(response, agent, modern=modern, sample_index=sample_index)
                        if isinstance(observed, AccessObservation):
                            vulnerabilities.extend(observed.findings)
                        proven = (verify_access_response(response, agent=agent, endpoint=endpoint, headers=headers)
                                  if observed is None else False)
                        if observed is None:
                            record_interaction(proven and (response.status in (401, 403) or 200 <= response.status < 300),
                                               proven and _denied_without_marker(response, text, agent['protected_response_marker']))
                        if observed is None and proven and self._is_successful_bypass(response.status, text, agent.get('protected_response_marker')):
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
                
            except CheckpointError:
                raise
            except Exception:
                ensure_evidence_active()
                record_interaction(False)
                self.logger.debug("Credential test failed")
                continue
            ensure_evidence_active()
        
        return vulnerabilities
    
    @_with_access_evidence
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
        controls = await self._has_access_controls(agent, endpoint, agent['protected_response_marker'], candidates)
        if not controls:
            return []
        modern = isinstance(controls, AccessObservation)
        
        # Test various API key weaknesses
        for sample_index, api_key in enumerate(self.test_api_keys[:5]):  # Test first 5
            ensure_evidence_active()
            if not access_evidence_usable(agent):
                break
            try:
                # Test different API key header formats
                header_variations = self._api_key_headers(api_key)
                
                for header_index, headers in enumerate(header_variations):
                    ensure_evidence_active()
                    if not access_evidence_usable(agent):
                        break
                    selected_headers = _protected_headers(headers)
                    async with _protected_response(endpoint, selected_headers) as response:
                            
                            text = await response.text()
                            observed = await _access_observation(response, agent, modern=modern,
                                                                 sample_index=sample_index, header_index=header_index)
                            if isinstance(observed, AccessObservation):
                                vulnerabilities.extend(observed.findings)
                                if observed.findings:
                                    break
                            proven = (verify_access_response(response, agent=agent, endpoint=endpoint, headers=selected_headers)
                                      if observed is None else False)
                            if observed is None:
                                record_interaction(proven and (response.status in (401, 403) or 200 <= response.status < 300),
                                                   proven and _denied_without_marker(response, text, agent['protected_response_marker']))
                            if observed is None and proven and self._is_successful_bypass(response.status, text, agent.get('protected_response_marker')):
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
                
            except CheckpointError:
                raise
            except Exception:
                ensure_evidence_active()
                record_interaction(False)
                self.logger.debug("API key test failed")
                continue
            ensure_evidence_active()
        
        return vulnerabilities

    @staticmethod
    def _api_key_headers(api_key):
        return [{'x-api-key': api_key}, {'api-key': api_key}, {'apikey': api_key},
                {'X-API-KEY': api_key}, {'Authorization': f'Bearer {api_key}'},
                {'Authorization': f'ApiKey {api_key}'}]
    
    @_with_access_evidence
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
            ensure_evidence_active()
            if not access_evidence_usable(agent):
                break
            marker = agent.get('protected_path_markers', {}).get(path)
            if not isinstance(marker, str) or len(marker) < 16:
                continue
            try:
                test_url = urljoin(endpoint.rstrip('/'), path)
                path_index = PROTECTED_ACCESS_PATHS.index(path) if path in PROTECTED_ACCESS_PATHS else None
                controls = await self._has_access_controls(agent, test_url, marker, [],
                                                          protected_path_index=path_index)
                if not controls:
                    continue
                modern = isinstance(controls, AccessObservation)
                
                headers = _protected_headers({})
                async with _protected_response(test_url, headers) as response:
                        
                        response_text = await response.text()
                        observed = await _access_observation(response, agent, modern=modern,
                                                             protected_path_index=path_index)
                        if isinstance(observed, AccessObservation):
                            vulnerabilities.extend(observed.findings)
                        proven = (verify_access_response(response, agent=agent, endpoint=test_url, headers=headers)
                                  if observed is None else False)
                        if observed is None:
                            record_interaction(proven and (response.status in (401, 403) or 200 <= response.status < 300),
                                               proven and _denied_without_marker(response, response_text, marker))
                        
                        # Check for successful access to restricted areas
                        if observed is None and proven and self._is_admin_access(response.status, response_text, marker):
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
                
            except CheckpointError:
                raise
            except Exception:
                ensure_evidence_active()
                record_interaction(False)
                self.logger.debug("Authorization bypass test failed")
                continue
            ensure_evidence_active()
        
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
    
    async def _has_access_controls(self, agent, endpoint, marker, probe_values, *, protected_path_index=None):
        """Verify the exact resource with issued and invalid credentials, without reuse."""
        try:
            ensure_evidence_active()
            public_agent = {name: value for name, value in agent.items()
                            if name not in ('protected_response_marker', 'protected_path_markers',
                                            'system_prompt_canary', 'cross_tenant_canary')}
            if (contains_literal(public_agent, marker)
                    or marker.casefold() in json.dumps(public_agent).casefold()):
                record_interaction(False)
                return False
            plan = begin_access_controls(agent, protected_path_index=protected_path_index)
            if plan is not None:
                if plan.endpoint != str(URL(endpoint)):
                    raise CheckpointError()
                for phase, headers in (('authorized_control', plan.authorized_headers),
                                       ('denied_control', plan.denied_headers)):
                    async with _protected_response(plan.endpoint, dict(headers)) as response:
                        await response.text()
                        observed = await _access_observation(response, agent, modern=True, phase=phase,
                                                             protected_path_index=protected_path_index)
                        if not observed.valid:
                            return False
                return observed
            # Only explicit credential references authorize a baseline. Provider
            # defaults must not silently send an operator credential to this GET.
            context = get_access_evidence(agent)
            key = context.issued_key if context is not None else None
            url = URL(endpoint)
            if (not key or not access_evidence_usable(agent) or '\r' in key or '\n' in key
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

            async with _protected_response(endpoint, headers) as response:
                    text = await response.text()
                    authorized = (verify_access_response(response, agent=agent, endpoint=endpoint, headers=headers)
                                  and self._is_successful_bypass(response.status, text, marker))
                    record_interaction(authorized, authorized)
                    if not authorized:
                        return False

            # A separate session prevents an issued cookie from authorizing the
            # denied control or subsequent anonymous/invalid-credential probes.
            async with _protected_response(endpoint, invalid_headers) as response:
                    text = await response.text()
                    denied = (verify_access_response(response, agent=agent, endpoint=endpoint, headers=invalid_headers)
                              and _denied_without_marker(response, text, marker))
                    record_interaction(denied, denied)
                    return denied
        except CheckpointError:
            raise
        except Exception:
            ensure_evidence_active()
            record_interaction(False)
            return False

    def _is_successful_bypass(self, status_code: int, response_text: str, marker: Optional[str] = None) -> bool:
        """A successful status alone cannot establish access to protected data."""
        return bool(200 <= status_code < 300 and isinstance(marker, str) and len(marker) >= 16 and marker in response_text)
    
    def _is_admin_access(self, status_code: int, response_text: str, marker: Optional[str] = None) -> bool:
        """Require configured evidence of protected admin data."""
        return self._is_successful_bypass(status_code, response_text, marker)

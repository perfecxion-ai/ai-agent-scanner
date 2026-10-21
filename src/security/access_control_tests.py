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
import aiohttp
from src.core.transport import SafeSession
import logging
import base64
from http.cookies import SimpleCookie, CookieError
from typing import List, Dict, Any, Optional
from urllib.parse import urljoin, urlsplit
import uuid
from datetime import datetime, timezone
from src.core.contracts import checked, has_canary, record_interaction, usable_model_response
from src.utils.request_builder import construct_agent_request


def _authentication_prerequisite(agent):
    if agent.get('authentication_required') is not True or not has_canary(agent, 'protected_response_marker'):
        return "A protected response marker and explicit authentication requirement are required"
    return None

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
        
        # Configure HTTP client timeout (30 seconds prevents hanging)
        self.session_timeout = aiohttp.ClientTimeout(total=30)
        
        # Common weak credentials used in credential stuffing attacks
        # These are typical default/weak combinations found in real systems
        self.weak_credentials = [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('admin', '123456'),
            ('admin', ''),
            ('test', 'test'),
            ('user', 'user'),
            ('guest', 'guest'),
            ('api', 'api'),
            ('demo', 'demo'),
            ('root', 'root')
        ]
        
        # Common API key patterns for testing
        self.test_api_keys = [
            'test-key',
            'demo-key',
            'dev-key',
            'api-key',
            '123456789',
            'sk-1234567890abcdef',
            'Bearer test',
            'test_key_123',
            'development',
            'staging'
        ]
        
        # Rate limiting test patterns
        self.rate_limit_requests = 50  # Number of requests to test rate limiting
        self.sensitive_paths = [
            '/admin', '/admin/', '/administrator', '/api/admin', '/api/v1/admin',
            '/admin/users', '/admin/config', '/system', '/debug', '/internal',
            '/../admin', '/./admin', '/%2e%2e/admin', '/admin%00', '/admin.php', '/admin.json',
        ]
        
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
            async with SafeSession(timeout=self.session_timeout) as session:
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
    
    @checked("authentication_bypass", "18-header-variations-denied-control-v1",
             prerequisite=_authentication_prerequisite, oracle=lambda agent: True)
    async def _test_authentication_bypass(self, agent: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for authentication bypass vulnerabilities"""
        vulnerabilities = []
        agent.get('endpoint')
        
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
        
        for test in bypass_tests:
            try:
                vuln = await self._test_auth_bypass_method(agent, test)
                if vuln:
                    vulnerabilities.append(vuln)
                
                await asyncio.sleep(0.5)  # Rate limiting
                
            except Exception:
                self.logger.debug("Auth bypass test failed")
                continue
        
        return vulnerabilities
    
    async def _test_auth_bypass_method(self, agent: Dict[str, Any], 
                                     test: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Test a specific authentication bypass method"""
        if not await self._has_denied_control(agent):
            return None
        
        async with SafeSession(timeout=self.session_timeout) as session:
            endpoint = agent.get('endpoint')
            
            # Try the bypass method
            try:
                async with session.get(
                    endpoint,
                    headers=test['headers'], allow_redirects=False
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
                            'control_status': 'invalid_credential_denied',
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
    
    @checked("weak_credentials", lambda self: self.weak_credentials[:5],
             prerequisite=_authentication_prerequisite, oracle=lambda agent: True)
    async def _test_weak_credentials(self, agent: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for weak or default credentials"""
        vulnerabilities = []
        endpoint = agent.get('endpoint')
        if not await self._has_denied_control(agent):
            return []
        
        # Test basic authentication with common credentials
        for username, password in self.weak_credentials[:5]:  # Test first 5 to avoid overwhelming
            try:
                credentials = base64.b64encode(f"{username}:{password}".encode()).decode()
                
                async with SafeSession(timeout=self.session_timeout) as session:
                    async with session.get(
                        endpoint,
                        headers={'Authorization': f'Basic {credentials}'}, allow_redirects=False
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
                                'control_status': 'invalid_credential_denied',
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
    
    @checked("weak_api_key", lambda self: [self.test_api_keys[:5], "six-header-variations-v1"],
             prerequisite=_authentication_prerequisite, oracle=lambda agent: True)
    async def _test_api_key_security(self, agent: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test API key security implementation"""
        vulnerabilities = []
        endpoint = agent.get('endpoint')
        if not await self._has_denied_control(agent):
            return []
        
        # Test various API key weaknesses
        for api_key in self.test_api_keys[:5]:  # Test first 5
            try:
                # Test different API key header formats
                header_variations = [
                    {'x-api-key': api_key},
                    {'api-key': api_key},
                    {'apikey': api_key},
                    {'X-API-KEY': api_key},
                    {'Authorization': f'Bearer {api_key}'},
                    {'Authorization': f'ApiKey {api_key}'}
                ]
                
                for headers in header_variations:
                    async with SafeSession(timeout=self.session_timeout) as session:
                        async with session.get(endpoint, headers=headers, allow_redirects=False) as response:
                            
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
                                    'control_status': 'invalid_credential_denied',
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
    
    @checked("authorization_bypass", lambda self: ["admin-path-sample-v1", self.sensitive_paths[:8]],
             prerequisite=lambda agent: None if any(
                 has_canary(agent.get('protected_path_markers', {}), path)
                 for path in ('/admin', '/admin/', '/administrator', '/api/admin',
                              '/api/v1/admin', '/admin/users', '/admin/config', '/system'))
             else "Protected admin-path markers are required",
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
                
                async with SafeSession(timeout=self.session_timeout) as session:
                    async with session.get(test_url, allow_redirects=False) as response:
                        
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
                                'title': "Authorization Bypass - Admin Access",
                                'description': f"Agent allows unauthorized access to admin functionality via {path}",
                                'path': path,
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
            
            async with SafeSession(timeout=self.session_timeout) as session:
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
            async with SafeSession(timeout=self.session_timeout) as session:
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
    
    async def _has_denied_control(self, agent: Dict[str, Any]) -> bool:
        """Require an explicit private resource and a rejected random credential."""
        marker = agent.get('protected_response_marker')
        if agent.get('authentication_required') is not True or not isinstance(marker, str) or len(marker) < 16:
            return False
        try:
            async with SafeSession(timeout=self.session_timeout) as session:
                async with session.get(agent['endpoint'], headers={'Authorization': f'Bearer scanner-invalid-{uuid.uuid4()}'}, allow_redirects=False) as response:
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

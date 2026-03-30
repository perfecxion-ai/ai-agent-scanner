#!/usr/bin/env python3
"""
Access Control and Authentication Security Testing Module

This module implements comprehensive testing for access control vulnerabilities
in AI agents and their supporting infrastructure. It tests for authentication
bypass, weak credentials, authorization flaws, and session management issues.

Author: scthornton
Created: 2024
License: Private - All rights reserved

Security Focus: DEFENSIVE ONLY
This tool helps organizations identify authentication and authorization
vulnerabilities in their AI systems for remediation purposes.
"""

import asyncio
import aiohttp
import logging
import base64
from typing import List, Dict, Any, Optional
from urllib.parse import urljoin
import uuid
from datetime import datetime, timezone

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
        
    async def test_agent(self, agent: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test agent for access control vulnerabilities"""
        vulnerabilities = []
        
        endpoint = agent.get('endpoint')
        if not endpoint:
            return []
        
        self.logger.info(f"Testing agent {agent.get('name', 'unknown')} for access control vulnerabilities")
        
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
                
            except Exception as e:
                self.logger.debug(f"Auth bypass test failed: {str(e)}")
                continue
        
        return vulnerabilities
    
    async def _test_auth_bypass_method(self, agent: Dict[str, Any], 
                                     test: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Test a specific authentication bypass method"""
        
        async with aiohttp.ClientSession(timeout=self.session_timeout) as session:
            endpoint = agent.get('endpoint')
            
            # Try the bypass method
            try:
                async with session.get(
                    endpoint,
                    headers=test['headers']
                ) as response:
                    
                    response_text = await response.text()
                    
                    # Check if bypass was successful
                    if self._is_successful_bypass(response.status, response_text):
                        return {
                            'id': str(uuid.uuid4()),
                            'agent_id': agent.get('id'),
                            'vulnerability_type': 'authentication_bypass',
                            'severity': 'high',
                            'title': f"Authentication Bypass - {test['name']}",
                            'description': f"Agent allows access without proper authentication using {test['name']}.",
                            'method': test['name'],
                            'headers_used': test['headers'],
                            'status_code': response.status,
                            'response_excerpt': response_text[:300],
                            'timestamp': datetime.now(timezone.utc).isoformat(),
                            'confidence': 0.9,
                            'remediation': "Implement proper authentication checks and validate all authorization headers."
                        }
                        
            except Exception as e:
                self.logger.debug(f"Bypass test failed: {str(e)}")
                return None
        
        return None
    
    async def _test_weak_credentials(self, agent: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for weak or default credentials"""
        vulnerabilities = []
        endpoint = agent.get('endpoint')
        
        # Test basic authentication with common credentials
        for username, password in self.weak_credentials[:5]:  # Test first 5 to avoid overwhelming
            try:
                credentials = base64.b64encode(f"{username}:{password}".encode()).decode()
                
                async with aiohttp.ClientSession(timeout=self.session_timeout) as session:
                    async with session.get(
                        endpoint,
                        headers={'Authorization': f'Basic {credentials}'}
                    ) as response:
                        
                        if response.status == 200:
                            vulnerabilities.append({
                                'id': str(uuid.uuid4()),
                                'agent_id': agent.get('id'),
                                'vulnerability_type': 'weak_credentials',
                                'severity': 'critical',
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
                
            except Exception as e:
                self.logger.debug(f"Credential test failed: {str(e)}")
                continue
        
        return vulnerabilities
    
    async def _test_api_key_security(self, agent: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test API key security implementation"""
        vulnerabilities = []
        endpoint = agent.get('endpoint')
        
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
                    async with aiohttp.ClientSession(timeout=self.session_timeout) as session:
                        async with session.get(endpoint, headers=headers) as response:
                            
                            if response.status == 200:
                                vulnerabilities.append({
                                    'id': str(uuid.uuid4()),
                                    'agent_id': agent.get('id'),
                                    'vulnerability_type': 'weak_api_key',
                                    'severity': 'high',
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
                
            except Exception as e:
                self.logger.debug(f"API key test failed: {str(e)}")
                continue
        
        return vulnerabilities
    
    async def _test_authorization_bypass(self, agent: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for authorization bypass vulnerabilities"""
        vulnerabilities = []
        endpoint = agent.get('endpoint')
        
        # Test path traversal and privilege escalation
        bypass_paths = [
            '/admin',
            '/admin/',
            '/administrator',
            '/api/admin',
            '/api/v1/admin',
            '/admin/users',
            '/admin/config',
            '/system',
            '/debug',
            '/internal',
            '/../admin',
            '/./admin',
            '/%2e%2e/admin',
            '/admin%00',
            '/admin.php',
            '/admin.json'
        ]
        
        for path in bypass_paths[:8]:  # Test first 8 paths
            try:
                test_url = urljoin(endpoint.rstrip('/'), path)
                
                async with aiohttp.ClientSession(timeout=self.session_timeout) as session:
                    async with session.get(test_url) as response:
                        
                        response_text = await response.text()
                        
                        # Check for successful access to restricted areas
                        if self._is_admin_access(response.status, response_text):
                            vulnerabilities.append({
                                'id': str(uuid.uuid4()),
                                'agent_id': agent.get('id'),
                                'vulnerability_type': 'authorization_bypass',
                                'severity': 'high',
                                'title': "Authorization Bypass - Admin Access",
                                'description': f"Agent allows unauthorized access to admin functionality via {path}",
                                'path': path,
                                'full_url': test_url,
                                'status_code': response.status,
                                'response_excerpt': response_text[:300],
                                'timestamp': datetime.now(timezone.utc).isoformat(),
                                'confidence': 0.7,
                                'remediation': "Implement proper authorization checks for all admin endpoints."
                            })
                
                await asyncio.sleep(0.5)
                
            except Exception as e:
                self.logger.debug(f"Authorization bypass test failed: {str(e)}")
                continue
        
        return vulnerabilities
    
    async def _test_rate_limiting(self, agent: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for rate limiting implementation"""
        vulnerabilities = []
        endpoint = agent.get('endpoint')
        
        try:
            # Send rapid requests to test rate limiting
            request_times = []
            status_codes = []
            
            async with aiohttp.ClientSession(timeout=self.session_timeout) as session:
                for i in range(min(20, self.rate_limit_requests)):  # Test with 20 requests
                    start_time = datetime.now(timezone.utc)
                    
                    try:
                        async with session.get(endpoint) as response:
                            status_codes.append(response.status)
                            request_times.append((datetime.now(timezone.utc) - start_time).total_seconds())
                    except Exception:
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
                        'severity': 'medium',
                        'title': "No Rate Limiting Detected",
                        'description': f"Agent accepts {len(status_codes)} rapid requests without rate limiting",
                        'requests_sent': len(status_codes),
                        'successful_requests': sum(1 for code in status_codes if code == 200),
                        'avg_response_time': sum(request_times) / len(request_times) if request_times else 0,
                        'timestamp': datetime.now(timezone.utc).isoformat(),
                        'confidence': 0.6,
                        'remediation': "Implement rate limiting to prevent abuse and DoS attacks."
                    })
        
        except Exception as e:
            self.logger.debug(f"Rate limiting test failed: {str(e)}")
        
        return vulnerabilities
    
    async def _test_session_management(self, agent: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test session management security"""
        vulnerabilities = []
        endpoint = agent.get('endpoint')
        
        try:
            # Test session fixation and cookie security
            async with aiohttp.ClientSession(timeout=self.session_timeout) as session:
                async with session.get(endpoint) as response:
                    
                    # Check cookie security attributes
                    if 'set-cookie' in response.headers:
                        cookies = response.headers.getall('set-cookie')
                        
                        for cookie in cookies:
                            insecure_issues = []
                            
                            if 'secure' not in cookie.lower():
                                insecure_issues.append('Missing Secure flag')
                            if 'httponly' not in cookie.lower():
                                insecure_issues.append('Missing HttpOnly flag')
                            if 'samesite' not in cookie.lower():
                                insecure_issues.append('Missing SameSite attribute')
                            
                            if insecure_issues:
                                vulnerabilities.append({
                                    'id': str(uuid.uuid4()),
                                    'agent_id': agent.get('id'),
                                    'vulnerability_type': 'insecure_session_management',
                                    'severity': 'medium',
                                    'title': "Insecure Session Cookie",
                                    'description': f"Session cookie lacks security attributes: {', '.join(insecure_issues)}",
                                    'cookie': cookie,
                                    'issues': insecure_issues,
                                    'timestamp': datetime.now(timezone.utc).isoformat(),
                                    'confidence': 0.8,
                                    'remediation': "Set Secure, HttpOnly, and SameSite attributes on session cookies."
                                })
        
        except Exception as e:
            self.logger.debug(f"Session management test failed: {str(e)}")
        
        return vulnerabilities
    
    def _is_successful_bypass(self, status_code: int, response_text: str) -> bool:
        """Check if authentication bypass was successful"""
        if status_code == 200:
            # Look for indicators of successful access
            success_indicators = [
                'welcome', 'dashboard', 'admin', 'settings', 'config',
                'users', 'api', 'data', 'success', 'authenticated'
            ]
            
            response_lower = response_text.lower()
            return any(indicator in response_lower for indicator in success_indicators)
        
        return False
    
    def _is_admin_access(self, status_code: int, response_text: str) -> bool:
        """Check if admin access was obtained"""
        if status_code == 200:
            admin_indicators = [
                'admin', 'administrator', 'control panel', 'dashboard',
                'users', 'settings', 'configuration', 'system',
                'manage', 'delete', 'create user', 'permissions'
            ]
            
            response_lower = response_text.lower()
            return any(indicator in response_lower for indicator in admin_indicators)
        
        return False

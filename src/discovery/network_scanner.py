import asyncio
import aiohttp
from src.core.transport import SafeSession, current_budget, TransportPolicyError
from typing import List, Dict, Any
import ipaddress
import dns.resolver
import logging
import json

class NetworkScanner:
    """Network-based discovery of AI agents"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.common_ai_ports = [80, 443, 8000, 8080, 8443, 9000, 11434, 3000, 5000, 8888]
        self.timeout = 10
    
    async def scan_range(self, network_range: str, ai_signatures: Dict) -> List[Dict[str, Any]]:
        """Scan a network range for AI services"""
        agents = []
        
        try:
            network = ipaddress.ip_network(network_range, strict=False)
            
            # Limit scan size for safety
            if network.num_addresses > 1024:
                raise ValueError("Network range exceeds maximum of 1024 addresses")
            else:
                hosts = list(network.hosts())
            
            # Scan hosts concurrently
            semaphore = asyncio.Semaphore(50)  # Limit concurrent scans
            tasks = [
                self._scan_host(str(host), ai_signatures, semaphore)
                for host in hosts
            ]
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in results:
                if isinstance(result, list):
                    agents.extend(result)
        
        except ValueError:
            raise
        except Exception as e:
            self.logger.error(f"Error scanning network range {network_range}: {e}")
        
        return agents
    
    async def scan_domain(self, domain: str, ai_signatures: Dict) -> List[Dict[str, Any]]:
        """Scan a domain for AI services"""
        agents = []
        
        try:
            # Resolve domain to IPs
            ips = await self._resolve_domain(domain)
            
            # Scan each IP
            for ip in ips:
                host_agents = await self._scan_host(ip, ai_signatures)
                for agent in host_agents:
                    agent['domain'] = domain
                agents.extend(host_agents)
            
            # Also try common AI service subdomains
            common_subdomains = ['api', 'ai', 'ml', 'bot', 'chat', 'assistant']
            for subdomain in common_subdomains:
                subdomain_host = f"{subdomain}.{domain}"
                try:
                    subdomain_ips = await self._resolve_domain(subdomain_host)
                    for ip in subdomain_ips:
                        host_agents = await self._scan_host(ip, ai_signatures)
                        for agent in host_agents:
                            agent['domain'] = subdomain_host
                        agents.extend(host_agents)
                except Exception:
                    continue
        
        except Exception as e:
            self.logger.error(f"Error scanning domain {domain}: {e}")
        
        return agents
    
    async def _scan_host(self, host: str, ai_signatures: Dict, 
                        semaphore: asyncio.Semaphore = None) -> List[Dict[str, Any]]:
        """Scan a single host for AI services"""
        
        if semaphore:
            async with semaphore:
                return await self._do_scan_host(host, ai_signatures)
        else:
            return await self._do_scan_host(host, ai_signatures)
    
    async def _do_scan_host(self, host: str, ai_signatures: Dict) -> List[Dict[str, Any]]:
        """Actually perform the host scan"""
        agents = []
        
        # Scan common ports
        open_ports = await asyncio.gather(*(
            self._is_port_open(host, port) for port in self.common_ai_ports
        ))
        for port, is_open in zip(self.common_ai_ports, open_ports):
            if is_open:
                # Check for AI services on this port
                service_agents = await self._identify_ai_service(host, port, ai_signatures)
                agents.extend(service_agents)
        
        return agents
    
    async def _is_port_open(self, host: str, port: int) -> bool:
        """Check if a port is open on the host"""
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
        try:
            # Use asyncio to create connection with timeout
            future = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(future, timeout=self.timeout)
            writer.close()
            await writer.wait_closed()
            return True
        except Exception:
            return False
    
    async def _identify_ai_service(self, host: str, port: int, 
                                 ai_signatures: Dict) -> List[Dict[str, Any]]:
        """Identify if the service is an AI endpoint"""
        agents = []
        
        # Try HTTP and HTTPS
        schemes = ['https', 'http'] if port in [443, 8443] else ['http', 'https']
        
        for scheme in schemes:
            try:
                authority = f"[{host}]" if ':' in host else host
                base_url = f"{scheme}://{authority}:{port}"
                
                async with SafeSession(timeout=aiohttp.ClientTimeout(total=self.timeout)) as session:
                    # Check common AI API paths
                    for provider, signature in ai_signatures.items():
                        for path in signature.get('paths', ['/']):
                            url = f"{base_url}{path}"
                            
                            try:
                                async with session.get(url, allow_redirects=False) as response:
                                    # Analyze response for AI service indicators
                                    if await self._is_ai_service(response, signature):
                                        agent = {
                                            'id': f"{host}:{port}:{provider}",
                                            'name': f"{provider.title()} Service on {host}:{port}",
                                            'provider': provider,
                                            'endpoint': url,
                                            'discovery_method': 'network_scan',
                                            'confidence': 0.8,
                                            'metadata': {
                                                'host': host,
                                                'port': port,
                                                'scheme': scheme,
                                                'response_status': response.status,
                                                'internet_facing': self._is_internet_facing(host)
                                            }
                                        }
                                        agents.append(agent)
                                        break
                            except Exception:
                                continue
                
                if agents:  # Found service, no need to try other schemes
                    break
                    
            except Exception:
                continue
        
        return agents
    
    async def _is_ai_service(self, response: aiohttp.ClientResponse, signature: Dict) -> bool:
        """Determine if the response indicates an AI service"""
        
        if response.status not in (200, 401, 403):
            return False
        # Generic authentication headers do not identify an AI provider.
        for header in signature.get('headers', []):
            if header.lower() in {'authorization', 'x-api-key', 'api-key'}:
                continue
            if header.lower() in response.headers:
                return True
        if response.status != 200:
            return False
        try:
            body = bytearray()
            async for chunk in response.content.iter_chunked(4096):
                body.extend(chunk)
                if len(body) > 10000:
                    return False
            document = json.loads(body)
        except (ValueError, UnicodeDecodeError, aiohttp.ClientError):
            return False
        if not isinstance(document, dict):
            return False
        patterns = set(signature.get('response_patterns', []))
        # Match protocol structures rather than words appearing in HTML or prose.
        if 'modified_at' in patterns:
            models = document.get('models')
            return isinstance(models, list) and all(
                isinstance(model, dict) and 'name' in model and 'modified_at' in model
                for model in models
            )
        if 'choices' in patterns:
            return (
                isinstance(document.get('choices'), list) and 'model' in document
                and 'usage' in document
            ) or (
                document.get('object') == 'list' and isinstance(document.get('data'), list)
                and all(isinstance(model, dict) and model.get('object') == 'model'
                        and 'id' in model for model in document['data'])
            )
        return len(patterns.intersection(document)) >= 2
    
    async def _resolve_domain(self, domain: str) -> List[str]:
        """Resolve domain to IP addresses"""
        ips = []
        try:
            answers = await asyncio.to_thread(dns.resolver.resolve, domain, 'A')
            ips = [str(rdata) for rdata in answers]
        except Exception:
            pass
        
        return ips
    
    def _is_internet_facing(self, host: str) -> bool:
        """Determine if host is internet-facing"""
        try:
            ip = ipaddress.ip_address(host)
            return ip.is_global
        except Exception:
            return True  # Assume domain names are internet-facing

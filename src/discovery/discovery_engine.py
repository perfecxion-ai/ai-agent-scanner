import asyncio
import logging
from typing import List, Dict, Any, Optional, Callable
from dataclasses import dataclass
import ipaddress
import socket
import ssl
import re
import aiohttp
import dns.resolver
from urllib.parse import urlparse

from .network_scanner import NetworkScanner
from .code_scanner import CodebaseScanner
from .cloud_scanner import CloudInfrastructureScanner
from .traffic_analyzer import TrafficAnalyzer

@dataclass
class DiscoveryScope:
    include_network: bool = True
    include_repositories: bool = False
    include_cloud: bool = False
    include_traffic: bool = False
    
    # Network scope
    network_ranges: List[str] = None
    domains: List[str] = None
    
    # Repository scope
    repositories: List[str] = None
    
    # Cloud scope
    cloud_accounts: Dict[str, Any] = None
    
    # Traffic scope
    traffic_sources: List[str] = None

@dataclass
class DiscoveredAgent:
    id: str
    name: str
    type: str
    provider: Optional[str]
    endpoint: Optional[str]
    discovery_method: str
    confidence: float
    metadata: Dict[str, Any]

class DiscoveryEngine:
    """Main engine for discovering AI agents across infrastructure"""
    
    def __init__(self):
        self.network_scanner = NetworkScanner()
        self.code_scanner = CodebaseScanner()
        self.cloud_scanner = CloudInfrastructureScanner()
        self.traffic_analyzer = TrafficAnalyzer()
        
        # AI service signatures for detection
        self.ai_signatures = self._load_ai_signatures()
        
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
    
    def _load_ai_signatures(self) -> Dict[str, Any]:
        """Load signatures for identifying AI services"""
        return {
            "openai": {
                "domains": ["api.openai.com", "openai.azure.com"],
                "headers": ["openai-organization", "openai-version"],
                "paths": ["/v1/chat/completions", "/v1/completions"],
                "response_patterns": ["model", "choices", "usage"]
            },
            "anthropic": {
                "domains": ["api.anthropic.com"],
                "headers": ["anthropic-version", "x-api-key"],
                "paths": ["/v1/messages", "/v1/complete"],
                "response_patterns": ["content", "model", "usage"]
            },
            "cohere": {
                "domains": ["api.cohere.ai"],
                "headers": ["authorization"],
                "paths": ["/v1/generate", "/v1/chat"],
                "response_patterns": ["generations", "text"]
            },
            "huggingface": {
                "domains": ["api-inference.huggingface.co"],
                "headers": ["authorization"],
                "paths": ["/models/"],
                "response_patterns": ["generated_text", "score"]
            }
        }
    
    async def discover_agents(self, scope: DiscoveryScope, 
                            ai_signatures: Dict[str, Any] = None,
                            progress_callback: Optional[Callable] = None) -> List[DiscoveredAgent]:
        """Main discovery method that orchestrates all discovery techniques"""
        
        # Use provided signatures or fallback to default
        signatures = ai_signatures or self.ai_signatures
        all_agents = []
        total_phases = sum([
            scope.include_network,
            scope.include_repositories, 
            scope.include_cloud,
            scope.include_traffic
        ])
        
        current_phase = 0
        
        # Phase 1: Network Discovery
        if scope.include_network:
            self.logger.info("Starting network discovery...")
            if progress_callback:
                await progress_callback((current_phase / total_phases) * 100)
            
            network_agents = await self._discover_network_agents(scope, signatures)
            all_agents.extend(network_agents)
            current_phase += 1
        
        # Phase 2: Code Repository Discovery
        if scope.include_repositories:
            self.logger.info("Starting repository discovery...")
            if progress_callback:
                await progress_callback((current_phase / total_phases) * 100)
            
            repo_agents = await self._discover_repository_agents(scope, signatures)
            all_agents.extend(repo_agents)
            current_phase += 1
        
        # Phase 3: Cloud Infrastructure Discovery
        if scope.include_cloud:
            self.logger.info("Starting cloud discovery...")
            if progress_callback:
                await progress_callback((current_phase / total_phases) * 100)
            
            cloud_agents = await self._discover_cloud_agents(scope, signatures)
            all_agents.extend(cloud_agents)
            current_phase += 1
        
        # Phase 4: Traffic Analysis
        if scope.include_traffic:
            self.logger.info("Starting traffic analysis...")
            if progress_callback:
                await progress_callback((current_phase / total_phases) * 100)
            
            traffic_agents = await self._discover_traffic_agents(scope, signatures)
            all_agents.extend(traffic_agents)
            current_phase += 1
        
        # Deduplicate and classify agents
        unique_agents = self._deduplicate_agents(all_agents)
        classified_agents = await self._classify_agents(unique_agents)
        
        # Convert to DiscoveredAgent objects
        discovered_agents = [self._dict_to_discovered_agent(agent) for agent in classified_agents]
        
        if progress_callback:
            await progress_callback(100)
        
        self.logger.info(f"Discovery complete. Found {len(discovered_agents)} unique AI agents")
        return discovered_agents
    
    async def _discover_network_agents(self, scope: DiscoveryScope, signatures: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Discover AI agents through network scanning"""
        agents = []
        
        # Scan specified network ranges
        if scope.network_ranges:
            for network_range in scope.network_ranges:
                range_agents = await self.network_scanner.scan_range(
                    network_range, signatures
                )
                agents.extend(range_agents)
        
        # Scan specified domains
        if scope.domains:
            for domain in scope.domains:
                domain_agents = await self.network_scanner.scan_domain(
                    domain, signatures
                )
                agents.extend(domain_agents)
        
        return agents
    
    async def _discover_repository_agents(self, scope: DiscoveryScope, signatures: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Discover AI agents through code repository analysis"""
        agents = []
        
        if scope.repositories:
            for repo_url in scope.repositories:
                repo_agents = await self.code_scanner.scan_repository(
                    repo_url, signatures
                )
                agents.extend(repo_agents)
        
        return agents
    
    async def _discover_cloud_agents(self, scope: DiscoveryScope, signatures: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Discover AI agents in cloud infrastructure"""
        agents = []
        
        if scope.cloud_accounts:
            for provider, config in scope.cloud_accounts.items():
                if provider == 'aws':
                    cloud_agents = await self.cloud_scanner.scan_aws(config)
                elif provider == 'azure':
                    cloud_agents = await self.cloud_scanner.scan_azure(config)
                elif provider == 'gcp':
                    cloud_agents = await self.cloud_scanner.scan_gcp(config)
                
                agents.extend(cloud_agents)
        
        return agents
    
    async def _discover_traffic_agents(self, scope: DiscoveryScope, signatures: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Discover AI agents through traffic analysis"""
        agents = []
        
        if scope.traffic_sources:
            for source in scope.traffic_sources:
                traffic_agents = await self.traffic_analyzer.analyze_traffic(
                    source, signatures
                )
                agents.extend(traffic_agents)
        
        return agents
    
    def _deduplicate_agents(self, agents: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove duplicate agents based on endpoint similarity"""
        seen_endpoints = set()
        unique_agents = []
        
        for agent in agents:
            endpoint = agent.get('endpoint', agent.get('name', ''))
            endpoint_key = self._normalize_endpoint(endpoint)
            
            if endpoint_key not in seen_endpoints:
                seen_endpoints.add(endpoint_key)
                unique_agents.append(agent)
            else:
                # Merge metadata from duplicate
                existing = next(a for a in unique_agents if self._normalize_endpoint(a.get('endpoint', a.get('name', ''))) == endpoint_key)
                existing['metadata'].update(agent.get('metadata', {}))
        
        return unique_agents
    
    def _normalize_endpoint(self, endpoint: str) -> str:
        """Normalize endpoint for deduplication"""
        if not endpoint:
            return ""
        
        # Parse URL and normalize
        try:
            parsed = urlparse(endpoint)
            return f"{parsed.hostname}:{parsed.port or 443}{parsed.path}"
        except:
            return endpoint.lower().strip()
    
    async def _classify_agents(self, agents: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Classify discovered agents by type and capability"""
        
        classified = []
        
        for agent in agents:
            agent_type = self._determine_agent_type(agent)
            capabilities = self._analyze_capabilities(agent)
            risk_factors = self._identify_risk_factors(agent)
            
            classified_agent = {
                **agent,
                'type': agent_type,
                'capabilities': capabilities,
                'risk_factors': risk_factors,
                'classification_confidence': self._calculate_classification_confidence(agent)
            }
            
            classified.append(classified_agent)
        
        return classified
    
    def _determine_agent_type(self, agent: Dict[str, Any]) -> str:
        """Determine the type of AI agent based on characteristics"""
        
        endpoint = agent.get('endpoint', '').lower()
        metadata = agent.get('metadata', {})
        
        # Check for specific patterns
        if any(pattern in endpoint for pattern in ['chat', 'conversation', 'bot']):
            return 'chatbot'
        elif any(pattern in endpoint for pattern in ['code', 'completion', 'generate']):
            return 'code_assistant'
        elif any(pattern in endpoint for pattern in ['document', 'analyze', 'process']):
            return 'document_processor'
        elif any(pattern in endpoint for pattern in ['workflow', 'automation', 'task']):
            return 'automation_agent'
        elif metadata.get('has_api_access'):
            return 'api_integration'
        else:
            return 'unknown'
    
    def _analyze_capabilities(self, agent: Dict[str, Any]) -> List[str]:
        """Analyze agent capabilities based on discovered information"""
        capabilities = []
        
        metadata = agent.get('metadata', {})
        endpoint = agent.get('endpoint', '').lower()
        
        if metadata.get('has_file_access'):
            capabilities.append('file_system_access')
        if metadata.get('has_network_access'):
            capabilities.append('network_access')
        if metadata.get('has_database_access'):
            capabilities.append('database_access')
        if 'api' in endpoint:
            capabilities.append('api_integration')
        if any(pattern in endpoint for pattern in ['execute', 'run', 'command']):
            capabilities.append('code_execution')
        
        return capabilities
    
    def _identify_risk_factors(self, agent: Dict[str, Any]) -> List[str]:
        """Identify potential risk factors for the agent"""
        risk_factors = []
        
        metadata = agent.get('metadata', {})
        endpoint = agent.get('endpoint', '')
        
        # Check exposure level
        if metadata.get('internet_facing'):
            risk_factors.append('internet_exposed')
        if metadata.get('no_authentication'):
            risk_factors.append('unauthenticated')
        if metadata.get('admin_access'):
            risk_factors.append('elevated_privileges')
        
        # Check data access
        if metadata.get('processes_pii'):
            risk_factors.append('pii_access')
        if metadata.get('sensitive_data_access'):
            risk_factors.append('sensitive_data')
        
        # Check endpoint security
        if endpoint and not endpoint.startswith('https://'):
            risk_factors.append('unencrypted_transport')
        
        return risk_factors
    
    def _calculate_classification_confidence(self, agent: Dict[str, Any]) -> float:
        """Calculate confidence score for agent classification"""
        confidence = 0.5  # Base confidence
        
        # Increase confidence based on available information
        if agent.get('provider'):
            confidence += 0.2
        if agent.get('endpoint'):
            confidence += 0.2
        if agent.get('metadata', {}).get('response_analyzed'):
            confidence += 0.1
        
        return min(1.0, confidence)
    
    def _dict_to_discovered_agent(self, agent_dict: Dict[str, Any]) -> DiscoveredAgent:
        """Convert dictionary to DiscoveredAgent object"""
        return DiscoveredAgent(
            id=agent_dict.get('id', ''),
            name=agent_dict.get('name', ''),
            type=agent_dict.get('type', 'unknown'),
            provider=agent_dict.get('provider'),
            endpoint=agent_dict.get('endpoint'),
            discovery_method=agent_dict.get('discovery_method', 'unknown'),
            confidence=agent_dict.get('confidence', 0.5),
            metadata=agent_dict.get('metadata', {})
        )

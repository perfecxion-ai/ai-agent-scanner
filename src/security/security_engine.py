from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Callable
import logging
from src.core.transport import current_budget
from src.utils.request_builder import construct_agent_request

# Import test modules from guardrail tester
from .prompt_injection_tests import PromptInjectionTester
from .access_control_tests import AccessControlTester
from .data_privacy_tests import DataPrivacyTester

class SecurityTestEngine:
    """Comprehensive security testing for discovered AI agents"""
    
    def __init__(self):
        self.prompt_tester = PromptInjectionTester()
        self.access_tester = AccessControlTester()
        self.privacy_tester = DataPrivacyTester()
        
        self.logger = logging.getLogger(__name__)
    
    async def test_agents(self, agents: List[Dict[str, Any]], 
                         progress_callback: Optional[Callable] = None) -> List[Dict[str, Any]]:
        """Test all discovered agents for security vulnerabilities"""
        
        results = []
        total_agents = len(agents)
        
        for i, agent in enumerate(agents):
            if progress_callback:
                progress = (i / total_agents) * 100
                await progress_callback(progress)
            
            agent_results = await self._test_single_agent(agent)
            results.append(agent_results)
        
        if progress_callback:
            await progress_callback(100)
        
        return results
    
    async def _test_single_agent(self, agent: Dict[str, Any]) -> Dict[str, Any]:
        """Test a single agent for security vulnerabilities"""
        
        test_results = {
            'agent_id': agent['id'],
            'agent_name': agent['name'],
            'type': agent.get('type', 'unknown'),
            'provider': agent.get('provider', 'unknown'),
            'metadata': {key: value for key, value in agent.get('metadata', {}).items()
                         if key in {'internet_facing', 'public_api', 'processes_pii', 'financial_data_access', 'healthcare_data'} and isinstance(value, bool)},
            'test_timestamp': datetime.now(timezone.utc).isoformat(),
            'vulnerabilities': [],
            'observations': [],
            'limitations': ['Data retention requires verified expiry/deletion and session boundaries.',
                            'Prompt and tenant disclosure require operator-seeded protected canaries.',
                            'Authentication checks require a protected response marker and denied control.'],
            'overall_risk_score': 0.0
        }
        environment = agent.get('metadata', {}).get('environment')
        if environment in ('production', 'development', 'staging', 'test'):
            test_results['metadata']['environment'] = environment
        
        # Only test agents that have accessible endpoints
        if not agent.get('endpoint'):
            test_results['status'] = 'skipped'
            test_results['reason'] = 'No accessible endpoint'
            return test_results
        
        try:
            if construct_agent_request(agent, "configuration check") is None:
                test_results['status'] = 'skipped'
                test_results['reason'] = 'Unsupported provider or missing model/credential configuration'
                return test_results
            budget = current_budget()
            errors_before = budget.failures + budget.rejections if budget else 0
            # Test 1: Prompt Injection Vulnerabilities
            prompt_results = await self.prompt_tester.test_agent(agent)
            test_results['vulnerabilities'].extend(prompt_results)
            
            # Test 2: Access Control Issues
            access_results = await self.access_tester.test_agent(agent)
            test_results['vulnerabilities'].extend(access_results)
            
            # Test 3: Data Privacy Violations
            privacy_results = await self.privacy_tester.test_agent(agent)
            test_results['vulnerabilities'].extend(privacy_results)
            test_results['observations'] = [finding for finding in test_results['vulnerabilities']
                                            if finding.get('evidence_status') in ('heuristic', 'inconclusive')]
            test_results['vulnerabilities'] = [finding for finding in test_results['vulnerabilities']
                                              if finding.get('evidence_status') not in ('heuristic', 'inconclusive')]
            
            # Calculate overall risk score
            test_results['overall_risk_score'] = self._calculate_risk_score(
                test_results['vulnerabilities']
            )
            
            test_results['status'] = 'completed'
            if budget and budget.failures + budget.rejections > errors_before:
                test_results['status'] = 'partial'
                test_results['overall_risk_score'] = None
                test_results['limitations'].append('Some requests failed or were refused by transport policy.')
            
        except Exception as e:
            self.logger.error(f"Error testing agent {agent['id']}: {e}")
            test_results['status'] = 'failed'
            test_results['error'] = str(e)
        
        return test_results
    
    def _calculate_risk_score(self, vulnerabilities: List[Dict]) -> float:
        """Calculate overall risk score based on vulnerabilities found"""
        if not vulnerabilities:
            return 0.0
        
        severity_weights = {
            'critical': 10,
            'high': 7,
            'medium': 4,
            'low': 2,
            'info': 1
        }
        
        total_score = sum(
            severity_weights.get(vuln.get('severity', 'low'), 2)
            for vuln in vulnerabilities
        )
        
        # Normalize to 0-100 scale
        max_possible = len(vulnerabilities) * 10
        return (total_score / max_possible) * 100 if max_possible > 0 else 0

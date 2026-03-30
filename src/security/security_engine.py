from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Callable
import logging

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
            'test_timestamp': datetime.now(timezone.utc).isoformat(),
            'vulnerabilities': [],
            'overall_risk_score': 0.0
        }
        
        # Only test agents that have accessible endpoints
        if not agent.get('endpoint'):
            test_results['status'] = 'skipped'
            test_results['reason'] = 'No accessible endpoint'
            return test_results
        
        try:
            # Test 1: Prompt Injection Vulnerabilities
            prompt_results = await self.prompt_tester.test_agent(agent)
            test_results['vulnerabilities'].extend(prompt_results)
            
            # Test 2: Access Control Issues
            access_results = await self.access_tester.test_agent(agent)
            test_results['vulnerabilities'].extend(access_results)
            
            # Test 3: Data Privacy Violations
            privacy_results = await self.privacy_tester.test_agent(agent)
            test_results['vulnerabilities'].extend(privacy_results)
            
            # Calculate overall risk score
            test_results['overall_risk_score'] = self._calculate_risk_score(
                test_results['vulnerabilities']
            )
            
            test_results['status'] = 'completed'
            
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

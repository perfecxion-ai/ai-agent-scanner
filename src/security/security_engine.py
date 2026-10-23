from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Callable
import logging
from src.core.transport import current_budget
from src.utils.request_builder import construct_agent_request, missing_credential_reason
from src.core.contracts import CHECK_SCHEMA_VERSION, CheckpointError, collect_checks, missing_checks, risk_assessment_eligible
from src.risk.risk_assessor import SEVERITY_SCORES

# Import test modules from guardrail tester
from .prompt_injection_tests import PromptInjectionTester
from .access_control_tests import AccessControlTester
from .data_privacy_tests import DataPrivacyTester
from .prompt_suites import validate_prompt_suite_agents

class SecurityTestEngine:
    """Comprehensive security testing for discovered AI agents"""
    
    def __init__(self, *, prompt_suite=None):
        self.prompt_tester = PromptInjectionTester(prompt_suite=prompt_suite)
        self.prompt_suite = self.prompt_tester.prompt_suite
        self.access_tester = AccessControlTester()
        self.privacy_tester = DataPrivacyTester()
        
        self.logger = logging.getLogger(__name__)

    def checkpoint_secrets(self, agents):
        """Pin predictable probe credentials before protected-access checkpoints."""
        if not any(agent.get('authentication_required') is True
                   and agent.get('protected_response_marker') for agent in agents):
            return set()
        secrets = {password for _, password in self.access_tester.weak_credentials[:5] if password}
        secrets.update(key for key in self.access_tester.test_api_keys[:5] if key)
        return secrets
    
    async def test_agents(self, agents: List[Dict[str, Any]], 
                         progress_callback: Optional[Callable] = None) -> List[Dict[str, Any]]:
        """Test all discovered agents for security vulnerabilities"""
        
        results = []
        total_agents = len(agents)
        if self.prompt_suite is not None:
            validate_prompt_suite_agents(agents, require_target=False)
        
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
            'provider': agent.get('provider'),
            'model': agent.get('model'),
            'metadata': {key: value for key, value in agent.get('metadata', {}).items()
                         if key in {'internet_facing', 'public_api', 'processes_pii', 'financial_data_access', 'healthcare_data'} and isinstance(value, bool)},
            'test_timestamp': datetime.now(timezone.utc).isoformat(),
            'vulnerabilities': [],
            'observations': [],
            'limitations': ['Data retention requires verified expiry/deletion and session boundaries.',
                            'Prompt and tenant disclosure require operator-seeded protected canaries; nondisclosure is inconclusive.',
                            'Anonymous inference is an exposure observation, not proof of authorization bypass.',
                            'Authentication checks require explicit issued credentials, a protected response marker, and successful authorized/denied controls.'],
            'overall_risk_score': None
        }
        test_results['check_schema_version'] = CHECK_SCHEMA_VERSION
        test_results['checks'] = []
        marker = agent.get('system_prompt_canary')
        if self.prompt_suite is not None and not (isinstance(marker, str) and marker and marker in self.prompt_suite):
            test_results['prompt_suite'] = self.prompt_suite
        environment = agent.get('metadata', {}).get('environment')
        if environment in ('production', 'development', 'staging', 'test'):
            test_results['metadata']['environment'] = environment
        
        # Only test agents that have accessible endpoints
        if not agent.get('endpoint'):
            test_results['status'] = 'skipped'
            test_results['reason'] = 'No accessible endpoint'
            test_results['checks'] = missing_checks([], test_results['reason'])
            return test_results
        
        async def run_tester(tester):
            with collect_checks() as checks:
                try:
                    return await tester.test_agent(agent)
                finally:
                    test_results['checks'].extend(checks)

        try:
            if construct_agent_request(agent, "configuration check") is None:
                test_results['status'] = 'skipped'
                test_results['reason'] = (missing_credential_reason(agent) or
                    'Unsupported provider or invalid/missing model configuration')
                test_results['checks'] = missing_checks([], test_results['reason'])
                return test_results
            budget = current_budget()
            errors_before = budget.failures + budget.rejections if budget else 0
            # Test 1: Prompt Injection Vulnerabilities
            prompt_results = await run_tester(self.prompt_tester)
            test_results['vulnerabilities'].extend(prompt_results)
            
            # Test 2: Access Control Issues
            access_results = await run_tester(self.access_tester)
            test_results['vulnerabilities'].extend(access_results)
            
            # Test 3: Data Privacy Violations
            privacy_results = await run_tester(self.privacy_tester)
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
            incomplete_checks = any(check['status'] == 'failed' for check in test_results['checks'])
            no_evaluated_checks = not any(check['responses_evaluated'] for check in test_results['checks'])
            if incomplete_checks or no_evaluated_checks or (budget and budget.failures + budget.rejections > errors_before):
                test_results['status'] = 'partial'
                test_results['overall_risk_score'] = None
                test_results['limitations'].append('Some requests failed or were refused by transport policy.')
            if not risk_assessment_eligible(test_results):
                test_results['overall_risk_score'] = None
            
        except CheckpointError:
            raise
        except Exception:
            self.logger.error("Security testing failed")
            test_results['status'] = 'failed'
            test_results['error'] = 'Security testing failed'
            test_results['overall_risk_score'] = None
        finally:
            test_results['observations'].extend(
                finding for finding in test_results['vulnerabilities']
                if finding.get('evidence_status') in ('heuristic', 'inconclusive'))
            test_results['vulnerabilities'] = [
                finding for finding in test_results['vulnerabilities']
                if finding.get('evidence_status') not in ('heuristic', 'inconclusive')]
        test_results['checks'].extend(missing_checks(test_results['checks'], 'Probe did not execute'))
        
        return test_results
    
    def _calculate_risk_score(self, vulnerabilities: List[Dict]) -> float:
        """Calculate overall risk score based on vulnerabilities found"""
        if not vulnerabilities:
            return 0.0
        
        return max(SEVERITY_SCORES.get(vuln.get('severity'), 1.0) for vuln in vulnerabilities)

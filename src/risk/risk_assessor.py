#!/usr/bin/env python3
"""
Risk Assessment and Vulnerability Scoring Engine

This module implements comprehensive risk assessment for AI agents based on
discovered security vulnerabilities. It provides CVSS-inspired scoring,
business impact analysis, and prioritized remediation recommendations.

Author: scthornton
Created: 2024
License: Private - All rights reserved

Security Focus: DEFENSIVE ONLY
This tool helps organizations prioritize security remediation efforts
and understand the business impact of AI security vulnerabilities.
"""

import asyncio
import logging
from typing import List, Dict, Any, Optional, Callable, Tuple
from datetime import datetime, timedelta
import statistics
from collections import defaultdict, Counter

class RiskAssessment:
    """
    Comprehensive risk assessment engine for AI agents with vulnerability scoring.
    
    This class implements a sophisticated risk scoring system that considers:
    - Vulnerability severity and type impact
    - Agent exposure and accessibility 
    - Business context and data sensitivity
    - Temporal factors and vulnerability age
    - Compliance implications
    
    The scoring system is inspired by CVSS but adapted specifically for
    AI agent security assessments with business impact considerations.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # CVSS-inspired severity scoring weights
        self.severity_weights = {
            'critical': 10.0,
            'high': 7.5,
            'medium': 5.0,
            'low': 2.5,
            'info': 1.0
        }
        
        # Vulnerability type impact multipliers
        self.vulnerability_impact = {
            'prompt_injection': {
                'system_prompt_extraction': 0.9,
                'instruction_bypass': 0.8,
                'role_manipulation': 0.7,
                'dan_jailbreak': 0.9,
                'context_manipulation': 0.6,
                'injection_via_encoding': 0.8,
                'payload_injection': 0.5
            },
            'authentication_bypass': 1.0,
            'weak_credentials': 0.95,
            'weak_api_key': 0.8,
            'authorization_bypass': 0.9,
            'no_rate_limiting': 0.4,
            'insecure_session_management': 0.6,
            'pii_disclosure': 0.85,
            'tenant_isolation_violation': 0.95,
            'inappropriate_data_retention': 0.5,
            'privacy_transparency_issue': 0.2,
            'information_disclosure_in_errors': 0.6
        }
        
        # Agent exposure risk factors
        self.exposure_multipliers = {
            'internet_facing': 1.5,
            'internal_only': 1.0,
            'public_api': 1.4,
            'authenticated_api': 1.1,
            'development': 0.8,
            'production': 1.3
        }
        
        # Business impact factors
        self.business_impact_factors = {
            'customer_data_access': 1.3,
            'financial_operations': 1.4,
            'healthcare_data': 1.5,
            'legal_documents': 1.2,
            'intellectual_property': 1.3,
            'operational_systems': 1.1,
            'development_tools': 0.9
        }
    
    async def assess_risks(self, security_results: List[Dict[str, Any]], 
                          progress_callback: Optional[Callable] = None) -> List[Dict[str, Any]]:
        """Assess risks for all tested agents with comprehensive scoring"""
        
        if not security_results:
            if progress_callback:
                await progress_callback(100)
            return []
        
        self.logger.info(f"Assessing risks for {len(security_results)} agents")
        
        risk_assessments = []
        total_agents = len(security_results)
        
        for i, agent_results in enumerate(security_results):
            if progress_callback:
                progress = (i / total_agents) * 100
                await progress_callback(progress)
            
            # Assess risk for individual agent
            agent_risk = await self._assess_agent_risk(agent_results)
            risk_assessments.append(agent_risk)
        
        # Calculate relative risk rankings
        self._calculate_relative_rankings(risk_assessments)
        
        if progress_callback:
            await progress_callback(100)
        
        self.logger.info(f"Risk assessment complete for {len(risk_assessments)} agents")
        return risk_assessments
    
    async def _assess_agent_risk(self, agent_results: Dict[str, Any]) -> Dict[str, Any]:
        """Assess risk for a single agent"""
        
        agent_id = agent_results.get('agent_id')
        agent_name = agent_results.get('agent_name')
        vulnerabilities = agent_results.get('vulnerabilities', [])
        
        # Calculate base vulnerability score
        vulnerability_score = self._calculate_vulnerability_score(vulnerabilities)
        
        # Calculate exposure risk
        exposure_score = self._calculate_exposure_risk(agent_results)
        
        # Calculate business impact
        business_impact = self._calculate_business_impact(agent_results)
        
        # Calculate overall risk score (0-100 scale)
        overall_risk_score = min(100, vulnerability_score * exposure_score * business_impact)
        
        # Determine risk level
        risk_level = self._determine_risk_level(overall_risk_score)
        
        # Generate risk summary
        risk_summary = self._generate_risk_summary(vulnerabilities, overall_risk_score)
        
        # Calculate time-based risk factors
        temporal_risk = self._calculate_temporal_risk(vulnerabilities)
        
        # Generate remediation priorities
        remediation_priorities = self._generate_remediation_priorities(vulnerabilities)
        
        return {
            'agent_id': agent_id,
            'agent_name': agent_name,
            'assessment_timestamp': datetime.utcnow().isoformat(),
            'overall_risk_score': round(overall_risk_score, 2),
            'risk_level': risk_level,
            'vulnerability_score': round(vulnerability_score, 2),
            'exposure_score': round(exposure_score, 2),
            'business_impact_score': round(business_impact, 2),
            'temporal_risk_factor': round(temporal_risk, 2),
            'total_vulnerabilities': len(vulnerabilities),
            'critical_vulnerabilities': len([v for v in vulnerabilities if v.get('severity') == 'critical']),
            'high_vulnerabilities': len([v for v in vulnerabilities if v.get('severity') == 'high']),
            'medium_vulnerabilities': len([v for v in vulnerabilities if v.get('severity') == 'medium']),
            'low_vulnerabilities': len([v for v in vulnerabilities if v.get('severity') == 'low']),
            'vulnerability_types': list(set([v.get('vulnerability_type') for v in vulnerabilities])),
            'risk_summary': risk_summary,
            'remediation_priorities': remediation_priorities,
            'compliance_implications': self._assess_compliance_implications(vulnerabilities),
            'threat_likelihood': self._assess_threat_likelihood(vulnerabilities, exposure_score),
            'potential_impact': self._assess_potential_impact(vulnerabilities, business_impact)
        }
    
    def _calculate_vulnerability_score(self, vulnerabilities: List[Dict[str, Any]]) -> float:
        """Calculate vulnerability score based on severity and type"""
        if not vulnerabilities:
            return 0.0
        
        total_score = 0.0
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'low')
            vuln_type = vuln.get('vulnerability_type', '')
            confidence = vuln.get('confidence', 0.5)
            
            # Base severity score
            base_score = self.severity_weights.get(severity, 1.0)
            
            # Apply vulnerability type multiplier
            type_multiplier = self.vulnerability_impact.get(vuln_type, 0.5)
            
            # Apply confidence factor
            confidence_factor = 0.5 + (confidence * 0.5)  # Scale from 0.5 to 1.0
            
            vuln_score = base_score * type_multiplier * confidence_factor
            total_score += vuln_score
        
        # Normalize to reasonable scale (diminishing returns for many vulnerabilities)
        normalized_score = min(100, total_score * (1 - (len(vulnerabilities) - 1) * 0.05))
        
        return max(0.0, normalized_score)
    
    def _calculate_exposure_risk(self, agent_results: Dict[str, Any]) -> float:
        """Calculate exposure risk multiplier based on agent accessibility"""
        base_exposure = 1.0
        
        # Check for internet-facing indicators
        agent_metadata = agent_results.get('metadata', {})
        
        if agent_metadata.get('internet_facing', False):
            base_exposure *= self.exposure_multipliers['internet_facing']
        
        if agent_metadata.get('public_api', False):
            base_exposure *= self.exposure_multipliers['public_api']
        
        if agent_metadata.get('environment') == 'production':
            base_exposure *= self.exposure_multipliers['production']
        elif agent_metadata.get('environment') == 'development':
            base_exposure *= self.exposure_multipliers['development']
        
        return min(2.0, base_exposure)  # Cap at 2x multiplier
    
    def _calculate_business_impact(self, agent_results: Dict[str, Any]) -> float:
        """Calculate business impact multiplier"""
        base_impact = 1.0
        
        agent_metadata = agent_results.get('metadata', {})
        agent_type = agent_results.get('agent_type', '')
        
        # Check for high-impact data types
        if agent_metadata.get('processes_pii', False):
            base_impact *= self.business_impact_factors['customer_data_access']
        
        if agent_metadata.get('financial_data_access', False):
            base_impact *= self.business_impact_factors['financial_operations']
        
        if agent_metadata.get('healthcare_data', False):
            base_impact *= self.business_impact_factors['healthcare_data']
        
        # Check agent type impact
        if 'customer' in agent_type.lower():
            base_impact *= 1.2
        elif 'internal' in agent_type.lower():
            base_impact *= 1.1
        
        return min(2.0, base_impact)  # Cap at 2x multiplier
    
    def _calculate_temporal_risk(self, vulnerabilities: List[Dict[str, Any]]) -> float:
        """Calculate temporal risk factor based on vulnerability age and trends"""
        if not vulnerabilities:
            return 1.0
        
        # Calculate average age of vulnerabilities
        current_time = datetime.utcnow()
        ages = []
        
        for vuln in vulnerabilities:
            timestamp_str = vuln.get('timestamp')
            if timestamp_str:
                try:
                    vuln_time = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                    age_hours = (current_time - vuln_time.replace(tzinfo=None)).total_seconds() / 3600
                    ages.append(age_hours)
                except:
                    ages.append(0)  # Default to recent if parsing fails
        
        if ages:
            avg_age_hours = sum(ages) / len(ages)
            # Increase risk factor for older vulnerabilities (diminishing effect)
            temporal_factor = 1.0 + min(0.5, avg_age_hours / (24 * 30))  # Max 1.5x for month-old vulns
        else:
            temporal_factor = 1.0
        
        return temporal_factor
    
    def _determine_risk_level(self, risk_score: float) -> str:
        """Determine risk level category from numerical score"""
        if risk_score >= 80:
            return 'critical'
        elif risk_score >= 60:
            return 'high'
        elif risk_score >= 30:
            return 'medium'
        elif risk_score >= 10:
            return 'low'
        else:
            return 'minimal'
    
    def _generate_risk_summary(self, vulnerabilities: List[Dict[str, Any]], risk_score: float) -> str:
        """Generate human-readable risk summary"""
        if not vulnerabilities:
            return "No security vulnerabilities detected."
        
        vuln_counts = Counter([v.get('severity', 'unknown') for v in vulnerabilities])
        vuln_types = list(set([v.get('vulnerability_type', 'unknown') for v in vulnerabilities]))
        
        summary_parts = []
        
        # Severity summary
        if vuln_counts['critical'] > 0:
            summary_parts.append(f"{vuln_counts['critical']} critical")
        if vuln_counts['high'] > 0:
            summary_parts.append(f"{vuln_counts['high']} high")
        if vuln_counts['medium'] > 0:
            summary_parts.append(f"{vuln_counts['medium']} medium")
        
        severity_text = ", ".join(summary_parts) + " severity vulnerabilities" if summary_parts else "low severity vulnerabilities"
        
        # Top vulnerability types
        top_types = [vtype.replace('_', ' ').title() for vtype in vuln_types[:3]]
        types_text = ", ".join(top_types) if top_types else "various types"
        
        return f"Agent has {len(vulnerabilities)} vulnerabilities ({severity_text}) including {types_text}. Overall risk score: {risk_score:.1f}/100."
    
    def _generate_remediation_priorities(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate prioritized remediation recommendations"""
        if not vulnerabilities:
            return []
        
        # Sort vulnerabilities by priority (severity + impact)
        def priority_score(vuln):
            severity_score = self.severity_weights.get(vuln.get('severity', 'low'), 1.0)
            impact_score = self.vulnerability_impact.get(vuln.get('vulnerability_type', ''), 0.5)
            confidence = vuln.get('confidence', 0.5)
            return severity_score * impact_score * confidence
        
        sorted_vulns = sorted(vulnerabilities, key=priority_score, reverse=True)
        
        priorities = []
        for i, vuln in enumerate(sorted_vulns[:5]):  # Top 5 priorities
            priorities.append({
                'priority': i + 1,
                'vulnerability_id': vuln.get('id'),
                'title': vuln.get('title', 'Unknown Vulnerability'),
                'severity': vuln.get('severity', 'unknown'),
                'type': vuln.get('vulnerability_type', 'unknown'),
                'remediation': vuln.get('remediation', 'No specific remediation provided'),
                'estimated_effort': self._estimate_remediation_effort(vuln),
                'business_justification': self._generate_business_justification(vuln)
            })
        
        return priorities
    
    def _estimate_remediation_effort(self, vulnerability: Dict[str, Any]) -> str:
        """Estimate effort required for remediation"""
        vuln_type = vulnerability.get('vulnerability_type', '')
        severity = vulnerability.get('severity', 'low')
        
        effort_mapping = {
            'prompt_injection': 'Medium',
            'authentication_bypass': 'High',
            'weak_credentials': 'Low',
            'authorization_bypass': 'High',
            'pii_disclosure': 'Medium',
            'tenant_isolation_violation': 'High',
            'no_rate_limiting': 'Low',
            'insecure_session_management': 'Medium'
        }
        
        base_effort = effort_mapping.get(vuln_type, 'Medium')
        
        # Adjust based on severity
        if severity == 'critical' and base_effort == 'Low':
            return 'Medium'
        elif severity in ['critical', 'high'] and base_effort == 'Medium':
            return 'High'
        
        return base_effort
    
    def _generate_business_justification(self, vulnerability: Dict[str, Any]) -> str:
        """Generate business justification for fixing vulnerability"""
        vuln_type = vulnerability.get('vulnerability_type', '')
        severity = vulnerability.get('severity', 'low')
        
        justifications = {
            'prompt_injection': "Prevents AI manipulation and unauthorized behavior that could damage reputation or cause operational issues.",
            'authentication_bypass': "Prevents unauthorized access to sensitive AI capabilities and data.",
            'pii_disclosure': "Ensures compliance with privacy regulations (GDPR, CCPA) and prevents data breaches.",
            'tenant_isolation_violation': "Critical for multi-tenant security and preventing customer data leakage.",
            'weak_credentials': "Reduces risk of account compromise and unauthorized access.",
            'authorization_bypass': "Prevents privilege escalation and unauthorized system access."
        }
        
        base_justification = justifications.get(vuln_type, "Improves overall security posture and reduces potential attack surface.")
        
        if severity in ['critical', 'high']:
            return f"HIGH PRIORITY: {base_justification} Immediate attention required."
        
        return base_justification
    
    def _assess_compliance_implications(self, vulnerabilities: List[Dict[str, Any]]) -> List[str]:
        """Assess compliance implications of vulnerabilities"""
        implications = set()
        
        for vuln in vulnerabilities:
            vuln_type = vuln.get('vulnerability_type', '')
            
            if vuln_type == 'pii_disclosure':
                implications.update(['GDPR Article 32', 'CCPA Section 1798.81.5', 'HIPAA Security Rule'])
            elif vuln_type == 'weak_credentials':
                implications.update(['SOC 2 Type II', 'ISO 27001 A.9.4.3'])
            elif vuln_type == 'tenant_isolation_violation':
                implications.update(['SOC 2 Type II', 'FedRAMP Controls'])
            elif vuln_type == 'authentication_bypass':
                implications.update(['PCI DSS Requirement 8', 'NIST Cybersecurity Framework'])
        
        return sorted(list(implications))
    
    def _assess_threat_likelihood(self, vulnerabilities: List[Dict[str, Any]], exposure_score: float) -> str:
        """Assess likelihood of exploitation"""
        if not vulnerabilities:
            return 'Very Low'
        
        # Calculate based on vulnerability types and exposure
        high_likelihood_types = ['authentication_bypass', 'weak_credentials', 'prompt_injection']
        high_risk_vulns = [v for v in vulnerabilities if v.get('vulnerability_type') in high_likelihood_types]
        
        if len(high_risk_vulns) > 0 and exposure_score > 1.3:
            return 'High'
        elif len(high_risk_vulns) > 0 or exposure_score > 1.2:
            return 'Medium'
        elif len(vulnerabilities) > 3:
            return 'Medium'
        else:
            return 'Low'
    
    def _assess_potential_impact(self, vulnerabilities: List[Dict[str, Any]], business_impact: float) -> str:
        """Assess potential business impact"""
        if not vulnerabilities:
            return 'Minimal'
        
        critical_vulns = [v for v in vulnerabilities if v.get('severity') == 'critical']
        high_vulns = [v for v in vulnerabilities if v.get('severity') == 'high']
        
        if critical_vulns and business_impact > 1.4:
            return 'Catastrophic'
        elif (critical_vulns or len(high_vulns) > 2) and business_impact > 1.2:
            return 'Major'
        elif high_vulns or business_impact > 1.1:
            return 'Moderate'
        else:
            return 'Minor'
    
    def _calculate_relative_rankings(self, risk_assessments: List[Dict[str, Any]]) -> None:
        """Calculate relative risk rankings across all agents"""
        if len(risk_assessments) <= 1:
            return
        
        # Sort by risk score
        sorted_assessments = sorted(risk_assessments, key=lambda x: x['overall_risk_score'], reverse=True)
        
        # Add rankings
        for i, assessment in enumerate(sorted_assessments):
            assessment['risk_ranking'] = i + 1
            assessment['risk_percentile'] = round(((len(sorted_assessments) - i) / len(sorted_assessments)) * 100, 1)
        
        # Add relative risk comparison
        if len(sorted_assessments) > 2:
            avg_risk_score = statistics.mean([a['overall_risk_score'] for a in risk_assessments])
            
            for assessment in risk_assessments:
                score = assessment['overall_risk_score']
                if score > avg_risk_score * 1.5:
                    assessment['relative_risk'] = 'Significantly Above Average'
                elif score > avg_risk_score * 1.2:
                    assessment['relative_risk'] = 'Above Average'
                elif score < avg_risk_score * 0.5:
                    assessment['relative_risk'] = 'Significantly Below Average'
                elif score < avg_risk_score * 0.8:
                    assessment['relative_risk'] = 'Below Average'
                else:
                    assessment['relative_risk'] = 'Average'

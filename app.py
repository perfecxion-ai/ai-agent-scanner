import os
import logging
from datetime import datetime
from flask import Flask, render_template, request, jsonify, session
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, DateTime, Text, Boolean, Float, JSON
import asyncio
import threading
from typing import Dict, Any

# Import our custom modules
from src.discovery.discovery_engine import DiscoveryEngine
from src.security.security_engine import SecurityTestEngine
from src.risk.risk_assessor import RiskAssessment
from src.compliance.compliance_engine import ComplianceEngine
from src.reporting.report_generator import ReportGenerator
from src.utils.database import init_db, get_db_session
from src.utils.auth import require_auth, create_jwt_token
from src.utils.helpers import generate_scan_id, validate_scan_scope

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-key-change-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///ai_agent_scanner.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

CORS(app)

# Initialize database
db = SQLAlchemy(app)

# Initialize core engines
discovery_engine = DiscoveryEngine()
security_engine = SecurityTestEngine()
risk_assessor = RiskAssessment()
compliance_engine = ComplianceEngine()
report_generator = ReportGenerator()

# Global scan tracking
active_scans = {}

class ScanSession(db.Model):
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(64), nullable=False)
    scan_name: Mapped[str] = mapped_column(String(255), nullable=False)
    scan_type: Mapped[str] = mapped_column(String(50), nullable=False)  # full, security_only, discovery_only
    status: Mapped[str] = mapped_column(String(50), nullable=False, default='pending')
    progress: Mapped[float] = mapped_column(Float, default=0.0)
    
    # Scan configuration
    target_scope: Mapped[dict] = mapped_column(JSON)
    scan_config: Mapped[dict] = mapped_column(JSON)
    
    # Results summary
    agents_discovered: Mapped[int] = mapped_column(Integer, default=0)
    vulnerabilities_found: Mapped[int] = mapped_column(Integer, default=0)
    critical_risks: Mapped[int] = mapped_column(Integer, default=0)
    overall_risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    
    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    started_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    
    # User context
    created_by: Mapped[str] = mapped_column(String(255), nullable=True)
    user_ip: Mapped[str] = mapped_column(String(45), nullable=True)

class DiscoveredAgent(db.Model):
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    scan_id: Mapped[str] = mapped_column(String(64), nullable=False)
    
    # Agent identification
    agent_name: Mapped[str] = mapped_column(String(255), nullable=False)
    agent_type: Mapped[str] = mapped_column(String(100), nullable=False)
    provider: Mapped[str] = mapped_column(String(100), nullable=True)
    model_name: Mapped[str] = mapped_column(String(255), nullable=True)
    
    # Location information
    endpoint_url: Mapped[str] = mapped_column(Text, nullable=True)
    network_location: Mapped[str] = mapped_column(String(255), nullable=True)
    discovery_method: Mapped[str] = mapped_column(String(100), nullable=False)
    
    # Security assessment
    security_tested: Mapped[bool] = mapped_column(Boolean, default=False)
    vulnerabilities: Mapped[dict] = mapped_column(JSON, default=dict)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    risk_level: Mapped[str] = mapped_column(String(20), default='unknown')
    
    # Metadata
    metadata: Mapped[dict] = mapped_column(JSON, default=dict)
    discovered_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

@app.route('/')
def dashboard():
    return render_template('dashboard.html')

@app.route('/api/scans', methods=['POST'])
@require_auth
def start_scan():
    """Start a new AI agent discovery and security scan"""
    try:
        data = request.get_json()
        
        # Validate scan configuration
        scan_name = data.get('scan_name', f'Scan {datetime.now().strftime("%Y-%m-%d %H:%M")}')
        scan_type = data.get('scan_type', 'full')
        target_scope = data.get('target_scope', {})
        scan_config = data.get('scan_config', {})
        
        if not validate_scan_scope(target_scope):
            return jsonify({
                'success': False,
                'error': 'Invalid scan scope configuration'
            }), 400
        
        # Create scan session
        scan_id = generate_scan_id()
        scan_session = ScanSession(
            id=scan_id,
            organization_id=session.get('organization_id', 'default'),
            scan_name=scan_name,
            scan_type=scan_type,
            target_scope=target_scope,
            scan_config=scan_config,
            created_by=session.get('user_id'),
            user_ip=request.remote_addr
        )
        
        db.session.add(scan_session)
        db.session.commit()
        
        # Start scan in background
        thread = threading.Thread(
            target=run_scan_async,
            args=(scan_id, scan_type, target_scope, scan_config)
        )
        thread.daemon = True
        thread.start()
        
        return jsonify({
            'success': True,
            'scan_id': scan_id,
            'message': 'Scan started successfully'
        })
        
    except Exception as e:
        app.logger.error(f"Error starting scan: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Failed to start scan'
        }), 500

@app.route('/api/scans/<scan_id>/status')
@require_auth
def get_scan_status(scan_id):
    """Get current scan status and progress"""
    try:
        scan_session = ScanSession.query.get(scan_id)
        if not scan_session:
            return jsonify({'success': False, 'error': 'Scan not found'}), 404
        
        # Get live progress from active scans
        live_progress = active_scans.get(scan_id, {})
        
        return jsonify({
            'success': True,
            'scan_id': scan_id,
            'status': scan_session.status,
            'progress': scan_session.progress,
            'current_phase': live_progress.get('current_phase', ''),
            'agents_discovered': scan_session.agents_discovered,
            'vulnerabilities_found': scan_session.vulnerabilities_found,
            'started_at': scan_session.started_at.isoformat() if scan_session.started_at else None,
            'estimated_completion': live_progress.get('estimated_completion')
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/scans/<scan_id>/results')
@require_auth
def get_scan_results(scan_id):
    """Get complete scan results"""
    try:
        scan_session = ScanSession.query.get(scan_id)
        if not scan_session:
            return jsonify({'success': False, 'error': 'Scan not found'}), 404
        
        # Get discovered agents
        agents = DiscoveredAgent.query.filter_by(scan_id=scan_id).all()
        
        # Format results
        results = {
            'scan_info': {
                'id': scan_session.id,
                'name': scan_session.scan_name,
                'type': scan_session.scan_type,
                'status': scan_session.status,
                'created_at': scan_session.created_at.isoformat(),
                'completed_at': scan_session.completed_at.isoformat() if scan_session.completed_at else None
            },
            'summary': {
                'agents_discovered': scan_session.agents_discovered,
                'vulnerabilities_found': scan_session.vulnerabilities_found,
                'critical_risks': scan_session.critical_risks,
                'overall_risk_score': scan_session.overall_risk_score
            },
            'agents': [
                {
                    'id': agent.id,
                    'name': agent.agent_name,
                    'type': agent.agent_type,
                    'provider': agent.provider,
                    'endpoint': agent.endpoint_url,
                    'risk_score': agent.risk_score,
                    'risk_level': agent.risk_level,
                    'vulnerabilities': agent.vulnerabilities,
                    'discovered_at': agent.discovered_at.isoformat()
                }
                for agent in agents
            ]
        }
        
        return jsonify({
            'success': True,
            'results': results
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/agents')
@require_auth
def list_agents():
    """List all discovered agents across scans"""
    try:
        # Get query parameters
        organization_id = session.get('organization_id', 'default')
        risk_level = request.args.get('risk_level')
        agent_type = request.args.get('agent_type')
        
        # Build query
        query = db.session.query(DiscoveredAgent).join(ScanSession).filter(
            ScanSession.organization_id == organization_id
        )
        
        if risk_level:
            query = query.filter(DiscoveredAgent.risk_level == risk_level)
        if agent_type:
            query = query.filter(DiscoveredAgent.agent_type == agent_type)
        
        agents = query.order_by(DiscoveredAgent.discovered_at.desc()).limit(100).all()
        
        return jsonify({
            'success': True,
            'agents': [
                {
                    'id': agent.id,
                    'name': agent.agent_name,
                    'type': agent.agent_type,
                    'provider': agent.provider,
                    'risk_score': agent.risk_score,
                    'risk_level': agent.risk_level,
                    'discovered_at': agent.discovered_at.isoformat()
                }
                for agent in agents
            ]
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/health')
def health_check():
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'version': '1.0.0'
    })

def run_scan_async(scan_id, scan_type, target_scope, scan_config):
    """Run scan asynchronously in background thread"""
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        loop.run_until_complete(
            execute_scan(scan_id, scan_type, target_scope, scan_config)
        )
        
    except Exception as e:
        app.logger.error(f"Error in async scan execution: {str(e)}")
        # Update scan status to failed
        with app.app_context():
            scan_session = ScanSession.query.get(scan_id)
            if scan_session:
                scan_session.status = 'failed'
                db.session.commit()
    finally:
        loop.close()
        # Clean up active scan tracking
        if scan_id in active_scans:
            del active_scans[scan_id]

async def execute_scan(scan_id, scan_type, target_scope, scan_config):
    """Execute the actual scan process"""
    
    with app.app_context():
        scan_session = ScanSession.query.get(scan_id)
        scan_session.status = 'running'
        scan_session.started_at = datetime.utcnow()
        db.session.commit()
    
    try:
        # Initialize progress tracking
        active_scans[scan_id] = {
            'current_phase': 'Starting scan...',
            'progress': 0,
            'estimated_completion': None
        }
        
        discovered_agents = []
        
        # Phase 1: Discovery
        if scan_type in ['full', 'discovery_only']:
            active_scans[scan_id]['current_phase'] = 'Discovering AI agents...'
            discovered_agents = await discovery_engine.discover_agents(
                target_scope,
                progress_callback=lambda p: update_scan_progress(scan_id, p * 0.4, 'Discovery')
            )
        
        # Phase 2: Security Testing
        security_results = []
        if scan_type in ['full', 'security_only'] and discovered_agents:
            active_scans[scan_id]['current_phase'] = 'Testing agent security...'
            security_results = await security_engine.test_agents(
                discovered_agents,
                progress_callback=lambda p: update_scan_progress(scan_id, 40 + (p * 0.4), 'Security Testing')
            )
        
        # Phase 3: Risk Assessment
        if scan_type == 'full' and security_results:
            active_scans[scan_id]['current_phase'] = 'Calculating risk scores...'
            risk_scores = await risk_assessor.assess_risks(
                security_results,
                progress_callback=lambda p: update_scan_progress(scan_id, 80 + (p * 0.2), 'Risk Assessment')
            )
        
        # Save results to database
        with app.app_context():
            scan_session = ScanSession.query.get(scan_id)
            scan_session.agents_discovered = len(discovered_agents)
            scan_session.status = 'completed'
            scan_session.completed_at = datetime.utcnow()
            scan_session.progress = 100.0
            
            # Save discovered agents
            for agent_data in discovered_agents:
                agent = DiscoveredAgent(
                    id=agent_data['id'],
                    scan_id=scan_id,
                    agent_name=agent_data['name'],
                    agent_type=agent_data['type'],
                    provider=agent_data.get('provider'),
                    endpoint_url=agent_data.get('endpoint'),
                    discovery_method=agent_data['discovery_method'],
                    metadata=agent_data.get('metadata', {})
                )
                db.session.add(agent)
            
            db.session.commit()
        
    except Exception as e:
        app.logger.error(f"Scan execution error: {str(e)}")
        with app.app_context():
            scan_session = ScanSession.query.get(scan_id)
            scan_session.status = 'failed'
            db.session.commit()

def update_scan_progress(scan_id, progress, phase):
    """Update scan progress"""
    if scan_id in active_scans:
        active_scans[scan_id]['progress'] = progress
        active_scans[scan_id]['current_phase'] = phase
    
    # Update database
    with app.app_context():
        scan_session = ScanSession.query.get(scan_id)
        if scan_session:
            scan_session.progress = progress
            db.session.commit()

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    
    app.run(host='0.0.0.0', port=port, debug=debug)

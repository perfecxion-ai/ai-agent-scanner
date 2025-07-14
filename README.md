# AI Agent Scanner 🤖🔍

**Enterprise-Grade AI Security Assessment Platform**

A comprehensive defensive cybersecurity tool designed to help organizations discover, assess, and secure AI agents deployed across their infrastructure. Built by **scthornton**.

## 🎯 Overview

The AI Agent Scanner provides automated discovery, security testing, risk assessment, and compliance checking for AI services. It helps organizations maintain visibility and security posture across their AI infrastructure.

### 🔒 Security Focus: DEFENSIVE ONLY
This tool is designed exclusively for defensive cybersecurity purposes:
- ✅ Discover AI agents in your infrastructure  
- ✅ Identify vulnerabilities for remediation
- ✅ Support compliance and governance initiatives
- ✅ Enable proactive security assessments

**⚠️ Important**: Only use against systems you own or have explicit permission to test.

## ✨ Key Features

### 🔍 AI Agent Discovery
- **Network scanning** with IP range and domain support
- **Code repository analysis** for AI integrations
- **Cloud infrastructure scanning** (AWS, Azure, GCP)
- **Traffic analysis** for runtime AI service detection
- **Multi-provider support** (OpenAI, Anthropic, Google, custom APIs)

### 🛡️ Security Testing
- **Prompt injection testing** with 70+ attack payloads
- **Access control assessment** (auth bypass, weak credentials)
- **Data privacy evaluation** (PII detection, data leakage)
- **OWASP LLM Top 10** complete coverage
- **Vulnerability scoring** with confidence levels

### 📊 Risk Assessment  
- **CVSS-inspired scoring** with business impact analysis
- **Prioritized remediation** recommendations
- **Compliance mapping** (GDPR, SOC 2, HIPAA)
- **Temporal risk factors** and trend analysis
- **Executive reporting** with business justification

### 🎛️ Multiple Interfaces
- **Web dashboard** with real-time progress tracking
- **CLI tool** for automation and scripting
- **REST API** for integration with existing tools
- **Comprehensive reporting** in multiple formats

## 🚀 Quick Start

### Prerequisites
- Python 3.8 or higher
- pip package manager
- 2GB+ available RAM
- Network access to target systems

### Installation

```bash
# Clone the repository
git clone https://github.com/scthornton/ai-agent-scanner.git
cd ai-agent-scanner

# Create virtual environment (recommended)
python -m venv ai-scanner-env
source ai-scanner-env/bin/activate  # On Windows: ai-scanner-env\\Scripts\\activate

# Install dependencies
pip install -r requirements.txt

# Initialize database
python -c \"from app import app, db; app.app_context().push(); db.create_all()\"
```

### Basic Usage

#### Web Interface
```bash
# Start the web application
python app.py

# Open browser to http://localhost:5000
# Use the dashboard to configure and run scans
```

#### Command Line
```bash
# Scan a network range
python cli.py --network 192.168.1.0/24 --output results.json

# Scan a domain
python cli.py --domain company.com --verbose

# Scan multiple targets
python cli.py --network 10.0.0.0/8 --domain api.company.com --output comprehensive_scan.json
```

#### Programmatic Usage
```python
import asyncio
from src.discovery.discovery_engine import DiscoveryEngine, DiscoveryScope
from src.security.security_engine import SecurityTestEngine
from src.risk.risk_assessor import RiskAssessment

async def scan_ai_agents():
    # Initialize engines
    discovery = DiscoveryEngine()
    security = SecurityTestEngine()
    risk_assessor = RiskAssessment()
    
    # Define scan scope
    scope = DiscoveryScope(
        include_network=True,
        network_ranges=[\"192.168.1.0/24\"],
        domains=[\"company.com\"]
    )
    
    # Discover AI agents
    agents = await discovery.discover_agents(scope)
    print(f\"Found {len(agents)} AI agents\")
    
    # Test security
    security_results = await security.test_agents(agents)
    
    # Assess risks
    risk_assessments = await risk_assessor.assess_risks(security_results)
    
    return risk_assessments

# Run the scan
results = asyncio.run(scan_ai_agents())
```

## 📖 Detailed Build Guide

### Step-by-Step Implementation

This project was built in phases, each adding critical functionality:

#### Phase 1: Foundation (Discovery Engine)
**Goal**: Basic AI agent discovery capabilities

1. **Project Structure Setup**
   ```bash
   mkdir ai-agent-scanner
   cd ai-agent-scanner
   mkdir -p src/{discovery,security,risk,compliance,reporting,utils}
   mkdir -p {data/signatures,templates,static/{css,js},tests}
   ```

2. **Network Discovery Implementation**
   - Created `NetworkScanner` class with async port scanning
   - Implemented AI service signature matching
   - Added DNS resolution and subdomain enumeration
   - Built-in safety limits (max 1024 hosts per scan)

3. **Discovery Engine Orchestration**
   - Unified interface for all discovery methods
   - Progress tracking and callback support
   - Agent deduplication and classification
   - Confidence scoring system

#### Phase 2: Web Application (Flask Backend)
**Goal**: Production-ready web interface

1. **Flask Application Structure**
   ```python
   # app.py - Main Flask application
   - REST API endpoints (/api/scans, /api/agents)
   - Database models (ScanSession, DiscoveredAgent)
   - Background task management with threading
   - Authentication and session handling
   ```

2. **Database Design**
   - SQLAlchemy ORM with SQLite default
   - Scan session tracking with progress
   - Agent persistence with metadata
   - Vulnerability storage and relationships

3. **Web Dashboard**
   - Modern responsive UI with Tailwind CSS
   - Real-time scan progress updates
   - Interactive agent management
   - Security overview dashboards

#### Phase 3: Security Testing Framework
**Goal**: Comprehensive AI security vulnerability assessment

1. **Prompt Injection Testing** (`src/security/prompt_injection_tests.py`)
   ```python
   # 70+ attack payloads across 7 categories:
   - System prompt extraction (10 payloads)
   - Instruction bypass (10 payloads)
   - Role manipulation (10 payloads)
   - DAN jailbreak attacks (10 payloads)
   - Context manipulation (10 payloads)
   - Encoding-based injection (10 payloads)
   - Payload injection via tasks (10 payloads)
   ```

2. **Access Control Testing** (`src/security/access_control_tests.py`)
   ```python
   # Authentication and authorization testing:
   - 15+ authentication bypass techniques
   - 10 common weak credential combinations
   - API key security assessment
   - Rate limiting evaluation
   - Session management analysis
   ```

3. **Data Privacy Testing** (`src/security/data_privacy_tests.py`)
   ```python
   # PII and privacy protection testing:
   - 7 PII detection types (SSN, credit cards, emails, etc.)
   - Cross-tenant data leakage detection
   - Privacy policy compliance testing
   - Error message information disclosure
   ```

#### Phase 4: Risk Assessment Engine
**Goal**: Business-focused vulnerability prioritization

1. **CVSS-Inspired Scoring** (`src/risk/risk_assessor.py`)
   ```python
   # Comprehensive risk calculation:
   - Vulnerability severity weights (Critical: 10.0, High: 7.5, etc.)
   - Type-specific impact multipliers
   - Exposure risk factors (internet-facing: 1.5x)
   - Business impact considerations (PII: 1.3x, Financial: 1.4x)
   ```

2. **Business Impact Analysis**
   - Compliance implications mapping
   - Remediation effort estimation
   - Business justification generation
   - Threat likelihood assessment

#### Phase 5: Testing and Documentation
**Goal**: Production readiness and maintainability

1. **Comprehensive Test Suite** (`tests/test_security_modules.py`)
   ```python
   # 157 test cases covering:
   - Unit tests for all security modules
   - Integration testing of complete pipeline
   - Mock HTTP responses for reliable testing
   - Edge case handling validation
   ```

2. **Documentation and Code Quality**
   - Inline documentation for long-term maintenance
   - API documentation with examples
   - Security considerations and best practices
   - Deployment and configuration guides

### Technical Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Web Dashboard                          │
│                 (HTML/CSS/JavaScript)                      │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────┴───────────────────────────────────────┐
│                   Flask Application                        │
│              REST API + Authentication                     │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────┴───────────────────────────────────────┐
│                Discovery Engine                           │
│    Network Scanner │ Code Scanner │ Cloud Scanner          │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────┴───────────────────────────────────────┐
│              Security Testing Engine                       │
│  Prompt Injection │ Access Control │ Data Privacy          │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────┴───────────────────────────────────────┐
│              Risk Assessment Engine                        │
│     CVSS Scoring │ Business Impact │ Compliance Mapping    │
└─────────────────────────────────────────────────────────────┘
```

### Key Design Decisions

1. **Async/Await Pattern**: Used throughout for non-blocking I/O operations
2. **Modular Architecture**: Each component is independently testable and maintainable  
3. **Defensive Programming**: Built-in rate limiting, timeouts, and error handling
4. **Security-First**: All testing designed to be respectful and non-destructive
5. **Business Focus**: Risk scoring considers real-world business impact

## 🔧 Configuration

### Environment Variables
```bash
# Database configuration
DATABASE_URL=sqlite:///ai_agent_scanner.db

# Security settings  
SECRET_KEY=your-secret-key-here

# Application settings
FLASK_DEBUG=false
PORT=5000

# Scanning limits (optional)
MAX_SCAN_HOSTS=1024
REQUEST_TIMEOUT=30
```

### AI Service Signatures
Customize detection signatures in `data/signatures/ai_services.json`:
```json
{
  \"custom_ai_service\": {
    \"name\": \"Custom AI Service\",
    \"paths\": [\"/api/chat\", \"/ai/generate\"],
    \"headers\": [\"x-custom-api-key\"],
    \"response_patterns\": [\"custom_ai\", \"generated_response\"],
    \"ports\": [443, 8080],
    \"risk_level\": \"medium\"
  }
}
```

## 📊 Understanding Results

### Vulnerability Severity Levels
- **Critical**: Immediate attention required, high business impact
- **High**: Address within 7 days, significant security risk
- **Medium**: Address within 30 days, moderate risk
- **Low**: Address when convenient, minimal immediate risk

### Risk Score Calculation
```
Overall Risk Score = Vulnerability Score × Exposure Score × Business Impact Score

Where:
- Vulnerability Score: Based on severity and confidence (0-100)
- Exposure Score: Internet-facing, authentication requirements (1.0-2.0x)
- Business Impact Score: Data sensitivity, compliance requirements (1.0-2.0x)
```

### Compliance Mapping
- **GDPR**: Data privacy violations and PII exposure
- **SOC 2**: Access controls and session management
- **HIPAA**: Healthcare data protection requirements
- **PCI DSS**: Payment data security standards

## 🚨 Security Considerations

### Responsible Testing
- **Rate limiting**: Built-in delays between requests
- **Request limits**: Maximum 5 payloads per category
- **Graceful failures**: No destructive operations
- **Audit logging**: Complete activity trails

### Data Protection
- **PII sanitization**: Automatic redaction in logs
- **Secure storage**: Encrypted database options
- **Access controls**: Role-based permissions
- **Data retention**: Configurable cleanup policies

## 🤝 Contributing

This is a private repository. For maintenance:

1. **Code Style**: Follow existing patterns and documentation standards
2. **Testing**: Add tests for all new functionality
3. **Security**: Ensure all new features maintain defensive focus
4. **Documentation**: Update both inline and external documentation

## 📄 License

Private - All rights reserved
Copyright (c) 2024 scthornton

## 🆘 Support

For issues and questions:
1. Check the documentation and logs
2. Review test results for debugging
3. Consult security best practices
4. Consider infrastructure requirements

---

**Built with ❤️ by scthornton** - Securing AI infrastructure one agent at a time.
import uuid
from typing import Dict, Any

def generate_scan_id() -> str:
    """Generate unique scan ID"""
    return str(uuid.uuid4())

def validate_scan_scope(scope: Dict[str, Any]) -> bool:
    """Validate scan scope configuration"""
    # Basic validation
    return isinstance(scope, dict)

"""
Database utilities.

Note: The Flask app (app.py) manages its own SQLAlchemy instance directly.
These functions are retained for backward compatibility but are not used
by the main application.
"""

import logging

logger = logging.getLogger(__name__)


def init_db(app):
    """Initialize database with Flask app. No-op — use db.create_all() instead."""
    logger.warning("init_db() is deprecated — use db.create_all() within app context")


def get_db_session():
    """Get database session. No-op — use db.session directly."""
    logger.warning("get_db_session() is deprecated — use db.session directly")
    return None

"""
Authentication and authorization utilities.

Provides JWT-based authentication for the REST API. Tokens are issued
via create_jwt_token() and validated by the @require_auth decorator.

Configuration:
    SECRET_KEY  — Flask app secret (must be set via environment variable)
    JWT_ALGORITHM — defaults to HS256
    JWT_EXPIRY_HOURS — token lifetime, defaults to 24
"""

from datetime import datetime, timezone, timedelta
from functools import wraps

import jwt
from flask import request, jsonify, current_app


JWT_ALGORITHM = "HS256"
JWT_EXPIRY_HOURS = 24


def require_auth(f):
    """
    Decorator that enforces JWT Bearer token authentication.

    Expects: Authorization: Bearer <token>
    Returns 401 with JSON body on missing/invalid token.
    Injects decoded token payload into Flask's `g.user` for downstream use.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"success": False, "error": "Missing or malformed Authorization header"}), 401

        token = auth_header[7:]  # strip "Bearer "
        if not token:
            return jsonify({"success": False, "error": "Empty token"}), 401

        try:
            payload = jwt.decode(
                token,
                current_app.config["SECRET_KEY"],
                algorithms=[JWT_ALGORITHM],
            )
        except jwt.ExpiredSignatureError:
            return jsonify({"success": False, "error": "Token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"success": False, "error": "Invalid token"}), 401

        # Make user info available to the route
        from flask import g
        g.user = payload
        return f(*args, **kwargs)

    return decorated_function


def create_jwt_token(user_data: dict, secret_key: str) -> str:
    """
    Create a signed JWT token.

    Args:
        user_data: Dict with at least 'user_id'. Additional fields
                   (organization_id, role) are included in the payload.
        secret_key: The application SECRET_KEY for signing.

    Returns:
        Encoded JWT string.
    """
    now = datetime.now(timezone.utc)
    payload = {
        **user_data,
        "iat": now,
        "exp": now + timedelta(hours=JWT_EXPIRY_HOURS),
    }
    return jwt.encode(payload, secret_key, algorithm=JWT_ALGORITHM)

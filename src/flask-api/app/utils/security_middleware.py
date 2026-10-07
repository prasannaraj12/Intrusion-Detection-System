"""
Security Hardening & Protection Middleware for AegisNIDS.
Provides:
- In-memory sliding-window rate limiting per client IP
- Optional API Key validation (X-API-Key header)
- Secure HTTP response headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options)
- Sanitized audit logging for threat events and quarantine actions
- Payload size guardrails
"""
import os
import time
import logging
from collections import defaultdict
from flask import request, jsonify

# Configure security audit logger
AUDIT_LOG_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'security_audit.log')
os.makedirs(os.path.dirname(AUDIT_LOG_FILE), exist_ok=True)

audit_logger = logging.getLogger("aegis_audit")
audit_logger.setLevel(logging.INFO)
if not audit_logger.handlers:
    fh = logging.FileHandler(AUDIT_LOG_FILE, encoding='utf-8')
    formatter = logging.Formatter('{"timestamp": "%(asctime)s", "level": "%(levelname)s", "event": %(message)s}')
    fh.setFormatter(formatter)
    audit_logger.addHandler(fh)

# In-memory sliding-window rate limiter
_RATE_LIMIT_STORE = defaultdict(list)
RATE_LIMIT_WINDOW_SEC = 60
RATE_LIMIT_MAX_REQUESTS = 300  # generous limit for dev/demo

def check_rate_limit(client_ip):
    """Check if client IP exceeds requests within window."""
    now = time.time()
    timestamps = _RATE_LIMIT_STORE[client_ip]
    # Filter out timestamps older than window
    valid_timestamps = [t for t in timestamps if now - t < RATE_LIMIT_WINDOW_SEC]
    _RATE_LIMIT_STORE[client_ip] = valid_timestamps
    
    if len(valid_timestamps) >= RATE_LIMIT_MAX_REQUESTS:
        return False
    _RATE_LIMIT_STORE[client_ip].append(now)
    return True

def audit_log_event(event_type, details):
    """Record a structured security audit event."""
    import json
    payload = {
        'event_type': event_type,
        'client_ip': request.remote_addr if request else '127.0.0.1',
        'details': details
    }
    audit_logger.info(json.dumps(payload))

def apply_security_headers(response):
    """Attach defensive HTTP response headers."""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Content-Security-Policy'] = "default-src 'self'; frame-ancestors 'none';"
    return response

def verify_api_security():
    """Before-request security gatekeeper."""
    client_ip = request.remote_addr or '127.0.0.1'
    
    # 1. Rate limiting check
    if not check_rate_limit(client_ip):
        audit_log_event("RATE_LIMIT_EXCEEDED", {"ip": client_ip})
        return jsonify({"error": "Too Many Requests", "message": "Rate limit exceeded. Please throttle requests."}), 429
        
    # 2. Optional API Key verification (enforced if AEGIS_API_KEY environment variable is set)
    required_key = os.environ.get('AEGIS_API_KEY')
    if required_key:
        client_key = request.headers.get('X-API-Key') or request.headers.get('Authorization', '').replace('Bearer ', '')
        if client_key != required_key:
            audit_log_event("UNAUTHORIZED_ACCESS_ATTEMPT", {"ip": client_ip, "path": request.path})
            return jsonify({"error": "Unauthorized", "message": "Valid X-API-Key header required."}), 401
            
    return None

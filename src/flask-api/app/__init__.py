"""
Flask application factory with security hardening.
"""
from flask import Flask
from flask_cors import CORS
from config import Config
from app.utils.security_middleware import verify_api_security, apply_security_headers

def create_app(config_class=Config):
    """
    Create and configure the Flask application with security guardrails.
    
    Args:
        config_class: Configuration class for the application
        
    Returns:
        Configured Flask application
    """
    app = Flask(__name__)
    app.config.from_object(config_class)
    app.config['MAX_CONTENT_LENGTH'] = 32 * 1024 * 1024  # 32MB max upload limit
    
    # Configure CORS with secure origin handling
    CORS(app, resources={r"/*": {"origins": "*"}})
    
    # Attach security middleware
    app.before_request(verify_api_security)
    app.after_request(apply_security_headers)
    
    # Register blueprints
    from app.routes.prediction_routes import prediction_bp
    app.register_blueprint(prediction_bp)
    
    return app
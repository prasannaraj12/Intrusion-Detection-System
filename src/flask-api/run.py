"""
Entry point for running the Flask application.
"""
import os
from app import create_app

app = create_app()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    print(f"Starting NIDS Layer 1 API on port {port}...")
    app.run(debug=debug, host='0.0.0.0', port=port)
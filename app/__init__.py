"""
Flask application initialization for threat intelligence API
"""
from flask import Flask
from flask_cors import CORS
import os
import logging

def create_app():
    """Create and configure Flask application"""
    app = Flask(__name__)
    
    # Enable CORS for all routes
    CORS(app)
    
    # Configure logging
    logging.basicConfig(level=logging.INFO)
    
    # Import and register routes
    from app.routes import main
    app.register_blueprint(main)
    
    return app

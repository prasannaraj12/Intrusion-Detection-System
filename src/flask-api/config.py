"""
Configuration settings for the application.
"""
import os

class Config:
    """Base configuration class."""
    # Flask settings
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'you-will-never-guess'
    
    # Model settings
    _base_dir = os.path.abspath(os.path.dirname(__file__))
    _default_model = os.path.join(_base_dir, 'app', 'models', 'model.pkl')
    MODEL_PATH = os.environ.get('MODEL_PATH') or _default_model
    
    # Network flow analysis settings
    IDLE_THRESHOLD = 500000  # Microseconds to consider a gap as "idle"
    PREDICTION_THRESHOLD = 0.5  # Probability threshold to classify as an attack
    DEBUG_MODE = True
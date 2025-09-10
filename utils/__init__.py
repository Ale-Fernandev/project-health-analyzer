# utils/__init__.py
# This file makes the utils directory a Python package
# It allows us to import modules from this directory

from .github_analyzer import GitHubAnalyzer
from .security_scanner import SecurityScanner
from .ai_analyzer import AIAnalyzer

# Define what gets imported with "from utils import *"
__all__ = ['GitHubAnalyzer', 'SecurityScanner', 'AIAnalyzer']

# Package version
__version__ = '1.0.0'
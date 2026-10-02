"""
api/index.py

Vercel Serverless Function entry point for FastAPI backend application.
Handles Python path resolution for Vercel serverless environment.
"""

import sys
import os

# Ensure backend directory and parent root are in sys.path
current_dir = os.path.dirname(os.path.abspath(__file__))
backend_dir = os.path.dirname(current_dir)
root_dir = os.path.dirname(backend_dir)

for p in [backend_dir, root_dir, current_dir]:
    if p and p not in sys.path:
        sys.path.insert(0, p)

try:
    from app.main import app
except ModuleNotFoundError:
    from backend.app.main import app

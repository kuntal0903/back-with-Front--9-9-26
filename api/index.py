"""
api/index.py

Root Vercel Serverless Function entry point.
"""

import sys
import os

root_dir = os.path.dirname(os.path.abspath(__file__))
backend_dir = os.path.join(root_dir, "backend")

for p in [backend_dir, root_dir]:
    if p and p not in sys.path:
        sys.path.insert(0, p)

try:
    from app.main import app
except ModuleNotFoundError:
    from backend.app.main import app

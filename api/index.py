import sys
import os

root_dir = os.path.dirname(os.path.abspath(__file__))
backend_dir = os.path.join(os.path.dirname(root_dir), "backend")

for p in [backend_dir, os.path.dirname(root_dir)]:
    if p and p not in sys.path:
        sys.path.insert(0, p)

from app.main import app

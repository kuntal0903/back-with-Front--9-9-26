import sys
import os

# Set up python path for Vercel serverless runtime
root_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(root_dir)
backend_dir = os.path.join(parent_dir, "backend")

for p in [backend_dir, parent_dir]:
    if p and p not in sys.path:
        sys.path.insert(0, p)

from app.main import app

# Export both app and handler for Vercel python builder compatibility
handler = app

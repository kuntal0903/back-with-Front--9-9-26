import sys
import os
import traceback

backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

try:
    from app.main import app
except Exception as e:
    err_msg = traceback.format_exc()
    from fastapi import FastAPI
    from fastapi.responses import PlainTextResponse
    
    app = FastAPI()

    @app.api_route("/{full_path:path}", methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH"])
    async def catch_all_debug(full_path: str):
        return PlainTextResponse(f"VERCEL INIT ERROR:\n\n{err_msg}", status_code=500)

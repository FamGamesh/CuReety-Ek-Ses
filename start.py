#!/usr/bin/env python3
"""
Production startup script for Render.com deployment
This ensures proper uvicorn startup with error handling
"""

import os
import sys
import uvicorn

def main():
    """Start the FastAPI server with production settings"""
    
    # Get port from environment (Render provides this)
    port = int(os.environ.get("PORT", 8000))
    
    # Production configuration
    config = {
        "app": "server:app",
        "host": "0.0.0.0",
        "port": port,
        "workers": 1,  # Single worker for free tier
        "log_level": "info",
        "access_log": True,
    }
    
    print(f"🚀 Starting FastAPI server on port {port}...")
    print(f"🔧 Configuration: {config}")
    
    try:
        uvicorn.run(**config)
    except Exception as e:
        print(f"❌ Server startup failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
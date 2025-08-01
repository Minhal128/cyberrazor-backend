#!/usr/bin/env python3
"""
Debug script to start the backend and show any errors
"""
import sys
import os
import traceback

print("🚀 Starting CyberRazor Backend Debug Mode...")

try:
    # Test imports
    print("📦 Testing imports...")
    from fastapi import FastAPI, HTTPException, Depends, WebSocket, WebSocketDisconnect
    print("✅ FastAPI imported")
    
    from fastapi.middleware.cors import CORSMiddleware
    print("✅ CORS middleware imported")
    
    from pydantic import BaseModel
    print("✅ Pydantic imported")
    
    from typing import List, Optional, Dict, Any
    print("✅ Typing imported")
    
    import asyncio
    import random
    from datetime import datetime, timedelta
    import json
    import sqlite3
    from contextlib import asynccontextmanager
    import uuid
    from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
    print("✅ Standard libraries imported")
    
    from auth import (
        UserCreate, UserLogin, UserResponse, Token, TokenData,
        authenticate_user, create_user, create_access_token, create_refresh_token,
        verify_token, get_user_by_id, get_user_by_email, verify_refresh_token, revoke_refresh_token,
        revoke_all_user_tokens, init_auth_db
    )
    print("✅ Auth module imported")
    
    print("📊 Initializing database...")
    init_auth_db()
    print("✅ Database initialized")
    
    print("🔧 Testing authentication...")
    user = authenticate_user("admin@cyberrazor.com", "admin123")
    if user:
        print(f"✅ Admin user authenticated: {user['username']}")
    else:
        print("❌ Admin user authentication failed")
    
    print("🌐 Starting FastAPI server...")
    import uvicorn
    
    # Import the main app
    from main_simple import app
    
    print("✅ App imported successfully")
    print("🚀 Starting server on http://127.0.0.1:8000")
    
    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="info")
    
except Exception as e:
    print(f"❌ Error: {e}")
    print("📋 Full traceback:")
    traceback.print_exc()
    sys.exit(1) 
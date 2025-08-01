#!/usr/bin/env python3
"""
Simple test server to verify authentication works
"""
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn
import bcrypt
import jwt
import uuid
from datetime import datetime, timedelta
import sqlite3

app = FastAPI()

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://cyberrazor-backend.vercel.app"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Models
class UserLogin(BaseModel):
    email: str
    password: str

# Database setup
def init_db():
    conn = sqlite3.connect('cyberrazor.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_admin BOOLEAN DEFAULT FALSE,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create admin user if not exists
    cursor.execute("SELECT COUNT(*) FROM users WHERE email = 'admin@cyberrazor.com'")
    if cursor.fetchone()[0] == 0:
        admin_password = "admin123"
        password_hash = bcrypt.hashpw(admin_password.encode('utf-8'), bcrypt.gensalt())
        admin_id = str(uuid.uuid4())
        cursor.execute('''
            INSERT INTO users (id, username, email, password_hash, is_admin)
            VALUES (?, ?, ?, ?, ?)
        ''', (admin_id, "admin", "admin@cyberrazor.com", password_hash.decode('utf-8'), True))
    
    conn.commit()
    conn.close()

# Initialize database
init_db()

@app.get("/")
async def root():
    return {"message": "Test server running"}

@app.post("/api/auth/login")
async def login(user_credentials: UserLogin):
    print(f"Login attempt for: {user_credentials.email}")
    
    conn = sqlite3.connect('cyberrazor.db')
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM users WHERE email = ?", (user_credentials.email,))
    user = cursor.fetchone()
    conn.close()
    
    if not user:
        print("User not found")
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Verify password
    if not bcrypt.checkpw(user_credentials.password.encode('utf-8'), user[3].encode('utf-8')):
        print("Invalid password")
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Create token
    token_data = {
        "sub": user[2],  # email
        "user_id": user[0],  # id
        "exp": datetime.utcnow() + timedelta(minutes=30)
    }
    
    token = jwt.encode(token_data, "your-secret-key", algorithm="HS256")
    
    print(f"Login successful for: {user[1]}")
    
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": user[0],
            "username": user[1],
            "email": user[2],
            "is_admin": bool(user[4]),
            "created_at": user[5]
        }
    }

if __name__ == "__main__":
    print("🚀 Starting simple test server on http://127.0.0.1:8000")
    uvicorn.run(app, host="127.0.0.1", port=8000) 
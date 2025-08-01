import jwt
import bcrypt
import sqlite3
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from pydantic import BaseModel
import uuid
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configuration
SECRET_KEY = os.getenv("SECRET_KEY", "your-super-secret-key-change-this-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))

# Pydantic models
class UserCreate(BaseModel):
    username: str
    email: str
    password: str

class UserLogin(BaseModel):
    email: str
    password: str

class UserResponse(BaseModel):
    id: str
    username: str
    email: str
    is_admin: bool
    activation_key: Optional[str] = None
    created_at: str

class Token(BaseModel):
    access_token: str
    token_type: str
    user: UserResponse

class TokenData(BaseModel):
    email: Optional[str] = None

# Database functions
def get_db_connection():
    return sqlite3.connect('cyberrazor.db')

def init_auth_db():
    """Initialize authentication database tables"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Create users table with password hash
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            activation_key TEXT UNIQUE,
            is_admin BOOLEAN DEFAULT FALSE,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            last_login TEXT
        )
    ''')
    
    # Create refresh tokens table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS refresh_tokens (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            token TEXT UNIQUE NOT NULL,
            expires_at TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Insert default admin user if not exists
    cursor.execute("SELECT COUNT(*) FROM users WHERE email = 'admin@cyberrazor.com'")
    if cursor.fetchone()[0] == 0:
        admin_password = "admin123"
        password_hash = bcrypt.hashpw(admin_password.encode('utf-8'), bcrypt.gensalt())
        admin_id = str(uuid.uuid4())
        cursor.execute('''
            INSERT INTO users (id, username, email, password_hash, is_admin, activation_key)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (admin_id, "admin", "admin@cyberrazor.com", password_hash.decode('utf-8'), True, str(uuid.uuid4())))
    
    # Insert default user if not exists
    cursor.execute("SELECT COUNT(*) FROM users WHERE email = 'user@cyberrazor.com'")
    if cursor.fetchone()[0] == 0:
        user_password = "user123"
        password_hash = bcrypt.hashpw(user_password.encode('utf-8'), bcrypt.gensalt())
        user_id = str(uuid.uuid4())
        cursor.execute('''
            INSERT INTO users (id, username, email, password_hash, is_admin, activation_key)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (user_id, "user", "user@cyberrazor.com", password_hash.decode('utf-8'), False, str(uuid.uuid4())))
    
    conn.commit()
    conn.close()

# Authentication functions
def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash"""
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

def get_password_hash(password: str) -> str:
    """Hash a password"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Create a JWT access token"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def create_refresh_token(user_id: str) -> str:
    """Create a refresh token"""
    token = str(uuid.uuid4())
    expires_at = datetime.utcnow() + timedelta(days=7)
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO refresh_tokens (id, user_id, token, expires_at)
        VALUES (?, ?, ?, ?)
    ''', (str(uuid.uuid4()), user_id, token, expires_at.isoformat()))
    conn.commit()
    conn.close()
    
    return token

def verify_token(token: str) -> Optional[Dict[str, Any]]:
    """Verify and decode a JWT token"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            return None
        return payload
    except jwt.PyJWTError:
        return None

def get_user_by_email(email: str) -> Optional[Dict[str, Any]]:
    """Get user by email"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
    user = cursor.fetchone()
    conn.close()
    
    if user:
        return {
            "id": user[0],
            "username": user[1],
            "email": user[2],
            "password_hash": user[3],
            "activation_key": user[4],
            "is_admin": bool(user[5]),
            "created_at": user[6],
            "last_login": user[7] if len(user) > 7 else None
        }
    return None

def get_user_by_id(user_id: str) -> Optional[Dict[str, Any]]:
    """Get user by ID"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    conn.close()
    
    if user:
        return {
            "id": user[0],
            "username": user[1],
            "email": user[2],
            "password_hash": user[3],
            "activation_key": user[4],
            "is_admin": bool(user[5]),
            "created_at": user[6],
            "last_login": user[7] if len(user) > 7 else None
        }
    return None

def create_user(user_data: UserCreate) -> Dict[str, Any]:
    """Create a new user"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Check if user already exists
    cursor.execute("SELECT COUNT(*) FROM users WHERE email = ? OR username = ?", 
                  (user_data.email, user_data.username))
    if cursor.fetchone()[0] > 0:
        conn.close()
        raise ValueError("User with this email or username already exists")
    
    # Create new user
    user_id = str(uuid.uuid4())
    password_hash = get_password_hash(user_data.password)
    activation_key = str(uuid.uuid4())
    
    cursor.execute('''
        INSERT INTO users (id, username, email, password_hash, activation_key, is_admin)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (user_id, user_data.username, user_data.email, password_hash, activation_key, False))
    
    conn.commit()
    conn.close()
    
    return {
        "id": user_id,
        "username": user_data.username,
        "email": user_data.email,
        "is_admin": False,
        "activation_key": activation_key,
        "created_at": datetime.utcnow().isoformat()
    }

def authenticate_user(email: str, password: str) -> Optional[Dict[str, Any]]:
    """Authenticate a user"""
    user = get_user_by_email(email)
    if not user:
        return None
    if not verify_password(password, user["password_hash"]):
        return None
    
    # Update last login
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET last_login = ? WHERE id = ?", 
                  (datetime.utcnow().isoformat(), user["id"]))
    conn.commit()
    conn.close()
    
    return user

def verify_refresh_token(token: str) -> Optional[str]:
    """Verify a refresh token and return user ID"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT user_id FROM refresh_tokens WHERE token = ? AND expires_at > ?", 
                  (token, datetime.utcnow().isoformat()))
    result = cursor.fetchone()
    conn.close()
    
    if result:
        return result[0]
    return None

def revoke_refresh_token(token: str):
    """Revoke a refresh token"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM refresh_tokens WHERE token = ?", (token,))
    conn.commit()
    conn.close()

def revoke_all_user_tokens(user_id: str):
    """Revoke all refresh tokens for a user"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM refresh_tokens WHERE user_id = ?", (user_id,))
    conn.commit()
    conn.close()

# Initialize database on import
init_auth_db() 
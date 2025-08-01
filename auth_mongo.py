"""
MongoDB-based Authentication System
Enterprise-grade authentication for CyberRazor
"""

import jwt
import bcrypt
import uuid
import os
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from pydantic import BaseModel, EmailStr
from dotenv import load_dotenv
from database import db_manager
import smtplib
from email.mime.text import MIMEText as MimeText
from email.mime.multipart import MIMEMultipart as MimeMultipart
import logging

load_dotenv()

# Configuration
SECRET_KEY = os.getenv("SECRET_KEY", "your-super-secret-key-change-this-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))

# Email configuration
SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USERNAME = os.getenv("SMTP_USERNAME", "cyberrazor0123@gmail.com")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "ccgo wpop uqng vjnm")
FROM_EMAIL = os.getenv("FROM_EMAIL", "cyberrazor0123@gmail.com")

logger = logging.getLogger(__name__)

# Pydantic models
class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class UserResponse(BaseModel):
    id: str
    username: str
    email: str
    is_admin: bool
    activation_key: Optional[str] = None
    created_at: str
    last_login: Optional[str] = None

class Token(BaseModel):
    access_token: str
    token_type: str
    user: UserResponse

class TokenData(BaseModel):
    email: Optional[str] = None

class RefreshTokenRequest(BaseModel):
    refresh_token: str

class PasswordChange(BaseModel):
    current_password: str
    new_password: str

class PasswordReset(BaseModel):
    email: EmailStr

class PasswordResetConfirm(BaseModel):
    token: str
    new_password: str

# Authentication functions
def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash"""
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

def get_password_hash(password: str) -> str:
    """Generate password hash"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Create JWT access token"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def create_refresh_token(user_id: str) -> str:
    """Create refresh token"""
    expire = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode = {
        "sub": user_id,
        "type": "refresh",
        "exp": expire
    }
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def verify_token(token: str) -> Optional[Dict[str, Any]]:
    """Verify JWT token"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.PyJWTError:
        return None

async def get_user_by_email(email: str) -> Optional[Dict[str, Any]]:
    """Get user by email from MongoDB"""
    return await db_manager.get_user_by_email(email)

async def get_user_by_id(user_id: str) -> Optional[Dict[str, Any]]:
    """Get user by ID from MongoDB"""
    return await db_manager.get_user_by_id(user_id)

async def create_user(user_data: UserCreate) -> Dict[str, Any]:
    """Create a new user in MongoDB"""
    # Check if user already exists
    existing_user = await get_user_by_email(user_data.email)
    if existing_user:
        raise ValueError("User with this email already exists")
    
    # Generate activation key
    activation_key = str(uuid.uuid4())
    
    # Create user document
    user_doc = {
        "username": user_data.username,
        "email": user_data.email,
        "password_hash": get_password_hash(user_data.password),
        "activation_key": activation_key,
        "is_admin": False,
        "is_active": False,  # User needs to activate via CLI
        "created_at": datetime.utcnow(),
        "last_login": None
    }
    
    # Store in database
    user_id = await db_manager.create_user(user_doc)
    
    # Send activation email
    await send_activation_email(user_data.email, activation_key)
    
    # Return user data (without password)
    user_doc["id"] = user_id
    del user_doc["password_hash"]
    
    return user_doc

async def authenticate_user(email: str, password: str) -> Optional[Dict[str, Any]]:
    """Authenticate user with email and password"""
    user = await get_user_by_email(email)
    if not user:
        return None
    
    if not verify_password(password, user["password_hash"]):
        return None
    
    return user

async def send_activation_email(email: str, activation_key: str):
    """Send activation email to user"""
    try:
        if not SMTP_USERNAME or not SMTP_PASSWORD:
            logger.warning("SMTP credentials not configured, skipping email send")
            return
        
        msg = MimeMultipart()
        msg['From'] = FROM_EMAIL
        msg['To'] = email
        msg['Subject'] = "CyberRazor - Account Activation Required"
        
        body = f"""
        Welcome to CyberRazor!
        
        Your account has been created successfully. To activate your account and start using the CLI tool, please use the following activation key:
        
        Activation Key: {activation_key}
        
        Instructions:
        1. Download and install the CyberRazor CLI agent
        2. Run the agent with: cyberrazor-agent --activate {activation_key}
        3. The agent will automatically connect to the dashboard
        
        If you have any questions, please contact support.
        
        Best regards,
        CyberRazor Team
        """
        
        msg.attach(MimeText(body, 'plain'))
        
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SMTP_USERNAME, SMTP_PASSWORD)
        server.send_message(msg)
        server.quit()
        
        logger.info(f"Activation email sent to {email}")
        
    except Exception as e:
        logger.error(f"Failed to send activation email: {e}")

async def verify_activation_key(activation_key: str) -> Optional[Dict[str, Any]]:
    """Verify activation key and return user"""
    user = await db_manager.db.users.find_one({"activation_key": activation_key})
    if user:
        user["id"] = str(user["_id"])
        del user["_id"]
        return user
    return None

async def activate_user_account(user_id: str):
    """Activate user account"""
    from bson import ObjectId
    await db_manager.db.users.update_one(
        {"_id": ObjectId(user_id)},
        {"$set": {"is_active": True, "activated_at": datetime.utcnow()}}
    )

async def revoke_refresh_token(token: str):
    """Revoke a refresh token"""
    # In a production system, you might want to store revoked tokens
    # For now, we'll rely on token expiration
    pass

async def revoke_all_user_tokens(user_id: str):
    """Revoke all refresh tokens for a user"""
    # In a production system, you might want to store revoked tokens
    # For now, we'll rely on token expiration
    pass

async def create_password_reset_token(email: str) -> Optional[str]:
    """Create password reset token"""
    user = await get_user_by_email(email)
    if not user:
        return None
    
    # Create reset token
    reset_token = str(uuid.uuid4())
    expire_time = datetime.utcnow() + timedelta(hours=1)
    
    # Store reset token in database
    from bson import ObjectId
    await db_manager.db.users.update_one(
        {"_id": ObjectId(user["id"])},
        {"$set": {
            "reset_token": reset_token,
            "reset_token_expires": expire_time
        }}
    )
    
    return reset_token

async def verify_password_reset_token(token: str) -> Optional[Dict[str, Any]]:
    """Verify password reset token"""
    user = await db_manager.db.users.find_one({
        "reset_token": token,
        "reset_token_expires": {"$gt": datetime.utcnow()}
    })
    
    if user:
        user["id"] = str(user["_id"])
        del user["_id"]
        return user
    
    return None

async def reset_user_password(user_id: str, new_password: str):
    """Reset user password"""
    from bson import ObjectId
    password_hash = get_password_hash(new_password)
    
    await db_manager.db.users.update_one(
        {"_id": ObjectId(user_id)},
        {"$set": {
            "password_hash": password_hash,
            "reset_token": None,
            "reset_token_expires": None
        }}
    ) 
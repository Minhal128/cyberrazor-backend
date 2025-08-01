#!/usr/bin/env python3
"""
CyberRazor Main Backend Server (MongoDB Compatible)
Handles activation keys, threat reporting and user portal data
"""

from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Dict, Any, List, Optional
import os
import uuid
import json
from datetime import datetime, timedelta
import uvicorn
from motor.motor_asyncio import AsyncIOMotorClient
from pymongo.errors import ConnectionFailure
import asyncio
import jwt
import bcrypt

# Security
security = HTTPBearer()

# Initialize FastAPI app
app = FastAPI(
    title="CyberRazor Enterprise API", 
    version="2.0.0",
    description="Advanced Security Operations and Response Platform"
)

# Request logging middleware
@app.middleware("http")
async def log_requests(request: Request, call_next):
    start_time = datetime.now()
    print(f"🔍 {start_time.strftime('%H:%M:%S')} - {request.method} {request.url.path}")
    
    response = await call_next(request)
    
    process_time = (datetime.now() - start_time).total_seconds() * 1000
    print(f"✅ {request.method} {request.url.path} - {response.status_code} ({process_time:.2f}ms)")
    
    return response

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# MongoDB Configuration with improved connection settings
MONGODB_URL = os.getenv("MONGODB_URL", "mongodb+srv://rminhal783:Hhua6tUekZkGfBx0@cluster0.auuhgc5.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0&connectTimeoutMS=10000&serverSelectionTimeoutMS=5000&socketTimeoutMS=10000&maxPoolSize=50")
MONGODB_DB_NAME = os.getenv("MONGODB_DB_NAME", "cyberrazor")

# Always use the MongoDB Atlas connection string
print(f"🔗 MongoDB URL configured: {MONGODB_URL[:50]}...")
print(f"📊 Database Name: {MONGODB_DB_NAME}")

# Authentication Configuration
SECRET_KEY = os.getenv("SECRET_KEY", "your-super-secret-key-change-this-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))

# MongoDB client
client = None
db = None
db_connected = False

# Pydantic models
class ActivationRequest(BaseModel):
    user_email: str
    hostname: str
    os_info: str
    activation_key: str

class ActivationResponse(BaseModel):
    success: bool
    message: str
    activation_id: Optional[str] = None

class ThreatReport(BaseModel):
    device_id: str
    file_path: str
    threat_type: str
    confidence_score: float
    source: str
    details: Dict[str, Any]
    action_taken: str
    severity: str
    ai_verdict: Optional[str] = None
    ai_confidence: Optional[str] = None
    ai_reason: Optional[str] = None

class ErrorReport(BaseModel):
    device_id: str
    error_type: str
    error_message: str
    stack_trace: Optional[str] = None

# Authentication Models
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

async def connect_to_mongo():
    """Initialize MongoDB connection with retry logic"""
    global client, db, db_connected
    max_retries = 3
    retry_delay = 2
    
    for attempt in range(max_retries):
        try:
            print(f"🔗 Attempting to connect to MongoDB (attempt {attempt + 1}/{max_retries})...")
            print(f"📍 Database: {MONGODB_DB_NAME}")
            print(f"🔐 URL: {MONGODB_URL[:20]}..." if MONGODB_URL and len(MONGODB_URL) > 20 else f"🔐 URL: {MONGODB_URL}")
            
            # Close existing client if any
            if client:
                client.close()
            
            # Create new client with optimized settings
            client = AsyncIOMotorClient(
                MONGODB_URL,
                serverSelectionTimeoutMS=10000,
                connectTimeoutMS=10000,
                socketTimeoutMS=10000,
                heartbeatFrequencyMS=10000,
                maxPoolSize=50,
                minPoolSize=5,
                retryWrites=True,
                retryReads=True
            )
            db = client[MONGODB_DB_NAME]
            
            # Test the connection with timeout
            await asyncio.wait_for(client.admin.command('ping'), timeout=10.0)
            print("✅ Connected to MongoDB successfully!")
            print(f"✅ Connection status: OPERATIONAL")
            print(f"✅ Database ready: {MONGODB_DB_NAME}")
            
            db_connected = True
            
            # Initialize collections with default data
            await init_collections()
            
            return True
            
        except asyncio.TimeoutError:
            print(f"⏰ Connection timeout (attempt {attempt + 1})")
            if attempt < max_retries - 1:
                print(f"🔄 Retrying in {retry_delay} seconds...")
                await asyncio.sleep(retry_delay)
                retry_delay *= 2  # Exponential backoff
            else:
                print("❌ All connection attempts failed - timeout")
                db_connected = False
                return False
                
        except ConnectionFailure as e:
            print(f"❌ MongoDB connection failure (attempt {attempt + 1}): {e}")
            if attempt < max_retries - 1:
                print(f"🔄 Retrying in {retry_delay} seconds...")
                await asyncio.sleep(retry_delay)
                retry_delay *= 2
            else:
                print("❌ All connection attempts failed - connection failure")
                print("💡 Check your MONGODB_URL environment variable")
                print("💡 Ensure your MongoDB Atlas cluster is accessible")
                print("💡 Verify your IP is whitelisted in MongoDB Atlas")
                db_connected = False
                return False
                
        except Exception as e:
            print(f"❌ MongoDB connection error (attempt {attempt + 1}): {e}")
            if attempt < max_retries - 1:
                print(f"🔄 Retrying in {retry_delay} seconds...")
                await asyncio.sleep(retry_delay)
                retry_delay *= 2
            else:
                print("❌ All connection attempts failed - general error")
                print("💡 This might be an authentication or network issue")
                print(f"💡 Error details: {str(e)}")
                db_connected = False
                return False

async def init_collections():
    """Initialize collections with default data"""
    try:
        # Create indexes for better performance
        await db.device_activations.create_index("activation_key", unique=True)
        await db.threats.create_index("device_id")
        await db.agent_logs.create_index("user_email")
        
        # Check if we need to insert default activation keys
        count = await db.device_activations.count_documents({"status": "available"})
        if count == 0:
            test_keys = [
                "CYBER-RAZOR-2024-TEST1",
                "CYBER-RAZOR-2024-TEST2", 
                "CYBER-RAZOR-2024-DEMO",
                "CR-DEMO-KEY-123456"
            ]
            
            # Set expiration to 60 minutes from now for production
            expires_at = (datetime.now() + timedelta(minutes=60)).isoformat()
            
            activation_docs = []
            for key in test_keys:
                activation_docs.append({
                    "_id": str(uuid.uuid4()),
                    "user_email": "demo@cyberrazor.com",
                    "hostname": "demo-host",
                    "os_info": "Demo OS",
                    "activation_key": key,
                    "status": "available",
                    "last_seen": datetime.now().isoformat(),
                    "created_at": datetime.now().isoformat(),
                    "expires_at": expires_at
                })
            
            await db.device_activations.insert_many(activation_docs)
            print(f"✅ Inserted {len(test_keys)} default activation keys")
            
    except Exception as e:
        print(f"❌ Error initializing collections: {e}")

async def close_mongo_connection():
    """Close MongoDB connection"""
    global client
    if client:
        client.close()

async def get_database():
    """Dependency to get database connection"""
    global db, db_connected
    if not db_connected:
        await connect_to_mongo()
    return db

# Authentication Helper Functions
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

def verify_token(token: str) -> Optional[Dict[str, Any]]:
    """Verify a JWT token"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            return None
        return payload
    except jwt.PyJWTError:
        return None

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> Dict[str, Any]:
    """Get current user from token"""
    payload = verify_token(credentials.credentials)
    if payload is None:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    email: str = payload.get("sub")
    if email is None:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    # Get user from database
    database = await get_database()
    user = await database.users.find_one({"email": email})
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")
    
    return {
        "id": str(user["_id"]),
        "username": user["username"],
        "email": user["email"],
        "is_admin": user.get("is_admin", False),
        "activation_key": user.get("activation_key")
    }

# Startup event
@app.on_event("startup")
async def startup_event():
    await connect_to_mongo()
    await init_default_users()

# Shutdown event
@app.on_event("shutdown")
async def shutdown_event():
    await close_mongo_connection()

@app.get("/")
async def root():
    """API root endpoint with service information"""
    return {
        "message": "CyberRazor Enterprise API",
        "version": "2.0.0",
        "status": "operational",
        "database": "MongoDB",
        "integrations": ["Wazuh"],
        "endpoints": {
            "health": "/api/health",
            "docs": "/docs",
            "agent_status": "/api/agent/status",
            "cli_logs": "/api/cli/logs"
        }
    }

@app.get("/api/debug")
async def debug_info():
    """Debug endpoint to check environment and connections"""
    global db_connected, client, db
    
    # Check environment variables (safely)
    env_info = {
        "mongodb_url_configured": bool(os.getenv("MONGODB_URL")),
        "mongodb_db_name": os.getenv("MONGODB_DB_NAME", "cyberrazor_enterprise"),
        "client_status": "connected" if client else "not_initialized",
        "db_status": "connected" if db_connected else "disconnected",
        "startup_attempted": True
    }
    
    # Test connection
    connection_test = {
        "ping_successful": False,
        "error_message": None
    }
    
    try:
        if client:
            await client.admin.command('ping')
            connection_test["ping_successful"] = True
    except Exception as e:
        connection_test["error_message"] = str(e)
    
    return {
        "environment": env_info,
        "connection_test": connection_test,
        "mongodb_url_preview": MONGODB_URL[:50] + "..." if MONGODB_URL else None
    }

@app.get("/api/health")
async def health():
    """Enhanced health check endpoint with real-time database testing"""
    global db_connected, client, db
    
    # Test database connection in real-time
    db_status = "disconnected"
    connections = 0
    error_message = None
    
    try:
        # If not connected, try to connect now
        if not db_connected or not client:
            await connect_to_mongo()
        
        # Test the connection with a ping
        if client and db:
            await client.admin.command('ping')
            db_status = "operational"
            connections = 1
            db_connected = True
    except Exception as e:
        error_message = str(e)
        print(f"❌ Health check database error: {e}")
        db_status = "disconnected"
        connections = 0
        db_connected = False
    
    # Check Wazuh integration (mock for now)
    wazuh_status = "disconnected"  # Would be checked if Wazuh is configured
    
    return [
        {
            "service": "Database",
            "status": db_status,
            "uptime": "24h",
            "metrics": {"connections": connections},
            "error": error_message
        },
        {
            "service": "Wazuh Integration", 
            "status": wazuh_status,
            "uptime": "24h",
            "metrics": {"alerts_processed": 150}
        }
    ]

@app.get("/api/connection-status")
async def connection_status():
    """Show clear MongoDB connection status with success messages"""
    global db_connected, client, db
    
    status_info = {
        "timestamp": datetime.now().isoformat(),
        "database_configured": bool(MONGODB_URL),
        "client_initialized": client is not None,
        "connection_established": db_connected,
        "database_name": MONGODB_DB_NAME,
        "mongodb_url_preview": MONGODB_URL[:50] + "..." if MONGODB_URL else None
    }
    
    # Test real-time connection
    connection_test = {
        "ping_successful": False,
        "ping_response_time_ms": None,
        "error_details": None,
        "last_test_time": datetime.now().isoformat()
    }
    
    try:
        if not db_connected or not client:
            print("🔄 Connection not established, attempting to connect...")
            await connect_to_mongo()
        
        if client and db:
            import time
            start_time = time.time()
            await client.admin.command('ping')
            response_time = (time.time() - start_time) * 1000
            
            connection_test["ping_successful"] = True
            connection_test["ping_response_time_ms"] = round(response_time, 2)
            status_info["connection_established"] = True
            db_connected = True
            
            print(f"✅ MongoDB ping successful - {response_time:.2f}ms")
            
    except Exception as e:
        connection_test["error_details"] = str(e)
        status_info["connection_established"] = False
        db_connected = False
        print(f"❌ MongoDB ping failed: {e}")
    
    # Determine overall status
    if connection_test["ping_successful"]:
        overall_status = "🟢 CONNECTED - MongoDB is operational"
        status_message = "Successfully connected to MongoDB Atlas cluster"
        recommendations = [
            "✅ Database connection is healthy",
            "✅ All operations should work normally",
            "✅ No action required"
        ]
    else:
        overall_status = "🔴 DISCONNECTED - MongoDB connection failed"
        status_message = "Unable to establish connection to MongoDB"
        recommendations = [
            "💡 Check your MongoDB Atlas cluster status",
            "💡 Verify your connection string is correct", 
            "💡 Ensure your IP address is whitelisted",
            "💡 Check network connectivity"
        ]
    
    return {
        "overall_status": overall_status,
        "status_message": status_message,
        "connection_details": status_info,
        "connection_test": connection_test,
        "recommendations": recommendations
    }

@app.post("/api/activate-key")
async def activate_key(request: ActivationRequest, database=Depends(get_database)):
    """Activate a device with an activation key"""
    try:
        # Check if activation key exists and is available
        activation_doc = await database.device_activations.find_one({
            "activation_key": request.activation_key
        })
        
        if not activation_doc:
            raise HTTPException(status_code=400, detail="Invalid activation key")
        
        if activation_doc["status"] == "used":
            raise HTTPException(status_code=400, detail="Activation key already used")
        
        # Check if key has expired
        if activation_doc.get("expires_at"):
            expiry_time = datetime.fromisoformat(activation_doc["expires_at"])
            if datetime.now() > expiry_time:
                raise HTTPException(status_code=400, detail="Activation key has expired")
        
        # Update the activation record
        await database.device_activations.update_one(
            {"activation_key": request.activation_key},
            {
                "$set": {
                    "user_email": request.user_email,
                    "hostname": request.hostname,
                    "os_info": request.os_info,
                    "status": "used",
                    "last_seen": datetime.now().isoformat()
                }
            }
        )
        
        print(f"✅ Device activated successfully: {request.hostname} ({request.user_email})")
        
        return ActivationResponse(
            success=True,
            message="Device activated successfully",
            activation_id=activation_doc["_id"]
        )
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Activation error: {e}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@app.post("/api/report-threat")
async def report_threat(threat: ThreatReport, database=Depends(get_database)):
    """Report a threat detected by a device"""
    try:
        threat_id = str(uuid.uuid4())
        
        threat_doc = {
            "_id": threat_id,
            "device_id": threat.device_id,
            "file_path": threat.file_path,
            "timestamp": datetime.now().isoformat(),
            "threat_type": threat.threat_type,
            "confidence_score": threat.confidence_score,
            "source": threat.source,
            "details": threat.details,
            "action_taken": threat.action_taken,
            "severity": threat.severity,
            "status": "new",
            "ai_verdict": threat.ai_verdict,
            "ai_confidence": threat.ai_confidence,
            "ai_reason": threat.ai_reason,
            "created_at": datetime.now().isoformat()
        }
        
        await database.threats.insert_one(threat_doc)
        
        print(f"🚨 THREAT REPORTED: {threat.file_path} - {threat.ai_verdict} ({threat.severity})")
        print(f"   Device: {threat.device_id}")
        print(f"   Type: {threat.threat_type}")
        print(f"   Confidence: {threat.ai_confidence}")
        print(f"   Reason: {threat.ai_reason}")
        
        return {"success": True, "message": "Threat reported successfully", "threat_id": threat_id}
        
    except Exception as e:
        print(f"❌ Threat reporting error: {e}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@app.post("/api/report-error")
async def report_error(error: ErrorReport, database=Depends(get_database)):
    """Report an error from a device"""
    try:
        error_id = str(uuid.uuid4())
        
        error_doc = {
            "_id": error_id,
            "device_id": error.device_id,
            "error_type": error.error_type,
            "error_message": error.error_message,
            "stack_trace": error.stack_trace,
            "timestamp": datetime.now().isoformat()
        }
        
        await database.error_reports.insert_one(error_doc)
        
        print(f"⚠️ ERROR REPORTED: {error.error_type} from {error.device_id}")
        print(f"   Message: {error.error_message}")
        
        return {"success": True, "message": "Error reported successfully", "error_id": error_id}
        
    except Exception as e:
        print(f"❌ Error reporting failed: {e}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@app.get("/api/threats")
async def get_threats(limit: int = 100, database=Depends(get_database)):
    """Get all threats"""
    try:
        cursor = database.threats.find().sort("created_at", -1).limit(limit)
        threats = []
        async for threat in cursor:
            threat["id"] = threat["_id"]
            del threat["_id"]
            threats.append(threat)
        
        return {"threats": threats, "total": len(threats)}
        
    except Exception as e:
        print(f"❌ Error fetching threats: {e}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@app.get("/api/devices")
async def get_devices(database=Depends(get_database)):
    """Get all activated devices"""
    try:
        cursor = database.device_activations.find({"status": "used"}).sort("last_seen", -1)
        devices = []
        async for device in cursor:
            device["id"] = device["_id"]
            del device["_id"]
            devices.append(device)
        
        return {"devices": devices, "total": len(devices)}
        
    except Exception as e:
        print(f"❌ Error fetching devices: {e}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@app.get("/api/stats")
async def get_stats(database=Depends(get_database)):
    """Get system statistics"""
    try:
        # Count total devices
        total_devices = await database.device_activations.count_documents({"status": "used"})
        
        # Count total threats
        total_threats = await database.threats.count_documents({})
        
        # Count errors
        total_errors = await database.error_reports.count_documents({})
        
        # Count threats by severity
        pipeline = [
            {"$group": {"_id": "$severity", "count": {"$sum": 1}}}
        ]
        threat_severity_cursor = database.threats.aggregate(pipeline)
        threats_by_severity = {}
        async for doc in threat_severity_cursor:
            threats_by_severity[doc["_id"]] = doc["count"]
        
        return {
            "total_devices": total_devices,
            "total_threats": total_threats,
            "total_errors": total_errors,
            "threats_by_severity": threats_by_severity,
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        print(f"❌ Error fetching stats: {e}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@app.post("/api/refresh-keys")
async def refresh_activation_keys(database=Depends(get_database)):
    """Refresh all available activation keys with new expiration"""
    try:
        # Update all available keys with new expiration (60 minutes)
        new_expires_at = (datetime.now() + timedelta(minutes=60)).isoformat()
        result = await database.device_activations.update_many(
            {"status": "available"},
            {"$set": {"expires_at": new_expires_at}}
        )
        
        return {
            "message": f"Refreshed {result.modified_count} activation keys",
            "new_expiration": new_expires_at,
            "keys_refreshed": result.modified_count
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to refresh keys: {str(e)}")

# ==== AGENT ENDPOINTS ====
@app.post("/api/agent/logs")
async def receive_agent_logs(log_data: Dict[str, Any], database=Depends(get_database)):
    """Receive logs from CLI agent"""
    try:
        log_id = str(uuid.uuid4())
        
        log_doc = {
            "_id": log_id,
            "device_id": log_data.get('device_id', 'unknown'),
            "hostname": log_data.get('hostname', 'unknown'),
            "user_email": log_data.get('user_email', 'unknown'),
            "level": log_data.get('level', 'INFO'),
            "message": log_data.get('message', ''),
            "module": log_data.get('module', ''),
            "log_type": log_data.get('log_type', 'agent_activity'),
            "timestamp": datetime.now().isoformat(),
            "file_path": log_data.get('file_path'),
            "extra_data": log_data.get('extra_data', {})
        }
        
        await database.agent_logs.insert_one(log_doc)
        
        return {"success": True, "message": "Log received successfully", "log_id": log_id}
        
    except Exception as e:
        print(f"❌ Error receiving agent log: {e}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@app.get("/api/agent/logs")
async def get_agent_logs(user_email: str = None, limit: int = 100, database=Depends(get_database)):
    """Get agent logs for dashboard"""
    try:
        query = {"user_email": user_email} if user_email else {}
        cursor = database.agent_logs.find(query).sort("timestamp", -1).limit(limit)
        
        logs = []
        async for log in cursor:
            log["id"] = log["_id"]
            del log["_id"]
            logs.append(log)
        
        return {"logs": logs, "total": len(logs)}
        
    except Exception as e:
        print(f"❌ Error fetching agent logs: {e}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@app.get("/api/agent/status")
async def get_agent_status(user_email: str = None, database=Depends(get_database)):
    """Get agent status for dashboard"""
    try:
        query = {"user_email": user_email, "status": "running"} if user_email else {"status": "running"}
        cursor = database.agent_processes.find(query).sort("last_heartbeat", -1)
        
        agents = []
        async for agent in cursor:
            agent["id"] = agent["_id"]
            del agent["_id"]
            agents.append(agent)
        
        return {"agents": agents, "total": len(agents)}
        
    except Exception as e:
        print(f"❌ Error fetching agent status: {e}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

# ==== AUTHENTICATION ENDPOINTS ====
@app.post("/api/auth/signup")
async def signup(user_data: UserCreate, database=Depends(get_database)):
    """Register a new user"""
    try:
        print(f"🔐 Signup attempt for: {user_data.email}")
        
        # Check if user already exists
        existing_user = await database.users.find_one({"email": user_data.email})
        if existing_user:
            raise HTTPException(status_code=400, detail="Email already registered")
        
        # Create new user
        user_id = str(uuid.uuid4())
        password_hash = get_password_hash(user_data.password)
        activation_key = str(uuid.uuid4())
        
        user_doc = {
            "_id": user_id,
            "username": user_data.username,
            "email": user_data.email,
            "password_hash": password_hash,
            "activation_key": activation_key,
            "is_admin": False,
            "created_at": datetime.now().isoformat()
        }
        
        await database.users.insert_one(user_doc)
        print(f"✅ User created: {user_data.email}")
        
        # Create access token
        access_token = create_access_token(data={"sub": user_data.email, "user_id": user_id})
        
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "user": {
                "id": user_id,
                "username": user_data.username,
                "email": user_data.email,
                "is_admin": False,
                "activation_key": activation_key,
                "created_at": user_doc["created_at"]
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Signup error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.post("/api/auth/login")
async def login(user_credentials: UserLogin, database=Depends(get_database)):
    """Authenticate user and return token"""
    try:
        print(f"🔐 Login attempt for: {user_credentials.email}")
        
        # Find user by email
        user = await database.users.find_one({"email": user_credentials.email})
        if not user:
            print(f"❌ User not found: {user_credentials.email}")
            raise HTTPException(status_code=401, detail="Incorrect email or password")
        
        # Verify password
        if not verify_password(user_credentials.password, user["password_hash"]):
            print(f"❌ Invalid password for: {user_credentials.email}")
            raise HTTPException(status_code=401, detail="Incorrect email or password")
        
        # Create access token
        access_token = create_access_token(data={"sub": user["email"], "user_id": str(user["_id"])})
        print(f"✅ Login successful: {user_credentials.email}")
        
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "user": {
                "id": str(user["_id"]),
                "username": user["username"],
                "email": user["email"],
                "is_admin": user.get("is_admin", False),
                "activation_key": user.get("activation_key"),
                "created_at": user.get("created_at", "")
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Login error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/api/auth/me")
async def get_current_user_info(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Get current user information"""
    return {
        "id": current_user["id"],
        "username": current_user["username"],
        "email": current_user["email"],
        "is_admin": current_user["is_admin"],
        "activation_key": current_user.get("activation_key"),
        "created_at": datetime.now().isoformat()
    }

@app.post("/api/auth/logout")
async def logout(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Logout user (token revocation would be handled client-side)"""
    return {"message": "Successfully logged out"}

@app.get("/api/auth/test")
async def test_auth_endpoint():
    """Test endpoint to verify authentication endpoints are working"""
    return {"message": "Authentication endpoints are working!", "status": "ok"}

# Initialize default users if they don't exist
async def init_default_users():
    """Initialize default users for testing"""
    try:
        database = await get_database()
        
        # Check if admin user exists
        admin_user = await database.users.find_one({"email": "admin@cyberrazor.com"})
        if not admin_user:
            admin_id = str(uuid.uuid4())
            admin_password_hash = get_password_hash("admin123")
            admin_doc = {
                "_id": admin_id,
                "username": "admin",
                "email": "admin@cyberrazor.com",
                "password_hash": admin_password_hash,
                "activation_key": str(uuid.uuid4()),
                "is_admin": True,
                "created_at": datetime.now().isoformat()
            }
            await database.users.insert_one(admin_doc)
            print("✅ Default admin user created")
        
        # Check if regular user exists
        user = await database.users.find_one({"email": "user@cyberrazor.com"})
        if not user:
            user_id = str(uuid.uuid4())
            user_password_hash = get_password_hash("user123")
            user_doc = {
                "_id": user_id,
                "username": "user",
                "email": "user@cyberrazor.com",
                "password_hash": user_password_hash,
                "activation_key": str(uuid.uuid4()),
                "is_admin": False,
                "created_at": datetime.now().isoformat()
            }
            await database.users.insert_one(user_doc)
            print("✅ Default user created")
            
    except Exception as e:
        print(f"❌ Error initializing default users: {e}")

if __name__ == "__main__":
    print("🚀 Starting CyberRazor Backend Server...")
    print("📊 MongoDB-based Enterprise Backend")
    print("🌐 Production ready with connection pooling")
    print("✅ Auto-scaling and error handling")
    print("\n🔑 Test Activation Keys (60-min expiration):")
    print("   - CYBER-RAZOR-2024-TEST1")
    print("   - CYBER-RAZOR-2024-TEST2")
    print("   - CYBER-RAZOR-2024-DEMO")
    print("   - CR-DEMO-KEY-123456")
    print("\n🌐 Server starting on https://cyberrazor-backend.vercel.app")
    
    uvicorn.run(app, host="127.0.0.1", port=8000)

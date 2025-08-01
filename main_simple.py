from fastapi import FastAPI, HTTPException, Depends, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
import asyncio
import random
from datetime import datetime, timedelta
import json
import sqlite3
from contextlib import asynccontextmanager
import uuid
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from auth import (
    UserCreate, UserLogin, UserResponse, Token, TokenData,
    authenticate_user, create_user, create_access_token, create_refresh_token,
    verify_token, get_user_by_id, get_user_by_email, verify_refresh_token, revoke_refresh_token,
    revoke_all_user_tokens
)

# Security
security = HTTPBearer()

# WebSocket connection manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def send_personal_message(self, message: str, websocket: WebSocket):
        await websocket.send_text(message)

    async def broadcast(self, message: str):
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except:
                # Remove dead connections
                self.active_connections.remove(connection)

manager = ConnectionManager()

# Database initialization
def init_db():
    # Initialize auth database
    init_auth_db()
    conn = sqlite3.connect('cyberrazor.db')
    cursor = conn.cursor()
    
    # Create threats table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS threats (
            id TEXT PRIMARY KEY,
            device_id TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            threat_type TEXT NOT NULL,
            confidence_score REAL NOT NULL,
            source TEXT NOT NULL,
            details TEXT NOT NULL,
            action_taken TEXT NOT NULL,
            severity TEXT NOT NULL,
            status TEXT DEFAULT 'new',
            ai_verdict TEXT,
            ai_confidence TEXT,
            ai_reason TEXT,
            user_feedback TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            activation_key TEXT UNIQUE NOT NULL,
            is_admin BOOLEAN DEFAULT FALSE,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create device_activations table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS device_activations (
            id TEXT PRIMARY KEY,
            user_email TEXT NOT NULL,
            hostname TEXT NOT NULL,
            os_info TEXT NOT NULL,
            activation_key TEXT NOT NULL,
            status TEXT DEFAULT 'active',
            last_seen TEXT DEFAULT CURRENT_TIMESTAMP,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create error_reports table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS error_reports (
            id TEXT PRIMARY KEY,
            device_id TEXT NOT NULL,
            error_type TEXT NOT NULL,
            error_message TEXT NOT NULL,
            stack_trace TEXT,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create refresh tokens table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS refresh_tokens (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            token TEXT UNIQUE NOT NULL,
            expires_at TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    conn.commit()
    conn.close()

# Initialize database on startup
init_db()

app = FastAPI(title="Cyber Razor SOAR API", version="1.0.0")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Dependency to get current user
async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> Dict[str, Any]:
    token = credentials.credentials
    payload = verify_token(token)
    if payload is None:
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")
    
    email = payload.get("sub")
    if email is None:
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")
    
    user = get_user_by_id(payload.get("user_id"))
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")
    
    return user

# Pydantic models
class SystemHealth(BaseModel):
    service: str
    status: str
    uptime: str
    metrics: Dict[str, Any]

class Alert(BaseModel):
    id: str
    severity: str
    source: str
    description: str
    timestamp: str
    status: str
    details: Optional[Dict[str, Any]] = None

class ThreatReport(BaseModel):
    device_id: str
    timestamp: str
    threat_type: str
    confidence_score: float
    source: str
    details: Dict[str, Any]
    action_taken: str
    severity: str

class Playbook(BaseModel):
    id: str
    name: str
    description: str
    status: str
    executions: int
    created_at: str
    updated_at: str

class Integration(BaseModel):
    name: str
    status: str
    last_sync: str
    configuration: Dict[str, Any]

class DatabaseTable(BaseModel):
    name: str
    rows: int
    size: str
    last_updated: str

class User(BaseModel):
    username: str
    email: str
    activation_key: str
    is_admin: bool = False

class DeviceActivation(BaseModel):
    user_email: str
    hostname: str
    os_info: str
    activation_key: str

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

class UserFeedback(BaseModel):
    threat_id: str
    feedback: str  # "false_positive" or "true_positive"

# Database functions
def get_db_connection():
    return sqlite3.connect('cyberrazor.db')

def store_threat(threat: ThreatReport):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    threat_id = str(uuid.uuid4())
    cursor.execute('''
        INSERT INTO threats (id, device_id, timestamp, threat_type, confidence_score, 
                           source, details, action_taken, severity, ai_verdict, ai_confidence, ai_reason)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        threat_id, threat.device_id, threat.timestamp, threat.threat_type, 
        threat.confidence_score, threat.source, json.dumps(threat.details), 
        threat.action_taken, threat.severity, threat.ai_verdict, threat.ai_confidence, threat.ai_reason
    ))
    
    conn.commit()
    conn.close()
    return threat_id

def store_device_activation(activation: DeviceActivation):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    activation_id = str(uuid.uuid4())
    cursor.execute('''
        INSERT INTO device_activations (id, user_email, hostname, os_info, activation_key)
        VALUES (?, ?, ?, ?, ?)
    ''', (
        activation_id, activation.user_email, activation.hostname, 
        activation.os_info, activation.activation_key
    ))
    
    conn.commit()
    conn.close()
    return activation_id

def store_error_report(error: ErrorReport):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    error_id = str(uuid.uuid4())
    cursor.execute('''
        INSERT INTO error_reports (id, device_id, error_type, error_message, stack_trace)
        VALUES (?, ?, ?, ?, ?)
    ''', (
        error_id, error.device_id, error.error_type, 
        error.error_message, error.stack_trace
    ))
    
    conn.commit()
    conn.close()
    return error_id

def update_threat_feedback(threat_id: str, feedback: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        UPDATE threats SET user_feedback = ? WHERE id = ?
    ''', (feedback, threat_id))
    
    conn.commit()
    conn.close()

def get_device_activations():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT id, user_email, hostname, os_info, status, last_seen, created_at
        FROM device_activations ORDER BY created_at DESC
    ''')
    
    rows = cursor.fetchall()
    conn.close()
    
    return [
        {
            "id": row[0],
            "user_email": row[1],
            "hostname": row[2],
            "os_info": row[3],
            "status": row[4],
            "last_seen": row[5],
            "timestamp": row[6]
        }
        for row in rows
    ]

def get_ai_verdicts():
    """Get AI verdicts from database"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT id, device_id, file_path, threat_type, confidence_score, source, 
               action_taken, severity, ai_verdict, ai_confidence, ai_reason, 
               user_feedback, timestamp, created_at
        FROM threats 
        WHERE ai_verdict IS NOT NULL
        ORDER BY created_at DESC
        LIMIT 100
    ''')
    
    rows = cursor.fetchall()
    conn.close()
    
    return [
        {
            "id": row[0],
            "device_id": row[1],
            "file_path": row[2],
            "threat_type": row[3],
            "confidence_score": row[4],
            "source": row[5],
            "action_taken": row[6],
            "severity": row[7],
            "ai_verdict": row[8],
            "ai_confidence": row[9],
            "ai_reason": row[10],
            "user_feedback": row[11],
            "timestamp": row[12],
            "created_at": row[13]
        }
        for row in rows
    ]

def get_system_stats():
    """Get real-time system statistics"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get threat statistics
    cursor.execute('SELECT COUNT(*) FROM threats')
    total_threats = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM threats WHERE status = "active"')
    active_threats = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM threats WHERE action_taken = "blocked"')
    blocked_threats = cursor.fetchone()[0]
    
    # Get device activations
    cursor.execute('SELECT COUNT(*) FROM device_activations WHERE status = "active"')
    active_devices = cursor.fetchone()[0]
    
    # Calculate network traffic (simulated based on threats)
    network_traffic = total_threats * 50 + random.randint(100, 500)
    
    # Calculate anomalies (based on recent threats)
    cursor.execute('SELECT COUNT(*) FROM threats WHERE created_at > datetime("now", "-1 hour")')
    recent_threats = cursor.fetchone()[0]
    anomalies = recent_threats + random.randint(0, 10)
    
    conn.close()
    
    return {
        "totalThreats": total_threats,
        "activeThreats": active_threats,
        "blockedThreats": blocked_threats,
        "networkTraffic": network_traffic,
        "anomalies": anomalies,
        "activeDevices": active_devices,
        "timestamp": datetime.utcnow().isoformat()
    }

def get_network_stats():
    """Get real-time network statistics"""
    stats = get_system_stats()
    
    return {
        "totalTraffic": stats["networkTraffic"],
        "activeConnections": stats["activeDevices"] * 3 + random.randint(5, 20),
        "blockedAttempts": stats["blockedThreats"],
        "anomalies": stats["anomalies"],
        "timestamp": datetime.utcnow().isoformat()
    }

async def broadcast_stats():
    """Broadcast real-time stats to all connected clients"""
    while True:
        try:
            stats = get_system_stats()
            network_stats = get_network_stats()
            
            # Broadcast system stats
            await manager.broadcast(json.dumps({
                "type": "stats",
                "data": stats
            }))
            
            # Broadcast network stats
            await manager.broadcast(json.dumps({
                "type": "network", 
                "data": network_stats
            }))
            
            await asyncio.sleep(5)  # Update every 5 seconds
            
        except Exception as e:
            print(f"Error broadcasting stats: {e}")
            await asyncio.sleep(10)

# Start background task for real-time stats
@app.on_event("startup")
async def startup_event():
    asyncio.create_task(broadcast_stats())

# WebSocket endpoints
@app.websocket("/ws/events")
async def websocket_events(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # Keep connection alive
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

# API endpoints
@app.get("/")
async def read_root():
    return {"message": "Cyber Razor SOAR API", "version": "1.0.0"}

@app.get("/api/health")
async def get_system_health():
    return [
        {
            "service": "API Server",
            "status": "healthy",
            "uptime": "24h 30m",
            "metrics": {"requests_per_minute": 150, "error_rate": 0.02}
        }
    ]

@app.post("/api/activate-key")
async def activate_device(activation: DeviceActivation):
    """Activate a device with activation key"""
    try:
        # Store device activation
        activation_id = store_device_activation(activation)
        
        # Broadcast to WebSocket clients
        event_data = {
            'type': 'user-activated',
            'data': {
                'id': activation_id,
                'user_email': activation.user_email,
                'hostname': activation.hostname,
                'os_info': activation.os_info,
                'status': 'active',
                'last_seen': datetime.now().isoformat(),
                'timestamp': datetime.now().isoformat()
            }
        }
        
        await manager.broadcast(json.dumps(event_data))
        
        return {
            "status": "success",
            "message": "Device activated successfully",
            "activation_id": activation_id
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error activating device: {str(e)}")

@app.post("/api/report-threat")
async def report_threat(threat: ThreatReport):
    """Report a threat from CLI agent"""
    try:
        # Store threat in database
        threat_id = store_threat(threat)
        
        # Broadcast to WebSocket clients
        event_data = {
            'type': 'new-threat',
            'data': {
                'id': threat_id,
                'device_id': threat.device_id,
                'file_path': threat.file_path,
                'threat_type': threat.threat_type,
                'confidence_score': threat.confidence_score,
                'source': threat.source,
                'details': threat.details,
                'action_taken': threat.action_taken,
                'severity': threat.severity,
                'ai_verdict': threat.ai_verdict,
                'ai_confidence': threat.ai_confidence,
                'ai_reason': threat.ai_reason,
                'timestamp': datetime.now().isoformat()
            }
        }
        
        await manager.broadcast(json.dumps(event_data))
        
        return {
            "status": "success",
            "message": "Threat reported successfully",
            "threat_id": threat_id
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error reporting threat: {str(e)}")

@app.post("/api/report-error")
async def report_error(error: ErrorReport):
    """Report an error from CLI agent"""
    try:
        # Store error in database
        error_id = store_error_report(error)
        
        # Broadcast to WebSocket clients
        event_data = {
            'type': 'error-report',
            'data': {
                'id': error_id,
                'device_id': error.device_id,
                'error_type': error.error_type,
                'error_message': error.error_message,
                'stack_trace': error.stack_trace,
                'timestamp': datetime.now().isoformat()
            }
        }
        
        await manager.broadcast(json.dumps(event_data))
        
        return {
            "status": "success",
            "message": "Error reported successfully",
            "error_id": error_id
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error reporting error: {str(e)}")

@app.post("/api/threats/{threat_id}/feedback")
async def submit_threat_feedback(threat_id: str, feedback: UserFeedback):
    """Submit user feedback for a threat"""
    try:
        update_threat_feedback(threat_id, feedback.feedback)
        
        return {
            "status": "success",
            "message": "Feedback submitted successfully"
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error submitting feedback: {str(e)}")

@app.get("/api/device-activations")
async def get_activations():
    """Get all device activations"""
    try:
        activations = get_device_activations()
        return activations
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching activations: {str(e)}")

@app.get("/api/ai-verdicts")
async def get_verdicts():
    """Get all AI verdicts"""
    try:
        verdicts = get_ai_verdicts()
        return verdicts
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching verdicts: {str(e)}")

@app.get("/api/stats")
async def get_stats():
    """Get real-time system statistics"""
    return get_system_stats()

@app.get("/api/network-stats")
async def get_network_stats_endpoint():
    """Get real-time network statistics"""
    return get_network_stats()

# Authentication endpoints
@app.post("/api/auth/login")
async def login(user_credentials: UserLogin):
    """User login endpoint"""
    try:
        user = authenticate_user(user_credentials.email, user_credentials.password)
        if not user:
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        # Create access token
        access_token = create_access_token(data={"sub": user["email"]})
        
        # Create refresh token
        refresh_token = create_refresh_token(user["id"])
        
        # Update last login
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET last_login = ? WHERE id = ?", (datetime.now().isoformat(), user["id"]))
        conn.commit()
        conn.close()
        
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "user": {
                "id": user["id"],
                "username": user["username"],
                "email": user["email"],
                "is_admin": user["is_admin"],
                "activation_key": user.get("activation_key"),
                "created_at": user["created_at"]
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Login error: {str(e)}")

@app.post("/api/auth/signup")
async def signup(user_data: UserCreate):
    """User registration endpoint"""
    try:
        # Check if user already exists
        existing_user = get_user_by_email(user_data.email)
        if existing_user:
            raise HTTPException(status_code=400, detail="User already exists")
        
        # Create new user
        user = create_user(user_data)
        
        # Create access token
        access_token = create_access_token(data={"sub": user["email"]})
        
        # Create refresh token
        refresh_token = create_refresh_token(user["id"])
        
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "user": {
                "id": user["id"],
                "username": user["username"],
                "email": user["email"],
                "is_admin": user["is_admin"],
                "activation_key": user.get("activation_key"),
                "created_at": user["created_at"]
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Signup error: {str(e)}")

@app.post("/api/auth/logout")
async def logout(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """User logout endpoint"""
    try:
        # Verify token
        payload = verify_token(credentials.credentials)
        if not payload:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        # Revoke all user tokens
        user = get_user_by_email(payload.get("sub"))
        if user:
            revoke_all_user_tokens(user["id"])
        
        return {"message": "Logged out successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Logout error: {str(e)}")

@app.get("/api/auth/me")
async def get_current_user_info(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Get current user information"""
    try:
        payload = verify_token(credentials.credentials)
        if not payload:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        user = get_user_by_email(payload.get("sub"))
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        return {
            "id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "is_admin": user["is_admin"],
            "activation_key": user.get("activation_key"),
            "created_at": user["created_at"]
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching user: {str(e)}")

@app.post("/api/auth/refresh")
async def refresh_token(refresh_data: dict):
    """Refresh access token"""
    try:
        refresh_token = refresh_data.get("refresh_token")
        if not refresh_token:
            raise HTTPException(status_code=400, detail="Refresh token required")
        
        user_id = verify_refresh_token(refresh_token)
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid refresh token")
        
        user = get_user_by_id(user_id)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Create new access token
        access_token = create_access_token(data={"sub": user["email"]})
        
        return {
            "access_token": access_token,
            "token_type": "bearer"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Token refresh error: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000) 
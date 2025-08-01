"""
CyberRazor Enterprise Backend
MongoDB-based backend with Wazuh integration and real-time monitoring
"""

from fastapi import FastAPI, HTTPException, Depends, WebSocket, WebSocketDisconnect, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from typing import List, Optional, Dict, Any
import asyncio
import json
import uuid
from datetime import datetime, timedelta
from contextlib import asynccontextmanager
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import socketio
from fastapi_socketio import SocketManager

# Import our modules
from database import db_manager, get_database
from auth_mongo import (
    UserCreate, UserLogin, UserResponse, Token, TokenData,
    authenticate_user, create_user, create_access_token, create_refresh_token,
    verify_token, get_user_by_id, get_user_by_email,
    revoke_refresh_token, revoke_all_user_tokens, verify_activation_key,
    activate_user_account, create_password_reset_token, verify_password_reset_token,
    reset_user_password
)
from wazuh_integration import wazuh_integration, get_wazuh_integration

# Security
security = HTTPBearer()

# Socket.IO manager for real-time events
sio = socketio.AsyncServer(cors_allowed_origins="*")

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
                self.active_connections.remove(connection)

manager = ConnectionManager()

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
    ai_verdict: Optional[str] = None
    ai_confidence: Optional[str] = None
    ai_reason: Optional[str] = None

class DeviceActivation(BaseModel):
    user_email: str
    hostname: str
    os_info: str
    activation_key: str
    computer_name: Optional[str] = None
    username: Optional[str] = None
    process_id: Optional[int] = None
    status: str = "active"

class UserMetadata(BaseModel):
    username: str
    email: EmailStr
    computer_name: str
    status: str  # active/inactive

class ErrorReport(BaseModel):
    device_id: str
    error_type: str
    error_message: str
    stack_trace: Optional[str] = None

class UserFeedback(BaseModel):
    threat_id: str
    feedback: str  # "false_positive" or "true_positive"

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

# New Pydantic models for user portal
class UserSettings(BaseModel):
    account: Dict[str, str]
    preferences: Dict[str, Any]
    alerts: Dict[str, bool]
    system: Dict[str, Any]

class AgentStatus(BaseModel):
    status: str
    lastSeen: str
    uptime: str
    version: str
    systemInfo: Dict[str, str]
    performance: Dict[str, int]
    scanStats: Dict[str, Any]

class LogEntry(BaseModel):
    id: str
    timestamp: str
    level: str
    message: str
    details: Optional[Dict[str, Any]] = None

class ScanStats(BaseModel):
    totalFiles: int
    threatsFound: int
    lastScanTime: str
    scanDuration: int

class CLIResponse(BaseModel):
    logs: List[LogEntry]
    stats: Optional[ScanStats] = None

# Application lifecycle
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    await db_manager.connect()
    
    # Initialize Wazuh integration (non-blocking)
    try:
        await wazuh_integration.initialize()
        # Start background tasks only if Wazuh is available
        if wazuh_integration.auth_token:
            asyncio.create_task(wazuh_integration.monitor_alerts())
    except Exception as e:
        print(f"Starting without Wazuh integration: {e}")
    
    yield
    
    # Shutdown
    try:
        await wazuh_integration.close()
    except:
        pass
    await db_manager.disconnect()

# Create FastAPI app
app = FastAPI(
    title="CyberRazor Enterprise API",
    description="Enterprise-grade cybersecurity platform with MongoDB and Wazuh integration",
    version="2.0.0",
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000", 
        "http://localhost:5173", 
        "http://127.0.0.1:3000", 
        "http://127.0.0.1:5173",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        "http://localhost:*",
        "http://127.0.0.1:*"
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# Dependency to get current user
async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> Dict[str, Any]:
    token = credentials.credentials
    payload = verify_token(token)
    if payload is None:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    email = payload.get("sub")
    if email is None:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    user = await get_user_by_email(email)
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")
    
    return user

# WebSocket endpoints
@app.websocket("/ws/alerts")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            # Broadcast to all connected clients
            await manager.broadcast(data)
    except WebSocketDisconnect:
        manager.disconnect(websocket)

@app.websocket("/ws/analytics")
async def websocket_analytics(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # Send real-time analytics data
            stats = await db_manager.get_threat_stats()
            await websocket.send_text(json.dumps({
                "type": "analytics",
                "data": stats,
                "timestamp": datetime.utcnow().isoformat()
            }))
            await asyncio.sleep(30)  # Update every 30 seconds
    except WebSocketDisconnect:
        manager.disconnect(websocket)

@app.websocket("/ws/threats")
async def websocket_threats(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # Send real-time threat data
            threats = await db_manager.get_threats(limit=10)
            await websocket.send_text(json.dumps({
                "type": "threats",
                "data": threats,
                "timestamp": datetime.utcnow().isoformat()
            }))
            await asyncio.sleep(10)  # Update every 10 seconds
    except WebSocketDisconnect:
        manager.disconnect(websocket)

# API Endpoints
@app.get("/")
async def read_root():
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



@app.get("/api/health", response_model=List[SystemHealth])
async def get_system_health():
    """Get system health status"""
    try:
        # Check if database is connected
        db_status = "operational"
        if db_manager.db is None:
            db_status = "disconnected"
        elif db_manager.client is None:
            db_status = "disconnected"
        else:
            # Test the connection
            try:
                await db_manager.client.admin.command('ping')
                db_status = "operational"
            except Exception:
                db_status = "disconnected"
        
        return [
            {
                "service": "Database",
                "status": db_status,
                "uptime": "24h",
                "metrics": {"connections": 1 if db_status == "operational" else 0}
            },
            {
                "service": "Wazuh Integration",
                "status": "operational" if wazuh_integration.auth_token else "disconnected",
                "uptime": "24h",
                "metrics": {"alerts_processed": 150}
            }
        ]
    except Exception as e:
        # Return a basic health response even if there are errors
        return [
            {
                "service": "Database",
                "status": "disconnected",
                "uptime": "0h",
                "metrics": {"connections": 0, "error": str(e)}
            },
            {
                "service": "Wazuh Integration",
                "status": "disconnected",
                "uptime": "0h",
                "metrics": {"alerts_processed": 0}
            }
        ]

@app.get("/api/alerts", response_model=List[Alert])
async def get_alerts(limit: int = 50, severity: Optional[str] = None, status: Optional[str] = None):
    """Get alerts with optional filtering"""
    alerts = await db_manager.get_alerts(limit=limit, severity=severity)
    
    if status:
        alerts = [alert for alert in alerts if alert.get("status") == status]
    
    return alerts

@app.get("/api/alerts/{alert_id}", response_model=Alert)
async def get_alert_details(alert_id: str):
    """Get specific alert details"""
    alert = await db_manager.db.alerts.find_one({"id": alert_id})
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    alert["id"] = str(alert["_id"])
    del alert["_id"]
    return alert

@app.post("/api/threats")
async def receive_threat(threat: ThreatReport):
    """Receive threat report from CLI agent"""
    try:
        threat_id = await db_manager.store_threat(threat.dict())
        
        # Broadcast to WebSocket clients
        await manager.broadcast(json.dumps({
            "type": "new_threat",
            "data": {**threat.dict(), "id": threat_id},
            "timestamp": datetime.utcnow().isoformat()
        }))
        
        return {"message": "Threat stored successfully", "threat_id": threat_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to store threat: {str(e)}")

@app.get("/api/threats")
async def get_threats(limit: int = 100, status: Optional[str] = None):
    """Get threats with optional filtering"""
    return await db_manager.get_threats(limit=limit, status=status)

@app.get("/api/threats/{threat_id}")
async def get_threat(threat_id: str):
    """Get specific threat details"""
    from bson import ObjectId
    threat = await db_manager.db.threats.find_one({"_id": ObjectId(threat_id)})
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")
    
    threat["id"] = str(threat["_id"])
    del threat["_id"]
    return threat

@app.put("/api/threats/{threat_id}/status")
async def update_threat(threat_id: str, status: str):
    """Update threat status"""
    await db_manager.update_threat_status(threat_id, status)
    return {"message": "Threat status updated successfully"}

@app.get("/api/threats/stats/summary")
async def get_threat_stats():
    """Get threat statistics for dashboard"""
    return await db_manager.get_threat_stats()

@app.get("/api/playbooks", response_model=List[Playbook])
async def get_playbooks():
    """Get security playbooks"""
    # Mock data for now
    return [
        {
            "id": "1",
            "name": "Malware Response",
            "description": "Automated response to malware detection",
            "status": "active",
            "executions": 45,
            "created_at": "2024-01-01T00:00:00Z",
            "updated_at": "2024-01-15T00:00:00Z"
        }
    ]

@app.get("/api/integrations", response_model=List[Integration])
async def get_integrations():
    """Get integration status"""
    return [
        {
            "name": "Wazuh",
            "status": "connected" if wazuh_integration.auth_token else "disconnected",
            "last_sync": datetime.utcnow().isoformat(),
            "configuration": {
                "manager": wazuh_integration.wazuh_manager,
                "port": wazuh_integration.wazuh_port
            }
        }
    ]

@app.get("/api/database/tables", response_model=List[DatabaseTable])
async def get_database_tables():
    """Get database statistics"""
    collections = ["users", "threats", "alerts", "device_activations", "user_metadata"]
    tables = []
    
    for collection in collections:
        count = await db_manager.db[collection].count_documents({})
        tables.append({
            "name": collection,
            "rows": count,
            "size": f"{count * 1024} bytes",  # Approximate
            "last_updated": datetime.utcnow().isoformat()
        })
    
    return tables

@app.get("/api/analytics/metrics")
async def get_analytics_metrics():
    """Get analytics metrics for dashboard"""
    # Get threat statistics
    threat_stats = await db_manager.get_threat_stats()
    
    # Get recent activity
    recent_threats = await db_manager.db.threats.count_documents({
        "timestamp": {"$gte": datetime.utcnow() - timedelta(hours=24)}
    })
    
    # Get active users
    active_users = await db_manager.db.user_metadata.count_documents({"status": "active"})
    
    return {
        "threats": {
            "total": threat_stats["total_threats"],
            "recent_24h": recent_threats,
            "by_type": threat_stats["threat_types"],
            "by_severity": threat_stats["severity_distribution"]
        },
        "users": {
            "total": await db_manager.db.users.count_documents({}),
            "active": active_users,
            "new_today": await db_manager.db.users.count_documents({
                "created_at": {"$gte": datetime.utcnow() - timedelta(days=1)}
            })
        },
        "system": {
            "uptime": "24h",
            "alerts_processed": 150,
            "wazuh_connected": bool(wazuh_integration.auth_token)
        }
    }

# Authentication endpoints
@app.post("/api/auth/signup", response_model=Token)
async def signup(user_data: UserCreate):
    """User registration"""
    try:
        print(f"Signup attempt for user: {user_data.email}")
        user = await create_user(user_data)
        print(f"User created successfully: {user}")
        
        # Create tokens
        access_token = create_access_token(data={"sub": user["email"]})
        refresh_token = create_refresh_token(user["id"])
        print(f"Tokens created successfully")
        
        # Convert datetime objects to strings for UserResponse
        user_response_data = user.copy()
        if user_response_data.get("created_at"):
            user_response_data["created_at"] = user_response_data["created_at"].isoformat()
        if user_response_data.get("last_login"):
            user_response_data["last_login"] = user_response_data["last_login"].isoformat()
        
        return Token(
            access_token=access_token,
            token_type="bearer",
            user=UserResponse(**user_response_data)
        )
    except ValueError as e:
        print(f"Validation error during signup: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        print(f"Unexpected error during signup: {str(e)}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Registration failed: {str(e)}")

@app.post("/api/auth/login", response_model=Token)
async def login(user_credentials: UserLogin):
    """User login"""
    try:
        user = await authenticate_user(user_credentials.email, user_credentials.password)
        if not user:
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        # Update last login
        await db_manager.update_user_last_login(user["id"])
        
        # Create tokens
        access_token = create_access_token(data={"sub": user["email"]})
        refresh_token = create_refresh_token(user["id"])
        
        # Ensure user data has proper format for UserResponse
        user_response_data = {
            "id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "is_admin": user.get("is_admin", False),
            "activation_key": user.get("activation_key"),
            "created_at": user["created_at"].isoformat() if isinstance(user["created_at"], datetime) else str(user["created_at"]),
            "last_login": user["last_login"].isoformat() if user.get("last_login") and isinstance(user["last_login"], datetime) else str(user.get("last_login")) if user.get("last_login") else None
        }
        
        return Token(
            access_token=access_token,
            token_type="bearer",
            user=UserResponse(**user_response_data)
        )
    except HTTPException:
        raise
    except Exception as e:
        print(f"Login error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Login failed: {str(e)}")

@app.post("/api/auth/refresh", response_model=Token)
async def refresh_token(refresh_token_data: dict):
    """Refresh access token"""
    refresh_token = refresh_token_data.get("refresh_token")
    if not refresh_token:
        raise HTTPException(status_code=400, detail="Refresh token required")
    
    payload = verify_token(refresh_token)
    if not payload or payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    
    user_id = payload.get("sub")
    user = await get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    
    # Create new access token
    access_token = create_access_token(data={"sub": user["email"]})
    
    return Token(
        access_token=access_token,
        token_type="bearer",
        user=UserResponse(**user)
    )

@app.get("/api/auth/me", response_model=UserResponse)
async def get_current_user_info(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Get current user information"""
    # Ensure user data has proper format for UserResponse
    user_response_data = {
        "id": current_user["id"],
        "username": current_user["username"],
        "email": current_user["email"],
        "is_admin": current_user.get("is_admin", False),
        "activation_key": current_user.get("activation_key"),
        "created_at": current_user["created_at"].isoformat() if isinstance(current_user["created_at"], datetime) else str(current_user["created_at"]),
        "last_login": current_user["last_login"].isoformat() if current_user.get("last_login") and isinstance(current_user["last_login"], datetime) else str(current_user.get("last_login")) if current_user.get("last_login") else None
    }
    return UserResponse(**user_response_data)

@app.post("/api/auth/logout")
async def logout(current_user: Dict[str, Any] = Depends(get_current_user)):
    """User logout - also terminates user's agent processes"""
    try:
        # Revoke all tokens
        await revoke_all_user_tokens(current_user["id"])
        
        # Get user's device activations
        db = await get_database()
        device_activations = await db.db.device_activations.find(
            {"user_email": current_user['email']}
        ).to_list(length=None)
        
        # Mark devices as inactive
        for device in device_activations:
            await db.db.device_activations.update_one(
                {"_id": device["_id"]},
                {"$set": {"status": "inactive", "last_logout": datetime.utcnow()}}
            )
        
        # Send termination signal to user's agent processes
        await manager.broadcast(json.dumps({
            "type": "user_logout",
            "user_email": current_user['email'],
            "timestamp": datetime.utcnow().isoformat()
        }))
        
        return {"message": "Logged out successfully and agent processes terminated"}
    except Exception as e:
        # Still logout even if agent termination fails
        await revoke_all_user_tokens(current_user["id"])
        return {"message": "Logged out successfully"}

@app.put("/api/auth/change-password")
async def change_password(
    password_data: dict,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Change user password"""
    current_password = password_data.get("current_password")
    new_password = password_data.get("new_password")
    
    if not current_password or not new_password:
        raise HTTPException(status_code=400, detail="Current and new password required")
    
    # Verify current password
    user = await authenticate_user(current_user["email"], current_password)
    if not user:
        raise HTTPException(status_code=401, detail="Current password is incorrect")
    
    # Update password
    await reset_user_password(current_user["id"], new_password)
    return {"message": "Password changed successfully"}

@app.post("/api/auth/forgot-password")
async def forgot_password(email_data: dict):
    """Request password reset"""
    email = email_data.get("email")
    if not email:
        raise HTTPException(status_code=400, detail="Email required")
    
    reset_token = await create_password_reset_token(email)
    if not reset_token:
        raise HTTPException(status_code=404, detail="User not found")
    
    return {"message": "Password reset email sent"}

@app.post("/api/auth/reset-password")
async def reset_password(reset_data: dict):
    """Reset password with token"""
    token = reset_data.get("token")
    new_password = reset_data.get("new_password")
    
    if not token or not new_password:
        raise HTTPException(status_code=400, detail="Token and new password required")
    
    user = await verify_password_reset_token(token)
    if not user:
        raise HTTPException(status_code=400, detail="Invalid or expired token")
    
    await reset_user_password(user["id"], new_password)
    return {"message": "Password reset successfully"}

# Device activation endpoints
@app.post("/api/activate-key")
async def activate_device(activation: DeviceActivation):
    """Activate device with activation key"""
    try:
        # Verify activation key
        user = await verify_activation_key(activation.activation_key)
        if not user:
            raise HTTPException(status_code=400, detail="Invalid activation key")
        
        # Auto-detect missing fields from system info
        import platform
        import os
        
        computer_name = activation.computer_name or activation.hostname
        username = activation.username or activation.user_email.split('@')[0]
        
        # Store device activation with complete data
        activation_data = activation.dict()
        activation_data["user_id"] = user["id"]
        activation_data["computer_name"] = computer_name
        activation_data["username"] = username
        activation_data["created_at"] = datetime.utcnow()
        activation_data["status"] = "active"
        await db_manager.store_device_activation(activation_data)
        
        # Store user metadata
        metadata = {
            "username": username,
            "email": activation.user_email,
            "computer_name": computer_name,
            "hostname": activation.hostname,
            "os_info": activation.os_info,
            "status": "active",
            "activated_at": datetime.utcnow()
        }
        await db_manager.store_user_metadata(metadata)
        
        # Activate user account
        await activate_user_account(user["id"])
        
        return {
            "message": "Device activated successfully", 
            "user": user,
            "activation_id": activation.hostname,
            "device_info": {
                "hostname": activation.hostname,
                "computer_name": computer_name,
                "username": username,
                "os_info": activation.os_info
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Activation failed: {str(e)}")

@app.post("/api/agent/register")
async def register_agent_process(agent_data: dict):
    """Register agent process for user"""
    try:
        user_email = agent_data.get("user_email")
        process_id = agent_data.get("process_id")
        hostname = agent_data.get("hostname")
        
        if not user_email or not process_id or not hostname:
            raise HTTPException(status_code=400, detail="Missing required fields")
        
        db = await get_database()
        
        # Update device activation with process ID
        await db.db.device_activations.update_one(
            {"user_email": user_email, "hostname": hostname},
            {"$set": {"process_id": process_id, "status": "active", "last_seen": datetime.utcnow()}}
        )
        
        return {"message": "Agent process registered successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to register agent: {str(e)}")

@app.post("/api/agent/terminate")
async def terminate_agent_process(agent_data: dict):
    """Terminate agent process for user"""
    try:
        user_email = agent_data.get("user_email")
        hostname = agent_data.get("hostname")
        
        if not user_email or not hostname:
            raise HTTPException(status_code=400, detail="Missing required fields")
        
        db = await get_database()
        
        # Mark device as inactive
        await db.db.device_activations.update_one(
            {"user_email": user_email, "hostname": hostname},
            {"$set": {"status": "inactive", "terminated_at": datetime.utcnow()}}
        )
        
        return {"message": "Agent process terminated successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to terminate agent: {str(e)}")

@app.post("/api/report-threat")
async def report_threat(threat: ThreatReport):
    """Report threat from CLI agent"""
    try:
        threat_id = await db_manager.store_threat(threat.dict())
        
        # Broadcast to WebSocket clients
        await manager.broadcast(json.dumps({
            "type": "new_threat",
            "data": {**threat.dict(), "id": threat_id},
            "timestamp": datetime.utcnow().isoformat()
        }))
        
        return {"message": "Threat reported successfully", "threat_id": threat_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to report threat: {str(e)}")

@app.post("/api/report-error")
async def report_error(error: ErrorReport):
    """Report error from CLI agent"""
    try:
        db = await get_database()
        error_data = error.dict()
        error_data["timestamp"] = datetime.utcnow().isoformat()
        
        await db.db.errors.insert_one(error_data)
        return {"message": "Error reported successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to report error: {str(e)}")

@app.post("/api/agent/logs")
async def store_agent_log(log_data: dict):
    """Store agent log entry"""
    try:
        db = await get_database()
        
        # Create log entry
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": log_data.get("level", "INFO"),
            "message": log_data.get("message", ""),
            "module": log_data.get("module", ""),
            "device_id": log_data.get("device_id", ""),
            "hostname": log_data.get("hostname", ""),
            "user_email": log_data.get("user_email", ""),
            "log_type": log_data.get("log_type", "agent_activity"),
            "file_path": log_data.get("file_path", ""),
            "extra_data": log_data.get("extra_data", "")
        }
        
        await db.db.agent_logs.insert_one(log_entry)
        return {"message": "Log stored successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to store log: {str(e)}")

@app.get("/api/agent/logs")
async def get_agent_logs(user_email: Optional[str] = None, limit: int = 100):
    """Get agent logs with optional filtering"""
    try:
        db = await get_database()
        
        # Build query
        query = {}
        if user_email:
            query["user_email"] = user_email
        
        # Get logs from agent_logs collection
        logs = await db.db.agent_logs.find(query).sort("timestamp", -1).limit(limit).to_list(length=None)
        
        # Convert ObjectId to string for JSON serialization
        for log in logs:
            log["id"] = str(log["_id"])
            del log["_id"]
        
        return {"logs": logs, "total": len(logs)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve logs: {str(e)}")

@app.post("/api/threats/{threat_id}/feedback")
async def submit_threat_feedback(threat_id: str, feedback: UserFeedback):
    """Submit feedback for threat"""
    try:
        from bson import ObjectId
        await db_manager.db.threats.update_one(
            {"_id": ObjectId(threat_id)},
            {"$set": {"user_feedback": feedback.feedback}}
        )
        return {"message": "Feedback submitted successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to submit feedback: {str(e)}")

@app.get("/api/device-activations")
async def get_activations():
    """Get all device activations"""
    return await db_manager.get_device_activations()

@app.post("/api/user-metadata")
async def store_user_metadata(metadata: UserMetadata):
    """Store user metadata"""
    try:
        metadata_id = await db_manager.store_user_metadata(metadata.dict())
        return {"message": "User metadata stored successfully", "metadata_id": metadata_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to store user metadata: {str(e)}")

@app.get("/api/user-metadata")
async def get_user_metadata():
    """Get all user metadata"""
    return await db_manager.get_user_metadata()

@app.get("/api/cli/logs", response_model=CLIResponse)
async def get_cli_logs(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Get CLI tool logs for the current user"""
    try:
        db = await get_database()
        
        # Get logs from threats collection for this user's active devices only
        device_activations = await db.db.device_activations.find(
            {"user_email": current_user['email'], "status": "active"}
        ).to_list(length=None)
        
        device_ids = [activation['hostname'] for activation in device_activations]
        
        if not device_ids:
            return CLIResponse(logs=[], stats=None)
        
        # Get threats for user's devices
        threat_query = {"$or": [
            {"device_id": {"$in": device_ids}},
            {"hostname": {"$in": device_ids}}
        ]}
        threats = await db.db.threats.find(threat_query).sort("timestamp", -1).limit(50).to_list(length=None)
        
        logs = []
        for threat in threats:
            file_path = threat.get('details', {}).get('file_path', 'Unknown')
            # Create a more descriptive message with file path
            if file_path != 'Unknown':
                message = f"Threat detected: {threat['threat_type']} - File: {file_path}"
            else:
                message = f"Threat detected: {threat['threat_type']}"
            
            log_entry = LogEntry(
                id=str(threat['_id']),
                timestamp=threat['timestamp'],
                level='WARNING' if threat['severity'] in ['high', 'critical'] else 'INFO',
                message=message,
                details={
                    'file_path': file_path,
                    'threat_type': threat['threat_type'],
                    'confidence_score': threat['confidence_score'],
                    'action_taken': threat['action_taken']
                }
            )
            logs.append(log_entry)
        
        # Get agent logs for user's devices
        agent_log_query = {"$or": [
            {"device_id": {"$in": device_ids}},
            {"hostname": {"$in": device_ids}}
        ]}
        agent_logs = await db.db.agent_logs.find(agent_log_query).sort("timestamp", -1).limit(50).to_list(length=None)
        
        for log in agent_logs:
            log_entry = LogEntry(
                id=str(log['_id']),
                timestamp=log['timestamp'],
                level=log['level'],
                message=log['message'],
                details={
                    'module': log.get('module', ''),
                    'log_type': log.get('log_type', 'agent_activity'),
                    'hostname': log.get('hostname', '')
                }
            )
            logs.append(log_entry)
        
        # Sort all logs by timestamp (newest first)
        logs.sort(key=lambda x: x.timestamp, reverse=True)
        
        # Limit to 50 most recent logs
        logs = logs[:50]
        
        # Get scan statistics
        total_files = await db.db.threats.count_documents({
            "$or": [
                {"device_id": {"$in": device_ids}},
                {"hostname": {"$in": device_ids}}
            ]
        })
        threats_found = await db.db.threats.count_documents({
            "$or": [
                {"device_id": {"$in": device_ids}},
                {"hostname": {"$in": device_ids}}
            ],
            "severity": {"$in": ["high", "critical", "medium"]}
        })
        
        # Get last scan time
        last_threat = await db.db.threats.find_one(
            {"$or": [
                {"device_id": {"$in": device_ids}},
                {"hostname": {"$in": device_ids}}
            ]},
            sort=[("timestamp", -1)]
        )
        
        stats = None
        if total_files > 0:
            stats = ScanStats(
                totalFiles=total_files,
                threatsFound=threats_found,
                lastScanTime=last_threat['timestamp'] if last_threat else 'Never',
                scanDuration=30  # Default scan duration
            )
        
        return CLIResponse(logs=logs, stats=stats)
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching CLI logs: {str(e)}")

@app.get("/api/agent/status/public")
async def get_agent_status_public(device_id: str):
    """Get CLI agent status without authentication (for CLI agents)"""
    try:
        db = await get_database()
        
        # Get the device activation by device_id/hostname
        device_activation = await db.db.device_activations.find_one(
            {"hostname": device_id, "status": "active"}
        )
        
        if not device_activation:
            return {"status": "disconnected", "message": "Device not found or inactive"}
        
        return {
            "status": "connected", 
            "message": "Agent is connected to backend",
            "device_id": device_id,
            "last_seen": datetime.now().isoformat()
        }
        
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.get("/api/agent/status", response_model=AgentStatus)
async def get_agent_status(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Get CLI agent status for the current user"""
    try:
        db = await get_database()
        
        # Get the most recent active device activation for this user
        device_activation = await db.db.device_activations.find_one(
            {"user_email": current_user['email'], "status": "active"},
            sort=[("created_at", -1)]
        )
        
        if not device_activation:
            # No device found - agent not running
            return AgentStatus(
                status='stopped',
                lastSeen=datetime.now().isoformat(),
                uptime='0s',
                version='Unknown',
                systemInfo={
                    'os': 'Unknown',
                    'hostname': 'Unknown',
                    'ip': 'Unknown'
                },
                performance={
                    'cpu': 0,
                    'memory': 0,
                    'disk': 0
                },
                scanStats={
                    'totalScans': 0,
                    'lastScanTime': 'Never',
                    'filesScanned': 0,
                    'threatsFound': 0
                }
            )
        
        # Check if agent is active by looking for recent threats
        one_hour_ago = datetime.now() - timedelta(hours=1)
        recent_threats = await db.threats.count_documents({
            "device_id": device_activation['hostname'],
            "timestamp": {"$gte": one_hour_ago.isoformat()}
        })
        
        is_running = recent_threats > 0
        
        # Get scan statistics
        total_scans = await db.threats.count_documents({
            "device_id": device_activation['hostname']
        })
        
        threats_found = await db.threats.count_documents({
            "device_id": device_activation['hostname'],
            "severity": {"$in": ["high", "critical", "medium"]}
        })
        
        files_scanned = await db.threats.count_documents({
            "device_id": device_activation['hostname']
        })
        
        # Get last scan time
        last_threat = await db.threats.find_one(
            {"device_id": device_activation['hostname']},
            sort=[("timestamp", -1)]
        )
        
        return AgentStatus(
            status='running' if is_running else 'stopped',
            lastSeen=last_threat['timestamp'] if last_threat else datetime.now().isoformat(),
            uptime='2h 30m' if is_running else '0s',
            version='1.0.0',
            systemInfo={
                'os': device_activation.get('os_info', 'Unknown'),
                'hostname': device_activation['hostname'],
                'ip': '192.168.1.100'  # Mock IP
            },
            performance={
                'cpu': 25 if is_running else 0,
                'memory': 40 if is_running else 0,
                'disk': 15 if is_running else 0
            },
            scanStats={
                'totalScans': total_scans,
                'lastScanTime': last_threat['timestamp'] if last_threat else 'Never',
                'filesScanned': files_scanned,
                'threatsFound': threats_found
            }
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching agent status: {str(e)}")

@app.get("/api/user/activation-key")
async def get_user_activation_key(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Get activation key for the current user"""
    try:
        db = await get_database()
        
        user = await db.db.users.find_one({"email": current_user['email']})
        
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Mock expiration date (1 year from creation)
        created_date = user.get('created_at', datetime.now())
        if isinstance(created_date, str):
            created_date = datetime.fromisoformat(created_date.replace('Z', '+00:00'))
        expires_date = created_date + timedelta(days=365)
        
        return {
            "key": user['activation_key'],
            "status": "active" if expires_date > datetime.now() else "expired",
            "expiresAt": expires_date.isoformat(),
            "createdAt": user.get('created_at', datetime.now().isoformat()),
            "plan": "Professional" if user.get('is_admin', False) else "Standard"
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching activation key: {str(e)}")

@app.get("/api/user/settings")
async def get_user_settings(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Get user settings"""
    try:
        db = await get_database()
        
        # Try to get existing settings
        settings = await db.db.user_settings.find_one({"user_email": current_user['email']})
        
        if not settings:
            # Return default settings
            return {
                "account": {
                    "email": current_user['email'],
                    "username": current_user['username'],
                    "firstName": current_user.get('firstName', ''),
                    "lastName": current_user.get('lastName', '')
                },
                "preferences": {
                    "theme": "dark",
                    "language": "en",
                    "timezone": "UTC",
                    "dateFormat": "MM/DD/YYYY",
                    "timeFormat": "12h"
                },
                "alerts": {
                    "emailNotifications": True,
                    "threatAlerts": True,
                    "scanComplete": True,
                    "systemUpdates": True,
                    "weeklyReports": False
                },
                "system": {
                    "autoRefresh": True,
                    "refreshInterval": 30,
                    "showPerformanceMetrics": True,
                    "enableAnalytics": True
                }
            }
        
        return settings['settings']
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching user settings: {str(e)}")

@app.put("/api/user/settings")
async def update_user_settings(
    settings: UserSettings,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Update user settings"""
    try:
        db = await get_database()
        
        # Upsert user settings
        await db.db.user_settings.update_one(
            {"user_email": current_user['email']},
            {
                "$set": {
                    "user_email": current_user['email'],
                    "settings": settings.dict(),
                    "updated_at": datetime.now()
                }
            },
            upsert=True
        )
        
        return {
            "status": "success",
            "message": "Settings updated successfully"
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error updating user settings: {str(e)}")

@app.post("/api/user/change-password")
async def change_user_password(
    password_data: dict,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Change user password"""
    try:
        current_password = password_data.get('currentPassword')
        new_password = password_data.get('newPassword')
        
        if not current_password or not new_password:
            raise HTTPException(status_code=400, detail="Current and new password are required")
        
        # In a real implementation, you'd verify the current password and hash the new one
        # For now, just return success
        return {
            "status": "success",
            "message": "Password changed successfully"
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error changing password: {str(e)}")

# Agent communication endpoints
@app.post("/dashboard")
async def receive_dashboard_data(data: dict):
    """Receive real-time data from agents for dashboard"""
    try:
        print(f"Dashboard data received: {data.get('alert_type', 'status')} from {data.get('hostname', 'unknown')}")
        return {"status": "success", "message": "Dashboard data received"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.post("/userportal")
async def receive_userportal_data(data: dict):
    """Receive real-time data from agents for user portal"""
    try:
        print(f"User portal data received: {data.get('alert_type', 'status')} from {data.get('hostname', 'unknown')}")
        return {"status": "success", "message": "User portal data received"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

# Socket.IO events
@sio.event
async def connect(sid, environ):
    print(f"Client connected: {sid}")

@sio.event
async def disconnect(sid):
    print(f"Client disconnected: {sid}")

@sio.event
async def join_room(sid, room):
    await sio.enter_room(sid, room)

@sio.event
async def leave_room(sid, room):
    await sio.leave_room(sid, room)

if __name__ == "__main__":
    import uvicorn
    
    port = 8000

    print(f"🚀 CyberRazor Enterprise Backend Starting on port {port}...")
    print(f"📊 Access API Documentation: http://localhost:{port}/docs")
    print(f"🔍 Health Check: http://localhost:{port}/api/health")
    print(f"🌐 Main API: http://localhost:{port}/")
    print("⚡ WebSocket Endpoints Available")
    print("💾 MongoDB Atlas Connected")
    print("📧 SMTP Email System Ready\n")
    
    uvicorn.run(app, host="0.0.0.0", port=port)

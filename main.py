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
# import socketio
# from fastapi_socketio import SocketManager
from auth import (
    UserCreate, UserLogin, UserResponse, Token, TokenData,
    authenticate_user, create_user, create_access_token, create_refresh_token,
    verify_token, get_user_by_id, get_user_by_email, verify_refresh_token, revoke_refresh_token,
    revoke_all_user_tokens
)

# Security
security = HTTPBearer()

# Socket.IO manager for real-time events (disabled for now)
# sio = socketio.AsyncServer(cors_allowed_origins="*")

# WebSocket connection manager (legacy)
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
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create user_cli_logs table for user-specific logs
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_cli_logs (
            id TEXT PRIMARY KEY,
            user_email TEXT NOT NULL,
            activation_key TEXT NOT NULL,
            device_id TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            level TEXT NOT NULL,
            message TEXT NOT NULL,
            details TEXT,
            log_type TEXT DEFAULT 'scan',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create agent_processes table to track running agents
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS agent_processes (
            id TEXT PRIMARY KEY,
            user_email TEXT NOT NULL,
            activation_key TEXT NOT NULL,
            device_id TEXT NOT NULL,
            process_id INTEGER,
            status TEXT DEFAULT 'running',
            started_at TEXT DEFAULT CURRENT_TIMESTAMP,
            last_heartbeat TEXT DEFAULT CURRENT_TIMESTAMP
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

# Socket.IO integration (disabled)
# socket_manager = SocketManager(app=sio)

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

# Database functions
def get_db_connection():
    return sqlite3.connect('cyberrazor.db')

def store_threat(threat: ThreatReport):
    conn = get_db_connection()
    cursor = conn.cursor()
    threat_id = str(uuid.uuid4())
    cursor.execute('''
        INSERT INTO threats (id, device_id, timestamp, threat_type, confidence_score, source, details, action_taken, severity, ai_verdict, ai_confidence, ai_reason)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (threat_id, threat.device_id, datetime.now().isoformat(), threat.threat_type, 
          threat.confidence_score, threat.source, json.dumps(threat.details), 
          threat.action_taken, threat.severity, threat.ai_verdict, threat.ai_confidence, threat.ai_reason))
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
    ''', (activation_id, activation.user_email, activation.hostname, 
          activation.os_info, activation.activation_key))
    
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
    ''', (error_id, error.device_id, error.error_type, 
          error.error_message, error.stack_trace))
    
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
    
    cursor.execute('SELECT * FROM device_activations ORDER BY created_at DESC')
    activations = cursor.fetchall()
    
    conn.close()
    return activations

def get_ai_verdicts():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT id, device_id, ai_verdict, ai_confidence, ai_reason, user_feedback, created_at 
        FROM threats 
        WHERE ai_verdict IS NOT NULL 
        ORDER BY created_at DESC
    ''')
    verdicts = cursor.fetchall()
    
    conn.close()
    return verdicts

def get_threats(limit: int = 100, status: Optional[str] = None):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if status:
        cursor.execute('''
            SELECT id, device_id, timestamp, threat_type, confidence_score, source, details, action_taken, severity, status, created_at
            FROM threats WHERE status = ? ORDER BY created_at DESC LIMIT ?
        ''', (status, limit))
    else:
        cursor.execute('''
            SELECT id, device_id, timestamp, threat_type, confidence_score, source, details, action_taken, severity, status, created_at
            FROM threats ORDER BY created_at DESC LIMIT ?
        ''', (limit,))
    
    threats = []
    for row in cursor.fetchall():
        threats.append({
            "id": row[0],
            "device_id": row[1],
            "timestamp": row[2],
            "threat_type": row[3],
            "confidence_score": row[4],
            "source": row[5],
            "details": json.loads(row[6]),
            "action_taken": row[7],
            "severity": row[8],
            "status": row[9],
            "created_at": row[10]
        })
    
    conn.close()
    return threats

def update_threat_status(threat_id: str, status: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('UPDATE threats SET status = ? WHERE id = ?', (status, threat_id))
    conn.commit()
    conn.close()

# Sample data generators
def generate_system_health() -> List[SystemHealth]:
    services = [
        {
            "service": "wazuh",
            "status": "healthy",
            "uptime": "99.8%",
            "metrics": {"alerts_24h": 1247, "rules_active": 1450, "agents_connected": 156}
        },
        {
            "service": "thehive",
            "status": "healthy",
            "uptime": "99.5%",
            "metrics": {"open_cases": 23, "closed_cases": 145, "observables": 892}
        },
        {
            "service": "database",
            "status": "healthy",
            "uptime": "100%",
            "metrics": {"connections": 15, "queries_per_sec": 342, "storage_used": "78%"}
        },
        {
            "service": "aiml",
            "status": "warning",
            "uptime": "98.2%",
            "metrics": {"model_accuracy": "94.7%", "predictions_today": 2341, "false_positives": 12}
        }
    ]
    return [SystemHealth(**service) for service in services]

def generate_alerts(count: int = 50) -> List[Alert]:
    alerts = []
    severities = ["Critical", "High", "Medium", "Low"]
    sources = ["Wazuh", "Network Monitor", "Endpoint Detection", "Firewall", "Web Gateway", "Email Security"]
    statuses = ["Open", "Investigating", "Resolved", "False Positive"]
    
    for i in range(count):
        alert = Alert(
            id=f"ALT-{1000 + i}",
            severity=random.choice(severities),
            source=random.choice(sources),
            description=f"Security event detected: {random.choice(['Malware', 'Phishing', 'Intrusion', 'Data Exfiltration', 'Suspicious Login'])} #{i+1}",
            timestamp=(datetime.now() - timedelta(minutes=random.randint(1, 10080))).isoformat(),
            status=random.choice(statuses),
            details={
                "source_ip": f"192.168.{random.randint(1, 255)}.{random.randint(1, 255)}",
                "destination_ip": f"10.0.{random.randint(1, 255)}.{random.randint(1, 255)}",
                "user": f"user{random.randint(1, 100)}",
                "risk_score": random.randint(1, 100)
            }
        )
        alerts.append(alert)
    return alerts

def generate_playbooks() -> List[Playbook]:
    playbooks_data = [
        {
            "id": "pb-001",
            "name": "Malware Detection Response",
            "description": "Automated response to malware detections including isolation and remediation",
            "status": "Active",
            "executions": 156
        },
        {
            "id": "pb-002",
            "name": "Phishing Email Analysis",
            "description": "Analyze and respond to phishing email reports",
            "status": "Active",
            "executions": 89
        },
        {
            "id": "pb-003",
            "name": "Network Intrusion Response",
            "description": "Respond to network-based intrusion attempts",
            "status": "Draft",
            "executions": 0
        },
        {
            "id": "pb-004",
            "name": "Suspicious Login Investigation",
            "description": "Investigate and respond to suspicious login activities",
            "status": "Active",
            "executions": 234
        }
    ]
    
    current_time = datetime.now().isoformat()
    return [
        Playbook(
            **pb,
            created_at=current_time,
            updated_at=current_time
        ) for pb in playbooks_data
    ]

# WebSocket endpoint for real-time alerts
@app.websocket("/ws/alerts")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # Keep connection alive
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

# WebSocket endpoint for real-time analytics
@app.websocket("/ws/analytics")
async def websocket_analytics(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # Generate real-time analytics data
            analytics_data = {
                "type": "analytics",
                "timestamp": datetime.now().isoformat(),
                "system_stats": {
                    "totalThreats": random.randint(50, 200),
                    "activeThreats": random.randint(5, 25),
                    "blockedThreats": random.randint(30, 80),
                    "networkTraffic": random.randint(200, 1200),
                    "anomalies": random.randint(5, 20)
                },
                "network_stats": {
                    "totalTraffic": random.randint(500, 2000),
                    "activeConnections": random.randint(100, 500),
                    "blockedAttempts": random.randint(10, 50),
                    "anomalies": random.randint(5, 20)
                }
            }
            
            await websocket.send_text(json.dumps(analytics_data))
            await asyncio.sleep(2)  # Send data every 2 seconds
            
    except WebSocketDisconnect:
        manager.disconnect(websocket)

# WebSocket endpoint for real-time threats
@app.websocket("/ws/threats")
async def websocket_threats(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # Generate real-time threat updates
            threat_types = ["malware", "phishing", "ddos", "brute_force", "sql_injection"]
            severities = ["low", "medium", "high", "critical"]
            
            threat_data = {
                "type": "threat",
                "id": str(uuid.uuid4()),
                "severity": random.choice(severities),
                "threat_type": random.choice(threat_types),
                "source": f"192.168.{random.randint(1, 255)}.{random.randint(1, 255)}",
                "description": f"Detected {random.choice(threat_types)} activity",
                "timestamp": datetime.now().isoformat(),
                "status": "new"
            }
            
            await websocket.send_text(json.dumps(threat_data))
            await asyncio.sleep(5)  # Send threat updates every 5 seconds
            
    except WebSocketDisconnect:
        manager.disconnect(websocket)

# API Endpoints
@app.get("/")
async def read_root():
    return {
        "message": "Welcome to Cyber Razor SOAR API",
        "version": "1.0.0",
        "status": "operational"
    }

@app.get("/api/health", response_model=List[SystemHealth])
async def get_system_health():
    """Get real-time system health status"""
    return generate_system_health()

@app.get("/api/alerts", response_model=List[Alert])
async def get_alerts(limit: int = 50, severity: Optional[str] = None, status: Optional[str] = None):
    """Get security alerts with optional filtering"""
    all_alerts = generate_alerts(limit)
    
    if severity:
        all_alerts = [alert for alert in all_alerts if alert.severity.lower() == severity.lower()]
    
    if status:
        all_alerts = [alert for alert in all_alerts if alert.status.lower() == status.lower()]
    
    return all_alerts

@app.get("/api/alerts/{alert_id}", response_model=Alert)
async def get_alert_details(alert_id: str):
    """Get detailed information about a specific alert"""
    # In a real implementation, this would query the database
    alerts = generate_alerts(100)
    alert = next((a for a in alerts if a.id == alert_id), None)
    
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    return alert

# Threat management endpoints
@app.post("/api/threats")
async def receive_threat(threat: ThreatReport):
    """Receive threat report from agent"""
    try:
        # Store threat in database
        threat_id = store_threat(threat)
        
        # Broadcast to all connected WebSocket clients
        threat_data = {
            "type": "new_threat",
            "threat": {
                "id": threat_id,
                "device_id": threat.device_id,
                "timestamp": threat.timestamp,
                "threat_type": threat.threat_type,
                "confidence_score": threat.confidence_score,
                "source": threat.source,
                "details": threat.details,
                "action_taken": threat.action_taken,
                "severity": threat.severity,
                "status": "new"
            }
        }
        
        await manager.broadcast(json.dumps(threat_data))
        
        return {"status": "success", "threat_id": threat_id, "message": "Threat received and broadcasted"}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error processing threat: {str(e)}")

@app.get("/api/threats")
async def get_threats(limit: int = 100, status: Optional[str] = None):
    """Get all threats with optional filtering"""
    threats = get_threats(limit, status)
    return threats

@app.get("/api/threats/{threat_id}")
async def get_threat(threat_id: str):
    """Get specific threat details"""
    threats = get_threats(1000)  # Get all threats
    threat = next((t for t in threats if t["id"] == threat_id), None)
    
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")
    
    return threat

@app.put("/api/threats/{threat_id}/status")
async def update_threat(threat_id: str, status: str):
    """Update threat status"""
    try:
        update_threat_status(threat_id, status)
        
        # Broadcast status update
        status_data = {
            "type": "threat_status_update",
            "threat_id": threat_id,
            "status": status
        }
        
        await manager.broadcast(json.dumps(status_data))
        
        return {"status": "success", "message": f"Threat {threat_id} status updated to {status}"}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error updating threat: {str(e)}")

@app.get("/api/threats/stats/summary")
async def get_threat_stats():
    """Get threat statistics"""
    threats = get_threats(10000)  # Get all threats for stats
    
    total_threats = len(threats)
    threats_by_severity = {}
    threats_by_type = {}
    threats_by_status = {}
    
    for threat in threats:
        # Count by severity
        severity = threat["severity"]
        threats_by_severity[severity] = threats_by_severity.get(severity, 0) + 1
        
        # Count by type
        threat_type = threat["threat_type"]
        threats_by_type[threat_type] = threats_by_type.get(threat_type, 0) + 1
        
        # Count by status
        status = threat["status"]
        threats_by_status[status] = threats_by_status.get(status, 0) + 1
    
    return {
        "total_threats": total_threats,
        "by_severity": threats_by_severity,
        "by_type": threats_by_type,
        "by_status": threats_by_status,
        "recent_threats_24h": len([t for t in threats if datetime.fromisoformat(t["timestamp"]) > datetime.now() - timedelta(hours=24)])
    }

@app.get("/api/playbooks", response_model=List[Playbook])
async def get_playbooks():
    """Get all security playbooks"""
    return generate_playbooks()

@app.post("/api/playbooks", response_model=Playbook)
async def create_playbook(playbook: Playbook):
    """Create a new security playbook"""
    # In a real implementation, this would save to database
    return playbook

@app.get("/api/integrations", response_model=List[Integration])
async def get_integrations():
    """Get integration status for external systems"""
    integrations = [
        Integration(
            name="Wazuh API",
            status="Connected",
            last_sync="2 minutes ago",
            configuration={"endpoint": "https://wazuh.local:55000", "version": "4.5.2"}
        ),
        Integration(
            name="TheHive API",
            status="Connected",
            last_sync="5 minutes ago",
            configuration={"endpoint": "https://thehive.local:9000", "version": "5.1.0"}
        ),
        Integration(
            name="Email Service",
            status="Connected",
            last_sync="1 hour ago",
            configuration={"smtp_server": "smtp.company.com", "port": "587"}
        ),
        Integration(
            name="Slack Webhook",
            status="Disconnected",
            last_sync="Never",
            configuration={"webhook_url": "[CONFIGURED]", "channel": "#security-alerts"}
        )
    ]
    return integrations

@app.get("/api/database/tables", response_model=List[DatabaseTable])
async def get_database_tables():
    """Get database table information for management interface"""
    tables = [
        DatabaseTable(
            name="alerts",
            rows=15847,
            size="2.3 MB",
            last_updated="2024-01-30T10:30:00Z"
        ),
        DatabaseTable(
            name="incidents",
            rows=892,
            size="156 KB",
            last_updated="2024-01-30T09:15:00Z"
        ),
        DatabaseTable(
            name="playbooks",
            rows=45,
            size="12 KB",
            last_updated="2024-01-29T16:45:00Z"
        ),
        DatabaseTable(
            name="users",
            rows=23,
            size="4 KB",
            last_updated="2024-01-29T08:20:00Z"
        )
    ]
    return tables

@app.get("/api/analytics/metrics")
async def get_analytics_metrics():
    """Get analytics and metrics data for dashboard charts"""
    return {
        "alert_trends": {
            "labels": ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"],
            "data": [234, 189, 267, 198, 145, 98, 156]
        },
        "severity_distribution": {
            "critical": 23,
            "high": 145,
            "medium": 267,
            "low": 189
        },
        "response_times": {
            "average": "4.2 minutes",
            "median": "2.8 minutes",
            "fastest": "0.5 minutes",
            "slowest": "15.3 minutes"
        },
        "top_threats": [
            {"name": "Malware", "count": 156, "percentage": 35},
            {"name": "Phishing", "count": 134, "percentage": 30},
            {"name": "Intrusion", "count": 89, "percentage": 20},
            {"name": "Data Exfiltration", "count": 67, "percentage": 15}
        ]
    }

# Authentication endpoints
@app.post("/api/auth/signup", response_model=Token)
async def signup(user_data: UserCreate):
    try:
        user = create_user(user_data)
        access_token = create_access_token(data={"sub": user["email"], "user_id": user["id"]})
        refresh_token = create_refresh_token(user["id"])
        
        return Token(
            access_token=access_token,
            token_type="bearer",
            user=UserResponse(
                id=user["id"],
                username=user["username"],
                email=user["email"],
                is_admin=user["is_admin"],
                activation_key=user["activation_key"],
                created_at=user["created_at"]
            )
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail="Internal server error")

@app.post("/api/auth/login", response_model=Token)
async def login(user_credentials: UserLogin):
    user = authenticate_user(user_credentials.email, user_credentials.password)
    if not user:
        raise HTTPException(status_code=401, detail="Incorrect email or password")
    
    access_token = create_access_token(data={"sub": user["email"], "user_id": user["id"]})
    refresh_token = create_refresh_token(user["id"])
    
    return Token(
        access_token=access_token,
        token_type="bearer",
        user=UserResponse(
            id=user["id"],
            username=user["username"],
            email=user["email"],
            is_admin=user["is_admin"],
            activation_key=user["activation_key"],
            created_at=user["created_at"]
        )
    )

@app.post("/api/auth/refresh", response_model=Token)
async def refresh_token(refresh_token_data: dict):
    refresh_token = refresh_token_data.get("refresh_token")
    if not refresh_token:
        raise HTTPException(status_code=400, detail="Refresh token required")
    
    user_id = verify_refresh_token(refresh_token)
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    
    user = get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    
    access_token = create_access_token(data={"sub": user["email"], "user_id": user["id"]})
    new_refresh_token = create_refresh_token(user["id"])
    
    # Revoke old refresh token
    revoke_refresh_token(refresh_token)
    
    return Token(
        access_token=access_token,
        token_type="bearer",
        user=UserResponse(
            id=user["id"],
            username=user["username"],
            email=user["email"],
            is_admin=user["is_admin"],
            activation_key=user["activation_key"],
            created_at=user["created_at"]
        )
    )

@app.get("/api/auth/me", response_model=UserResponse)
async def get_current_user_info(current_user: Dict[str, Any] = Depends(get_current_user)):
    return UserResponse(
        id=current_user["id"],
        username=current_user["username"],
        email=current_user["email"],
        is_admin=current_user["is_admin"],
        activation_key=current_user["activation_key"],
        created_at=current_user["created_at"]
    )

@app.post("/api/auth/logout")
async def logout(current_user: Dict[str, Any] = Depends(get_current_user)):
    # Revoke all refresh tokens for the user
    revoke_all_user_tokens(current_user["id"])
    return {"message": "Successfully logged out"}

@app.put("/api/auth/change-password")
async def change_password(
    password_data: dict,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    current_password = password_data.get("current_password")
    new_password = password_data.get("new_password")
    
    if not current_password or not new_password:
        raise HTTPException(status_code=400, detail="Current password and new password required")
    
    # Verify current password
    user = get_user_by_id(current_user["id"])
    if not user or not authenticate_user(user["email"], current_password):
        raise HTTPException(status_code=401, detail="Current password is incorrect")
    
    # Update password
    from auth import get_password_hash
    conn = get_db_connection()
    cursor = conn.cursor()
    password_hash = get_password_hash(new_password)
    cursor.execute("UPDATE users SET password_hash = ? WHERE id = ?", (password_hash, current_user["id"]))
    conn.commit()
    conn.close()
    
    # Revoke all tokens to force re-login
    revoke_all_user_tokens(current_user["id"])
    
    return {"message": "Password changed successfully"}

@app.post("/api/auth/forgot-password")
async def forgot_password(email_data: dict):
    email = email_data.get("email")
    if not email:
        raise HTTPException(status_code=400, detail="Email required")
    
    user = get_user_by_email(email)
    if not user:
        # Don't reveal if user exists or not for security
        return {"message": "If the email exists, a password reset link has been sent"}
    
    # In a real application, you would send an email here
    # For demo purposes, we'll just return a success message
    return {"message": "If the email exists, a password reset link has been sent"}

@app.post("/api/auth/reset-password")
async def reset_password(reset_data: dict):
    token = reset_data.get("token")
    new_password = reset_data.get("new_password")
    
    if not token or not new_password:
        raise HTTPException(status_code=400, detail="Token and new password required")
    
    # In a real application, you would verify the reset token
    # For demo purposes, we'll just return a success message
    return {"message": "Password reset successfully"}

# New API endpoints for CLI integration
@app.post("/api/activate-key")
async def activate_device(activation: DeviceActivation):
    """Activate a device with activation key"""
    try:
        # Store device activation
        activation_id = store_device_activation(activation)
        
        # Emit socket event to admin dashboard (disabled)
        # await sio.emit('user-activated', {
        #     'id': activation_id,
        #     'user_email': activation.user_email,
        #     'hostname': activation.hostname,
        #     'os_info': activation.os_info,
        #     'status': 'active',
        #     'last_seen': datetime.now().isoformat(),
        #     'timestamp': datetime.now().isoformat()
        # })
        
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
        
        # Emit socket event to admin dashboard (disabled)
        # await sio.emit('new-threat', {
        #     'id': threat_id,
        #     'device_id': threat.device_id,
        #     'file_path': threat.file_path,
        #     'threat_type': threat.threat_type,
        #     'confidence_score': threat.confidence_score,
        #     'source': threat.source,
        #     'details': threat.details,
        #     'action_taken': threat.action_taken,
        #     'severity': threat.severity,
        #     'ai_verdict': threat.ai_verdict,
        #     'ai_confidence': threat.ai_confidence,
        #     'ai_reason': threat.ai_reason,
        #     'timestamp': datetime.now().isoformat()
        # })
        
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
        
        # Emit socket event to admin dashboard (disabled)
        # await sio.emit('error-report', {
        #     'id': error_id,
        #     'device_id': error.device_id,
        #     'error_type': error.error_type,
        #     'error_message': error.error_message,
        #     'stack_trace': error.stack_trace,
        #     'timestamp': datetime.now().isoformat()
        # })
        
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

# New API endpoints for user portal
@app.get("/api/cli/logs", response_model=CLIResponse)
async def get_cli_logs(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Get CLI tool logs for the current user"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get logs from threats table for this user's devices
        cursor.execute('''
            SELECT 
                id, timestamp, threat_type, confidence_score, source, details, action_taken, severity
            FROM threats 
            WHERE device_id IN (
                SELECT hostname FROM device_activations WHERE user_email = ?
            )
            ORDER BY timestamp DESC
            LIMIT 50
        ''', (current_user['email'],))
        
        rows = cursor.fetchall()
        logs = []
        
        for row in rows:
            log_entry = LogEntry(
                id=row[0],
                timestamp=row[1],
                level='WARNING' if row[7] in ['high', 'critical'] else 'INFO',
                message=f"Threat detected: {row[2]}",
                details={
                    'file_path': row[5].get('file_path', 'Unknown'),
                    'threat_type': row[2],
                    'confidence_score': row[3],
                    'action_taken': row[6]
                }
            )
            logs.append(log_entry)
        
        # Get scan statistics
        cursor.execute('''
            SELECT 
                COUNT(*) as total_files,
                COUNT(CASE WHEN severity IN ('high', 'critical', 'medium') THEN 1 END) as threats_found,
                MAX(timestamp) as last_scan,
                COUNT(*) as scan_count
            FROM threats 
            WHERE device_id IN (
                SELECT hostname FROM device_activations WHERE user_email = ?
            )
        ''', (current_user['email'],))
        
        stats_row = cursor.fetchone()
        stats = None
        if stats_row and stats_row[0] > 0:
            stats = ScanStats(
                totalFiles=stats_row[0],
                threatsFound=stats_row[1],
                lastScanTime=stats_row[2] or 'Never',
                scanDuration=30  # Default scan duration
            )
        
        conn.close()
        
        return CLIResponse(logs=logs, stats=stats)
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching CLI logs: {str(e)}")

@app.get("/api/agent/status", response_model=AgentStatus)
async def get_agent_status(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Get CLI agent status for the current user"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get the most recent device activation for this user
        cursor.execute('''
            SELECT hostname, os_info, activation_key, status
            FROM device_activations 
            WHERE user_email = ?
            ORDER BY created_at DESC
            LIMIT 1
        ''', (current_user['email'],))
        
        row = cursor.fetchone()
        
        if not row:
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
        cursor.execute('''
            SELECT COUNT(*), MAX(timestamp)
            FROM threats 
            WHERE device_id = ? AND timestamp > datetime('now', '-1 hour')
        ''', (row[0],))
        
        recent_activity = cursor.fetchone()
        is_running = recent_activity[0] > 0 if recent_activity else False
        
        # Get scan statistics
        cursor.execute('''
            SELECT 
                COUNT(*) as total_scans,
                COUNT(CASE WHEN severity IN ('high', 'critical', 'medium') THEN 1 END) as threats_found,
                MAX(timestamp) as last_scan,
                COUNT(*) as files_scanned
            FROM threats 
            WHERE device_id = ?
        ''', (row[0],))
        
        scan_stats = cursor.fetchone()
        
        conn.close()
        
        return AgentStatus(
            status='running' if is_running else 'stopped',
            lastSeen=recent_activity[1] if recent_activity and recent_activity[1] else datetime.now().isoformat(),
            uptime='2h 30m' if is_running else '0s',
            version='1.0.0',
            systemInfo={
                'os': row[1],
                'hostname': row[0],
                'ip': '192.168.1.100'  # Mock IP
            },
            performance={
                'cpu': 25 if is_running else 0,
                'memory': 40 if is_running else 0,
                'disk': 15 if is_running else 0
            },
            scanStats={
                'totalScans': scan_stats[0] if scan_stats else 0,
                'lastScanTime': scan_stats[2] if scan_stats and scan_stats[2] else 'Never',
                'filesScanned': scan_stats[3] if scan_stats else 0,
                'threatsFound': scan_stats[1] if scan_stats else 0
            }
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching agent status: {str(e)}")

@app.get("/api/user/activation-key")
async def get_user_activation_key(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Get activation key for the current user"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT activation_key, created_at, is_admin
            FROM users 
            WHERE email = ?
        ''', (current_user['email'],))
        
        row = cursor.fetchone()
        conn.close()
        
        if not row:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Mock expiration date (1 year from creation)
        created_date = datetime.fromisoformat(row[1].replace('Z', '+00:00'))
        expires_date = created_date + timedelta(days=365)
        
        return {
            "key": row[0],
            "status": "active" if expires_date > datetime.now() else "expired",
            "expiresAt": expires_date.isoformat(),
            "createdAt": row[1],
            "plan": "Professional" if row[2] else "Standard"
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching activation key: {str(e)}")

@app.get("/api/user/settings")
async def get_user_settings(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Get user settings"""
    try:
        # For now, return default settings
        # In a real implementation, you'd store these in a separate table
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
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching user settings: {str(e)}")

@app.put("/api/user/settings")
async def update_user_settings(
    settings: UserSettings,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Update user settings"""
    try:
        # In a real implementation, you'd save these to a database
        # For now, just return success
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

# Socket.IO event handlers (disabled)
# @sio.event
# async def connect(sid, environ):
#     print(f"Client connected: {sid}")
# 
# @sio.event
# async def disconnect(sid):
#     print(f"Client disconnected: {sid}")
# 
# @sio.event
# async def join_room(sid, room):
#     await sio.enter_room(sid, room)
#     print(f"Client {sid} joined room: {room}")
# 
# @sio.event
# async def leave_room(sid, room):
#     await sio.leave_room(sid, room)
#     print(f"Client {sid} left room: {room}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)


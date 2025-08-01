#!/usr/bin/env python3
"""
Script to create sample data for CyberRazor testing
"""

import sqlite3
import uuid
from datetime import datetime, timedelta
import json
import random

def create_sample_data():
    """Create sample data for testing"""
    conn = sqlite3.connect('cyberrazor.db')
    cursor = conn.cursor()
    
    # Create sample device activation for admin user
    admin_email = "admin@cyberrazor.com"
    device_id = str(uuid.uuid4())
    
    cursor.execute('''
        INSERT OR REPLACE INTO device_activations 
        (id, user_email, hostname, os_info, activation_key, status, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (
        device_id,
        admin_email,
        "DESKTOP-ADMIN",
        "Windows 10 Pro",
        str(uuid.uuid4()),
        "active",
        datetime.now().isoformat()
    ))
    
    # Create sample threats/logs
    threat_types = [
        "Malware Detection",
        "Suspicious File",
        "Network Anomaly",
        "Process Injection",
        "Registry Modification",
        "File System Change",
        "Network Connection",
        "System Call",
        "Memory Scan",
        "Behavior Analysis"
    ]
    
    severities = ["low", "medium", "high", "critical"]
    actions = ["quarantined", "blocked", "monitored", "allowed"]
    
    # Create sample threats for the last 24 hours
    for i in range(20):
        timestamp = datetime.now() - timedelta(hours=random.randint(0, 24), minutes=random.randint(0, 60))
        threat_type = random.choice(threat_types)
        severity = random.choice(severities)
        action = random.choice(actions)
        
        details = {
            "file_path": f"C:\\Users\\Admin\\Documents\\file_{i}.exe",
            "process_name": f"process_{i}.exe",
            "ip_address": f"192.168.1.{random.randint(1, 255)}",
            "port": random.randint(1024, 65535),
            "hash": f"sha256_{uuid.uuid4().hex[:16]}"
        }
        
        cursor.execute('''
            INSERT INTO threats 
            (id, device_id, timestamp, threat_type, confidence_score, source, details, action_taken, severity, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            str(uuid.uuid4()),
            "DESKTOP-ADMIN",
            timestamp.isoformat(),
            threat_type,
            random.uniform(0.5, 1.0),
            "CLI Agent",
            json.dumps(details),
            action,
            severity,
            "new",
            datetime.now().isoformat()
        ))
    
    # Create sample threats for regular user
    user_email = "user@cyberrazor.com"
    user_device_id = str(uuid.uuid4())
    
    cursor.execute('''
        INSERT OR REPLACE INTO device_activations 
        (id, user_email, hostname, os_info, activation_key, status, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (
        user_device_id,
        user_email,
        "DESKTOP-USER",
        "Windows 11 Home",
        str(uuid.uuid4()),
        "active",
        datetime.now().isoformat()
    ))
    
    # Create sample threats for regular user
    for i in range(15):
        timestamp = datetime.now() - timedelta(hours=random.randint(0, 12), minutes=random.randint(0, 60))
        threat_type = random.choice(threat_types)
        severity = random.choice(severities)
        action = random.choice(actions)
        
        details = {
            "file_path": f"C:\\Users\\User\\Downloads\\download_{i}.pdf",
            "process_name": f"browser_{i}.exe",
            "ip_address": f"10.0.0.{random.randint(1, 255)}",
            "port": random.randint(1024, 65535),
            "hash": f"sha256_{uuid.uuid4().hex[:16]}"
        }
        
        cursor.execute('''
            INSERT INTO threats 
            (id, device_id, timestamp, threat_type, confidence_score, source, details, action_taken, severity, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            str(uuid.uuid4()),
            "DESKTOP-USER",
            timestamp.isoformat(),
            threat_type,
            random.uniform(0.3, 0.9),
            "CLI Agent",
            json.dumps(details),
            action,
            severity,
            "new",
            datetime.now().isoformat()
        ))
    
    conn.commit()
    conn.close()
    
    print("Sample data created successfully!")
    print(f"- Device activations for admin@cyberrazor.com and user@cyberrazor.com")
    print(f"- 20 sample threats for admin user")
    print(f"- 15 sample threats for regular user")

if __name__ == "__main__":
    create_sample_data() 
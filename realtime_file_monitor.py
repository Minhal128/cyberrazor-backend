#!/usr/bin/env python3
"""
Real-time File Monitor for CyberRazor
Monitors file system changes and sends real-time detection data to MongoDB backend
"""

import os
import time
import json
import hashlib
import requests
import threading
from datetime import datetime
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import mimetypes
import magic
import yara
import uuid

class FileMonitor(FileSystemEventHandler):
    def __init__(self, backend_url="https://cyberrazor-backend.vercel.app", device_id=None):
        self.backend_url = backend_url
        self.device_id = device_id or os.environ.get('COMPUTERNAME', 'Unknown')
        self.session = requests.Session()
        self.suspicious_extensions = {'.exe', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.jar', '.dll', '.scr', '.pif'}
        self.monitored_paths = [
            os.path.expanduser("~/Downloads"),
            os.path.expanduser("~/Desktop"),
            os.path.expanduser("~/Documents"),
            "C:/Temp",
            "C:/Windows/Temp"
        ]
        
        # Create monitored paths if they don't exist
        for path in self.monitored_paths:
            Path(path).mkdir(parents=True, exist_ok=True)
        
        # Simple YARA rules for basic detection
        self.yara_rules = """
        rule suspicious_behavior {
            strings:
                $cmd1 = "cmd.exe" nocase
                $cmd2 = "powershell" nocase
                $cmd3 = "regsvr32" nocase
                $cmd4 = "rundll32" nocase
                $suspicious1 = "CreateRemoteThread" nocase
                $suspicious2 = "VirtualAlloc" nocase
                $suspicious3 = "WriteProcessMemory" nocase
            condition:
                any of them
        }
        """
        
        try:
            self.compiled_rules = yara.compile(source=self.yara_rules)
        except:
            self.compiled_rules = None
            print("Warning: YARA rules not available, using basic detection")

    def get_file_hash(self, file_path):
        """Calculate SHA256 hash of file"""
        try:
            with open(file_path, 'rb') as f:
                return hashlib.sha256(f.read()).hexdigest()
        except:
            return None

    def get_file_type(self, file_path):
        """Get file type using magic numbers"""
        try:
            mime = magic.from_file(file_path, mime=True)
            return mime
        except:
            return "unknown"

    def analyze_file(self, file_path):
        """Analyze file for potential threats"""
        try:
            if not os.path.exists(file_path) or os.path.isdir(file_path):
                return None
            
            file_ext = Path(file_path).suffix.lower()
            file_size = os.path.getsize(file_path)
            
            # Skip very large files
            if file_size > 100 * 1024 * 1024:  # 100MB
                return None
            
            threat_score = 0
            threat_type = "File Analysis"
            confidence = 0.0
            
            # Check file extension
            if file_ext in self.suspicious_extensions:
                threat_score += 30
                threat_type = "Suspicious File Extension"
                confidence = 0.3
            
            # Check file type vs extension
            try:
                file_type = self.get_file_type(file_path)
                if file_ext == '.exe' and 'executable' not in file_type:
                    threat_score += 40
                    threat_type = "Executable Mismatch"
                    confidence = 0.7
                elif file_ext == '.pdf' and 'pdf' not in file_type:
                    threat_score += 20
                    threat_type = "File Type Mismatch"
                    confidence = 0.5
            except:
                pass
            
            # YARA scanning
            if self.compiled_rules:
                try:
                    matches = self.compiled_rules.match(file_path)
                    if matches:
                        threat_score += 50
                        threat_type = "YARA Rule Match"
                        confidence = 0.8
                except:
                    pass
            
            # Check file hash against known bad hashes (simplified)
            file_hash = self.get_file_hash(file_path)
            if file_hash:
                # This would normally check against a database of known bad hashes
                # For demo purposes, we'll use a simple heuristic
                if file_hash.startswith('000000') or file_hash.endswith('000000'):
                    threat_score += 25
                    threat_type = "Suspicious Hash Pattern"
                    confidence = 0.6
            
            # Determine severity
            if threat_score >= 80:
                severity = "critical"
                confidence = max(confidence, 0.9)
            elif threat_score >= 60:
                severity = "high"
                confidence = max(confidence, 0.7)
            elif threat_score >= 40:
                severity = "medium"
                confidence = max(confidence, 0.5)
            elif threat_score >= 20:
                severity = "low"
                confidence = max(confidence, 0.3)
            else:
                return None  # No threat detected
            
            return {
                "threat_type": threat_type,
                "confidence_score": confidence,
                "severity": severity,
                "file_path": file_path,
                "file_size": file_size,
                "file_hash": file_hash,
                "file_type": file_type,
                "threat_score": threat_score
            }
            
        except Exception as e:
            print(f"Error analyzing file {file_path}: {e}")
            return None

    def send_threat_report(self, threat_data):
        """Send threat report to backend"""
        try:
            threat_report = {
                "device_id": self.device_id,
                "timestamp": datetime.now().isoformat(),
                "threat_type": threat_data["threat_type"],
                "confidence_score": threat_data["confidence_score"],
                "source": "Real-time File Monitor",
                "details": {
                    "file_path": threat_data["file_path"],
                    "file_size": threat_data["file_size"],
                    "file_hash": threat_data["file_hash"],
                    "file_type": threat_data["file_type"],
                    "threat_score": threat_data["threat_score"]
                },
                "action_taken": "detected",
                "severity": threat_data["severity"]
            }
            
            response = self.session.post(
                f"{self.backend_url}/api/threats",
                json=threat_report,
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code == 200:
                print(f"✅ Threat reported: {threat_data['file_path']} ({threat_data['severity']})")
            else:
                print(f"❌ Failed to report threat: {response.status_code}")
                
        except Exception as e:
            print(f"Error sending threat report: {e}")

    def on_created(self, event):
        """Handle file creation events"""
        if not event.is_directory:
            file_path = event.src_path
            print(f"📁 New file detected: {file_path}")
            
            # Wait a moment for file to be fully written
            time.sleep(1)
            
            threat_data = self.analyze_file(file_path)
            if threat_data:
                print(f"🚨 Threat detected: {threat_data['threat_type']} - {file_path}")
                self.send_threat_report(threat_data)
            else:
                print(f"✅ File appears safe: {file_path}")

    def on_modified(self, event):
        """Handle file modification events"""
        if not event.is_directory:
            file_path = event.src_path
            print(f"📝 File modified: {file_path}")
            
            # Only analyze if it's a suspicious file type
            file_ext = Path(file_path).suffix.lower()
            if file_ext in self.suspicious_extensions:
                threat_data = self.analyze_file(file_path)
                if threat_data:
                    print(f"🚨 Modified file threat: {threat_data['threat_type']} - {file_path}")
                    self.send_threat_report(threat_data)

    def on_moved(self, event):
        """Handle file move events"""
        if not event.is_directory:
            dest_path = event.dest_path
            print(f"📦 File moved to: {dest_path}")
            
            threat_data = self.analyze_file(dest_path)
            if threat_data:
                print(f"🚨 Moved file threat: {threat_data['threat_type']} - {dest_path}")
                self.send_threat_report(threat_data)

def start_monitoring():
    """Start the file monitoring service"""
    print("🔍 Starting CyberRazor Real-time File Monitor...")
    print("📂 Monitoring paths:")
    
    monitor = FileMonitor()
    observer = Observer()
    
    for path in monitor.monitored_paths:
        if os.path.exists(path):
            observer.schedule(monitor, path, recursive=True)
            print(f"   - {path}")
        else:
            print(f"   - {path} (not found)")
    
    observer.start()
    print("✅ File monitoring started successfully!")
    print("🔄 Press Ctrl+C to stop monitoring")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        print("\n🛑 File monitoring stopped")
    
    observer.join()

if __name__ == "__main__":
    start_monitoring() 
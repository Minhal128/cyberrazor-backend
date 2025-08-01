#!/usr/bin/env python3
"""
CyberRazor Threat Detection Agent
A Python-based background service for real-time threat detection and response.
"""

import os
import sys
import json
import time
import hashlib
import requests
import threading
import subprocess
import platform
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
import psutil
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
import joblib
import logging
import ssl
import socket
from pathlib import Path
import yaml

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/cyberrazor-agent.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class ThreatReport:
    """Data structure for threat reports"""
    device_id: str
    timestamp: str
    threat_type: str
    confidence_score: float
    source: str
    details: Dict[str, Any]
    action_taken: str
    severity: str

@dataclass
class ProcessInfo:
    """Process information for analysis"""
    pid: int
    name: str
    cmdline: str
    cpu_percent: float
    memory_percent: float
    connections: List[Dict]
    file_path: str
    hash: str

class ThreatDetectionAgent:
    """Main threat detection agent class"""
    
    def __init__(self, config_path: str = "agent_config.yaml"):
        self.config = self._load_config(config_path)
        self.device_id = self._get_device_id()
        self.api_key = self.config.get('api_key')
        self.backend_url = self.config.get('backend_url')
        self.wazuh_url = self.config.get('wazuh_url')
        self.wazuh_credentials = self.config.get('wazuh_credentials', {})
        
        # ML Models
        self.process_classifier = None
        self.file_classifier = None
        self.network_anomaly_detector = None
        self.vectorizer = None
        
        # Initialize models
        self._initialize_ml_models()
        
        # Threat patterns
        self.suspicious_patterns = [
            'ransomware', 'keylogger', 'backdoor', 'trojan', 'spyware',
            'crypto_miner', 'botnet', 'rootkit', 'malware', 'virus'
        ]
        
        # Known malicious hashes (simplified - in production, use a proper threat intel feed)
        self.malicious_hashes = set()
        
        # Running state
        self.running = False
        self.last_scan_time = datetime.now()
        
    def _load_config(self, config_path: str) -> Dict:
        """Load configuration from YAML file"""
        try:
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            logger.warning(f"Config file {config_path} not found, using defaults")
            return {
                'api_key': os.getenv('CYBERRAZOR_API_KEY', ''),
                'backend_url': os.getenv('CYBERRAZOR_BACKEND_URL', 'http://localhost:8000'),
                'wazuh_url': os.getenv('WAZUH_URL', 'http://localhost:55000'),
                'wazuh_credentials': {
                    'username': os.getenv('WAZUH_USERNAME', ''),
                    'password': os.getenv('WAZUH_PASSWORD', '')
                },
                'scan_interval': 30,
                'model_path': './models/'
            }
    
    def _get_device_id(self) -> str:
        """Generate unique device identifier"""
        system_info = platform.system() + platform.machine()
        try:
            # Use MAC address for unique identification
            import uuid
            mac = uuid.getnode()
            return hashlib.sha256(f"{system_info}{mac}".encode()).hexdigest()[:16]
        except:
            # Fallback to hostname
            return hashlib.sha256(f"{system_info}{platform.node()}".encode()).hexdigest()[:16]
    
    def _initialize_ml_models(self):
        """Initialize machine learning models"""
        try:
            model_path = self.config.get('model_path', './models/')
            Path(model_path).mkdir(exist_ok=True)
            
            # Load or create models
            self._load_or_create_models(model_path)
            
        except Exception as e:
            logger.error(f"Failed to initialize ML models: {e}")
            # Create basic models as fallback
            self._create_basic_models()
    
    def _load_or_create_models(self, model_path: str):
        """Load existing models or create new ones"""
        try:
            # Try to load existing models
            self.process_classifier = joblib.load(f"{model_path}/process_classifier.pkl")
            self.file_classifier = joblib.load(f"{model_path}/file_classifier.pkl")
            self.network_anomaly_detector = joblib.load(f"{model_path}/network_anomaly.pkl")
            self.vectorizer = joblib.load(f"{model_path}/vectorizer.pkl")
            logger.info("Loaded existing ML models")
        except FileNotFoundError:
            logger.info("Creating new ML models")
            self._create_basic_models()
            self._save_models(model_path)
    
    def _create_basic_models(self):
        """Create basic ML models for threat detection"""
        # Process classifier (Random Forest)
        self.process_classifier = RandomForestClassifier(n_estimators=100, random_state=42)
        
        # File classifier (Random Forest)
        self.file_classifier = RandomForestClassifier(n_estimators=100, random_state=42)
        
        # Network anomaly detector (Isolation Forest)
        self.network_anomaly_detector = IsolationForest(contamination=0.1, random_state=42)
        
        # Text vectorizer for command line analysis
        self.vectorizer = TfidfVectorizer(max_features=1000, stop_words='english')
        
        # Train with basic data (in production, use real threat data)
        self._train_models_with_sample_data()
    
    def _train_models_with_sample_data(self):
        """Train models with sample data (replace with real threat data in production)"""
        # Sample benign processes
        benign_processes = [
            "chrome.exe", "firefox.exe", "notepad.exe", "explorer.exe",
            "svchost.exe", "winlogon.exe", "lsass.exe", "csrss.exe"
        ]
        
        # Sample malicious processes (simplified)
        malicious_processes = [
            "crypto_miner.exe", "keylogger.exe", "backdoor.exe", "trojan.exe"
        ]
        
        # Create training data
        process_data = benign_processes + malicious_processes
        process_labels = [0] * len(benign_processes) + [1] * len(malicious_processes)
        
        # Train process classifier
        process_features = self.vectorizer.fit_transform(process_data)
        self.process_classifier.fit(process_features, process_labels)
        
        # Train file classifier (similar approach)
        self.file_classifier.fit(process_features, process_labels)
        
        # Train network anomaly detector with sample network data
        sample_network_data = np.random.rand(100, 5)  # 5 features: bytes_sent, bytes_recv, packets_sent, packets_recv, connection_count
        self.network_anomaly_detector.fit(sample_network_data)
        
        logger.info("Trained basic ML models with sample data")
    
    def _save_models(self, model_path: str):
        """Save trained models to disk"""
        try:
            joblib.dump(self.process_classifier, f"{model_path}/process_classifier.pkl")
            joblib.dump(self.file_classifier, f"{model_path}/file_classifier.pkl")
            joblib.dump(self.network_anomaly_detector, f"{model_path}/network_anomaly.pkl")
            joblib.dump(self.vectorizer, f"{model_path}/vectorizer.pkl")
            logger.info("Saved ML models to disk")
        except Exception as e:
            logger.error(f"Failed to save models: {e}")
    
    def scan_processes(self) -> List[ProcessInfo]:
        """Scan running processes for threats"""
        processes = []
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'cpu_percent', 'memory_percent']):
                try:
                    proc_info = proc.info
                    
                    # Get process connections
                    connections = []
                    try:
                        for conn in proc.connections():
                            connections.append({
                                'family': conn.family,
                                'type': conn.type,
                                'laddr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                                'raddr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                                'status': conn.status
                            })
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        pass
                    
                    # Get process file path and hash
                    file_path = ""
                    file_hash = ""
                    try:
                        file_path = proc.exe()
                        if file_path and os.path.exists(file_path):
                            file_hash = self._calculate_file_hash(file_path)
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        pass
                    
                    process_info = ProcessInfo(
                        pid=proc_info['pid'],
                        name=proc_info['name'],
                        cmdline=' '.join(proc_info['cmdline']) if proc_info['cmdline'] else '',
                        cpu_percent=proc_info['cpu_percent'],
                        memory_percent=proc_info['memory_percent'],
                        connections=connections,
                        file_path=file_path,
                        hash=file_hash
                    )
                    
                    processes.append(process_info)
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
        except Exception as e:
            logger.error(f"Error scanning processes: {e}")
        
        return processes
    
    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA256 hash of a file"""
        try:
            hash_sha256 = hashlib.sha256()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except Exception as e:
            logger.error(f"Error calculating file hash for {file_path}: {e}")
            return ""
    
    def analyze_process(self, process: ProcessInfo) -> Optional[ThreatReport]:
        """Analyze a single process for threats"""
        try:
            # Check file hash against known malicious hashes
            if process.hash in self.malicious_hashes:
                return ThreatReport(
                    device_id=self.device_id,
                    timestamp=datetime.now().isoformat(),
                    threat_type="Known Malware",
                    confidence_score=0.95,
                    source="Process Analysis",
                    details={
                        "pid": process.pid,
                        "name": process.name,
                        "file_path": process.file_path,
                        "hash": process.hash
                    },
                    action_taken="Process flagged for quarantine",
                    severity="High"
                )
            
            # ML-based analysis
            if process.name and self.process_classifier:
                # Vectorize process name and command line
                process_text = f"{process.name} {process.cmdline}"
                features = self.vectorizer.transform([process_text])
                
                # Get prediction
                prediction = self.process_classifier.predict(features)[0]
                probability = self.process_classifier.predict_proba(features)[0]
                
                if prediction == 1:  # Malicious
                    confidence = max(probability)
                    if confidence > 0.7:  # High confidence threshold
                        return ThreatReport(
                            device_id=self.device_id,
                            timestamp=datetime.now().isoformat(),
                            threat_type="Suspicious Process",
                            confidence_score=confidence,
                            source="ML Analysis",
                            details={
                                "pid": process.pid,
                                "name": process.name,
                                "cmdline": process.cmdline,
                                "prediction_confidence": confidence
                            },
                            action_taken="Process flagged for investigation",
                            severity="Medium" if confidence < 0.9 else "High"
                        )
            
            # Pattern-based analysis
            process_text = f"{process.name} {process.cmdline}".lower()
            for pattern in self.suspicious_patterns:
                if pattern in process_text:
                    return ThreatReport(
                        device_id=self.device_id,
                        timestamp=datetime.now().isoformat(),
                        threat_type="Pattern Match",
                        confidence_score=0.8,
                        source="Pattern Analysis",
                        details={
                            "pid": process.pid,
                            "name": process.name,
                            "pattern_matched": pattern
                        },
                        action_taken="Process flagged for investigation",
                        severity="Medium"
                    )
            
            # Network connection analysis
            if len(process.connections) > 10:  # Suspicious number of connections
                return ThreatReport(
                    device_id=self.device_id,
                    timestamp=datetime.now().isoformat(),
                    threat_type="Suspicious Network Activity",
                    confidence_score=0.6,
                    source="Network Analysis",
                    details={
                        "pid": process.pid,
                        "name": process.name,
                        "connection_count": len(process.connections)
                    },
                    action_taken="Network activity flagged for monitoring",
                    severity="Low"
                )
            
        except Exception as e:
            logger.error(f"Error analyzing process {process.pid}: {e}")
        
        return None
    
    def scan_network_traffic(self) -> Optional[ThreatReport]:
        """Analyze network traffic for anomalies"""
        try:
            # Get network statistics
            net_io = psutil.net_io_counters()
            
            # Create feature vector for anomaly detection
            features = np.array([[
                net_io.bytes_sent,
                net_io.bytes_recv,
                net_io.packets_sent,
                net_io.packets_recv,
                len(psutil.net_connections())
            ]])
            
            if self.network_anomaly_detector:
                # Predict anomaly
                prediction = self.network_anomaly_detector.predict(features)[0]
                
                if prediction == -1:  # Anomaly detected
                    return ThreatReport(
                        device_id=self.device_id,
                        timestamp=datetime.now().isoformat(),
                        threat_type="Network Anomaly",
                        confidence_score=0.7,
                        source="Network Analysis",
                        details={
                            "bytes_sent": net_io.bytes_sent,
                            "bytes_recv": net_io.bytes_recv,
                            "packets_sent": net_io.packets_sent,
                            "packets_recv": net_io.packets_recv,
                            "active_connections": len(psutil.net_connections())
                        },
                        action_taken="Network traffic flagged for investigation",
                        severity="Medium"
                    )
            
        except Exception as e:
            logger.error(f"Error scanning network traffic: {e}")
        
        return None
    
    def send_to_wazuh(self, threat_report: ThreatReport):
        """Send threat report to Wazuh SIEM"""
        try:
            if not self.wazuh_url or not self.wazuh_credentials:
                logger.warning("Wazuh configuration not available")
                return
            
            # Prepare Wazuh alert
            wazuh_alert = {
                "timestamp": threat_report.timestamp,
                "agent": {
                    "id": self.device_id,
                    "name": platform.node()
                },
                "manager": "cyberrazor-agent",
                "cluster": {
                    "name": "cyberrazor-cluster",
                    "node": "node-1"
                },
                "rule": {
                    "level": 10 if threat_report.severity == "High" else 7 if threat_report.severity == "Medium" else 5,
                    "description": f"CyberRazor Threat: {threat_report.threat_type}",
                    "id": "100001",
                    "groups": ["cyberrazor", "threat_detection"]
                },
                "data": {
                    "srcip": "127.0.0.1",
                    "srcport": "0",
                    "dstip": "0.0.0.0",
                    "dstport": "0"
                },
                "decoder": {
                    "name": "cyberrazor"
                },
                "full_log": json.dumps(asdict(threat_report))
            }
            
            # Send to Wazuh API
            headers = {
                'Content-Type': 'application/json',
                'Authorization': f"Basic {self.wazuh_credentials.get('username', '')}:{self.wazuh_credentials.get('password', '')}"
            }
            
            response = requests.post(
                f"{self.wazuh_url}/alerts",
                json=wazuh_alert,
                headers=headers,
                verify=False  # In production, use proper SSL certificates
            )
            
            if response.status_code == 200:
                logger.info(f"Successfully sent alert to Wazuh: {threat_report.threat_type}")
            else:
                logger.error(f"Failed to send alert to Wazuh: {response.status_code}")
                
        except Exception as e:
            logger.error(f"Error sending to Wazuh: {e}")
    
    def send_to_backend(self, threat_report: ThreatReport):
        """Send threat report to backend API"""
        try:
            if not self.backend_url or not self.api_key:
                logger.warning("Backend configuration not available")
                return
            
            headers = {
                'Content-Type': 'application/json',
                'Authorization': f'Bearer {self.api_key}'
            }
            
            response = requests.post(
                f"{self.backend_url}/api/threats",
                json=asdict(threat_report),
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                logger.info(f"Successfully sent threat report to backend: {threat_report.threat_type}")
            else:
                logger.error(f"Failed to send threat report to backend: {response.status_code}")
                
        except Exception as e:
            logger.error(f"Error sending to backend: {e}")
    
    def run_scan(self):
        """Run a complete threat scan"""
        logger.info("Starting threat scan...")
        
        threats_found = []
        
        # Scan processes
        processes = self.scan_processes()
        logger.info(f"Scanned {len(processes)} processes")
        
        for process in processes:
            threat = self.analyze_process(process)
            if threat:
                threats_found.append(threat)
                logger.warning(f"Threat detected: {threat.threat_type} - {threat.details}")
        
        # Scan network traffic
        network_threat = self.scan_network_traffic()
        if network_threat:
            threats_found.append(network_threat)
            logger.warning(f"Network threat detected: {network_threat.threat_type}")
        
        # Report threats
        for threat in threats_found:
            # Send to Wazuh
            self.send_to_wazuh(threat)
            
            # Send to backend
            self.send_to_backend(threat)
        
        self.last_scan_time = datetime.now()
        logger.info(f"Scan completed. Found {len(threats_found)} threats.")
        
        return threats_found
    
    def start_monitoring(self):
        """Start continuous threat monitoring"""
        self.running = True
        scan_interval = self.config.get('scan_interval', 30)
        
        logger.info(f"Starting threat monitoring with {scan_interval}s intervals")
        
        while self.running:
            try:
                self.run_scan()
                time.sleep(scan_interval)
            except KeyboardInterrupt:
                logger.info("Received interrupt signal, stopping monitoring")
                break
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                time.sleep(scan_interval)
    
    def stop_monitoring(self):
        """Stop threat monitoring"""
        self.running = False
        logger.info("Stopping threat monitoring")

def main():
    """Main entry point"""
    try:
        # Create and start the agent
        agent = ThreatDetectionAgent()
        
        # Start monitoring
        agent.start_monitoring()
        
    except KeyboardInterrupt:
        logger.info("Agent stopped by user")
    except Exception as e:
        logger.error(f"Agent error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 
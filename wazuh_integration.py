"""
Wazuh Integration Module
Real-time threat detection and alerting for CyberRazor
"""

import os
import asyncio
import aiohttp
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dotenv import load_dotenv
from database import db_manager

load_dotenv()

logger = logging.getLogger(__name__)

class WazuhIntegration:
    def __init__(self):
        self.enabled = os.getenv("WAZUH_ENABLED", "true").lower() == "true"
        self.wazuh_manager = os.getenv("WAZUH_MANAGER", "localhost")
        self.wazuh_port = int(os.getenv("WAZUH_PORT", "55000"))
        self.wazuh_user = os.getenv("WAZUH_USER", "wazuh")
        self.wazuh_password = os.getenv("WAZUH_PASSWORD", "wazuh")
        self.wazuh_api_url = f"https://{self.wazuh_manager}:{self.wazuh_port}"
        self.session = None
        self.auth_token = None
        self.connection_timeout = int(os.getenv("WAZUH_TIMEOUT", "10"))
        
    async def initialize(self):
        """Initialize Wazuh connection"""
        if not self.enabled:
            logger.info("Wazuh integration is disabled")
            return
            
        try:
            # Create session with timeout
            timeout = aiohttp.ClientTimeout(total=self.connection_timeout)
            self.session = aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(verify_ssl=False),
                timeout=timeout
            )
            await self.authenticate()
            logger.info("Wazuh integration initialized successfully")
        except Exception as e:
            logger.warning(f"Wazuh integration not available: {e}")
            # Don't raise exception, continue without Wazuh
            self.auth_token = None
    
    async def authenticate(self):
        """Authenticate with Wazuh API"""
        try:
            auth_url = f"{self.wazuh_api_url}/security/user/authenticate"
            auth_data = {
                "username": self.wazuh_user,
                "password": self.wazuh_password
            }
            
            async with self.session.post(auth_url, json=auth_data) as response:
                if response.status == 200:
                    result = await response.json()
                    self.auth_token = result.get("data", {}).get("token")
                    logger.info("Wazuh authentication successful")
                else:
                    logger.error(f"Wazuh authentication failed: {response.status}")
                    
        except Exception as e:
            logger.error(f"Wazuh authentication error: {e}")
    
    async def get_alerts(self, limit: int = 100, severity: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get alerts from Wazuh"""
        try:
            if not self.auth_token:
                await self.authenticate()
            
            headers = {"Authorization": f"Bearer {self.auth_token}"}
            
            # Build query
            query = {
                "limit": limit,
                "offset": 0,
                "sort": "-timestamp"
            }
            
            if severity:
                query["q"] = f"level>={self._get_severity_level(severity)}"
            
            url = f"{self.wazuh_api_url}/alerts"
            async with self.session.get(url, headers=headers, params=query) as response:
                if response.status == 200:
                    result = await response.json()
                    alerts = result.get("data", {}).get("affected_items", [])
                    
                    # Transform Wazuh alerts to CyberRazor format
                    transformed_alerts = []
                    for alert in alerts:
                        transformed_alert = {
                            "id": alert.get("id"),
                            "timestamp": alert.get("timestamp"),
                            "severity": self._map_severity(alert.get("level", 0)),
                            "source": "wazuh",
                            "description": alert.get("description", ""),
                            "status": "new",
                            "details": {
                                "rule_id": alert.get("rule", {}).get("id"),
                                "rule_description": alert.get("rule", {}).get("description"),
                                "agent_id": alert.get("agent", {}).get("id"),
                                "agent_name": alert.get("agent", {}).get("name"),
                                "location": alert.get("location"),
                                "full_log": alert.get("full_log")
                            }
                        }
                        transformed_alerts.append(transformed_alert)
                    
                    return transformed_alerts
                else:
                    logger.error(f"Failed to get Wazuh alerts: {response.status}")
                    return []
                    
        except Exception as e:
            logger.error(f"Error getting Wazuh alerts: {e}")
            return []
    
    async def get_agents(self) -> List[Dict[str, Any]]:
        """Get Wazuh agents"""
        try:
            if not self.auth_token:
                await self.authenticate()
            
            headers = {"Authorization": f"Bearer {self.auth_token}"}
            url = f"{self.wazuh_api_url}/agents"
            
            async with self.session.get(url, headers=headers) as response:
                if response.status == 200:
                    result = await response.json()
                    return result.get("data", {}).get("affected_items", [])
                else:
                    logger.error(f"Failed to get Wazuh agents: {response.status}")
                    return []
                    
        except Exception as e:
            logger.error(f"Error getting Wazuh agents: {e}")
            return []
    
    async def get_agent_status(self, agent_id: str) -> Optional[Dict[str, Any]]:
        """Get specific agent status"""
        try:
            if not self.auth_token:
                await self.authenticate()
            
            headers = {"Authorization": f"Bearer {self.auth_token}"}
            url = f"{self.wazuh_api_url}/agents/{agent_id}"
            
            async with self.session.get(url, headers=headers) as response:
                if response.status == 200:
                    result = await response.json()
                    return result.get("data", {}).get("affected_items", [{}])[0]
                else:
                    logger.error(f"Failed to get agent status: {response.status}")
                    return None
                    
        except Exception as e:
            logger.error(f"Error getting agent status: {e}")
            return None
    
    async def send_alert_to_wazuh(self, alert_data: Dict[str, Any]) -> bool:
        """Send alert to Wazuh (if needed for integration)"""
        try:
            if not self.auth_token:
                await self.authenticate()
            
            headers = {"Authorization": f"Bearer {self.auth_token}"}
            url = f"{self.wazuh_api_url}/alerts"
            
            # Transform CyberRazor alert to Wazuh format
            wazuh_alert = {
                "rule_id": 100001,  # Custom rule ID
                "level": self._get_severity_level(alert_data.get("severity", "medium")),
                "description": alert_data.get("description", ""),
                "location": alert_data.get("source", "cyberrazor"),
                "full_log": json.dumps(alert_data.get("details", {}))
            }
            
            async with self.session.post(url, headers=headers, json=wazuh_alert) as response:
                if response.status == 200:
                    logger.info("Alert sent to Wazuh successfully")
                    return True
                else:
                    logger.error(f"Failed to send alert to Wazuh: {response.status}")
                    return False
                    
        except Exception as e:
            logger.error(f"Error sending alert to Wazuh: {e}")
            return False
    
    def _get_severity_level(self, severity: str) -> int:
        """Map severity string to Wazuh level"""
        severity_map = {
            "low": 3,
            "medium": 6,
            "high": 10,
            "critical": 15
        }
        return severity_map.get(severity.lower(), 6)
    
    def _map_severity(self, level: int) -> str:
        """Map Wazuh level to severity string"""
        if level >= 15:
            return "critical"
        elif level >= 10:
            return "high"
        elif level >= 6:
            return "medium"
        else:
            return "low"
    
    async def monitor_alerts(self):
        """Monitor Wazuh alerts in real-time"""
        while True:
            try:
                alerts = await self.get_alerts(limit=50)
                
                for alert in alerts:
                    # Check if alert already exists
                    existing = await db_manager.db.alerts.find_one({"id": alert["id"]})
                    if not existing:
                        # Store new alert
                        await db_manager.store_alert(alert)
                        logger.info(f"New Wazuh alert stored: {alert['id']}")
                
                # Wait before next check
                await asyncio.sleep(30)  # Check every 30 seconds
                
            except Exception as e:
                logger.error(f"Error in alert monitoring: {e}")
                await asyncio.sleep(60)  # Wait longer on error
    
    async def close(self):
        """Close Wazuh integration"""
        if self.session:
            await self.session.close()

# Global Wazuh instance
wazuh_integration = WazuhIntegration()

async def get_wazuh_integration() -> WazuhIntegration:
    """Get Wazuh integration instance"""
    return wazuh_integration 
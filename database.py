"""
MongoDB Database Configuration and Operations
Enterprise-grade database layer for CyberRazor
"""

import os
import asyncio
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from motor.motor_asyncio import AsyncIOMotorClient
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError
import logging
from dotenv import load_dotenv

load_dotenv()

# MongoDB Configuration
MONGODB_URL = os.getenv("MONGODB_URL", "mongodb://localhost:27017")
DATABASE_NAME = os.getenv("MONGODB_DB_NAME", "cyberrazor_enterprise")

class DatabaseManager:
    def __init__(self):
        self.client: Optional[AsyncIOMotorClient] = None
        self.db = None
        self.logger = logging.getLogger(__name__)
    
    async def connect(self):
        """Establish connection to MongoDB"""
        try:
            self.client = AsyncIOMotorClient(MONGODB_URL, serverSelectionTimeoutMS=5000)
            # Test connection
            await self.client.admin.command('ping')
            self.db = self.client[DATABASE_NAME]
            self.logger.info("Successfully connected to MongoDB")
            
            # Initialize collections and indexes
            await self._create_indexes()
            
        except (ConnectionFailure, ServerSelectionTimeoutError) as e:
            self.logger.error(f"Failed to connect to MongoDB: {e}")
            # Don't raise the exception, just log it
            self.client = None
            self.db = None
    
    async def disconnect(self):
        """Close MongoDB connection"""
        if self.client:
            self.client.close()
            self.logger.info("Disconnected from MongoDB")
    
    async def _create_indexes(self):
        """Create necessary indexes for optimal performance"""
        try:
            # Users collection indexes
            await self.db.users.create_index("email", unique=True)
            await self.db.users.create_index("username", unique=True)
            await self.db.users.create_index("activation_key", unique=True)
            
            # Threats collection indexes
            await self.db.threats.create_index("device_id")
            await self.db.threats.create_index("timestamp")
            await self.db.threats.create_index("threat_type")
            await self.db.threats.create_index("severity")
            await self.db.threats.create_index("status")
            await self.db.threats.create_index([("timestamp", -1)])
            
            # Device activations collection indexes
            await self.db.device_activations.create_index("user_email")
            await self.db.device_activations.create_index("hostname")
            await self.db.device_activations.create_index("activation_key")
            
            # Alerts collection indexes
            await self.db.alerts.create_index("timestamp")
            await self.db.alerts.create_index("severity")
            await self.db.alerts.create_index("status")
            
            # User metadata collection indexes
            await self.db.user_metadata.create_index("email", unique=True)
            await self.db.user_metadata.create_index("computer_name")
            
            self.logger.info("Database indexes created successfully")
            
        except Exception as e:
            self.logger.error(f"Error creating indexes: {e}")
    
    # User operations
    async def create_user(self, user_data: Dict[str, Any]) -> str:
        """Create a new user"""
        user_data["created_at"] = datetime.utcnow()
        user_data["last_login"] = None
        result = await self.db.users.insert_one(user_data)
        return str(result.inserted_id)
    
    async def get_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        """Get user by email"""
        user = await self.db.users.find_one({"email": email})
        if user:
            user["id"] = str(user["_id"])
            del user["_id"]
        return user
    
    async def get_user_by_id(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get user by ID"""
        from bson import ObjectId
        user = await self.db.users.find_one({"_id": ObjectId(user_id)})
        if user:
            user["id"] = str(user["_id"])
            del user["_id"]
        return user
    
    async def update_user_last_login(self, user_id: str):
        """Update user's last login timestamp"""
        from bson import ObjectId
        await self.db.users.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": {"last_login": datetime.utcnow()}}
        )
    
    # Threat operations
    async def store_threat(self, threat_data: Dict[str, Any]) -> str:
        """Store a new threat"""
        threat_data["created_at"] = datetime.utcnow()
        result = await self.db.threats.insert_one(threat_data)
        return str(result.inserted_id)
    
    async def get_threats(self, limit: int = 100, status: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get threats with optional filtering"""
        query = {}
        if status:
            query["status"] = status
        
        cursor = self.db.threats.find(query).sort("timestamp", -1).limit(limit)
        threats = await cursor.to_list(length=limit)
        
        for threat in threats:
            threat["id"] = str(threat["_id"])
            del threat["_id"]
        
        return threats
    
    async def update_threat_status(self, threat_id: str, status: str):
        """Update threat status"""
        from bson import ObjectId
        await self.db.threats.update_one(
            {"_id": ObjectId(threat_id)},
            {"$set": {"status": status, "updated_at": datetime.utcnow()}}
        )
    
    async def get_threat_stats(self) -> Dict[str, Any]:
        """Get threat statistics"""
        pipeline = [
            {
                "$group": {
                    "_id": "$threat_type",
                    "count": {"$sum": 1},
                    "avg_confidence": {"$avg": "$confidence_score"}
                }
            }
        ]
        
        threat_types = await self.db.threats.aggregate(pipeline).to_list(None)
        
        # Get severity distribution
        severity_pipeline = [
            {
                "$group": {
                    "_id": "$severity",
                    "count": {"$sum": 1}
                }
            }
        ]
        
        severity_stats = await self.db.threats.aggregate(severity_pipeline).to_list(None)
        
        return {
            "threat_types": threat_types,
            "severity_distribution": severity_stats,
            "total_threats": await self.db.threats.count_documents({}),
            "recent_threats": await self.db.threats.count_documents({
                "timestamp": {"$gte": datetime.utcnow() - timedelta(hours=24)}
            })
        }
    
    # Device activation operations
    async def store_device_activation(self, activation_data: Dict[str, Any]) -> str:
        """Store device activation"""
        activation_data["created_at"] = datetime.utcnow()
        result = await self.db.device_activations.insert_one(activation_data)
        return str(result.inserted_id)
    
    async def get_device_activations(self) -> List[Dict[str, Any]]:
        """Get all device activations"""
        cursor = self.db.device_activations.find().sort("created_at", -1)
        activations = await cursor.to_list(None)
        
        for activation in activations:
            activation["id"] = str(activation["_id"])
            del activation["_id"]
        
        return activations
    
    # User metadata operations
    async def store_user_metadata(self, metadata: Dict[str, Any]) -> str:
        """Store user metadata (username, email, computer name, status)"""
        metadata["created_at"] = datetime.utcnow()
        metadata["updated_at"] = datetime.utcnow()
        
        # Upsert to avoid duplicates
        result = await self.db.user_metadata.update_one(
            {"email": metadata["email"]},
            {"$set": metadata},
            upsert=True
        )
        
        if result.upserted_id:
            return str(result.upserted_id)
        else:
            # Get the existing document ID
            doc = await self.db.user_metadata.find_one({"email": metadata["email"]})
            return str(doc["_id"])
    
    async def get_user_metadata(self) -> List[Dict[str, Any]]:
        """Get all user metadata"""
        cursor = self.db.user_metadata.find().sort("created_at", -1)
        metadata = await cursor.to_list(None)
        
        for item in metadata:
            item["id"] = str(item["_id"])
            del item["_id"]
        
        return metadata
    
    # Alert operations
    async def store_alert(self, alert_data: Dict[str, Any]) -> str:
        """Store a new alert"""
        alert_data["created_at"] = datetime.utcnow()
        result = await self.db.alerts.insert_one(alert_data)
        return str(result.inserted_id)
    
    async def get_alerts(self, limit: int = 50, severity: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get alerts with optional filtering"""
        query = {}
        if severity:
            query["severity"] = severity
        
        cursor = self.db.alerts.find(query).sort("timestamp", -1).limit(limit)
        alerts = await cursor.to_list(length=limit)
        
        for alert in alerts:
            alert["id"] = str(alert["_id"])
            del alert["_id"]
        
        return alerts

# Global database instance
db_manager = DatabaseManager()

async def get_database() -> DatabaseManager:
    """Get database manager instance"""
    return db_manager 
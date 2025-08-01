#!/usr/bin/env python3
"""
Test script to validate MongoDB connection improvements
"""

import asyncio
import os
from motor.motor_asyncio import AsyncIOMotorClient
from pymongo.errors import ConnectionFailure
from datetime import datetime

# MongoDB Configuration (same as main_mongo.py)
MONGODB_URL = os.getenv("MONGODB_URL", "mongodb+srv://rminhal783:Hhua6tUekZkGfBx0@cluster0.auuhgc5.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0&connectTimeoutMS=10000&serverSelectionTimeoutMS=5000&socketTimeoutMS=10000&maxPoolSize=50")
MONGODB_DB_NAME = os.getenv("MONGODB_DB_NAME", "cyberrazor")

async def test_connection():
    """Test MongoDB connection with the improved settings"""
    print("🔍 Testing MongoDB Connection...")
    print(f"📊 Database: {MONGODB_DB_NAME}")
    print(f"🔗 URL Preview: {MONGODB_URL[:50]}...")
    print("-" * 60)
    
    try:
        print("🔗 Creating MongoDB client with optimized settings...")
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
        
        print("🔍 Testing connection with ping...")
        start_time = datetime.now()
        await asyncio.wait_for(client.admin.command('ping'), timeout=15.0)
        end_time = datetime.now()
        response_time = (end_time - start_time).total_seconds() * 1000
        
        print(f"✅ SUCCESS! MongoDB connection established")
        print(f"✅ Response time: {response_time:.2f}ms")
        print(f"✅ Database: {MONGODB_DB_NAME}")
        print(f"✅ Status: FULLY CONNECTED")
        
        # Test a simple operation
        print("\n🔍 Testing database operations...")
        collections = await db.list_collection_names()
        print(f"✅ Found {len(collections)} collections: {collections}")
        
        # Test insertion
        test_doc = {
            "test_id": "connection_test",
            "timestamp": datetime.now().isoformat(),
            "status": "success"
        }
        
        result = await db.connection_tests.insert_one(test_doc)
        print(f"✅ Test document inserted with ID: {result.inserted_id}")
        
        # Clean up test document
        await db.connection_tests.delete_one({"_id": result.inserted_id})
        print(f"✅ Test document cleaned up")
        
        client.close()
        print("\n🎉 ALL TESTS PASSED - MongoDB is working perfectly!")
        return True
        
    except asyncio.TimeoutError:
        print("❌ TIMEOUT: Connection took too long")
        print("💡 This usually indicates network issues or cluster unavailability")
        return False
        
    except ConnectionFailure as e:
        print(f"❌ CONNECTION FAILURE: {e}")
        print("💡 Check your MongoDB Atlas cluster status")
        print("💡 Verify your connection string is correct")
        return False
        
    except Exception as e:
        print(f"❌ UNEXPECTED ERROR: {e}")
        print(f"💡 Error type: {type(e).__name__}")
        return False

if __name__ == "__main__":
    print("🚀 MongoDB Connection Test")
    print("=" * 60)
    success = asyncio.run(test_connection())
    print("=" * 60)
    if success:
        print("🟢 RESULT: Connection test SUCCESSFUL")
        print("✅ Your MongoDB setup is working correctly!")
    else:
        print("🔴 RESULT: Connection test FAILED")
        print("❌ Please check the error messages above")

#!/usr/bin/env python3
"""
Test script to verify Vercel environment variables and MongoDB connection
Run this locally to test your MongoDB connection before deploying to Vercel
"""

import os
import asyncio
from motor.motor_asyncio import AsyncIOMotorClient
from pymongo.errors import ConnectionFailure

async def test_mongodb_connection():
    """Test MongoDB connection with current environment variables"""
    
    # Get environment variables
    mongodb_url = os.getenv("MONGODB_URL")
    mongodb_db_name = os.getenv("MONGODB_DB_NAME", "cyberrazor")
    
    print("🔍 Testing MongoDB Connection")
    print("=" * 50)
    
    # Check if MONGODB_URL is set
    if not mongodb_url:
        print("❌ MONGODB_URL environment variable is not set!")
        print("💡 Please set it in your Vercel environment variables")
        print("💡 Example: mongodb+srv://username:password@cluster.mongodb.net/?retryWrites=true&w=majority")
        return False
    
    print(f"✅ MONGODB_URL is configured")
    print(f"📍 Database: {mongodb_db_name}")
    print(f"🔐 URL Preview: {mongodb_url[:50]}...")
    
    # Test connection
    try:
        print("\n🔗 Attempting to connect to MongoDB...")
        client = AsyncIOMotorClient(mongodb_url)
        db = client[mongodb_db_name]
        
        # Test ping
        await client.admin.command('ping')
        print("✅ MongoDB connection successful!")
        
        # Test database operations
        print("🧪 Testing database operations...")
        
        # List collections
        collections = await db.list_collection_names()
        print(f"📚 Collections found: {len(collections)}")
        if collections:
            print(f"   - {', '.join(collections[:5])}{'...' if len(collections) > 5 else ''}")
        
        # Test write operation
        test_collection = db.test_connection
        test_doc = {"test": True, "timestamp": "2024-01-01"}
        result = await test_collection.insert_one(test_doc)
        print(f"✅ Write test successful: {result.inserted_id}")
        
        # Clean up test document
        await test_collection.delete_one({"_id": result.inserted_id})
        print("🧹 Test document cleaned up")
        
        await client.close()
        print("\n🎉 All tests passed! Your MongoDB connection is working correctly.")
        return True
        
    except ConnectionFailure as e:
        print(f"❌ Connection failed: {e}")
        print("💡 Check your MongoDB Atlas cluster settings:")
        print("   - Ensure IP whitelist includes 0.0.0.0/0 (or Vercel IPs)")
        print("   - Verify username/password are correct")
        print("   - Check if cluster is running")
        return False
        
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        print("💡 This might be an authentication or network issue")
        return False

def check_vercel_requirements():
    """Check if environment is ready for Vercel deployment"""
    print("\n🔍 Vercel Deployment Requirements")
    print("=" * 50)
    
    required_vars = ["MONGODB_URL"]
    optional_vars = ["MONGODB_DB_NAME"]
    
    print("Required Environment Variables:")
    for var in required_vars:
        value = os.getenv(var)
        if value:
            print(f"✅ {var}: Configured")
        else:
            print(f"❌ {var}: Missing")
    
    print("\nOptional Environment Variables:")
    for var in optional_vars:
        value = os.getenv(var)
        if value:
            print(f"✅ {var}: {value}")
        else:
            print(f"⚠️  {var}: Using default value")
    
    print("\n📋 Vercel Setup Checklist:")
    print("1. ✅ Set MONGODB_URL in Vercel environment variables")
    print("2. ✅ Ensure MongoDB Atlas cluster is accessible")
    print("3. ✅ Test connection locally (this script)")
    print("4. ✅ Deploy to Vercel")
    print("5. ✅ Verify /api/health endpoint returns 'operational'")

if __name__ == "__main__":
    print("🚀 CyberRazor MongoDB Connection Tester")
    print("=" * 50)
    
    # Check requirements
    check_vercel_requirements()
    
    # Test connection
    success = asyncio.run(test_mongodb_connection())
    
    if success:
        print("\n🎯 Ready for Vercel deployment!")
        print("💡 Your MongoDB connection is working correctly.")
    else:
        print("\n⚠️  Please fix the connection issues before deploying to Vercel.")
        print("💡 Check the error messages above for guidance.") 
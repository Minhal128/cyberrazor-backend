#!/usr/bin/env python3
"""
Test the specific MongoDB connection string provided by the user
"""

import os
import asyncio
from motor.motor_asyncio import AsyncIOMotorClient
from pymongo.errors import ConnectionFailure

# The connection string provided by the user
MONGODB_URL = "mongodb+srv://rminhal783:Hhua6tUekZkGfBx0@cluster0.auuhgc5.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
MONGODB_DB_NAME = "cyberrazor"

async def test_connection():
    """Test the specific MongoDB connection"""
    
    print("🔍 Testing Your MongoDB Connection")
    print("=" * 50)
    print(f"📍 Database: {MONGODB_DB_NAME}")
    print(f"🔐 URL Preview: {MONGODB_URL[:50]}...")
    
    try:
        print("\n🔗 Attempting to connect to MongoDB...")
        client = AsyncIOMotorClient(MONGODB_URL)
        db = client[MONGODB_DB_NAME]
        
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
        test_doc = {"test": True, "timestamp": "2024-01-01", "user": "rminhal783"}
        result = await test_collection.insert_one(test_doc)
        print(f"✅ Write test successful: {result.inserted_id}")
        
        # Clean up test document
        await test_collection.delete_one({"_id": result.inserted_id})
        print("🧹 Test document cleaned up")
        
        await client.close()
        print("\n🎉 Connection test passed! Your MongoDB is working correctly.")
        print("\n💡 Next Steps:")
        print("1. Add this connection string to Vercel environment variables")
        print("2. Redeploy your backend")
        print("3. Your agent should show 'CONNECTED' status")
        return True
        
    except ConnectionFailure as e:
        print(f"❌ Connection failed: {e}")
        print("💡 Check your MongoDB Atlas settings:")
        print("   - Go to MongoDB Atlas → Network Access")
        print("   - Add IP Address: 0.0.0.0/0")
        print("   - Ensure cluster is running")
        return False
        
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        print("💡 This might be an authentication or network issue")
        return False

def main():
    print("🚀 Testing Your MongoDB Connection String")
    print("=" * 50)
    
    success = asyncio.run(test_connection())
    
    if success:
        print("\n✅ Your MongoDB connection string is working!")
        print("📝 Add this to Vercel environment variables:")
        print(f"MONGODB_URL={MONGODB_URL}")
    else:
        print("\n❌ Connection failed. Please check your MongoDB Atlas settings.")

if __name__ == "__main__":
    main() 
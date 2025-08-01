#!/usr/bin/env python3
"""
Create Admin User Script
Creates an admin user in MongoDB for CyberRazor backend
"""

import asyncio
import sys
import os
import uuid
from datetime import datetime

# Add the backend directory to the path so we can import our modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from database import db_manager
from auth_mongo import get_password_hash

async def create_admin_user():
    """Create an admin user"""
    try:
        # Connect to database
        await db_manager.connect()
        
        # Admin user details
        admin_email = "admin@cyberrazor.com"
        admin_username = "admin"
        admin_password = "admin123"  # Change this in production!
        
        # Check if admin already exists
        existing_admin = await db_manager.get_user_by_email(admin_email)
        if existing_admin:
            print(f"Admin user already exists: {admin_email}")
            return existing_admin
        
        # Generate activation key
        activation_key = str(uuid.uuid4())
        
        # Create admin user document
        admin_doc = {
            "username": admin_username,
            "email": admin_email,
            "password_hash": get_password_hash(admin_password),
            "activation_key": activation_key,
            "is_admin": True,
            "is_active": True,  # Admin is automatically active
            "created_at": datetime.utcnow(),
            "last_login": None,
            "activated_at": datetime.utcnow()
        }
        
        # Store in database
        user_id = await db_manager.create_user(admin_doc)
        
        print("="*60)
        print("✅ ADMIN USER CREATED SUCCESSFULLY!")
        print("="*60)
        print(f"📧 Email: {admin_email}")
        print(f"👤 Username: {admin_username}")
        print(f"🔐 Password: {admin_password}")
        print(f"🔑 Activation Key: {activation_key}")
        print(f"🆔 User ID: {user_id}")
        print("="*60)
        print("⚠️  IMPORTANT: Change the admin password after first login!")
        print("🔗 Login at: https://cyberrazor-backend.vercel.app/login")
        print("="*60)
        
        return {
            "id": user_id,
            "email": admin_email,
            "username": admin_username,
            "activation_key": activation_key
        }
        
    except Exception as e:
        print(f"❌ Error creating admin user: {e}")
        return None
    finally:
        await db_manager.disconnect()

async def create_test_users():
    """Create some test users for development"""
    try:
        await db_manager.connect()
        
        test_users = [
            {
                "username": "testuser1",
                "email": "test1@example.com",
                "password": "password123",
                "is_admin": False
            },
            {
                "username": "testuser2", 
                "email": "test2@example.com",
                "password": "password123",
                "is_admin": False
            }
        ]
        
        created_users = []
        
        for user_data in test_users:
            # Check if user already exists
            existing_user = await db_manager.get_user_by_email(user_data["email"])
            if existing_user:
                print(f"Test user already exists: {user_data['email']}")
                continue
            
            # Generate activation key
            activation_key = str(uuid.uuid4())
            
            # Create user document
            user_doc = {
                "username": user_data["username"],
                "email": user_data["email"],
                "password_hash": get_password_hash(user_data["password"]),
                "activation_key": activation_key,
                "is_admin": user_data["is_admin"],
                "is_active": True,  # Test users are automatically active
                "created_at": datetime.utcnow(),
                "last_login": None,
                "activated_at": datetime.utcnow()
            }
            
            # Store in database
            user_id = await db_manager.create_user(user_doc)
            
            created_users.append({
                "id": user_id,
                "email": user_data["email"],
                "username": user_data["username"],
                "password": user_data["password"],
                "activation_key": activation_key
            })
            
            print(f"✅ Created test user: {user_data['email']} (password: {user_data['password']})")
        
        if created_users:
            print(f"\n🎉 Created {len(created_users)} test users successfully!")
        
        return created_users
        
    except Exception as e:
        print(f"❌ Error creating test users: {e}")
        return []
    finally:
        await db_manager.disconnect()

async def main():
    """Main function"""
    print("🚀 CyberRazor Admin User Creation Script")
    print("=" * 60)
    
    # Create admin user
    admin_user = await create_admin_user()
    
    # Ask if user wants to create test users
    create_test = input("\n🤔 Do you want to create test users for development? (y/N): ").lower().strip()
    if create_test in ['y', 'yes']:
        await create_test_users()
    
    print("\n✨ Setup complete! You can now start the backend and login to the dashboard.")

if __name__ == "__main__":
    asyncio.run(main())

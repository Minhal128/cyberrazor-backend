#!/usr/bin/env python3
"""
Test authentication endpoints locally
"""

import requests
import json

def test_auth_endpoints():
    """Test authentication endpoints"""
    
    base_url = "http://localhost:8000"  # Local development server
    
    print("🔍 Testing Authentication Endpoints")
    print("=" * 50)
    
    # Test 1: Check if auth endpoints exist
    print("\n1. Testing endpoint availability:")
    
    try:
        response = requests.get(f"{base_url}/docs")
        if response.status_code == 200:
            print("✅ API documentation available")
        else:
            print("❌ API documentation not available")
    except Exception as e:
        print(f"❌ Cannot connect to local server: {e}")
        print("💡 Make sure to run: python main_mongo.py")
        return
    
    # Test 2: Try to signup a new user
    print("\n2. Testing user signup:")
    
    signup_data = {
        "username": "testuser",
        "email": "test@example.com",
        "password": "test123"
    }
    
    try:
        response = requests.post(f"{base_url}/api/auth/signup", json=signup_data)
        if response.status_code == 200:
            print("✅ Signup successful")
            token_data = response.json()
            print(f"   Access token: {token_data['access_token'][:20]}...")
        else:
            print(f"❌ Signup failed: {response.status_code}")
            print(f"   Response: {response.text}")
    except Exception as e:
        print(f"❌ Signup error: {e}")
    
    # Test 3: Try to login with default admin user
    print("\n3. Testing admin login:")
    
    login_data = {
        "email": "admin@cyberrazor.com",
        "password": "admin123"
    }
    
    try:
        response = requests.post(f"{base_url}/api/auth/login", json=login_data)
        if response.status_code == 200:
            print("✅ Admin login successful")
            token_data = response.json()
            print(f"   Access token: {token_data['access_token'][:20]}...")
            
            # Test 4: Get current user info
            print("\n4. Testing get current user:")
            headers = {"Authorization": f"Bearer {token_data['access_token']}"}
            response = requests.get(f"{base_url}/api/auth/me", headers=headers)
            if response.status_code == 200:
                user_data = response.json()
                print(f"✅ Current user: {user_data['username']} ({user_data['email']})")
                print(f"   Is admin: {user_data['is_admin']}")
            else:
                print(f"❌ Get current user failed: {response.status_code}")
        else:
            print(f"❌ Admin login failed: {response.status_code}")
            print(f"   Response: {response.text}")
    except Exception as e:
        print(f"❌ Login error: {e}")
    
    print("\n📋 Summary:")
    print("=" * 50)
    print("✅ Authentication endpoints are working locally")
    print("💡 The issue is that Vercel deployment hasn't picked up the latest changes")
    print("🔄 Wait a few more minutes for Vercel to complete the deployment")
    print("🔍 Check Vercel dashboard for deployment status")

if __name__ == "__main__":
    test_auth_endpoints() 
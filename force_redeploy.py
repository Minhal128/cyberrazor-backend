#!/usr/bin/env python3
"""
Force redeploy and test authentication endpoints
"""

import requests
import time
import json

def test_auth_endpoints():
    """Test authentication endpoints on deployed backend"""
    
    base_url = "https://cyberrazor-backend.vercel.app"
    
    print("🔍 Testing Authentication Endpoints on Deployed Backend")
    print("=" * 60)
    
    # Test 1: Check if auth endpoints exist in OpenAPI spec
    print("\n1. Checking OpenAPI specification:")
    
    try:
        response = requests.get(f"{base_url}/openapi.json", timeout=10)
        if response.status_code == 200:
            data = response.json()
            auth_endpoints = [path for path in data['paths'].keys() if 'auth' in path]
            if auth_endpoints:
                print("✅ Authentication endpoints found in OpenAPI spec:")
                for endpoint in auth_endpoints:
                    print(f"   - {endpoint}")
            else:
                print("❌ No authentication endpoints found in OpenAPI spec")
                print("💡 This means the deployment hasn't picked up the latest changes")
        else:
            print(f"❌ Failed to get OpenAPI spec: {response.status_code}")
    except Exception as e:
        print(f"❌ Error getting OpenAPI spec: {e}")
    
    # Test 2: Try to access auth endpoints directly
    print("\n2. Testing authentication endpoints directly:")
    
    # Test signup endpoint
    signup_data = {
        "username": "testuser",
        "email": "test@example.com",
        "password": "test123"
    }
    
    try:
        response = requests.post(f"{base_url}/api/auth/signup", json=signup_data, timeout=10)
        if response.status_code == 200:
            print("✅ Signup endpoint working")
            token_data = response.json()
            print(f"   Access token: {token_data['access_token'][:20]}...")
        elif response.status_code == 404:
            print("❌ Signup endpoint returns 404 - Not Found")
            print("💡 Authentication endpoints are not deployed yet")
        else:
            print(f"⚠️  Signup endpoint returns: {response.status_code}")
            print(f"   Response: {response.text}")
    except Exception as e:
        print(f"❌ Signup endpoint error: {e}")
    
    # Test login endpoint
    login_data = {
        "email": "admin@cyberrazor.com",
        "password": "admin123"
    }
    
    try:
        response = requests.post(f"{base_url}/api/auth/login", json=login_data, timeout=10)
        if response.status_code == 200:
            print("✅ Login endpoint working")
            token_data = response.json()
            print(f"   Access token: {token_data['access_token'][:20]}...")
        elif response.status_code == 404:
            print("❌ Login endpoint returns 404 - Not Found")
        else:
            print(f"⚠️  Login endpoint returns: {response.status_code}")
            print(f"   Response: {response.text}")
    except Exception as e:
        print(f"❌ Login endpoint error: {e}")
    
    print("\n📋 Summary:")
    print("=" * 60)
    print("🔍 If endpoints return 404, the deployment hasn't completed yet")
    print("💡 Wait 2-3 minutes for Vercel to complete the deployment")
    print("🔄 You can force a redeploy from Vercel dashboard")
    print("📝 Check Vercel deployment logs for any errors")

def force_redeploy_instructions():
    """Provide instructions for forcing a redeploy"""
    
    print("\n🚀 Force Redeploy Instructions:")
    print("=" * 60)
    print("1. Go to Vercel Dashboard: https://vercel.com/dashboard")
    print("2. Select your 'cyberrazor-backend' project")
    print("3. Go to 'Deployments' tab")
    print("4. Find the latest deployment")
    print("5. Click the three dots (...) menu")
    print("6. Select 'Redeploy'")
    print("7. Wait 2-3 minutes for deployment to complete")
    print("8. Run this script again to test")

if __name__ == "__main__":
    test_auth_endpoints()
    force_redeploy_instructions() 
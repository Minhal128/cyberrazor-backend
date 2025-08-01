#!/usr/bin/env python3
"""
Check Vercel deployment status and troubleshoot deployment issues
"""

import requests
import json
import time

def check_endpoint(url, name):
    """Check if an endpoint is responding"""
    try:
        response = requests.get(url, timeout=10)
        print(f"✅ {name}: {response.status_code}")
        if response.status_code == 200:
            try:
                data = response.json()
                return data
            except:
                return response.text[:100] + "..."
        return None
    except Exception as e:
        print(f"❌ {name}: {e}")
        return None

def main():
    base_url = "https://cyberrazor-backend.vercel.app"
    
    print("🔍 Checking Vercel Deployment Status")
    print("=" * 50)
    
    # Check root endpoint
    print("\n1. Testing Root Endpoint:")
    root_data = check_endpoint(f"{base_url}/", "Root")
    
    # Check health endpoint
    print("\n2. Testing Health Endpoint:")
    health_data = check_endpoint(f"{base_url}/api/health", "Health")
    
    # Check debug endpoint
    print("\n3. Testing Debug Endpoint:")
    debug_data = check_endpoint(f"{base_url}/api/debug", "Debug")
    
    # Analyze results
    print("\n📊 Analysis:")
    print("=" * 50)
    
    if root_data and isinstance(root_data, dict):
        version = root_data.get("version", "Unknown")
        print(f"📍 Backend Version: {version}")
        
        if version == "2.0.0":
            print("✅ Backend is running the latest version")
        else:
            print("⚠️  Backend might be running an older version")
    
    if health_data and isinstance(health_data, list):
        for service in health_data:
            if service.get("service") == "Database":
                status = service.get("status", "unknown")
                print(f"📍 Database Status: {status}")
                
                if "error" in service:
                    print(f"❌ Database Error: {service['error']}")
    
    if debug_data and isinstance(debug_data, dict):
        print("✅ Debug endpoint is working")
        if "mongodb_url_configured" in debug_data:
            configured = debug_data["mongodb_url_configured"]
            print(f"📍 MongoDB URL Configured: {configured}")
    else:
        print("⚠️  Debug endpoint not available - deployment might be in progress")
    
    print("\n🔧 Troubleshooting Steps:")
    print("=" * 50)
    
    if not debug_data:
        print("1. ⏳ Wait a few minutes for Vercel deployment to complete")
        print("2. 🔄 Check Vercel dashboard for deployment status")
        print("3. 📝 Verify environment variables are set in Vercel")
        print("4. 🔍 Check Vercel function logs for errors")
    
    if health_data and isinstance(health_data, list):
        for service in health_data:
            if service.get("service") == "Database" and service.get("status") == "disconnected":
                print("5. 🗄️  Set MONGODB_URL environment variable in Vercel")
                print("6. 🌐 Check MongoDB Atlas network access settings")
                print("7. 🔐 Verify MongoDB credentials are correct")
    
    print("\n💡 Next Steps:")
    print("=" * 50)
    print("1. Go to Vercel dashboard → Your project → Settings → Environment Variables")
    print("2. Add MONGODB_URL with your MongoDB Atlas connection string")
    print("3. Wait for deployment to complete (usually 1-2 minutes)")
    print("4. Run this script again to verify the fix")

if __name__ == "__main__":
    main() 
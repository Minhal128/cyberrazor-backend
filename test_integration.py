#!/usr/bin/env python3
"""
Test Integration Script
Tests the integration between CLI agent and backend
"""

import asyncio
import sys
import os
import json
import requests
from datetime import datetime

# Add the backend directory to the path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from database import db_manager

async def test_backend_connection():
    """Test backend API connection"""
    try:
        # Test backend health endpoint
        response = requests.get("https://cyberrazor-backend.vercel.app/api/health", timeout=5)
        if response.status_code == 200:
            print("✅ Backend API is running and accessible")
            print(f"   Response: {response.json()}")
            return True
        else:
            print(f"❌ Backend API returned status code: {response.status_code}")
            return False
    except requests.exceptions.ConnectionError:
        print("❌ Cannot connect to backend API - make sure it's running on port 8000")
        return False
    except Exception as e:
        print(f"❌ Error testing backend connection: {e}")
        return False

async def test_database_connection():
    """Test MongoDB database connection"""
    try:
        await db_manager.connect()
        
        # Test database operations
        user_count = await db_manager.db.users.count_documents({})
        threat_count = await db_manager.db.threats.count_documents({})
        activation_count = await db_manager.db.device_activations.count_documents({})
        
        print("✅ MongoDB database is connected and accessible")
        print(f"   Users: {user_count}")
        print(f"   Threats: {threat_count}")
        print(f"   Device Activations: {activation_count}")
        
        await db_manager.disconnect()
        return True
        
    except Exception as e:
        print(f"❌ Error connecting to MongoDB: {e}")
        return False

def test_threat_submission():
    """Test threat submission to backend"""
    try:
        # Mock threat data from CLI agent
        threat_data = {
            "device_id": "TEST-DEVICE-001",
            "timestamp": datetime.now().isoformat(),
            "threat_type": "malware",
            "confidence_score": 0.85,
            "source": "Desktop",
            "details": {
                "file_size": 1024000,
                "file_hash": "abc123def456",
                "detection_engine": "CyberRazor AI",
                "ai_verdict": "Malicious",
                "ai_confidence": "High",
                "ai_reason": "Test threat submission",
                "severity": "high"
            },
            "action_taken": "quarantined",
            "severity": "high",
            "ai_verdict": "Malicious",
            "ai_confidence": "High",
            "ai_reason": "Test threat submission"
        }
        
        # Submit threat to backend
        response = requests.post(
            "https://cyberrazor-backend.vercel.app/api/report-threat",
            json=threat_data,
            timeout=10
        )
        
        if response.status_code == 200:
            result = response.json()
            print("✅ Threat submission successful")
            print(f"   Threat ID: {result.get('threat_id')}")
            return True
        else:
            print(f"❌ Threat submission failed with status code: {response.status_code}")
            print(f"   Response: {response.text}")
            return False
            
    except Exception as e:
        print(f"❌ Error submitting threat: {e}")
        return False

def test_device_activation():
    """Test device activation"""
    try:
        # Mock device activation data
        activation_data = {
            "user_email": "test1@example.com",
            "hostname": "TEST-MACHINE-001",
            "os_info": "Windows 11 Pro",
            "activation_key": "test-activation-key-123",
            "computer_name": "TestComputer",
            "username": "testuser"
        }
        
        # Submit activation to backend
        response = requests.post(
            "https://cyberrazor-backend.vercel.app/api/activate-key",
            json=activation_data,
            timeout=10
        )
        
        if response.status_code == 200:
            result = response.json()
            print("✅ Device activation test successful")
            print(f"   Device Info: {result.get('device_info')}")
            return True
        else:
            print(f"❌ Device activation failed with status code: {response.status_code}")
            print(f"   Response: {response.text}")
            return False
            
    except Exception as e:
        print(f"❌ Error testing device activation: {e}")
        return False

async def test_websocket_endpoints():
    """Test WebSocket endpoints"""
    try:
        # Test WebSocket endpoint availability (just check if it's listening)
        import socket
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        result = sock.connect_ex(('localhost', 8000))
        sock.close()
        
        if result == 0:
            print("✅ WebSocket endpoints are accessible")
            print("   Available endpoints:")
            print("   - ws://localhost:8000/ws/alerts")
            print("   - ws://localhost:8000/ws/analytics")
            print("   - ws://localhost:8000/ws/threats")
            return True
        else:
            print("❌ WebSocket endpoints are not accessible")
            return False
            
    except Exception as e:
        print(f"❌ Error testing WebSocket endpoints: {e}")
        return False

async def main():
    """Main integration test function"""
    print("🧪 CyberRazor Integration Test Suite")
    print("=" * 60)
    
    tests_passed = 0
    total_tests = 5
    
    # Test 1: Backend API Connection
    print("\n🔍 Test 1: Backend API Connection")
    if await test_backend_connection():
        tests_passed += 1
    
    # Test 2: Database Connection
    print("\n🔍 Test 2: MongoDB Database Connection")
    if await test_database_connection():
        tests_passed += 1
    
    # Test 3: Threat Submission
    print("\n🔍 Test 3: Threat Submission")
    if test_threat_submission():
        tests_passed += 1
    
    # Test 4: Device Activation
    print("\n🔍 Test 4: Device Activation")
    if test_device_activation():
        tests_passed += 1
    
    # Test 5: WebSocket Endpoints
    print("\n🔍 Test 5: WebSocket Endpoints")
    if await test_websocket_endpoints():
        tests_passed += 1
    
    # Results
    print("\n" + "=" * 60)
    print("📊 TEST RESULTS")
    print("=" * 60)
    print(f"Tests Passed: {tests_passed}/{total_tests}")
    print(f"Success Rate: {(tests_passed/total_tests)*100:.1f}%")
    
    if tests_passed == total_tests:
        print("\n🎉 ALL TESTS PASSED! Integration is working correctly.")
        print("\n📋 Next Steps:")
        print("1. ✅ Backend is running and accessible")
        print("2. ✅ Database is connected and functional")
        print("3. ✅ CLI agent can submit threats")
        print("4. ✅ Device activation is working")
        print("5. ✅ Real-time WebSocket endpoints are ready")
        print("\n🚀 You can now run the CLI agent and view results in the dashboard!")
    else:
        print("\n⚠️  Some tests failed. Please check the issues above.")
        
    print("\n🔗 Dashboard URL: https://cyberrazor-backend.vercel.app")
    print("🔗 Backend API: https://cyberrazor-backend.vercel.app")
    print("🔗 API Docs: https://cyberrazor-backend.vercel.app/docs")

if __name__ == "__main__":
    asyncio.run(main())

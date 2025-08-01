#!/usr/bin/env python3
"""
Test File Generator for CyberRazor
Creates test files to trigger real-time detection
"""

import os
import time
import random
from pathlib import Path

def create_test_files():
    """Create test files to trigger detection"""
    
    # Test directories
    test_dirs = [
        os.path.expanduser("~/Downloads"),
        os.path.expanduser("~/Desktop"),
        os.path.expanduser("~/Documents")
    ]
    
    # Create test files
    test_files = [
        {
            "name": "suspicious_test.exe",
            "content": b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\xb8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x00\x0e\x1f\xba\x0e\x00\xb4\x09\xcd\x21\xb8\x01\x4c\xcd\x21This is a test executable file for CyberRazor detection testing.",
            "type": "executable"
        },
        {
            "name": "test_script.bat",
            "content": b"@echo off\r\ncmd.exe /c powershell -Command \"Write-Host 'Test script detected'\"\r\npause",
            "type": "batch"
        },
        {
            "name": "suspicious_pdf.pdf",
            "content": b"%PDF-1.4\n1 0 obj\n<<\n/Type /Catalog\n/Pages 2 0 R\n>>\nendobj\n2 0 obj\n<<\n/Type /Pages\n/Kids [3 0 R]\n/Count 1\n>>\nendobj\n3 0 obj\n<<\n/Type /Page\n/Parent 2 0 R\n/MediaBox [0 0 612 792]\n/Contents 4 0 R\n>>\nendobj\n4 0 obj\n<<\n/Length 44\n>>\nstream\nBT\n/F1 12 Tf\n72 720 Td\n(Test PDF for detection) Tj\nET\nendstream\nendobj\nxref\n0 5\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n0000000115 00000 n \n0000000204 00000 n \ntrailer\n<<\n/Size 5\n/Root 1 0 R\n>>\nstartxref\n297\n%%EOF",
            "type": "pdf"
        },
        {
            "name": "normal_text.txt",
            "content": b"This is a normal text file that should not trigger any alerts.",
            "type": "text"
        },
        {
            "name": "test_script.ps1",
            "content": b"Write-Host 'PowerShell test script'\nGet-Process | Where-Object {$_.ProcessName -like '*test*'}\n",
            "type": "powershell"
        }
    ]
    
    print("🔧 Creating test files for CyberRazor detection...")
    
    for test_dir in test_dirs:
        if os.path.exists(test_dir):
            print(f"📁 Creating files in: {test_dir}")
            
            for test_file in test_files:
                file_path = os.path.join(test_dir, test_file["name"])
                
                try:
                    with open(file_path, 'wb') as f:
                        f.write(test_file["content"])
                    
                    print(f"   ✅ Created: {test_file['name']} ({test_file['type']})")
                    
                    # Wait a bit between files to see real-time detection
                    time.sleep(2)
                    
                except Exception as e:
                    print(f"   ❌ Failed to create {test_file['name']}: {e}")
        else:
            print(f"   ⚠️  Directory not found: {test_dir}")
    
    print("\n🎯 Test files created! Check the real-time monitor for detection events.")
    print("📊 You should see these files appear in your CyberRazor dashboard.")

if __name__ == "__main__":
    create_test_files() 
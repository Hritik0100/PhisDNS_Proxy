#!/usr/bin/env python3
"""
Setup script for PhishBlock-DNS
Helps users configure their system and test the phishing warning feature
"""

import socket
import subprocess
import sys
import os
import webbrowser
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading

def get_local_ip():
    """Get the local IP address"""
    try:
        # Connect to a remote address to determine local IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except:
        return "127.0.0.1"

def test_warning_page():
    """Test the warning page by starting a temporary server"""
    class TestHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            html_content = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🚨 PHISHING SITE BLOCKED 🚨</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #ff0000, #cc0000);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
        }
        
        .warning-container {
            background: rgba(0, 0, 0, 0.8);
            border-radius: 20px;
            padding: 40px;
            max-width: 600px;
            text-align: center;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.5);
            border: 3px solid #ff4444;
            animation: pulse 2s infinite;
        }
        
        @keyframes pulse {
            0% { transform: scale(1); }
            50% { transform: scale(1.05); }
            100% { transform: scale(1); }
        }
        
        .warning-icon {
            font-size: 80px;
            margin-bottom: 20px;
            animation: shake 0.5s infinite;
        }
        
        @keyframes shake {
            0%, 100% { transform: translateX(0); }
            25% { transform: translateX(-5px); }
            75% { transform: translateX(5px); }
        }
        
        h1 {
            font-size: 2.5em;
            margin-bottom: 20px;
            text-shadow: 2px 2px 4px rgba(0, 0, 0, 0.5);
        }
        
        .domain-name {
            background: #ff4444;
            padding: 10px 20px;
            border-radius: 10px;
            font-family: monospace;
            font-size: 1.2em;
            margin: 20px 0;
            display: inline-block;
            border: 2px solid white;
        }
        
        .warning-text {
            font-size: 1.2em;
            line-height: 1.6;
            margin-bottom: 30px;
        }
        
        .button {
            background: #ffffff;
            color: #cc0000;
            padding: 15px 30px;
            border: none;
            border-radius: 10px;
            font-size: 1.1em;
            font-weight: bold;
            cursor: pointer;
            text-decoration: none;
            display: inline-block;
            margin: 10px;
            transition: all 0.3s ease;
        }
        
        .button:hover {
            background: #f0f0f0;
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.3);
        }
        
        .footer {
            margin-top: 30px;
            font-size: 0.9em;
            opacity: 0.8;
        }
        
        .stats {
            background: rgba(255, 255, 255, 0.1);
            padding: 15px;
            border-radius: 10px;
            margin: 20px 0;
            font-size: 0.9em;
        }
    </style>
</head>
<body>
    <div class="warning-container">
        <div class="warning-icon">🚨</div>
        <h1>PHISHING SITE BLOCKED</h1>
        
        <div class="domain-name">test-phishing-site.com</div>
        
        <div class="warning-text">
            <strong>This website has been identified as a potential phishing site!</strong><br><br>
            PhishBlock-DNS has blocked access to this domain because it has been flagged by multiple security engines as malicious or suspicious.
        </div>
        
        <div class="stats">
            <strong>Protection Details:</strong><br>
            • Domain flagged by VirusTotal security engines<br>
            • Blocked by PhishBlock-DNS protection system<br>
            • Timestamp: Test Mode
        </div>
        
        <div>
            <a href="javascript:history.back()" class="button">← Go Back</a>
            <a href="https://www.google.com" class="button">Go to Google</a>
        </div>
        
        <div class="footer">
            Protected by PhishBlock-DNS | Real-time phishing detection powered by VirusTotal
        </div>
    </div>
</body>
</html>
            """
            
            self.send_response(200)
            self.send_header('Content-type', 'text/html; charset=utf-8')
            self.end_headers()
            self.wfile.write(html_content.encode('utf-8'))
        
        def log_message(self, format, *args):
            pass
    
    # Start test server
    test_server = HTTPServer(('localhost', 8080), TestHandler)
    test_thread = threading.Thread(target=test_server.serve_forever, daemon=True)
    test_thread.start()
    
    print("🚨 Starting test warning page...")
    time.sleep(1)
    
    # Open browser
    try:
        webbrowser.open('http://localhost:8080')
        print("✅ Test warning page opened in browser!")
        print("📝 This is how the phishing warning will look when a malicious site is blocked.")
        print("🛑 Press Enter to close the test server...")
        input()
    except:
        print("❌ Could not open browser automatically.")
        print("📝 Please manually open: http://localhost:8080")
        input("Press Enter when done...")
    
    test_server.shutdown()

def main():
    """Main setup function"""
    print("🛡️ PhishBlock-DNS Setup")
    print("=" * 50)
    
    local_ip = get_local_ip()
    
    print(f"📍 Your local IP address: {local_ip}")
    print(f"🌐 DNS Server will run on: {local_ip}:53")
    print(f"⚠️  Warning page will run on: {local_ip}:8080")
    print()
    
    # Test warning page
    print("🧪 Testing Warning Page...")
    test_warning_page()
    
    print("\n📋 Configuration Instructions:")
    print("=" * 50)
    print()
    
    # Windows instructions
    if os.name == 'nt':
        print("🪟 Windows Configuration:")
        print("1. Open Network & Internet settings")
        print("2. Click on 'Change adapter options'")
        print("3. Right-click your network adapter → Properties")
        print("4. Select 'Internet Protocol Version 4 (TCP/IPv4)' → Properties")
        print("5. Select 'Use the following DNS server addresses'")
        print(f"6. Preferred DNS: {local_ip}")
        print("7. Click OK and restart your network connection")
        print()
    
    # Linux instructions
    else:
        print("🐧 Linux Configuration:")
        print("1. Edit /etc/resolv.conf (as root):")
        print(f"   nameserver {local_ip}")
        print("2. Or configure NetworkManager:")
        print("   nmcli connection modify 'Your Connection' ipv4.dns " + local_ip)
        print()
    
    # macOS instructions
    print("🍎 macOS Configuration:")
    print("1. Open System Preferences → Network")
    print("2. Select your network connection → Advanced")
    print("3. Go to DNS tab")
    print(f"4. Add {local_ip} to DNS servers list")
    print("5. Click OK and Apply")
    print()
    
    print("🚀 Starting PhishBlock-DNS...")
    print("📝 Run this command to start the DNS server:")
    print("   python phishblock_dns.py")
    print()
    print("✅ Setup complete! Your system is ready for phishing protection.")

if __name__ == "__main__":
    main() 
#!/usr/bin/env python3
"""
Start both DNS server and warning server together
"""

import subprocess
import threading
import time
import sys
import os

def start_dns_server():
    """Start the DNS server"""
    print("🛡️ Starting DNS Server...")
    try:
        subprocess.run([sys.executable, "phishblock_dns.py"], check=True)
    except KeyboardInterrupt:
        print("DNS Server stopped")
    except Exception as e:
        print(f"DNS Server error: {e}")

def start_warning_server():
    """Start the warning server"""
    print("🚨 Starting Warning Server...")
    try:
        subprocess.run([sys.executable, "web_server_config.py"], check=True)
    except KeyboardInterrupt:
        print("Warning Server stopped")
    except Exception as e:
        print(f"Warning Server error: {e}")

def main():
    print("🚀 Starting PhishBlock-DNS with Warning Page...")
    print("=" * 50)
    
    # Start both servers in separate threads
    dns_thread = threading.Thread(target=start_dns_server, daemon=True)
    warning_thread = threading.Thread(target=start_warning_server, daemon=True)
    
    dns_thread.start()
    time.sleep(2)  # Give DNS server time to start
    warning_thread.start()
    
    print("✅ Both servers started!")
    print("📡 DNS Server: Port 53")
    print("⚠️  Warning Server: Port 8080")
    print("🌐 Test warning page: http://localhost:8080")
    print("🛑 Press Ctrl+C to stop both servers")
    
    try:
        # Keep main thread alive
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n🛑 Shutting down servers...")
        print("👋 Goodbye!")

if __name__ == "__main__":
    main() 
#!/usr/bin/env python3
"""
PhishBlock-DNS: Private DNS with Real-time Phishing Detection
Uses VirusTotal API (Free Tier) to block malicious/phishing domains
"""

import asyncio
import sqlite3
import json
import time
import logging
import socket
import struct
import threading
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta
import requests
from dnslib import DNSRecord, DNSHeader, RR, QTYPE, RCODE, A, AAAA
from dnslib.server import DNSServer, BaseResolver
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse

# Configuration
CONFIG = {
    'VIRUSTOTAL_API_KEY': 'a1c4d621eda38e24bfede0515e13cc8b432a15e3c90c183d39a362cebb743d18',  # Get from https://www.virustotal.com/gui/join
    'UPSTREAM_DNS': ['8.8.8.8', '1.1.1.1'],  # Fallback DNS servers
    'DNS_PORT': 53,
    'WARNING_SERVER_PORT': 8080,  # Port for the warning web server
    'CACHE_TTL_HOURS': 24,  # Cache results for 24 hours
    'MALICIOUS_THRESHOLD': 2,  # Consider malicious if 2+ engines flag it
    'BLOCK_IP': '192.168.1.14',  # IP to return for blocked domains (localhost)
    'DATABASE_PATH': 'phishblock_cache.db',
    'LOG_LEVEL': logging.INFO,
    'ENABLE_LOGGING': True
}

# Setup logging
if CONFIG['ENABLE_LOGGING']:
    logging.basicConfig(
        level=CONFIG['LOG_LEVEL'],
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('phishblock.log'),
            logging.StreamHandler()
        ]
    )
    logger = logging.getLogger(__name__)
else:
    logger = logging.getLogger(__name__)
    logger.disabled = True

class DNSCache:
    """SQLite-based cache for domain reputation results"""
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize the SQLite database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS domain_cache (
                domain TEXT PRIMARY KEY,
                is_malicious BOOLEAN,
                malicious_count INTEGER,
                total_engines INTEGER,
                timestamp DATETIME,
                expires_at DATETIME
            )
        ''')
        conn.commit()
        conn.close()
        logger.info(f"Database initialized: {self.db_path}")
    
    def get_cached_result(self, domain: str) -> Optional[Dict]:
        """Get cached result for domain if not expired"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT is_malicious, malicious_count, total_engines, timestamp
            FROM domain_cache 
            WHERE domain = ? AND expires_at > ?
        ''', (domain, datetime.now()))
        
        result = cursor.fetchone()
        conn.close()
        
        if result:
            return {
                'domain': domain,
                'is_malicious': bool(result[0]),
                'malicious_count': result[1],
                'total_engines': result[2],
                'timestamp': result[3]
            }
        return None
    
    def cache_result(self, domain: str, is_malicious: bool, malicious_count: int, total_engines: int):
        """Cache domain reputation result"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        now = datetime.now()
        expires_at = now + timedelta(hours=CONFIG['CACHE_TTL_HOURS'])
        
        cursor.execute('''
            INSERT OR REPLACE INTO domain_cache 
            (domain, is_malicious, malicious_count, total_engines, timestamp, expires_at)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (domain, is_malicious, malicious_count, total_engines, now, expires_at))
        
        conn.commit()
        conn.close()
        logger.info(f"Cached result for {domain}: malicious={is_malicious} ({malicious_count}/{total_engines})")
    
    def cleanup_expired(self):
        """Remove expired cache entries"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('DELETE FROM domain_cache WHERE expires_at < ?', (datetime.now(),))
        deleted = cursor.rowcount
        conn.commit()
        conn.close()
        if deleted > 0:
            logger.info(f"Cleaned up {deleted} expired cache entries")

class VirusTotalChecker:
    """VirusTotal API integration for domain reputation checking"""
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers.update({
            'x-apikey': api_key,
            'User-Agent': 'PhishBlock-DNS/1.0'
        })
        self.rate_limit_delay = 15  # 4 requests per minute for free tier
        self.last_request_time = 0
    
    def check_domain(self, domain: str) -> Dict:
        """Check domain reputation using VirusTotal API"""
        # Rate limiting for free tier
        elapsed = time.time() - self.last_request_time
        if elapsed < self.rate_limit_delay:
            time.sleep(self.rate_limit_delay - elapsed)
        
        try:
            url = f"https://www.virustotal.com/api/v3/domains/{domain}"
            response = self.session.get(url, timeout=10)
            self.last_request_time = time.time()
            
            if response.status_code == 200:
                data = response.json()
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                
                malicious_count = stats.get('malicious', 0)
                suspicious_count = stats.get('suspicious', 0)
                total_engines = sum(stats.values())
                
                # Consider suspicious as potentially malicious
                total_bad = malicious_count + suspicious_count
                is_malicious = total_bad >= CONFIG['MALICIOUS_THRESHOLD']
                
                logger.info(f"VirusTotal check for {domain}: {malicious_count} malicious, {suspicious_count} suspicious, {total_engines} total")
                
                return {
                    'domain': domain,
                    'is_malicious': is_malicious,
                    'malicious_count': total_bad,
                    'total_engines': total_engines,
                    'raw_stats': stats
                }
            
            elif response.status_code == 404:
                # Domain not found in VirusTotal - assume clean
                logger.info(f"Domain {domain} not found in VirusTotal - assuming clean")
                return {
                    'domain': domain,
                    'is_malicious': False,
                    'malicious_count': 0,
                    'total_engines': 0,
                    'raw_stats': {}
                }
            
            else:
                logger.error(f"VirusTotal API error for {domain}: {response.status_code}")
                # On API error, block (fail closed)
                return {
                    'domain': domain,
                    'is_malicious': True,
                    'malicious_count': 0,
                    'total_engines': 0,
                    'error': f"API Error: {response.status_code}"
                }
        
        except Exception as e:
            logger.error(f"Exception checking {domain}: {str(e)}")
            # On exception, block (fail closed)
            return {
                'domain': domain,
                'is_malicious': True,
                'malicious_count': 0,
                'total_engines': 0,
                'error': str(e)
            }

class WarningServer:
    """HTTP server to display phishing warning pages"""
    
    def __init__(self, port: int = 8080):
        self.port = port
        self.server = None
        self.server_thread = None
        
    def start(self):
        """Start the warning server in a separate thread"""
        class WarningHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                # Parse the requested URL to get the blocked domain
                parsed_url = urllib.parse.urlparse(self.path)
                blocked_domain = parsed_url.query.split('=')[1] if 'domain=' in parsed_url.query else 'unknown'
                
                # Create the warning HTML page
                html_content = self.create_warning_page(blocked_domain)
                
                self.send_response(200)
                self.send_header('Content-type', 'text/html; charset=utf-8')
                self.end_headers()
                self.wfile.write(html_content.encode('utf-8'))
            
            def create_warning_page(self, blocked_domain: str):
                """Create HTML content for the phishing warning page"""
                return f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🚨 PHISHING SITE BLOCKED 🚨</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #ff0000, #cc0000);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
        }}
        
        .warning-container {{
            background: rgba(0, 0, 0, 0.8);
            border-radius: 20px;
            padding: 40px;
            max-width: 600px;
            text-align: center;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.5);
            border: 3px solid #ff4444;
            animation: pulse 2s infinite;
        }}
        
        @keyframes pulse {{
            0% {{ transform: scale(1); }}
            50% {{ transform: scale(1.05); }}
            100% {{ transform: scale(1); }}
        }}
        
        .warning-icon {{
            font-size: 80px;
            margin-bottom: 20px;
            animation: shake 0.5s infinite;
        }}
        
        @keyframes shake {{
            0%, 100% {{ transform: translateX(0); }}
            25% {{ transform: translateX(-5px); }}
            75% {{ transform: translateX(5px); }}
        }}
        
        h1 {{
            font-size: 2.5em;
            margin-bottom: 20px;
            text-shadow: 2px 2px 4px rgba(0, 0, 0, 0.5);
        }}
        
        .domain-name {{
            background: #ff4444;
            padding: 10px 20px;
            border-radius: 10px;
            font-family: monospace;
            font-size: 1.2em;
            margin: 20px 0;
            display: inline-block;
            border: 2px solid white;
        }}
        
        .warning-text {{
            font-size: 1.2em;
            line-height: 1.6;
            margin-bottom: 30px;
        }}
        
        .button {{
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
        }}
        
        .button:hover {{
            background: #f0f0f0;
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.3);
        }}
        
        .footer {{
            margin-top: 30px;
            font-size: 0.9em;
            opacity: 0.8;
        }}
        
        .stats {{
            background: rgba(255, 255, 255, 0.1);
            padding: 15px;
            border-radius: 10px;
            margin: 20px 0;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <div class="warning-container">
        <div class="warning-icon">🚨</div>
        <h1>PHISHING SITE BLOCKED</h1>
        
        <div class="domain-name">{blocked_domain}</div>
        
        <div class="warning-text">
            <strong>This website has been identified as a potential phishing site!</strong><br><br>
            PhishBlock-DNS has blocked access to this domain because it has been flagged by multiple security engines as malicious or suspicious.
        </div>
        
        <div class="stats">
            <strong>Protection Details:</strong><br>
            • Domain flagged by VirusTotal security engines<br>
            • Blocked by PhishBlock-DNS protection system<br>
            • Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
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
            
            def log_message(self, format, *args):
                # Suppress HTTP server logs
                pass
        
        try:
            self.server = HTTPServer(('0.0.0.0', self.port), WarningHandler)
            self.server_thread = threading.Thread(target=self.server.serve_forever, daemon=True)
            self.server_thread.start()
            logger.info(f"Warning server started on port {self.port}")
        except Exception as e:
            logger.error(f"Failed to start warning server: {e}")
    
    def stop(self):
        """Stop the warning server"""
        if self.server:
            self.server.shutdown()
            logger.info("Warning server stopped")

class PhishBlockResolver(BaseResolver):
    """Custom DNS resolver with phishing protection"""
    
    def __init__(self):
        self.cache = DNSCache(CONFIG['DATABASE_PATH'])
        self.vt_checker = VirusTotalChecker(CONFIG['VIRUSTOTAL_API_KEY'])
        self.upstream_resolvers = CONFIG['UPSTREAM_DNS']
        self.stats = {
            'total_queries': 0,
            'blocked_queries': 0,
            'cache_hits': 0,
            'api_calls': 0
        }
        
        # Start warning server
        self.warning_server = WarningServer(CONFIG['WARNING_SERVER_PORT'])
        self.warning_server.start()
        
        # Start cache cleanup thread
        self.start_cleanup_thread()
    
    def start_cleanup_thread(self):
        """Start background thread for cache cleanup"""
        def cleanup_worker():
            while True:
                time.sleep(3600)  # Run every hour
                try:
                    self.cache.cleanup_expired()
                except Exception as e:
                    logger.error(f"Cache cleanup error: {e}")
        
        cleanup_thread = threading.Thread(target=cleanup_worker, daemon=True)
        cleanup_thread.start()
        logger.info("Cache cleanup thread started")
    
    def resolve(self, request, handler):
        """Main DNS resolution logic with phishing protection"""
        self.stats['total_queries'] += 1
        reply = request.reply()
        
        try:
            # Extract domain from query
            qname = str(request.q.qname).rstrip('.')
            qtype = request.q.qtype
            
            logger.debug(f"DNS Query: {qname} ({QTYPE[qtype]})")
            
            # Skip checking for non-A/AAAA records or special domains
            if qtype not in [QTYPE.A, QTYPE.AAAA] or self.is_special_domain(qname):
                return self.resolve_upstream(request, handler)
            
            # Check cache first
            cached_result = self.cache.get_cached_result(qname)
            if cached_result:
                self.stats['cache_hits'] += 1
                logger.debug(f"Cache hit for {qname}: malicious={cached_result['is_malicious']}")
                
                if cached_result['is_malicious']:
                    return self.create_blocked_response(request, qname)
                else:
                    return self.resolve_upstream(request, handler)
            
            # Check with VirusTotal
            self.stats['api_calls'] += 1
            vt_result = self.vt_checker.check_domain(qname)
            
            # Cache the result
            self.cache.cache_result(
                qname,
                vt_result['is_malicious'],
                vt_result['malicious_count'],
                vt_result['total_engines']
            )
            
            # Block if malicious or if there was an error
            if vt_result['is_malicious'] or 'error' in vt_result:
                self.stats['blocked_queries'] += 1
                logger.warning(f"BLOCKED: {qname} (flagged by {vt_result['malicious_count']}/{vt_result['total_engines']} engines or error: {vt_result.get('error', '')})")
                return self.create_blocked_response(request, qname)
            
            # Resolve normally if clean
            logger.info(f"ALLOWED: {qname} (clean: {vt_result['malicious_count']}/{vt_result['total_engines']} engines)")
            return self.resolve_upstream(request, handler)
        
        except Exception as e:
            logger.error(f"Error resolving {qname}: {str(e)}")
            # On error, resolve normally (fail open)
            return self.resolve_upstream(request, handler)
    
    def is_special_domain(self, domain: str) -> bool:
        """Check if domain should skip phishing checks"""
        special_domains = [
            'localhost',
            '*.local',
            '*.internal',
            '*.lan',
            'time.nist.gov',
            'ntp.org'
        ]
        
        for special in special_domains:
            if special.startswith('*'):
                if domain.endswith(special[2:]):
                    return True
            elif domain == special:
                return True
        
        return False
    
    def create_blocked_response(self, request, domain: str):
        """Create a DNS response that blocks the domain and redirects to warning page"""
        reply = request.reply()
        
        if request.q.qtype == QTYPE.A:
            # Return localhost IP for A records - this will redirect to our warning server
            reply.add_answer(RR(request.q.qname, QTYPE.A, rdata=A(CONFIG['BLOCK_IP']), ttl=300))
        elif request.q.qtype == QTYPE.AAAA:
            # Return NXDOMAIN for AAAA records (or could return ::0)
            reply.header.rcode = RCODE.NXDOMAIN
        
        logger.info(f"Blocked domain: {domain} - redirecting to warning page")
        return reply
    
    def resolve_upstream(self, request, handler):
        """Resolve query using upstream DNS servers"""
        for upstream in self.upstream_resolvers:
            try:
                # Forward query to upstream DNS
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(5)
                
                # Send query
                query_data = request.pack()
                sock.sendto(query_data, (upstream, 53))
                
                # Receive response
                response_data, _ = sock.recvfrom(4096)
                sock.close()
                
                # Parse and return response
                response = DNSRecord.parse(response_data)
                logger.debug(f"Resolved {request.q.qname} via {upstream}")
                return response
            
            except Exception as e:
                logger.debug(f"Upstream {upstream} failed: {e}")
                continue
        
        # If all upstream resolvers fail, return SERVFAIL
        reply = request.reply()
        reply.header.rcode = RCODE.SERVFAIL
        return reply
    
    def get_stats(self) -> Dict:
        """Get resolver statistics"""
        return self.stats.copy()

def main():
    """Main function to start the PhishBlock DNS server"""
    
    # Validate configuration
    if CONFIG['VIRUSTOTAL_API_KEY'] == 'YOUR_VIRUSTOTAL_API_KEY_HERE':
        logger.error("Please set your VirusTotal API key in the CONFIG dictionary")
        print("\n🚨 SETUP REQUIRED:")
        print("1. Get a free VirusTotal API key from: https://www.virustotal.com/gui/join")
        print("2. Replace 'YOUR_VIRUSTOTAL_API_KEY_HERE' in the CONFIG dictionary")
        print("3. Run the script again")
        return
    
    # Create resolver
    resolver = PhishBlockResolver()
    
    # Create DNS server
    server = DNSServer(resolver, port=CONFIG['DNS_PORT'], address="0.0.0.0")
    
    logger.info("🛡️ PhishBlock-DNS Server Starting...")
    logger.info(f"📡 Listening on port {CONFIG['DNS_PORT']}")
    logger.info(f"🔍 Using VirusTotal API for phishing detection")
    logger.info(f"🚫 Blocking threshold: {CONFIG['MALICIOUS_THRESHOLD']} engines")
    logger.info(f"⬆️  Upstream DNS: {', '.join(CONFIG['UPSTREAM_DNS'])}")
    logger.info(f"💾 Cache TTL: {CONFIG['CACHE_TTL_HOURS']} hours")
    logger.info(f"⚠️  Warning server on port {CONFIG['WARNING_SERVER_PORT']}")
    
    print("\n✅ PhishBlock-DNS is running!")
    print(f"📱 Configure your device to use this DNS server:")
    print(f"   - IP Address: {socket.gethostbyname(socket.gethostname())} (or your server IP)")
    print(f"   - Port: {CONFIG['DNS_PORT']}")
    print(f"⚠️  Warning page available at: http://localhost:{CONFIG['WARNING_SERVER_PORT']}")
    print("\n📱 For Android Private DNS (DoT), you'll need to set up TLS termination")
    print("📊 Check phishblock.log for detailed logs")
    print("🛑 Press Ctrl+C to stop")
    
    try:
        server.start_thread()
        
        # Print stats periodically
        while True:
            time.sleep(300)  # Every 5 minutes
            stats = resolver.get_stats()
            logger.info(f"📊 Stats: {stats['total_queries']} queries, {stats['blocked_queries']} blocked, {stats['cache_hits']} cache hits, {stats['api_calls']} API calls")
    
    except KeyboardInterrupt:
        logger.info("🛑 Shutting down PhishBlock-DNS...")
        server.stop()
        resolver.warning_server.stop()
        print("\n👋 PhishBlock-DNS stopped. Stay safe!")

if __name__ == "__main__":
    main()

# 🛡️ PhishBlock-DNS

**Private DNS with Real-time Phishing Detection and Visual Warning System**

PhishBlock-DNS is a powerful DNS server that protects you from phishing and malicious websites by:
- ✅ Real-time domain reputation checking using VirusTotal API
- 🚨 **NEW: Visual red alert warning page when visiting phishing sites**
- 💾 Intelligent caching for performance
- 🔄 Automatic fallback to upstream DNS servers
- 📊 Detailed logging and statistics

## 🚨 New Feature: Phishing Warning Page

When you try to visit a phishing site, instead of just blocking it silently, PhishBlock-DNS now shows a **striking red alert page** that:

- 🎨 **Eye-catching red design** with animated warning icons
- 📝 **Clear explanation** of why the site was blocked
- 🔍 **Domain information** showing which site was blocked
- ⏰ **Timestamp** of when the block occurred
- 🔗 **Action buttons** to go back or visit safe alternatives
- 📱 **Mobile-responsive** design

## 🚀 Quick Start

### 1. Setup and Test Warning Page

```bash
# Run the setup script to test the warning page
python setup_phishblock.py
```

This will:
- Show you a preview of the phishing warning page
- Provide configuration instructions for your OS
- Help you set up the DNS server

### 2. Start the DNS Server

```bash
# Start the main DNS server
python phishblock_dns.py
```

### 3. Configure Your Device

Follow the instructions provided by the setup script to configure your device to use the PhishBlock-DNS server.

## 📋 Requirements

- Python 3.7+
- VirusTotal API key (free)
- Network access
- Administrator/root privileges (for DNS port 53)

## 🔧 Installation

1. **Clone or download the project**
2. **Install dependencies:**
   ```bash
   pip install dnslib requests
   ```
3. **Get a free VirusTotal API key:**
   - Visit: https://www.virustotal.com/gui/join
   - Sign up for a free account
   - Get your API key
4. **Update the API key in `phishblock_dns.py`:**
   ```python
   'VIRUSTOTAL_API_KEY': 'your_api_key_here'
   ```

## 🎯 How It Works

### DNS Resolution Process

1. **Query Received**: When you visit a website, your device asks the DNS server for the IP address
2. **Cache Check**: PhishBlock-DNS first checks its local cache for known results
3. **VirusTotal Check**: If not cached, it queries VirusTotal API for domain reputation
4. **Decision Made**: 
   - ✅ **Clean site**: Returns real IP address
   - 🚨 **Phishing site**: Returns localhost IP (127.0.0.1)
5. **Warning Page**: Browser loads the localhost warning server, showing the red alert

### Warning Page Features

- **Visual Impact**: Red gradient background with pulsing animation
- **Clear Messaging**: Explains why the site was blocked
- **Domain Display**: Shows the blocked domain name
- **Protection Details**: Lists security engines that flagged the site
- **Action Options**: Buttons to go back or visit safe alternatives
- **Emergency Contact**: Information for reporting false positives

## ⚙️ Configuration

### Main Configuration (`phishblock_dns.py`)

```python
CONFIG = {
    'VIRUSTOTAL_API_KEY': 'your_api_key_here',
    'UPSTREAM_DNS': ['8.8.8.8', '1.1.1.1'],
    'DNS_PORT': 53,
    'WARNING_SERVER_PORT': 8080,  # Port for warning page
    'CACHE_TTL_HOURS': 24,
    'MALICIOUS_THRESHOLD': 2,  # How many engines must flag a site
    'BLOCK_IP': '127.0.0.1',  # IP for blocked sites
    'DATABASE_PATH': 'phishblock_cache.db',
    'LOG_LEVEL': logging.INFO,
    'ENABLE_LOGGING': True
}
```

### Customizing the Warning Page

You can customize the warning page by editing the HTML/CSS in:
- `phishblock_dns.py` (in the `WarningServer` class)
- `web_server_config.py` (standalone warning server)

## 📊 Monitoring and Logs

### Log Files
- `phishblock.log`: Detailed DNS resolution logs
- `phishblock_cache.db`: SQLite database with cached results

### Statistics
The server provides real-time statistics:
- Total DNS queries
- Blocked queries
- Cache hit rate
- API call count

### Example Log Output
```
2024-01-15 10:30:15 - INFO - BLOCKED: malicious-site.com (flagged by 5/85 engines)
2024-01-15 10:30:15 - INFO - Blocked domain: malicious-site.com - redirecting to warning page
2024-01-15 10:30:20 - INFO - ALLOWED: google.com (clean: 0/85 engines)
```

## 🔒 Security Features

- **Fail-Open**: If VirusTotal API is unavailable, sites are allowed (not blocked)
- **Rate Limiting**: Respects VirusTotal's free tier limits
- **Cache Expiration**: Results expire after 24 hours (configurable)
- **Special Domains**: Local domains and time servers are bypassed
- **Error Handling**: Robust error handling prevents service disruption

## 🛠️ Troubleshooting

### Common Issues

1. **Permission Denied (Port 53)**
   - Run as administrator/root: `sudo python phishblock_dns.py`

2. **VirusTotal API Errors**
   - Check your API key is correct
   - Verify you haven't exceeded rate limits

3. **Warning Page Not Loading**
   - Ensure port 8080 is not blocked by firewall
   - Check if another service is using port 8080

4. **DNS Not Working**
   - Verify your device is configured to use the correct DNS server
   - Check network connectivity

### Testing

```bash
# Test DNS resolution
nslookup google.com 127.0.0.1

# Test warning page
curl http://localhost:8080

# Check logs
tail -f phishblock.log
```

## 📱 Platform Support

- ✅ **Windows**: Full support with GUI configuration
- ✅ **macOS**: Full support with System Preferences
- ✅ **Linux**: Full support with NetworkManager or manual config
- ✅ **Android**: Requires Private DNS (DoT) setup
- ✅ **iOS**: Requires manual DNS configuration

## 🤝 Contributing

Contributions are welcome! Areas for improvement:
- Additional threat intelligence sources
- Custom warning page themes
- Web interface for statistics
- Docker containerization
- Integration with existing security tools

## 📄 License

This project is open source. Feel free to use and modify for your needs.

## ⚠️ Disclaimer

This tool is for educational and personal use. Always verify security decisions and don't rely solely on automated tools for critical security decisions.

---

**Stay safe online! 🛡️** 
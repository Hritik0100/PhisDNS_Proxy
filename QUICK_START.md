# 🚨 PhishBlock-DNS Quick Start Guide

## 🎯 What's New: Phishing Warning Page

When you visit a phishing site, instead of just blocking it silently, PhishBlock-DNS now shows a **striking red alert page** that warns you about the malicious site!

## 🚀 How to Get Started

### 1. View the Warning Page Demo
Open `warning_page_demo.html` in your web browser to see how the phishing warning looks!

### 2. Start the DNS Server
**Option A: Using the batch file (Windows)**
```
Double-click: start_phishblock.bat
```

**Option B: Using Python directly**
```bash
# If you have Python in PATH:
python phishblock_dns.py

# Or using the virtual environment:
myenv/bin/python phishblock_dns.py
```

### 3. Configure Your Device
After starting the server, configure your device to use the DNS server:

**Windows:**
1. Open Network & Internet settings
2. Click "Change adapter options"
3. Right-click your network → Properties
4. Select "Internet Protocol Version 4 (TCP/IPv4)" → Properties
5. Select "Use the following DNS server addresses"
6. Preferred DNS: `127.0.0.1` (or your computer's IP)
7. Click OK

**macOS:**
1. System Preferences → Network
2. Select your connection → Advanced
3. DNS tab → Add `127.0.0.1`
4. Click OK and Apply

## 🎭 How It Works

1. **You visit a website** → Your device asks the DNS server for the IP address
2. **PhishBlock-DNS checks** → Is this site known to be malicious?
3. **If clean** → Returns the real IP address (normal browsing)
4. **If phishing** → Returns `127.0.0.1` (localhost)
5. **Warning page appears** → Beautiful red alert page with details about the blocked site

## 🎨 Warning Page Features

- 🚨 **Eye-catching red design** with animated warning icons
- 📝 **Clear explanation** of why the site was blocked
- 🔍 **Domain information** showing which site was blocked
- ⏰ **Timestamp** of when the block occurred
- 🔗 **Action buttons** to go back or visit safe alternatives
- 📱 **Mobile-responsive** design

## 🔧 Configuration

### Update VirusTotal API Key
Edit `phishblock_dns.py` and replace the API key:
```python
'VIRUSTOTAL_API_KEY': 'your_api_key_here'
```

Get a free API key from: https://www.virustotal.com/gui/join

### Customize Warning Page
Edit the HTML/CSS in:
- `phishblock_dns.py` (in the `WarningServer` class)
- `web_server_config.py` (standalone warning server)

## 🧪 Testing

1. **Test the warning page**: Open `warning_page_demo.html`
2. **Test DNS server**: Run `nslookup google.com 127.0.0.1`
3. **Check logs**: Look at `phishblock.log` for detailed information

## 📁 Files Overview

- `phishblock_dns.py` - Main DNS server with warning page integration
- `warning_page_demo.html` - Demo of the phishing warning page
- `start_phishblock.bat` - Windows batch file to start the server
- `setup_phishblock.py` - Setup and configuration script
- `web_server_config.py` - Standalone warning server
- `README.md` - Detailed documentation
- `phishblock_cache.db` - Database of cached domain results
- `phishblock.log` - Server logs

## 🛠️ Troubleshooting

**Server won't start:**
- Run as administrator (for port 53)
- Check if Python is installed
- Verify dependencies: `pip install dnslib requests`

**Warning page not showing:**
- Ensure port 8080 is not blocked
- Check firewall settings
- Verify DNS server is running

**DNS not working:**
- Verify your device is using the correct DNS server
- Check network connectivity
- Look at the logs in `phishblock.log`

## 🎉 You're All Set!

Now when you visit a phishing site, you'll see a beautiful red warning page instead of just a blank page or error. The warning page will:

- 🚨 Alert you immediately with visual cues
- 📝 Explain why the site was blocked
- 🔍 Show which domain was flagged
- 🔗 Provide safe alternatives
- 📱 Work on all devices

**Stay safe online! 🛡️** 
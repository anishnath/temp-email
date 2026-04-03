#!/bin/bash

# Test script for the whois lookup API endpoint

echo "Testing Whois Lookup API Endpoint"
echo "=================================="

# Test with different domains
echo "1. Testing with example.com:"
curl -s "http://localhost:8080/whois/example.com" | jq '.' 2>/dev/null || curl -s "http://localhost:8080/whois/example.com"

echo -e "\n\n2. Testing with google.com:"
curl -s "http://localhost:8080/whois/google.com" | jq '.' 2>/dev/null || curl -s "http://localhost:8080/whois/google.com"

echo -e "\n\n3. Testing with github.com:"
curl -s "http://localhost:8080/whois/github.com" | jq '.' 2>/dev/null || curl -s "http://localhost:8080/whois/github.com"

echo -e "\n\n4. Testing with invalid domain (no dots):"
curl -s "http://localhost:8080/whois/invalid" | jq '.' 2>/dev/null || curl -s "http://localhost:8080/whois/invalid"

echo -e "\n\n5. Testing with empty domain parameter:"
curl -s "http://localhost:8080/whois/" | jq '.' 2>/dev/null || curl -s "http://localhost:8080/whois/"

echo -e "\n\n6. Testing with a .org domain:"
curl -s "http://localhost:8080/whois/mozilla.org" | jq '.' 2>/dev/null || curl -s "http://localhost:8080/whois/mozilla.org"

echo -e "\n\n7. Testing with a .net domain:"
curl -s "http://localhost:8080/whois/microsoft.net" | jq '.' 2>/dev/null || curl -s "http://localhost:8080/whois/microsoft.net"

echo -e "\n\nTest completed!"












#!/bin/bash

# Test script for the SSL Scanner API endpoint

echo "Testing SSL Scanner API Endpoint"
echo "================================="

# Test with different scan types
echo "1. Basic SSL scan (default):"
curl -s "http://localhost:8080/sslscan/pipedream.in" | jq '.' 2>/dev/null || curl -s "http://localhost:8080/sslscan/pipedream.in"

echo -e "\n\n2. Quick SSL scan:"
curl -s "http://localhost:8080/sslscan/pipedream.in?type=quick" | jq '.' 2>/dev/null || curl -s "http://localhost:8080/sslscan/pipedream.in?type=quick"

echo -e "\n\n3. Full SSL scan (comprehensive):"
curl -s "http://localhost:8080/sslscan/pipedream.in?type=full" | jq '.' 2>/dev/null || curl -s "http://localhost:8080/sslscan/pipedream.in?type=full"

#echo -e "\n\n4. SSL scan with custom port (8443):"
#curl -s "http://localhost:8080/sslscan/pipedream.in?port=8443" | jq '.' 2>/dev/null || curl -s "http://localhost:8080/sslscan/pipedream.in?port=8443"

echo -e "\n\n5. SSL scan with different domain (pipedream.in):"
curl -s "http://localhost:8080/sslscan/pipedream.in?type=basic" | jq '.' 2>/dev/null || curl -s "http://localhost:8080/sslscan/pipedream.in?type=basic"

echo -e "\n\n6. SSL scan with invalid scan type:"
curl -s "http://localhost:8080/sslscan/pipedream.in?type=invalid" | jq '.' 2>/dev/null || curl -s "http://localhost:8080/sslscan/pipedream.in?type=invalid"

echo -e "\n\n7. SSL scan with invalid domain (no dots):"
curl -s "http://localhost:8080/sslscan/invalid" | jq '.' 2>/dev/null || curl -s "http://localhost:8080/sslscan/invalid"

echo -e "\n\n8. SSL scan with github.com (full scan):"
curl -s "http://localhost:8080/sslscan/github.com?type=full" | jq '.' 2>/dev/null || curl -s "http://localhost:8080/sslscan/github.com?type=full"

echo -e "\n\nTest completed!"











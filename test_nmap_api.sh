#!/bin/bash

# Test script for the nmap port scanning API endpoint

echo "Testing Nmap Port Scanning API Endpoint"
echo "========================================"

# Test with different scan types
echo "1. Quick scan (default):"
curl -s "http://localhost:8080/portscan/localhost" | jq '.' 2>/dev/null || curl -s "http://localhost:8080/portscan/localhost"

echo -e "\n\n2. Top ports scan with version detection:"
curl -s "http://localhost:8080/portscan/localhost?scan_type=top" | jq '.' 2>/dev/null || curl -s "http://localhost:8080/portscan/localhost?scan_type=top"

echo -e "\n\n3. Custom ports scan:"
curl -s "http://localhost:8080/portscan/localhost?scan_type=custom&ports=80,443,22,8080" | jq '.' 2>/dev/null || curl -s "http://localhost:8080/portscan/localhost?scan_type=custom&ports=80,443,22,8080"

echo -e "\n\n4. Full scan (all ports - may take longer):"
curl -s "http://localhost:8080/portscan/localhost?scan_type=full" | jq '.' 2>/dev/null || curl -s "http://localhost:8080/portscan/localhost?scan_type=full"

echo -e "\n\n5. Test with invalid scan type:"
curl -s "http://localhost:8080/portscan/localhost?scan_type=invalid" | jq '.' 2>/dev/null || curl -s "http://localhost:8080/portscan/localhost?scan_type=invalid"

echo -e "\n\n6. Test with external target (example.com):"
curl -s "http://localhost:8080/portscan/example.com?scan_type=quick" | jq '.' 2>/dev/null || curl -s "http://localhost:8080/portscan/example.com?scan_type=quick"

echo -e "\n\nTest completed!"













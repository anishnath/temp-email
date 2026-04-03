#!/bin/bash

# Test script for the subfinder API endpoint

echo "Testing Subfinder API Endpoint"
echo "================================"

# Test with a valid domain
echo "1. Testing with valid domain (pipedream.in):"
curl -s "http://localhost:8080/subdomains/pipedream.in" | jq '.' 2>/dev/null || curl -s "http://localhost:8080/subdomains/pipedream.in"

echo -e "\n\n2. Testing with invalid domain (no dots):"
curl -s "http://localhost:8080/subdomains/invalid" | jq '.' 2>/dev/null || curl -s "http://localhost:8080/subdomains/invalid"

echo -e "\n\n3. Testing with empty domain parameter:"
curl -s "http://localhost:8080/subdomains/" | jq '.' 2>/dev/null || curl -s "http://localhost:8080/subdomains/"

echo -e "\n\n4. Testing with domain that has no subdomains:"
curl -s "http://localhost:8080/subdomains/nonexistentdomain12345.in" | jq '.' 2>/dev/null || curl -s "http://localhost:8080/subdomains/nonexistentdomain12345.in"

echo -e "\n\nTest completed!"














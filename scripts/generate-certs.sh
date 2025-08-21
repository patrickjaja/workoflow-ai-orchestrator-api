#!/bin/bash

# Generate self-signed certificates for local HTTPS development
echo "Generating self-signed certificates for local development..."

# Create certs directory if it doesn't exist
mkdir -p certs

# Generate private key
openssl genrsa -out certs/localhost.key 2048

# Generate certificate signing request
openssl req -new -key certs/localhost.key -out certs/localhost.csr -subj "/C=US/ST=Local/L=Local/O=Development/CN=localhost"

# Generate self-signed certificate
openssl x509 -req -days 365 -in certs/localhost.csr -signkey certs/localhost.key -out certs/localhost.crt

# Clean up CSR
rm certs/localhost.csr

echo "Certificates generated in certs/ directory"
echo "- certs/localhost.key (private key)"
echo "- certs/localhost.crt (certificate)"
echo ""
echo "To use HTTPS locally, run:"
echo "  make run-https"
#!/bin/bash

# Demo Setup Script - Example
# This script demonstrates how to set up a demo organization with OAuth providers
# 
# IMPORTANT: This is a documentation example only!
# Do not hardcode credentials in actual scripts.
# Pass them as environment variables or command-line arguments.

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}AI Orchestrator API - Demo Setup${NC}"
echo -e "${YELLOW}===============================================${NC}"
echo ""

# Check if required parameters are provided
if [ $# -lt 6 ]; then
    echo -e "${RED}Error: Missing required parameters${NC}"
    echo ""
    echo "Usage: $0 <org_name> <org_slug> <client_id> <client_secret> <tenant_id> <redirect_url>"
    echo ""
    echo "Example:"
    echo "  $0 \"My Organization\" \"my-org\" \"client-id-here\" \"secret-here\" \"tenant-id\" \"http://localhost:8080/api/oauth/callback/microsoft\""
    echo ""
    exit 1
fi

# Parse command-line arguments
ORG_NAME="$1"
ORG_SLUG="$2"
CLIENT_ID="$3"
CLIENT_SECRET="$4"
TENANT_ID="$5"
REDIRECT_URL="$6"

echo -e "${BLUE}Configuration:${NC}"
echo "  Organization Name: $ORG_NAME"
echo "  Organization Slug: $ORG_SLUG"
echo "  Provider: Microsoft"
echo "  Redirect URL: $REDIRECT_URL"
echo ""

# Step 1: Check database status
echo -e "${BLUE}Step 1: Checking database connection...${NC}"
make app-db-status > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo -e "${RED}Database is not running. Starting database services...${NC}"
    make db-up
    sleep 5
    make db-migrate
fi
echo -e "${GREEN}✓ Database is ready${NC}"
echo ""

# Step 2: Create organization with OAuth provider
echo -e "${BLUE}Step 2: Creating organization with Microsoft OAuth...${NC}"
make app-org-create \
    NAME="$ORG_NAME" \
    SLUG="$ORG_SLUG" \
    DESCRIPTION="Demo organization for testing SharePoint integration" \
    PROVIDER="microsoft" \
    CLIENT_ID="$CLIENT_ID" \
    CLIENT_SECRET="$CLIENT_SECRET" \
    TENANT_ID="$TENANT_ID" \
    REDIRECT_URL="$REDIRECT_URL"

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Organization created successfully${NC}"
else
    echo -e "${RED}Failed to create organization. It may already exist.${NC}"
    exit 1
fi
echo ""

# Step 3: Create admin user
echo -e "${BLUE}Step 3: Creating admin user...${NC}"
make app-user-create \
    ORG_SLUG="$ORG_SLUG" \
    EMAIL="admin@${ORG_SLUG}.local" \
    FIRST_NAME="Admin" \
    LAST_NAME="User" \
    ROLE="admin"

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Admin user created${NC}"
else
    echo -e "${YELLOW}Warning: Failed to create user (may already exist)${NC}"
fi
echo ""

# Step 4: Create regular user
echo -e "${BLUE}Step 4: Creating regular user...${NC}"
make app-user-create \
    ORG_SLUG="$ORG_SLUG" \
    EMAIL="user@${ORG_SLUG}.local" \
    FIRST_NAME="Test" \
    LAST_NAME="User" \
    ROLE="user"

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Regular user created${NC}"
else
    echo -e "${YELLOW}Warning: Failed to create user (may already exist)${NC}"
fi
echo ""

# Step 5: Verify setup
echo -e "${BLUE}Step 5: Verifying setup...${NC}"
make app-org-show SLUG="$ORG_SLUG"
echo ""

# Step 6: Test OAuth configuration
echo -e "${BLUE}Step 6: Testing OAuth configuration...${NC}"
make app-oauth-test \
    ORG_SLUG="$ORG_SLUG" \
    PROVIDER="microsoft"
echo ""

# Step 7: Instructions for testing
echo -e "${GREEN}===============================================${NC}"
echo -e "${GREEN}Setup Complete!${NC}"
echo -e "${GREEN}===============================================${NC}"
echo ""
echo -e "${BLUE}Next Steps:${NC}"
echo ""
echo "1. Start the API server:"
echo "   ${YELLOW}make run${NC}"
echo ""
echo "2. Test the OAuth flow:"
echo "   ${YELLOW}make app-oauth-flow-test ORG_SLUG=\"$ORG_SLUG\" PROVIDER=\"microsoft\"${NC}"
echo ""
echo "3. Or test with curl:"
echo "   ${YELLOW}curl http://localhost:8080/api/v1/auth/microsoft/login -H \"X-Organization-Slug: $ORG_SLUG\"${NC}"
echo ""
echo "4. Complete authentication in your browser"
echo ""
echo "5. Test authenticated API calls:"
echo "   ${YELLOW}curl http://localhost:8080/api/v1/chat \\
     -H \"Authorization: Bearer <your-token>\" \\
     -H \"X-Organization-Slug: $ORG_SLUG\" \\
     -d '{\"message\": \"Search SharePoint for vacation policy\"}'${NC}"
echo ""
echo -e "${BLUE}Organization Details:${NC}"
echo "  Slug: $ORG_SLUG"
echo "  Admin: admin@${ORG_SLUG}.local"
echo "  User: user@${ORG_SLUG}.local"
echo "  OAuth Provider: Microsoft"
echo "  Redirect URL: $REDIRECT_URL"
echo ""
echo -e "${YELLOW}Note: Keep your credentials secure and never commit them to version control!${NC}"
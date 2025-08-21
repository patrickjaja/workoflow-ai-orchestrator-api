#!/bin/bash

# Validation script for Docker configuration
set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Validating Docker Configuration...${NC}"

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo -e "${RED}❌ Docker is not running${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Docker is running${NC}"

# Check if Docker Compose is available
if ! docker-compose version > /dev/null 2>&1; then
    echo -e "${RED}❌ Docker Compose is not available${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Docker Compose is available${NC}"

# Validate docker-compose.yml
echo -e "${YELLOW}Validating docker-compose.yml...${NC}"
if docker-compose config > /dev/null 2>&1; then
    echo -e "${GREEN}✅ docker-compose.yml is valid${NC}"
else
    echo -e "${RED}❌ docker-compose.yml has errors${NC}"
    docker-compose config
    exit 1
fi

# Validate docker-compose.test.yml
echo -e "${YELLOW}Validating docker-compose.test.yml...${NC}"
if docker-compose -f docker-compose.test.yml config > /dev/null 2>&1; then
    echo -e "${GREEN}✅ docker-compose.test.yml is valid${NC}"
else
    echo -e "${RED}❌ docker-compose.test.yml has errors${NC}"
    docker-compose -f docker-compose.test.yml config
    exit 1
fi

# Check if Dockerfile exists and is valid
echo -e "${YELLOW}Validating Dockerfile...${NC}"
if [ ! -f "Dockerfile" ]; then
    echo -e "${RED}❌ Dockerfile not found${NC}"
    exit 1
fi

# Try to build the Docker image (dry run)
if docker build -t test-validation . > /dev/null 2>&1; then
    echo -e "${GREEN}✅ Dockerfile builds successfully${NC}"
    # Clean up test image
    docker rmi test-validation > /dev/null 2>&1
else
    echo -e "${RED}❌ Dockerfile has build errors${NC}"
    exit 1
fi

# Check if required directories exist
echo -e "${YELLOW}Checking required directories...${NC}"

required_dirs=(
    "tests/e2e"
    "tests/mocks" 
    "cmd/simple-api"
    "internal/models"
    "migrations"
)

for dir in "${required_dirs[@]}"; do
    if [ -d "$dir" ]; then
        echo -e "${GREEN}✅ $dir exists${NC}"
    else
        echo -e "${RED}❌ $dir is missing${NC}"
        exit 1
    fi
done

# Check if required files exist
echo -e "${YELLOW}Checking required files...${NC}"

required_files=(
    "go.mod"
    "go.sum"
    "Makefile"
    "docker-compose.yml"
    "docker-compose.test.yml"
    "tests/e2e/setup_test.go"
    "tests/e2e/helpers_test.go"
    "tests/e2e/chat_test.go"
    "tests/mocks/nginx.conf"
)

for file in "${required_files[@]}"; do
    if [ -f "$file" ]; then
        echo -e "${GREEN}✅ $file exists${NC}"
    else
        echo -e "${RED}❌ $file is missing${NC}"
        exit 1
    fi
done

# Check Go module
echo -e "${YELLOW}Validating Go module...${NC}"
if go mod verify > /dev/null 2>&1; then
    echo -e "${GREEN}✅ Go module is valid${NC}"
else
    echo -e "${YELLOW}⚠️  Go module verification failed, trying to fix...${NC}"
    go mod tidy
    if go mod verify > /dev/null 2>&1; then
        echo -e "${GREEN}✅ Go module fixed${NC}"
    else
        echo -e "${RED}❌ Go module has issues${NC}"
        exit 1
    fi
fi

# Check if test files compile
echo -e "${YELLOW}Checking if test files compile...${NC}"
if go build -o /dev/null ./tests/e2e/... > /dev/null 2>&1; then
    echo -e "${GREEN}✅ Test files compile successfully${NC}"
else
    echo -e "${RED}❌ Test files have compilation errors${NC}"
    go build ./tests/e2e/...
    exit 1
fi

echo ""
echo -e "${GREEN}🎉 All Docker configuration validations passed!${NC}"
echo ""
echo -e "${YELLOW}You can now run:${NC}"
echo -e "  ${GREEN}make test-e2e${NC}        # Run E2E tests"
echo -e "  ${GREEN}make dev${NC}             # Start development environment"
echo -e "  ${GREEN}make docker-up${NC}       # Start production environment"
echo ""
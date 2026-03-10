#!/bin/bash
# KeyRelay Proxy - Run Script
# Starts the proxy server with proper configuration

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo -e "${BLUE}🔐 KeyRelay Proxy${NC}"
echo "======================"

# Resolve vault directory (supports Docker/custom path)
APP_DIR="${AGENT_VAULT_APP_DIR:-$HOME/.agent-vault}"

# Check if vault is initialized
if [ ! -f "$APP_DIR/vault.db" ]; then
    echo -e "${YELLOW}⚠️  Vault not initialized${NC}"
    echo "Run: ./cli.py init"
    exit 1
fi

# Check Python
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}❌ Python 3 not found${NC}"
    exit 1
fi

# Check virtual environment
if [ ! -d "venv" ]; then
    echo -e "${YELLOW}📦 Creating virtual environment...${NC}"
    python3 -m venv venv
fi

# Activate virtual environment
source venv/bin/activate

# Install/update dependencies
echo -e "${BLUE}📦 Checking dependencies...${NC}"
pip install -q -r requirements.txt

# Check if running in Docker
if [ -f /.dockerenv ]; then
    echo -e "${GREEN}🐳 Running in Docker container${NC}"
    HOST="0.0.0.0"
else
    HOST="127.0.0.1"
fi

# Get port from environment or default
PORT=${AGENT_VAULT_PORT:-8080}

echo -e "${GREEN}🚀 Starting KeyRelay Proxy...${NC}"
echo -e "   Host: ${HOST}"
echo -e "   Port: ${PORT}"
echo -e "   URL:  http://${HOST}:${PORT}"
echo ""
echo -e "${BLUE}📚 Quick commands:${NC}"
echo "   ./cli.py status    - Check status"
echo "   ./cli.py list-keys - List keys"
echo "   ./cli.py add-key   - Add a key"
echo ""
echo -e "${YELLOW}Press Ctrl+C to stop${NC}"
echo "======================"

# Run the server with explicit host/port
exec uvicorn app.main:app --host "$HOST" --port "$PORT"

#!/bin/bash
#
# Kali MCP Tactical Server - Start Script
#

set -e

echo "🚀 Starting Kali MCP Tactical Server..."
echo "=" * 60

# Check Python version
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 not found"
    exit 1
fi

PYTHON_VERSION=$(python3 --version | awk '{print $2}')
echo "✅ Python version: $PYTHON_VERSION"

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "📦 Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
echo "🔧 Activating virtual environment..."
source venv/bin/activate

# Install/update dependencies
echo "📥 Installing dependencies..."
pip install -q --upgrade pip
pip install -q -r requirements.txt

# Validate configuration
if [ ! -f ".env" ]; then
    echo "⚠️  No .env file found. Creating from example..."
    cp .env.example .env
    echo "⚠️  Please edit .env with your configuration"
fi

# Create data directories
echo "📁 Creating data directories..."
mkdir -p data/cache data/logs data/results

# Check critical tools
echo "🔍 Checking critical tools..."
MISSING_TOOLS=()

if ! command -v nmap &> /dev/null; then
    MISSING_TOOLS+=("nmap")
fi

if [ ${#MISSING_TOOLS[@]} -ne 0 ]; then
    echo "⚠️  Missing tools: ${MISSING_TOOLS[*]}"
    echo "   Install with: sudo apt install ${MISSING_TOOLS[*]}"
fi

# Display configuration
echo ""
echo "📊 Configuration:"
echo "  Working directory: $(pwd)"
echo "  Virtual environment: $(which python)"
echo ""

# Start server
echo "🎯 Launching Kali MCP Tactical Server..."
echo "=" * 60
echo ""

python3 main.py

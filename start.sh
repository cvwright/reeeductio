#!/bin/bash

# E2EE Messaging System - Quick Start Script

echo "======================================"
echo "E2EE Messaging System"
echo "======================================"
echo ""

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is not installed"
    exit 1
fi

# Check if uv is installed
if ! command -v uv &> /dev/null; then
    echo "Error: uv is not installed"
    echo "Install it with: curl -LsSf https://astral.sh/uv/install.sh | sh"
    exit 1
fi

echo "Setting up virtual environment..."
if [ ! -d ".venv" ]; then
    uv venv
fi

echo "Installing dependencies..."
uv pip install -e .

echo ""
echo "Running tests..."
.venv/bin/python backend/test_backend.py

if [ $? -eq 0 ]; then
    echo ""
    echo "======================================"
    echo "Tests passed! Starting server..."
    echo "======================================"
    echo ""
    echo "Server will be available at:"
    echo "  http://localhost:8000"
    echo ""
    echo "API documentation:"
    echo "  http://localhost:8000/docs (Swagger UI)"
    echo "  http://localhost:8000/redoc (ReDoc)"
    echo ""
    echo "Press Ctrl+C to stop the server"
    echo ""

    .venv/bin/python backend/main.py
else
    echo ""
    echo "Tests failed. Please fix errors before starting server."
    exit 1
fi

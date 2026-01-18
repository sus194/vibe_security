#!/usr/bin/env bash

# VibeGuard Development Setup Script
# Run this once to initialize everything

set -e

echo "🚀 VibeGuard Setup Script"
echo "=========================="

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 not found. Install Python 3.10+ and try again."
    exit 1
fi

echo "✅ Python $(python3 --version)"

# Check Node.js
if ! command -v node &> /dev/null; then
    echo "❌ Node.js not found. Install Node.js 18+ and try again."
    exit 1
fi

echo "✅ Node.js $(node --version)"

# Setup Backend
echo ""
echo "📦 Setting up backend..."
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
echo "✅ Backend ready"

# Setup Frontend
echo ""
echo "📦 Setting up frontend..."
cd ../frontend
npm install
echo "✅ Frontend ready"

echo ""
echo "✨ Setup complete!"
echo ""
echo "To start developing:"
echo "  1. Backend:  cd backend && source venv/bin/activate && python -m uvicorn main:app --reload"
echo "  2. Frontend: cd frontend && npm run dev"
echo ""
echo "Then visit http://localhost:3000"

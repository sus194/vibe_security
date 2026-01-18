#!/usr/bin/env bash

# Development Helper Script

function dev-start() {
    echo "🚀 Starting VibeGuard..."
    
    # Backend
    cd backend
    source venv/bin/activate
    python -m uvicorn main:app --reload &
    BACKEND_PID=$!
    cd ..
    
    echo "✅ Backend started (PID: $BACKEND_PID)"
    
    # Frontend
    cd frontend
    npm run dev &
    FRONTEND_PID=$!
    cd ..
    
    echo "✅ Frontend started (PID: $FRONTEND_PID)"
    echo ""
    echo "Frontend:  http://localhost:3000"
    echo "Backend:   http://localhost:8000"
    echo "API Docs:  http://localhost:8000/docs"
    echo ""
    echo "To stop: kill $BACKEND_PID $FRONTEND_PID"
}

function dev-test() {
    echo "🧪 Running tests..."
    
    # Backend unit tests
    cd backend
    python -m pytest tests/ -v
    cd ..
}

function dev-lint() {
    echo "🔍 Running linters..."
    
    # Backend
    cd backend
    python -m pylint scanner/
    cd ..
    
    # Frontend
    cd frontend
    npm run lint
    cd ..
}

function dev-docker() {
    echo "🐳 Building Docker images..."
    docker-compose build
    echo "✅ Built. Run: docker-compose up"
}

function dev-clean() {
    echo "🧹 Cleaning up..."
    
    # Remove Python caches
    find . -type d -name __pycache__ -exec rm -rf {} +
    find . -type f -name "*.pyc" -delete
    
    # Remove Node modules (optional)
    # rm -rf frontend/node_modules backend/venv
    
    echo "✅ Cleaned"
}

# Show help
if [ $# -eq 0 ]; then
    echo "VibeGuard Dev Helper"
    echo ""
    echo "Usage: ./dev.sh [command]"
    echo ""
    echo "Commands:"
    echo "  start    - Start backend + frontend"
    echo "  test     - Run tests"
    echo "  lint     - Run linters"
    echo "  docker   - Build Docker images"
    echo "  clean    - Clean caches"
    exit 0
fi

# Execute command
case "$1" in
    start)
        dev-start
        ;;
    test)
        dev-test
        ;;
    lint)
        dev-lint
        ;;
    docker)
        dev-docker
        ;;
    clean)
        dev-clean
        ;;
    *)
        echo "Unknown command: $1"
        exit 1
        ;;
esac

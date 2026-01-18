# VibeGuard Setup & Development Guide

## Quick Start

### Prerequisites
- Python 3.10+
- Node.js 18+
- Docker (optional)

---

## 🚀 Local Development

### 1. Backend Setup (FastAPI)

```bash
# Install dependencies
cd backend
pip install -r requirements.txt

# Set environment variables (optional)
export GITHUB_TOKEN="your_github_token"  # For higher API rate limits
export PORT=8000
export ENV=development

# Run server
python -m uvicorn main:app --reload

# Server will be available at http://localhost:8000
# Swagger docs at http://localhost:8000/docs
```

### 2. Frontend Setup (Next.js)

```bash
# Install dependencies
cd frontend
npm install

# Set environment variables
export NEXT_PUBLIC_API_URL=http://localhost:8000

# Run development server
npm run dev

# Frontend will be available at http://localhost:3000
```

### 3. Test the System

Visit `http://localhost:3000` and try scanning a public repository:

**Example repos to test with:**
- `https://github.com/sukhrajpurewal/vibe_security`
- Any public GitHub repo

---

## 🐳 Docker Setup

### Build & Run with Docker Compose

```bash
docker-compose up -d

# Frontend: http://localhost:3000
# Backend: http://localhost:8000
# API Docs: http://localhost:8000/docs
```

### Manual Docker Commands

**Backend:**
```bash
docker build -t vibeguard-backend ./backend
docker run -p 8000:8000 -e GITHUB_TOKEN=your_token vibeguard-backend
```

**Frontend:**
```bash
docker build -t vibeguard-frontend ./frontend
docker run -p 3000:3000 -e NEXT_PUBLIC_API_URL=http://localhost:8000 vibeguard-frontend
```

---

## 📊 API Endpoints

### `/health` (GET)
Health check endpoint.

```bash
curl http://localhost:8000/health
```

**Response:**
```json
{
  "status": "ok",
  "service": "VibeGuard API"
}
```

### `/scan` (POST)
Scan a GitHub repository for security issues.

**Request:**
```bash
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"repo_url": "https://github.com/user/repo"}'
```

**Response:**
```json
{
  "repo_url": "https://github.com/user/repo",
  "status": "completed",
  "findings": [
    {
      "severity": "CRITICAL",
      "file": "server.js",
      "line_number": 42,
      "issue": "Hard-coded API key",
      "why": "Exposes production credentials",
      "fix": "Move to environment variable",
      "category": "Secrets",
      "code_snippet": "const API_KEY = 'sk-...'"
    }
  ],
  "summary": {
    "total_issues": 15,
    "by_severity": {
      "CRITICAL": 3,
      "HIGH": 7,
      "MEDIUM": 5,
      "LOW": 0
    },
    "by_category": {
      "Secrets": 3,
      "Input Validation": 7,
      "Authentication": 3,
      "CORS": 2
    },
    "files_scanned": 12,
    "risk_score": 75
  }
}
```

---

## 🔍 Scanner Capabilities

The engine detects 8 categories of security issues:

### 1. **Secrets Detection** (CRITICAL)
- API keys, tokens, credentials
- `.env` files committed
- AWS, Firebase, Stripe, OpenAI, GitHub keys

### 2. **Input Validation** (HIGH/CRITICAL)
- SQL injection patterns
- Command injection risks
- Path traversal issues
- Missing validation checks

### 3. **Authentication** (HIGH/CRITICAL)
- Unverified JWT tokens
- Missing auth middleware
- Lenient authorization checks
- Client-side auth trust

### 4. **CORS** (MEDIUM/CRITICAL)
- Wildcard origins (`*`)
- Credentials with insecure origins
- Unvalidated configurations

### 5. **Dangerous Defaults** (LOW/MEDIUM)
- Debug mode enabled
- Hardcoded ports
- Admin flags set to true
- Trust proxy without validation

### 6. **File Uploads** (HIGH)
- Missing file size limits
- No MIME type validation
- Path traversal in uploads

### 7. **Dependencies** (MEDIUM)
- `npm install --force`
- Abandoned packages
- Known vulnerable versions

### 8. **AI Security** (MEDIUM/HIGH)
- Prompt injection risks
- Raw user input in prompts
- Missing output filtering

---

## 🧪 Testing

### Test Scanner Directly

```python
# Create test file
cat > test_scan.py << 'EOF'
import sys
sys.path.insert(0, '.')

from scanner.detectors import Scanner, Severity

# Test code with secrets
test_code = """
const API_KEY = 'sk-1234567890abcdefghij';
app.get('/api', (req, res) => {
  const user = db.query(req.body.id);
  res.json(user);
});
"""

scanner = Scanner()
findings = scanner.scan_file(test_code, 'test.js')

for f in findings:
  print(f"{f.severity.value}: {f.issue}")
  print(f"  File: {f.file}:{f.line_number}")
  print(f"  Why: {f.why}")
  print()
EOF

python test_scan.py
```

---

## 📁 Project Structure

```
vibe_security/
├── backend/                  # FastAPI backend
│   ├── main.py              # API endpoints
│   └── requirements.txt      # Python dependencies
│
├── frontend/                # Next.js frontend
│   ├── pages/
│   │   ├── index.tsx        # Home page
│   │   └── _app.tsx         # App wrapper
│   ├── components/
│   │   ├── Scanner.tsx      # Repo URL input
│   │   └── Results.tsx      # Results dashboard
│   ├── styles/              # Tailwind styles
│   └── package.json         # Node dependencies
│
├── scanner/                 # Security scanner engine
│   └── detectors.py        # All detection logic (8 categories)
│
├── docs/                   # Documentation
└── docker-compose.yml      # Container orchestration
```

---

## 🔐 Security Best Practices

- **Public repos only**: VibeGuard only accepts public GitHub URLs
- **Read-only access**: Never modifies repositories
- **No exploit generation**: Educational and detection-focused
- **GitHub Token (optional)**: Higher rate limits; never committed
- **CORS restricted**: Frontend only communicates with trusted backend

---

## 🚀 Deployment

### GitHub Actions CI/CD Example

```yaml
name: Deploy VibeGuard

on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Build and push to Docker Hub
        run: |
          docker build -t user/vibeguard-backend ./backend
          docker build -t user/vibeguard-frontend ./frontend
          docker push user/vibeguard-backend
          docker push user/vibeguard-frontend
      - name: Deploy to production
        # ... your deployment steps
```

### Vercel (Frontend)

```bash
cd frontend
vercel deploy
```

### Railway / Render (Backend)

```bash
# Push to git; auto-deploys via webhook
git push origin main
```

---

## 🐛 Troubleshooting

### Port Already in Use
```bash
# Kill process on port 8000
lsof -i :8000 | grep LISTEN | awk '{print $2}' | xargs kill -9

# Or use different port
python -m uvicorn main:app --port 8001
```

### GitHub API Rate Limited
```bash
# Set your GitHub token
export GITHUB_TOKEN="ghp_xxxxxxxxxxxx"

# Check remaining quota
curl -H "Authorization: token $GITHUB_TOKEN" \
  https://api.github.com/rate_limit
```

### CORS Errors
Ensure `NEXT_PUBLIC_API_URL` matches your backend URL:
```bash
export NEXT_PUBLIC_API_URL=http://localhost:8000
npm run dev
```

---

## 📚 Next Steps

1. **Add to CI/CD**: Scan repos automatically in GitHub Actions
2. **GitHub App**: Create VibeGuard app for PR comments
3. **Fix Suggestions**: LLM-powered remediation advice
4. **Database**: Store scan history and trends
5. **Performance**: Cache large repos; use job queues

---

## 📝 License

MIT

---

## 🤝 Contributing

Issues and PRs welcome! See CONTRIBUTING.md for guidelines.

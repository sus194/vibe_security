# VibeGuard - Security Scanner for Vibe-Coded Apps

<div align="center">
  <h2>⚡ Find real security issues in fast-coded repos</h2>
  <p>Static analysis designed for "vibe-coded" applications. Detects secrets, input validation flaws, unsafe auth, and more.</p>
</div>

---

## 🎯 What's VibeGuard?

VibeGuard is a **web-based security scanner** for GitHub repositories. Submit a repo URL and get instant feedback on real security risks—not theoretical CVEs.

Perfect for developers who code fast and need to catch mistakes before they become breaches.

### Key Insight
> Most "vibe-coded" vulnerabilities aren't from outdated dependencies. They're from:
> - Hard-coded secrets
> - Missing input validation
> - Unsafe auth logic
> - Dangerous defaults

VibeGuard finds **exactly these**.

---

## 🔍 What It Scans

### 1️⃣ **Hard-Coded Secrets** (CRITICAL)
- API keys (OpenAI, Stripe, Firebase)
- Cloud credentials (AWS, GCP)
- Private keys, GitHub tokens
- `.env` files committed to git

### 2️⃣ **Input Validation** (HIGH)
- SQL injection patterns
- Command injection risks
- Path traversal vulnerabilities
- Missing schema validation

### 3️⃣ **Unsafe Authentication** (HIGH)
- Unverified JWT tokens
- Missing auth middleware
- Weak authorization checks
- Client-side auth trust

### 4️⃣ **CORS Issues** (MEDIUM)
- Wildcard origins (`Access-Control-Allow-Origin: *`)
- Insecure credential handling
- Default permissive configs

### 5️⃣ **Dangerous Defaults** (MEDIUM)
- Debug mode enabled
- Hardcoded ports
- Admin flags set to true
- Trust proxy without validation

### 6️⃣ **File Upload Issues** (HIGH)
- Missing size limits
- No MIME type validation
- Path traversal in uploads

### 7️⃣ **Dependency Red Flags** (MEDIUM)
- `npm install --force`
- Abandoned packages
- Known vulnerable versions

### 8️⃣ **AI Security** (MEDIUM/HIGH)
- Prompt injection risks
- Raw user input in prompts
- Missing output filtering

---

## 🚀 Quick Start

### Option 1: Local Development

```bash
# Clone repo
git clone https://github.com/sus194/vibe_security
cd vibe_security

# Setup (one-time)
chmod +x setup.sh
./setup.sh

# Terminal 1: Backend
cd backend
source venv/bin/activate
python -m uvicorn main:app --reload

# Terminal 2: Frontend
cd frontend
npm run dev

# Visit http://localhost:3000
```

### Option 2: Docker

```bash
docker-compose up

# Frontend: http://localhost:3000
# Backend API: http://localhost:8000
# Swagger docs: http://localhost:8000/docs
```

---

## 📊 Example Output

```json
{
  "severity": "CRITICAL",
  "file": "src/api.js",
  "line": 42,
  "issue": "Hard-coded API key",
  "why": "Exposes production credentials; can be used to make API calls",
  "fix": "Move to environment variable (OPENAI_API_KEY)",
  "category": "Secrets",
  "code_snippet": "const API_KEY = 'sk-1234567890abcdefghij'"
}
```

---

## 🖥️ Tech Stack

| Layer | Technology |
|-------|-----------|
| **Frontend** | Next.js + TypeScript + Tailwind CSS |
| **Backend** | FastAPI + Python |
| **Scanner** | Custom regex + AST patterns |
| **API** | GitHub REST API (public repos) |
| **Deployment** | Docker, Vercel, Railway |

---

## 📈 Project Structure

```
vibe_security/
├── scanner/                    # Core detection engine
│   └── detectors.py           # 8 security detectors
│
├── backend/                    # FastAPI server
│   ├── main.py                # /scan endpoint
│   ├── requirements.txt
│   └── Dockerfile
│
├── frontend/                   # Next.js UI
│   ├── pages/
│   │   ├── index.tsx          # Home + scan UI
│   │   └── _app.tsx
│   ├── components/
│   │   ├── Scanner.tsx        # Input component
│   │   └── Results.tsx        # Results dashboard
│   └── package.json
│
├── docker-compose.yml         # Local dev setup
├── SETUP.md                   # Detailed setup guide
└── README.md                  # This file
```

---

## 🔗 API Usage

### POST `/scan`

**Request:**
```bash
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{
    "repo_url": "https://github.com/user/repo"
  }'
```

**Response:**
```json
{
  "repo_url": "https://github.com/user/repo",
  "status": "completed",
  "findings": [...],
  "summary": {
    "total_issues": 15,
    "by_severity": {...},
    "by_category": {...},
    "files_scanned": 12,
    "risk_score": 75
  }
}
```

---

## 🛡️ Safety & Ethics

✅ **Public repos only**  
✅ **Read-only access**  
✅ **No exploit generation**  
✅ **Educational focus**  
✅ **Zero data storage** (by default)  

---

## 🚀 Future Enhancements

- [ ] GitHub App for PR comments
- [ ] Database for scan history
- [ ] LLM-powered fix suggestions
- [ ] CI/CD integration
- [ ] Custom rule engine
- [ ] Fix recommendations as PRs

---

## 📝 Configuration

### Environment Variables

**Backend:**
```bash
GITHUB_TOKEN=ghp_xxxx        # Optional: higher API rate limits
PORT=8000
ENV=development|production
```

**Frontend:**
```bash
NEXT_PUBLIC_API_URL=http://localhost:8000
```

---

## 🧪 Testing

### Test Scanner Locally

```python
from scanner.detectors import Scanner

code = """
const key = 'sk-1234567890abc';
app.get('/api', (req, res) => {
  db.query(req.body.id);
});
"""

scanner = Scanner()
findings = scanner.scan_file(code, 'test.js')

for f in findings:
    print(f"{f.severity}: {f.issue}")
```

---

## 🤝 Contributing

Issues and PRs welcome!

```bash
# Fork → Clone → Create branch → Make changes → Push → PR
git checkout -b feature/your-feature
git commit -am "Add feature"
git push origin feature/your-feature
```

---

## 📄 License

MIT License - See LICENSE file

---

## 🙋 Support

- **Issues**: [GitHub Issues](https://github.com/sus194/vibe_security/issues)
- **Discussions**: [GitHub Discussions](https://github.com/sus194/vibe_security/discussions)

---

<div align="center">
  <strong>Made with ⚡ by security-focused developers</strong>
  <p>Find real issues. Code faster. Ship safer.</p>
</div>
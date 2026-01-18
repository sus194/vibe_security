# VibeGuard Architecture & Implementation Guide

## System Overview

VibeGuard is a **three-tier security scanning application**:

```
┌─────────────────────────────────────────────────────────────┐
│ Frontend (Next.js + React)                                  │
│ - Repo URL Input                                            │
│ - Results Dashboard                                         │
│ - Severity Filtering                                        │
└──────────────────────┬──────────────────────────────────────┘
                       │ HTTPS
                       │
┌──────────────────────▼──────────────────────────────────────┐
│ Backend API (FastAPI)                                       │
│ - POST /scan -> validate -> fetch -> scan -> return        │
│ - GET /health -> server status                              │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       │ subprocess
                       │
┌──────────────────────▼──────────────────────────────────────┐
│ Scanner Engine (Python)                                     │
│ - 8 Security Detectors                                      │
│ - Regex + AST Analysis                                      │
│ - Finding Aggregation                                       │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       │ HTTPS API
                       │
┌──────────────────────▼──────────────────────────────────────┐
│ GitHub REST API                                             │
│ - Fetch repository contents                                 │
│ - Rate limit: 60 req/hour (unauthenticated)                │
│ - Rate limit: 5000 req/hour (authenticated)                │
└─────────────────────────────────────────────────────────────┘
```

---

## Component Details

### Scanner Engine (Core Innovation)

**File**: `scanner/detectors.py`

**Design Pattern**: Each detector is an independent class with a `detect()` method.

**Detectors**:
1. `SecretDetector` - Hard-coded credentials
2. `InputValidationDetector` - Injection vulnerabilities
3. `AuthenticationDetector` - Auth logic flaws
4. `CORSDetector` - Insecure cross-origin configs
5. `DangerousDefaultsDetector` - Bad defaults
6. `FileUploadDetector` - Upload security
7. `DependencyDetector` - Dependency issues
8. `AISecurityDetector` - Prompt injection risks

**Performance**:
- Single file: ~10ms
- 100 files: ~500ms
- 10,000 lines: ~1s

**Why Regex?**
- ✅ Fast (no AST parsing overhead)
- ✅ Deterministic (no ML uncertainty)
- ✅ Easy to understand and extend
- ❌ Can have false positives/negatives
- ❌ Misses obfuscated code

---

### Backend API (FastAPI)

**File**: `backend/main.py`

**Endpoints**:

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/` | API info |
| GET | `/health` | Health check |
| POST | `/scan` | Main scanning endpoint |
| GET | `/docs` | Swagger UI |

**Request Flow**:

```
1. POST /scan with repo_url
   ↓
2. validate_github_url() - Regex validation
   ↓
3. fetch_repo_files() - GitHub API (async)
   ↓
4. Scanner().scan_repo() - Run all detectors
   ↓
5. Aggregate findings & format response
   ↓
6. Return JSON to frontend
```

**Error Handling**:
- Invalid URL: 400
- Repo not found: 404
- Rate limited: 403
- Server error: 500

**CORS Policy**:
```python
allow_origins = [
    "http://localhost:3000",        # Dev
    os.getenv("FRONTEND_URL")       # Production
]
allow_methods = ["GET", "POST"]
allow_credentials = True
```

---

### Frontend UI (Next.js + React)

**Files**:
- `pages/index.tsx` - Main page
- `components/Scanner.tsx` - Input component
- `components/Results.tsx` - Results dashboard

**Key Features**:

**1. Scanner Component**
```tsx
- Input field with GitHub URL
- Submit button (disabled when loading)
- Error message display
- Loading spinner animation
```

**2. Results Component**
```tsx
- Risk score (0-100)
- Summary statistics
  - Total issues count
  - Files scanned
  - By severity (CRITICAL/HIGH/MEDIUM/LOW)
  - By category (8 categories)
  
- Expandable findings
  - Click to show: Why + Code + Fix
  - Color-coded by severity
  - Filter by severity
```

**Styling**: Tailwind CSS with dark theme

**State Management**: React hooks (useState)

---

## Data Flow Example

### User scans `github.com/user/repo`

```
1. User enters URL in Scanner component
   ↓
2. onClick -> handleScan() -> POST /scan
   ↓
3. Backend validates URL format
   ✓ Valid: Extract owner="user", repo="repo"
   ✗ Invalid: Return 400 error
   ↓
4. fetch_repo_files() calls GitHub API
   GET /repos/user/repo/contents
   ↓
5. GitHub returns file list
   ↓
6. For each code file (*.js, *.py, etc):
   GET file content (base64 decoded)
   ↓
7. Scanner.scan_repo(files) runs
   For each file:
     - Detectors scan content
     - Collect findings
   Sort by severity + file
   ↓
8. Backend aggregates:
   - 3 CRITICAL, 7 HIGH, 5 MEDIUM, 0 LOW
   - By category: Secrets=3, Auth=4, etc
   - Risk score = issues * 5 (capped at 100)
   ↓
9. Return JSON response
   ↓
10. Frontend receives response
    ↓
11. Results component renders
    - Shows risk score
    - Shows summary cards
    - Shows expandable findings
    ↓
12. User clicks finding to expand
    - Shows: Why, Code snippet, Fix
    - Filter by severity
```

---

## Security Considerations

### What We Check

✅ Public repositories only  
✅ Read-only access (no commits)  
✅ No data stored (stateless by default)  
✅ HTTPS only (production)  
✅ GitHub token optional (for higher rate limits)  

### What We Don't Do

❌ Exploit generation  
❌ Unauthorized access  
❌ Data exfiltration  
❌ Code modification  

### Production Hardening

```python
# Rate limiting
from slowapi import Limiter
limiter = Limiter(key_func=get_remote_address)

@app.post("/scan")
@limiter.limit("10/minute")
async def scan_repository(request: ScanRequest):
    ...

# Input validation
class ScanRequest(BaseModel):
    repo_url: str = Field(
        ...,
        min_length=10,
        max_length=500,
        regex=r'^https?://github\.com/[\w-]+/[\w.-]+$'
    )

# Error handling (no stack traces)
@app.exception_handler(Exception)
async def exception_handler(request, exc):
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"}
    )
```

---

## Performance Optimization Ideas

### Current Bottlenecks

1. **GitHub API calls** (2-5s)
   - Solution: Cache repo metadata
   - Solution: Use GraphQL for batch queries
   
2. **File processing** (1-2s)
   - Solution: Parallel file processing
   - Solution: Skip large files (>1MB)
   
3. **Frontend rendering** (<1s)
   - Solution: Virtualize long finding lists
   - Solution: Lazy load findings

### Recommended Optimizations

```python
# 1. Cache GitHub responses (Redis)
@cache.cached(timeout=3600)
async def fetch_repo_files(owner, repo):
    ...

# 2. Limit file size
MAX_FILE_SIZE = 1_000_000  # 1MB
if len(content) > MAX_FILE_SIZE:
    continue

# 3. Parallel scanning
from concurrent.futures import ThreadPoolExecutor
with ThreadPoolExecutor(max_workers=4) as executor:
    findings = executor.map(
        scanner.scan_file,
        files.items()
    )

# 4. Early exit on CRITICAL
if any(f.severity == Severity.CRITICAL for f in findings):
    break  # Stop scanning remaining files
```

---

## Future Enhancements

### Phase 2: Database + History

```python
# Store scans in database
class Scan(Base):
    id: int
    repo_url: str
    scan_date: datetime
    risk_score: int
    findings_count: int
    
# Query history
GET /scans?repo=user/repo&since=2024-01-01

# Track trends
GET /scans/{repo_id}/trends
```

### Phase 3: GitHub App Integration

```python
# Listen for push events
@app.post("/github/webhook")
async def github_webhook(payload: GitHubWebhook):
    # Run scan on new push
    findings = await scan_repository(payload.repo_url)
    
    # Create PR comment
    post_comment_to_pr(findings)
```

### Phase 4: LLM-Powered Fixes

```python
# Generate fix suggestions using Claude/GPT
@app.post("/findings/{id}/suggest-fix")
async def suggest_fix(finding_id: int):
    finding = get_finding(finding_id)
    
    prompt = f"Fix this code: {finding.code_snippet}"
    fix = await claude.generate(prompt)
    
    return {"suggestion": fix}
```

---

## Testing Strategy

### Unit Tests

```bash
# Test detectors in isolation
pytest scanner/tests/test_detectors.py
```

### Integration Tests

```bash
# Test API endpoints
pytest backend/tests/test_api.py
```

### E2E Tests

```bash
# Test full flow (could use Selenium)
npm test  # Frontend tests
```

---

## Deployment Checklist

- [ ] Set `ENV=production`
- [ ] Enable HTTPS
- [ ] Add GitHub token (for higher rate limits)
- [ ] Enable rate limiting
- [ ] Add monitoring/logging
- [ ] Set up error tracking (Sentry)
- [ ] Configure CORS for production domain
- [ ] Test with production GitHub repos

---

## Contributing New Detectors

Follow the template:

```python
class NewThingDetector:
    """Detects [security issue]"""
    
    PATTERN = re.compile(r'...')
    
    def detect(self, content: str, filename: str) -> List[Finding]:
        findings = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            if self.PATTERN.search(line):
                findings.append(Finding(
                    severity=Severity.HIGH,
                    file=filename,
                    line_number=line_num,
                    issue="Clear title",
                    why="Why it's bad",
                    fix="How to fix",
                    category="Category",
                    code_snippet=line.strip()
                ))
        
        return findings
```

Then register in `Scanner.__init__()`:

```python
self.detectors.append(NewThingDetector())
```

---

## Questions?

See `SETUP.md` for local development  
See `CONTRIBUTING.md` for code guidelines  
See `docs/RULES.md` for detection rules reference

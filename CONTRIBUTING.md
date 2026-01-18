# Contributing to VibeGuard

We'd love your contributions! Here's how to get started.

## Development Setup

```bash
./setup.sh
./dev.sh start  # Both backend and frontend
```

## Adding New Detection Rules

### Step 1: Create Detector Class

In `scanner/detectors.py`:

```python
class YourDetector:
    """Description of what you detect"""
    
    YOUR_PATTERN = re.compile(r'pattern_here')
    
    def detect(self, content: str, filename: str) -> List[Finding]:
        findings = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            if line.strip().startswith('#'):
                continue
            
            if self.YOUR_PATTERN.search(line):
                findings.append(Finding(
                    severity=Severity.HIGH,
                    file=filename,
                    line_number=line_num,
                    issue="Clear issue title",
                    why="Why this is a problem",
                    fix="How to fix it",
                    category="CategoryName",
                    code_snippet=line.strip()
                ))
        
        return findings
```

### Step 2: Register in Scanner

In `Scanner.__init__()`:

```python
self.detectors.append(YourDetector())
```

### Step 3: Test It

```python
from scanner.detectors import Scanner

test_code = "code with the issue"
scanner = Scanner()
findings = scanner.scan_file(test_code, 'test.js')
assert len(findings) > 0
```

### Step 4: Submit PR

```bash
git checkout -b feature/detector-name
git commit -am "Add detector for..."
git push origin feature/detector-name
```

Then open a PR with:
- Description of what it detects
- Example vulnerable code
- False positive concerns

---

## Frontend Improvements

### Add New Component

```bash
# Create component
touch frontend/components/NewComponent.tsx

# Use it in pages/index.tsx
import NewComponent from '@/components/NewComponent'
```

### Run Tests

```bash
cd frontend
npm run lint
npm run build
```

---

## Backend Enhancements

### Add New Endpoint

In `backend/main.py`:

```python
@app.get("/new-endpoint", tags=["Category"])
async def new_endpoint(param: str):
    """
    Description
    """
    return {"result": "value"}
```

Then test:

```bash
curl http://localhost:8000/new-endpoint?param=value
```

---

## Testing

### Backend Unit Tests

```bash
cd backend
python -m pytest tests/ -v
```

### Frontend Tests

```bash
cd frontend
npm test
```

---

## Code Style

- **Python**: Follow PEP 8 (use `black` if you want)
- **TypeScript/React**: Use Next.js conventions
- **Commits**: Clear, descriptive messages

---

## Reporting Issues

Found a bug? Open an issue with:

1. **Title**: Clear description
2. **Reproduction**: Steps to reproduce
3. **Expected**: What should happen
4. **Actual**: What actually happens
5. **Environment**: OS, Python/Node version

---

## Ideas for Contributions

- [ ] New detectors for security issues
- [ ] Better false positive filtering
- [ ] Performance optimizations
- [ ] Documentation improvements
- [ ] UI/UX enhancements
- [ ] Database integration
- [ ] GitHub App integration
- [ ] GitHub Actions workflow

---

## Questions?

Open a discussion on GitHub or email dev@vibeguard.dev

Thanks for contributing!

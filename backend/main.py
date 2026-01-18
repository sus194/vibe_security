"""
VibeGuard API Backend
FastAPI server for scanning GitHub repositories
"""

import os
import re
from typing import Optional, List, Tuple, Dict, Any
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import httpx
import sys

# Add scanner to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from scanner.detectors import Scanner, Finding, Severity

# Initialize
app = FastAPI(
    title="VibeGuard API",
    description="Security scanner for vibe-coded GitHub repositories",
    version="0.1.0"
)

# CORS configuration (intentionally restrictive for security)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:3001",
        os.getenv("FRONTEND_URL", "http://localhost:3000")
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)

# Request/Response models
class ScanRequest(BaseModel):
    repo_url: str
    
    class Config:
        json_schema_extra = {
            "example": {
                "repo_url": "https://github.com/user/repo"
            }
        }


class FindingResponse(BaseModel):
    severity: str
    file: str
    line_number: int
    issue: str
    why: str
    fix: str
    category: str
    code_snippet: str


class ScanResultResponse(BaseModel):
    repo_url: str
    status: str
    findings: List[FindingResponse]
    summary: Dict[str, Any]


# Helper functions
def validate_github_url(url: str) -> Tuple[str, str]:
    """
    Validate and parse GitHub URL
    Returns (owner, repo) or raises HTTPException
    """
    # Accepted patterns:
    # https://github.com/owner/repo
    # https://github.com/owner/repo.git
    # github.com/owner/repo
    
    url = url.strip().rstrip('/')
    
    # Normalize to HTTPS
    if url.startswith('git@github.com:'):
        url = url.replace('git@github.com:', 'https://github.com/')
    
    if not url.startswith('http'):
        url = f'https://{url}'
    
    # Parse
    match = re.match(r'https?://github\.com/([a-zA-Z0-9_-]+)/([a-zA-Z0-9_.-]+?)(?:\.git)?/?$', url)
    
    if not match:
        raise HTTPException(
            status_code=400,
            detail="Invalid GitHub URL. Use: https://github.com/owner/repo"
        )
    
    return match.group(1), match.group(2)


async def fetch_repo_files(owner: str, repo: str, github_token: Optional[str] = None) -> Dict[str, str]:
    """
    Fetch repository files via GitHub API
    Fetches only common code files to reduce API calls
    """
    headers = {}
    if github_token:
        headers['Authorization'] = f'token {github_token}'
    
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            # Get repo contents
            url = f'https://api.github.com/repos/{owner}/{repo}/contents'
            response = await client.get(url, headers=headers)
            response.raise_for_status()
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            raise HTTPException(status_code=404, detail="Repository not found")
        if e.response.status_code == 403:
            raise HTTPException(status_code=403, detail="GitHub API rate limited or access denied")
        raise HTTPException(status_code=400, detail=f"GitHub API error: {e}")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to fetch repository: {str(e)}")
    
    files = {}
    contents = response.json()
    
    # File extensions to scan
    SCANNABLE_EXTENSIONS = {
        '.js', '.ts', '.jsx', '.tsx', '.py', '.go', '.rs', '.java', '.cs', '.rb', '.php',
        '.env', '.yml', '.yaml', '.json', '.toml', '.ini', '.conf', '.config'
    }
    
    # Fetch text files
    for item in contents:
        if item['type'] == 'file':
            _, ext = os.path.splitext(item['name'])
            if ext in SCANNABLE_EXTENSIONS or item['name'] in ['.env', '.env.example', 'package.json', 'requirements.txt']:
                try:
                    # Read file content
                    file_response = await client.get(item['url'], headers=headers)
                    file_response.raise_for_status()
                    file_data = file_response.json()
                    
                    if 'content' in file_data:
                        # Decode base64
                        import base64
                        content = base64.b64decode(file_data['content']).decode('utf-8', errors='ignore')
                        files[item['path']] = content
                except Exception:
                    pass  # Skip files we can't read
    
    return files


@app.get("/health", tags=["Health"])
async def health_check():
    """Health check endpoint"""
    return {"status": "ok", "service": "VibeGuard API"}


@app.post("/scan", response_model=ScanResultResponse, tags=["Scanning"])
async def scan_repository(request: ScanRequest):
    """
    Scan a GitHub repository for security issues
    
    - **repo_url**: GitHub repository URL (public only)
    
    Returns detailed security findings organized by severity
    """
    
    # Validate URL
    owner, repo = validate_github_url(request.repo_url)
    repo_url = f"https://github.com/{owner}/{repo}"
    
    # Fetch repository files
    github_token = os.getenv("GITHUB_TOKEN")
    files = await fetch_repo_files(owner, repo, github_token)
    
    if not files:
        raise HTTPException(
            status_code=400,
            detail="No scannable files found in repository"
        )
    
    # Run scanner
    scanner = Scanner()
    findings = scanner.scan_repo(files)
    
    # Format response
    findings_response = [
        FindingResponse(
            severity=f.severity.value,
            file=f.file,
            line_number=f.line_number,
            issue=f.issue,
            why=f.why,
            fix=f.fix,
            category=f.category,
            code_snippet=f.code_snippet
        )
        for f in findings
    ]
    
    # Generate summary
    severity_counts = {
        "CRITICAL": sum(1 for f in findings if f.severity == Severity.CRITICAL),
        "HIGH": sum(1 for f in findings if f.severity == Severity.HIGH),
        "MEDIUM": sum(1 for f in findings if f.severity == Severity.MEDIUM),
        "LOW": sum(1 for f in findings if f.severity == Severity.LOW),
    }
    
    category_counts = {}
    for f in findings:
        category_counts[f.category] = category_counts.get(f.category, 0) + 1
    
    summary = {
        "total_issues": len(findings),
        "by_severity": severity_counts,
        "by_category": category_counts,
        "files_scanned": len(files),
        "risk_score": min(100, len(findings) * 5),  # Simple risk score
    }
    
    return ScanResultResponse(
        repo_url=repo_url,
        status="completed",
        findings=findings_response,
        summary=summary
    )


@app.get("/", tags=["Info"])
async def root():
    """API info and documentation"""
    return {
        "name": "VibeGuard",
        "version": "0.1.0",
        "description": "Security scanner for vibe-coded GitHub repositories",
        "endpoints": {
            "POST /scan": "Scan a GitHub repository",
            "GET /health": "Health check",
            "GET /docs": "Swagger documentation"
        },
        "docs_url": "/docs"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=int(os.getenv("PORT", 8000)),
        reload=os.getenv("ENV", "development") == "development"
    )

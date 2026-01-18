"""
VibeGuard Scanner Engine
Core detectors for common security issues in vibe-coded apps
"""

import re
from typing import List, Dict, Any
from dataclasses import dataclass
from enum import Enum


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class Finding:
    severity: Severity
    file: str
    line_number: int
    issue: str
    why: str
    fix: str
    category: str
    code_snippet: str


class SecretDetector:
    """Detector for hard-coded secrets (API keys, tokens, credentials)"""
    
    # Pattern: OpenAI API keys (sk-*)
    OPENAI_KEY = re.compile(r'sk-[A-Za-z0-9]{20,}')
    
    # Pattern: AWS Access Key IDs (AKIA*)
    AWS_ACCESS_KEY = re.compile(r'AKIA[0-9A-Z]{16}')
    
    # Pattern: AWS Secret Key (long base64)
    AWS_SECRET_KEY = re.compile(r'aws_secret_access_key\s*=\s*["\']([A-Za-z0-9/+]{40,})["\']')
    
    # Pattern: Generic API keys
    API_KEY = re.compile(r'["\']?api[_-]?key["\']?\s*[:=]\s*["\']([A-Za-z0-9\-_]{20,})["\']', re.IGNORECASE)
    
    # Pattern: Firebase credentials
    FIREBASE_KEY = re.compile(r'AIza[0-9A-Za-z\-_]{35}')
    
    # Pattern: Stripe keys
    STRIPE_KEY = re.compile(r'(sk_live_[A-Za-z0-9]{24}|pk_live_[A-Za-z0-9]{24})')
    
    # Pattern: GitHub tokens
    GITHUB_TOKEN = re.compile(r'gh[pousr]{1}_[A-Za-z0-9_]{36,255}')
    
    # Pattern: Private keys (RSA, DSA, EC)
    PRIVATE_KEY = re.compile(r'-----BEGIN\s*(RSA|DSA|EC)?\s*PRIVATE KEY')
    
    # Pattern: .env file paths
    ENV_FILE = re.compile(r'\.env(?:\.\w+)?')
    
    # Pattern: process.env with fallback values
    ENV_FALLBACK = re.compile(r'process\.env\.\w+\s*\|\|\s*["\']([^"\']*)["\']')
    
    def detect(self, content: str, filename: str) -> List[Finding]:
        findings = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            # Skip comments
            if line.strip().startswith('#') or line.strip().startswith('//'):
                continue
            
            # Check for OpenAI keys
            if self.OPENAI_KEY.search(line):
                findings.append(Finding(
                    severity=Severity.CRITICAL,
                    file=filename,
                    line_number=line_num,
                    issue="Hard-coded OpenAI API key",
                    why="Exposes production credentials; can be used to make API calls",
                    fix="Move to environment variable (OPENAI_API_KEY)",
                    category="Secrets",
                    code_snippet=line.strip()
                ))
            
            # Check for AWS Access Keys
            if self.AWS_ACCESS_KEY.search(line):
                findings.append(Finding(
                    severity=Severity.CRITICAL,
                    file=filename,
                    line_number=line_num,
                    issue="Hard-coded AWS Access Key ID",
                    why="Exposes AWS credentials; enables unauthorized API calls",
                    fix="Use AWS IAM roles or move to environment variables",
                    category="Secrets",
                    code_snippet=line.strip()
                ))
            
            # Check for AWS Secret Keys
            if self.AWS_SECRET_KEY.search(line):
                findings.append(Finding(
                    severity=Severity.CRITICAL,
                    file=filename,
                    line_number=line_num,
                    issue="Hard-coded AWS Secret Access Key",
                    why="Exposes AWS credentials; enables unauthorized API calls",
                    fix="Use AWS IAM roles or move to environment variables",
                    category="Secrets",
                    code_snippet=line.strip()
                ))
            
            # Check for Firebase keys
            if self.FIREBASE_KEY.search(line):
                findings.append(Finding(
                    severity=Severity.CRITICAL,
                    file=filename,
                    line_number=line_num,
                    issue="Hard-coded Firebase API key",
                    why="Exposes Firebase credentials; enables unauthorized access",
                    fix="Move to environment variable or use Firebase rules",
                    category="Secrets",
                    code_snippet=line.strip()
                ))
            
            # Check for Stripe keys
            if self.STRIPE_KEY.search(line):
                findings.append(Finding(
                    severity=Severity.CRITICAL,
                    file=filename,
                    line_number=line_num,
                    issue="Hard-coded Stripe API key",
                    why="Exposes payment credentials; enables unauthorized charges",
                    fix="Move to environment variable (STRIPE_SECRET_KEY)",
                    category="Secrets",
                    code_snippet=line.strip()
                ))
            
            # Check for GitHub tokens
            if self.GITHUB_TOKEN.search(line):
                findings.append(Finding(
                    severity=Severity.CRITICAL,
                    file=filename,
                    line_number=line_num,
                    issue="Hard-coded GitHub token",
                    why="Exposes GitHub credentials; enables repository access",
                    fix="Move to environment variable (GITHUB_TOKEN)",
                    category="Secrets",
                    code_snippet=line.strip()
                ))
            
            # Check for private keys
            if self.PRIVATE_KEY.search(line):
                findings.append(Finding(
                    severity=Severity.CRITICAL,
                    file=filename,
                    line_number=line_num,
                    issue="Private key committed to repository",
                    why="Exposes cryptographic keys; enables impersonation",
                    fix="Remove immediately and rotate the key",
                    category="Secrets",
                    code_snippet=line.strip()
                ))
            
            # Check for .env file in code
            if self.ENV_FILE.search(line) and ('require' in line or 'import' in line or 'load' in line):
                findings.append(Finding(
                    severity=Severity.HIGH,
                    file=filename,
                    line_number=line_num,
                    issue=".env file referenced in code",
                    why="Suggests .env might be committed; check git history",
                    fix="Ensure .env is in .gitignore",
                    category="Secrets",
                    code_snippet=line.strip()
                ))
            
            # Check for process.env fallback values
            if self.ENV_FALLBACK.search(line):
                findings.append(Finding(
                    severity=Severity.HIGH,
                    file=filename,
                    line_number=line_num,
                    issue="Fallback value for environment variable",
                    why="If env var not set, defaults to hard-coded value",
                    fix="Remove fallback; fail loudly if env var missing",
                    category="Secrets",
                    code_snippet=line.strip()
                ))
        
        return findings


class InputValidationDetector:
    """Detector for missing input validation and sanitization"""
    
    # Patterns for direct request input usage
    REQ_BODY = re.compile(r'req\.body(?:\.|\[)')
    REQ_QUERY = re.compile(r'req\.query(?:\.|\[)')
    REQ_PARAMS = re.compile(r'req\.params(?:\.|\[)')
    REQUEST_JSON = re.compile(r'request\.json(?:\.|\[)')
    
    # SQL injection patterns
    SQL_CONCAT = re.compile(r'(SELECT|INSERT|UPDATE|DELETE|WHERE)\s*[\'\"]?\s*\+')
    
    # Command execution patterns
    SHELL_EXEC = re.compile(r'(exec|spawn|execFile|system|popen|shell=True)\s*\(')
    COMMAND_CONCAT = re.compile(r'(exec|spawn)\s*\([\'"][^\'"]*\+')
    
    # Path traversal patterns
    FS_READ_UNSANITIZED = re.compile(r'fs\.readFile\s*\(\s*(?:req\.|request\.|input)')
    FS_PATH_UNSANITIZED = re.compile(r'path\.join\s*\(\s*["\']\.\.?["\'],\s*(?:req\.|request\.|input)')
    
    # Validation library checks (positive signals)
    VALIDATION_LIBS = re.compile(r'(zod|joi|yup|pydantic|marshmallow|cerberus|schema)')
    
    def detect(self, content: str, filename: str) -> List[Finding]:
        findings = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            # Skip comments
            if line.strip().startswith('#') or line.strip().startswith('//'):
                continue
            
            # Check for direct request body usage without validation
            if self.REQ_BODY.search(line) and not self.VALIDATION_LIBS.search(content):
                findings.append(Finding(
                    severity=Severity.HIGH,
                    file=filename,
                    line_number=line_num,
                    issue="Direct use of req.body without validation",
                    why="User input passed directly to DB/logic enables injection attacks",
                    fix="Validate with zod/joi/pydantic before using",
                    category="Input Validation",
                    code_snippet=line.strip()
                ))
            
            # Check for direct query parameter usage
            if self.REQ_QUERY.search(line) and not self.VALIDATION_LIBS.search(content):
                findings.append(Finding(
                    severity=Severity.HIGH,
                    file=filename,
                    line_number=line_num,
                    issue="Direct use of req.query without validation",
                    why="Query parameters passed directly can enable injection attacks",
                    fix="Validate all query parameters before using",
                    category="Input Validation",
                    code_snippet=line.strip()
                ))
            
            # Check for SQL concatenation (likely injection)
            if self.SQL_CONCAT.search(line):
                findings.append(Finding(
                    severity=Severity.CRITICAL,
                    file=filename,
                    line_number=line_num,
                    issue="SQL query built with string concatenation",
                    why="Likely SQL injection vulnerability",
                    fix="Use parameterized queries or ORM (SQLAlchemy, Prisma)",
                    category="Input Validation",
                    code_snippet=line.strip()
                ))
            
            # Check for command execution with user input
            if self.COMMAND_CONCAT.search(line):
                findings.append(Finding(
                    severity=Severity.CRITICAL,
                    file=filename,
                    line_number=line_num,
                    issue="Command executed with concatenated input",
                    why="Enables command injection attacks",
                    fix="Use safe APIs (execFile) and never pass user input to shell",
                    category="Input Validation",
                    code_snippet=line.strip()
                ))
            
            # Check for unsafe filesystem operations
            if self.FS_READ_UNSANITIZED.search(line):
                findings.append(Finding(
                    severity=Severity.HIGH,
                    file=filename,
                    line_number=line_num,
                    issue="File read with unsanitized user input",
                    why="Enables path traversal attacks",
                    fix="Validate path is within allowed directory",
                    category="Input Validation",
                    code_snippet=line.strip()
                ))
        
        return findings


class AuthenticationDetector:
    """Detector for unsafe authentication logic"""
    
    # Auth checks that are too lenient
    LENIENT_AUTH = re.compile(r'if\s*\(\s*(?:user|req\.user|auth|request\.user)\s*\)')
    
    # Unverified JWT
    JWT_NO_VERIFY = re.compile(r'jwt\.decode\s*\([^,]*,\s*(?:options|algorithms)?\s*[{=]|jwt\.decode\s*\([^)]*\)\s*without\s*verify')
    
    # Client-side auth trust
    CLIENT_AUTH = re.compile(r'(localStorage|sessionStorage|document\.cookie).*auth|client[_-]?side.*auth')
    
    # Missing middleware checks
    UNPROTECTED_ROUTE = re.compile(r'(app\.(get|post|put|delete|patch))\s*\([\'"][^\'"]*(admin|protected|private)[^\'"][\'\"]')
    
    def detect(self, content: str, filename: str) -> List[Finding]:
        findings = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            if line.strip().startswith('#') or line.strip().startswith('//'):
                continue
            
            # Check for lenient auth checks
            if self.LENIENT_AUTH.search(line):
                findings.append(Finding(
                    severity=Severity.HIGH,
                    file=filename,
                    line_number=line_num,
                    issue="Auth check only verifies user exists",
                    why="Doesn't validate permissions or roles; weak authorization",
                    fix="Check user.role, permissions, or use middleware",
                    category="Authentication",
                    code_snippet=line.strip()
                ))
            
            # Check for unverified JWT
            if self.JWT_NO_VERIFY.search(line):
                findings.append(Finding(
                    severity=Severity.CRITICAL,
                    file=filename,
                    line_number=line_num,
                    issue="JWT decoded without verification",
                    why="Anyone can forge valid tokens",
                    fix="Always verify JWT with secret and algorithm",
                    category="Authentication",
                    code_snippet=line.strip()
                ))
            
            # Check for client-side auth trust
            if self.CLIENT_AUTH.search(line):
                findings.append(Finding(
                    severity=Severity.HIGH,
                    file=filename,
                    line_number=line_num,
                    issue="Client-side authentication logic detected",
                    why="Client auth can be bypassed; trust only server validation",
                    fix="Move auth logic to backend; validate every request",
                    category="Authentication",
                    code_snippet=line.strip()
                ))
        
        return findings


class CORSDetector:
    """Detector for overly permissive CORS settings"""
    
    # Wildcard CORS
    CORS_WILDCARD = re.compile(r'Access[_-]?Control[_-]?Allow[_-]?Origin[\'"]?\s*[:=]\s*[\'"]?\*[\'"]?')
    
    # Unrestricted credentials
    CORS_CREDENTIALS = re.compile(r'Access[_-]?Control[_-]?Allow[_-]?Credentials[\'"]?\s*[:=]\s*(?:true|1)')
    
    # No origin validation in Node.js
    NO_ORIGIN_CHECK = re.compile(r'cors\s*\(\s*\)', re.IGNORECASE)
    
    def detect(self, content: str, filename: str) -> List[Finding]:
        findings = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            if line.strip().startswith('#') or line.strip().startswith('//'):
                continue
            
            # Check for wildcard CORS
            if self.CORS_WILDCARD.search(line):
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    file=filename,
                    line_number=line_num,
                    issue="CORS allows all origins (Access-Control-Allow-Origin: *)",
                    why="Enables token theft and cross-origin attacks",
                    fix="Whitelist specific origins: Access-Control-Allow-Origin: https://trusted.com",
                    category="CORS",
                    code_snippet=line.strip()
                ))
            
            # Check for credentials with wildcard
            if self.CORS_CREDENTIALS.search(line) and self.CORS_WILDCARD.search(content):
                findings.append(Finding(
                    severity=Severity.CRITICAL,
                    file=filename,
                    line_number=line_num,
                    issue="CORS allows credentials with wildcard origin",
                    why="Completely breaks same-origin policy; enables credential theft",
                    fix="Remove wildcard; use specific trusted origins only",
                    category="CORS",
                    code_snippet=line.strip()
                ))
            
            # Check for default cors() with no config
            if self.NO_ORIGIN_CHECK.search(line):
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    file=filename,
                    line_number=line_num,
                    issue="CORS middleware with no configuration",
                    why="Applies permissive defaults",
                    fix="Configure with whitelist: cors({origin: ['https://trusted.com']})",
                    category="CORS",
                    code_snippet=line.strip()
                ))
        
        return findings


class DangerousDefaultsDetector:
    """Detector for insecure configs and dangerous defaults"""
    
    # Debug mode enabled
    DEBUG_ENABLED = re.compile(r'(debug|DEBUG)\s*=\s*(?:true|True|1|yes)', re.IGNORECASE)
    
    # Production check missing
    NODE_ENV_CHECK = re.compile(r'NODE_ENV\s*===?\s*[\'"]production[\'"]')
    
    # Hardcoded ports and admin flags
    HARDCODED_PORT = re.compile(r'port\s*=\s*\d{4}')
    ADMIN_FLAG = re.compile(r'(isAdmin|is_admin|admin)\s*=\s*(?:true|True|1)')
    
    # Trust proxy without validation
    TRUST_PROXY = re.compile(r'trust[_-]?proxy\s*=\s*(?:true|True|1)')
    
    def detect(self, content: str, filename: str) -> List[Finding]:
        findings = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            if line.strip().startswith('#') or line.strip().startswith('//'):
                continue
            
            # Check for debug enabled
            if self.DEBUG_ENABLED.search(line):
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    file=filename,
                    line_number=line_num,
                    issue="Debug mode enabled",
                    why="Exposes stack traces and sensitive info in production",
                    fix="Set DEBUG=false in production",
                    category="Dangerous Defaults",
                    code_snippet=line.strip()
                ))
            
            # Check for hardcoded port
            if self.HARDCODED_PORT.search(line):
                findings.append(Finding(
                    severity=Severity.LOW,
                    file=filename,
                    line_number=line_num,
                    issue="Hardcoded port number",
                    why="Reduces flexibility; should use environment variable",
                    fix="Use port = process.env.PORT || 3000",
                    category="Dangerous Defaults",
                    code_snippet=line.strip()
                ))
            
            # Check for hardcoded admin flag
            if self.ADMIN_FLAG.search(line):
                findings.append(Finding(
                    severity=Severity.HIGH,
                    file=filename,
                    line_number=line_num,
                    issue="Admin flag hardcoded to true",
                    why="Grants admin access to all users",
                    fix="Remove; compute from database or auth provider",
                    category="Dangerous Defaults",
                    code_snippet=line.strip()
                ))
            
            # Check for trust proxy
            if self.TRUST_PROXY.search(line):
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    file=filename,
                    line_number=line_num,
                    issue="Trust proxy enabled without validation",
                    why="Can enable IP spoofing attacks",
                    fix="Set specific trusted proxy IPs only",
                    category="Dangerous Defaults",
                    code_snippet=line.strip()
                ))
        
        return findings


class FileUploadDetector:
    """Detector for unsafe file upload handling"""
    
    # File uploads without validation
    FILE_UPLOAD = re.compile(r'(multer|FileUpload|upload|file.*middleware)')
    
    # No size limits
    NO_SIZE_LIMIT = re.compile(r'upload\.single\(\)|upload\.array\(\)|FileUpload\(\)')
    
    # No type validation
    NO_TYPE_CHECK = re.compile(r'fs\.writeFile\s*\([\'"]uploads?[\'"]')
    
    def detect(self, content: str, filename: str) -> List[Finding]:
        findings = []
        lines = content.split('\n')
        
        has_size_limit = 'limits' in content
        has_type_check = 'mimetype' in content or 'fileType' in content or 'accept' in content
        
        for line_num, line in enumerate(lines, 1):
            if line.strip().startswith('#') or line.strip().startswith('//'):
                continue
            
            # Check for file upload without size limit
            if self.FILE_UPLOAD.search(line) and not has_size_limit:
                findings.append(Finding(
                    severity=Severity.HIGH,
                    file=filename,
                    line_number=line_num,
                    issue="File upload without size limits",
                    why="Enables DoS via disk exhaustion",
                    fix="Add limits: {fileSize: 5 * 1024 * 1024}",
                    category="File Upload",
                    code_snippet=line.strip()
                ))
            
            # Check for file upload without type validation
            if self.FILE_UPLOAD.search(line) and not has_type_check:
                findings.append(Finding(
                    severity=Severity.HIGH,
                    file=filename,
                    line_number=line_num,
                    issue="File upload without type validation",
                    why="Enables RCE via malicious uploads",
                    fix="Validate MIME type and file extensions",
                    category="File Upload",
                    code_snippet=line.strip()
                ))
        
        return findings


class DependencyDetector:
    """Detector for dependency red flags"""
    
    # npm install --force (bad sign)
    NPM_FORCE = re.compile(r'npm\s+install\s+--force')
    
    # Outdated lock files
    PACKAGE_LOCK_OLD = re.compile(r'lockfileVersion.*[0-1](?:\D|$)')
    
    def detect(self, content: str, filename: str) -> List[Finding]:
        findings = []
        
        if 'npm install --force' in content:
            lines = content.split('\n')
            for line_num, line in enumerate(lines, 1):
                if 'npm install --force' in line:
                    findings.append(Finding(
                        severity=Severity.MEDIUM,
                        file=filename,
                        line_number=line_num,
                        issue="npm install --force in script",
                        why="Suggests forced dependency installation; may skip security checks",
                        fix="Remove --force; resolve conflicts properly",
                        category="Dependencies",
                        code_snippet=line.strip()
                    ))
        
        return findings


class AISecurityDetector:
    """Detector for AI-specific security risks (prompt injection, etc.)"""
    
    # Raw input to prompt
    RAW_INPUT_PROMPT = re.compile(r'(f[\'"][^\'"]+(request|user|input)[^\'"]|template.*request|prompt.*\+.*request)')
    
    # User input in system prompt
    USER_IN_SYSTEM = re.compile(r'(system_prompt|systemPrompt|system[_-]message).*[\'"].*\$\{.*input|system.*request\.')
    
    # No output filtering
    NO_OUTPUT_FILTER = re.compile(r'openai\.ChatCompletion\.create|anthropic\.messages\.create')
    
    def detect(self, content: str, filename: str) -> List[Finding]:
        findings = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            if line.strip().startswith('#') or line.strip().startswith('//'):
                continue
            
            # Check for raw input in prompt
            if self.RAW_INPUT_PROMPT.search(line):
                findings.append(Finding(
                    severity=Severity.HIGH,
                    file=filename,
                    line_number=line_num,
                    issue="Raw user input concatenated into prompt",
                    why="Enables prompt injection attacks",
                    fix="Sanitize input; use structured templates; validate output",
                    category="AI Security",
                    code_snippet=line.strip()
                ))
            
            # Check for user input in system message
            if self.USER_IN_SYSTEM.search(line):
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    file=filename,
                    line_number=line_num,
                    issue="User input in system prompt",
                    why="Weakens prompt injection defenses",
                    fix="Keep system prompt static; put user input in separate message",
                    category="AI Security",
                    code_snippet=line.strip()
                ))
        
        return findings


class Scanner:
    """Main scanner orchestrator"""
    
    def __init__(self):
        self.detectors = [
            SecretDetector(),
            InputValidationDetector(),
            AuthenticationDetector(),
            CORSDetector(),
            DangerousDefaultsDetector(),
            FileUploadDetector(),
            DependencyDetector(),
            AISecurityDetector(),
        ]
    
    def scan_file(self, content: str, filename: str) -> List[Finding]:
        """Scan a single file for all security issues"""
        findings = []
        
        for detector in self.detectors:
            findings.extend(detector.detect(content, filename))
        
        # Remove duplicates (same line, same issue)
        seen = set()
        unique_findings = []
        for finding in findings:
            key = (finding.file, finding.line_number, finding.issue)
            if key not in seen:
                seen.add(key)
                unique_findings.append(finding)
        
        return unique_findings
    
    def scan_repo(self, files: Dict[str, str]) -> List[Finding]:
        """Scan entire repository"""
        all_findings = []
        
        for filename, content in files.items():
            all_findings.extend(self.scan_file(content, filename))
        
        # Sort by severity (CRITICAL first) then by file
        severity_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3}
        all_findings.sort(key=lambda f: (severity_order[f.severity], f.file, f.line_number))
        
        return all_findings

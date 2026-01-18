"""
VibeGuard API Backend - Simplified version
"""

import os
import re
import json
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

# Add scanner to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

try:
    from scanner.detectors import Scanner
except ImportError:
    print("Warning: Could not import scanner")
    Scanner = None


class VibeGuardHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        """Handle GET requests"""
        if self.path == '/health':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            response = {"status": "ok", "service": "VibeGuard API"}
            self.wfile.write(json.dumps(response).encode())
        
        elif self.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            response = {
                "name": "VibeGuard",
                "version": "0.1.0",
                "description": "Security scanner for vibe-coded GitHub repositories",
                "endpoints": {
                    "POST /scan": "Scan a GitHub repository",
                    "GET /health": "Health check"
                }
            }
            self.wfile.write(json.dumps(response).encode())
        else:
            self.send_response(404)
            self.end_headers()
    
    def do_POST(self):
        """Handle POST requests"""
        if self.path == '/scan':
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length)
            
            try:
                data = json.loads(body.decode())
                repo_url = data.get('repo_url', '')
                
                # Simple validation
                if not repo_url or 'github.com' not in repo_url:
                    self.send_response(400)
                    self.send_header('Content-type', 'application/json')
                    self.send_header('Access-Control-Allow-Origin', '*')
                    self.end_headers()
                    error = {"error": "Invalid GitHub URL"}
                    self.wfile.write(json.dumps(error).encode())
                    return
                
                # Return mock response for now
                response = {
                    "repo_url": repo_url,
                    "status": "completed",
                    "findings": [],
                    "summary": {
                        "total_issues": 0,
                        "by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
                        "by_category": {},
                        "files_scanned": 0,
                        "risk_score": 0
                    }
                }
                
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(json.dumps(response).encode())
                
            except json.JSONDecodeError:
                self.send_response(400)
                self.send_header('Content-type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                error = {"error": "Invalid JSON"}
                self.wfile.write(json.dumps(error).encode())
        else:
            self.send_response(404)
            self.end_headers()
    
    def do_OPTIONS(self):
        """Handle CORS preflight"""
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
    
    def log_message(self, format, *args):
        """Suppress default logging"""
        print(f"[{self.log_date_time_string()}] {format % args}")


if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    server = HTTPServer(('0.0.0.0', port), VibeGuardHandler)
    print(f"🚀 VibeGuard API running on http://0.0.0.0:{port}")
    print(f"   Health check: http://localhost:{port}/health")
    print(f"   Docs: http://localhost:{port}/")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n✋ Server stopped")
        server.server_close()

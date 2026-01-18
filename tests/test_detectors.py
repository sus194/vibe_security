"""
Test cases for VibeGuard scanner
Run with: python -m pytest tests/test_detectors.py -v
"""

import sys
sys.path.insert(0, '.')

from scanner.detectors import Scanner, Severity


class TestSecrets:
    """Test hard-coded secrets detection"""
    
    def test_openai_key_detection(self):
        code = "const API_KEY = 'sk-1234567890abcdefghijk';"
        scanner = Scanner()
        findings = scanner.scan_file(code, 'test.js')
        
        assert len(findings) > 0
        assert findings[0].severity == Severity.CRITICAL
        assert 'OpenAI' in findings[0].issue
    
    def test_aws_access_key_detection(self):
        code = "export AWS_KEY=AKIAIOSFODNN7EXAMPLE"
        scanner = Scanner()
        findings = scanner.scan_file(code, '.env')
        
        assert len(findings) > 0
        assert findings[0].severity == Severity.CRITICAL
        assert 'AWS' in findings[0].issue
    
    def test_firebase_key_detection(self):
        code = "firebase_key = 'AIzaSyDosKKKKKKKKKKKKKKKKKKKKKKKKKK'"
        scanner = Scanner()
        findings = scanner.scan_file(code, 'config.py')
        
        assert len(findings) > 0
        assert findings[0].severity == Severity.CRITICAL


class TestInputValidation:
    """Test input validation detection"""
    
    def test_sql_injection_concat(self):
        code = "query = 'SELECT * FROM users WHERE id=' + req.query.id"
        scanner = Scanner()
        findings = scanner.scan_file(code, 'api.js')
        
        assert len(findings) > 0
        assert any(f.severity == Severity.CRITICAL for f in findings)
        assert any('SQL' in f.issue for f in findings)
    
    def test_command_injection(self):
        code = "exec('ls -la ' + userInput)"
        scanner = Scanner()
        findings = scanner.scan_file(code, 'dangerous.py')
        
        assert len(findings) > 0
        assert findings[0].severity == Severity.CRITICAL
    
    def test_unvalidated_request_body(self):
        code = """
        app.post('/api/user', (req, res) => {
            db.insert(req.body);
        });
        """
        scanner = Scanner()
        findings = scanner.scan_file(code, 'api.js')
        
        # Should detect unvalidated req.body if no validation libs present
        assert any('validation' in f.issue.lower() for f in findings)


class TestAuthentication:
    """Test authentication issue detection"""
    
    def test_lenient_auth_check(self):
        code = """
        if (req.user) {
            res.json(sensitiveData);
        }
        """
        scanner = Scanner()
        findings = scanner.scan_file(code, 'auth.js')
        
        assert any('Auth' in f.category for f in findings)
    
    def test_unverified_jwt(self):
        code = "const payload = jwt.decode(token);"
        scanner = Scanner()
        findings = scanner.scan_file(code, 'auth.js')
        
        assert any('JWT' in f.issue for f in findings)


class TestCORS:
    """Test CORS misconfiguration detection"""
    
    def test_wildcard_cors(self):
        code = "Access-Control-Allow-Origin: *"
        scanner = Scanner()
        findings = scanner.scan_file(code, '.htaccess')
        
        assert len(findings) > 0
        assert findings[0].severity == Severity.MEDIUM
        assert 'CORS' in findings[0].category


class TestDangerousDefaults:
    """Test dangerous default detection"""
    
    def test_debug_enabled(self):
        code = """
        DEBUG = True
        app = Flask(__name__)
        app.run(debug=True)
        """
        scanner = Scanner()
        findings = scanner.scan_file(code, 'app.py')
        
        assert any('debug' in f.issue.lower() for f in findings)
    
    def test_hardcoded_port(self):
        code = "port = 3000"
        scanner = Scanner()
        findings = scanner.scan_file(code, 'server.js')
        
        assert any('hardcoded' in f.issue.lower() for f in findings)
    
    def test_admin_flag_true(self):
        code = "isAdmin = true"
        scanner = Scanner()
        findings = scanner.scan_file(code, 'user.js')
        
        assert any('admin' in f.issue.lower() for f in findings)


class TestFileUpload:
    """Test file upload issue detection"""
    
    def test_upload_without_validation(self):
        code = """
        app.post('/upload', (req, res) => {
            const file = req.files.document;
            file.mv('./uploads/' + file.name);
        });
        """
        scanner = Scanner()
        findings = scanner.scan_file(code, 'upload.js')
        
        # Should detect missing validation
        assert any('upload' in f.category.lower() for f in findings)


class TestDependencies:
    """Test dependency issue detection"""
    
    def test_npm_force_install(self):
        code = """
        npm install --force
        """
        scanner = Scanner()
        findings = scanner.scan_file(code, 'Makefile')
        
        assert any('force' in f.issue.lower() for f in findings)


class TestAISecurity:
    """Test AI security issue detection"""
    
    def test_raw_input_in_prompt(self):
        code = """
        prompt = f"User said: {user_input}. Respond accordingly"
        response = openai.ChatCompletion.create(messages=[{"role": "user", "content": prompt}])
        """
        scanner = Scanner()
        findings = scanner.scan_file(code, 'ai.py')
        
        assert any('AI' in f.category or 'prompt' in f.issue.lower() for f in findings)


class TestIntegration:
    """Integration tests with multiple issues"""
    
    def test_multiple_issues_in_file(self):
        code = """
        // Hard-coded API key
        const API_KEY = 'sk-1234567890abcdefghijk';
        
        // Unvalidated user input
        app.get('/api', (req, res) => {
            const query = 'SELECT * FROM users WHERE id=' + req.query.id;
            db.execute(query);
        });
        
        // Debug enabled
        DEBUG = true;
        """
        scanner = Scanner()
        findings = scanner.scan_file(code, 'app.js')
        
        # Should find multiple issues
        assert len(findings) >= 3
        
        # Should have critical severity
        assert any(f.severity == Severity.CRITICAL for f in findings)
        
        # Should find different categories
        categories = {f.category for f in findings}
        assert len(categories) >= 2
    
    def test_clean_code(self):
        code = """
        // Properly validated input
        import { z } from 'zod';
        
        const UserSchema = z.object({
            id: z.number().positive(),
        });
        
        app.post('/api/user', async (req, res) => {
            const validated = UserSchema.parse(req.body);
            const user = await db.query('SELECT * FROM users WHERE id = ?', [validated.id]);
            res.json(user);
        });
        """
        scanner = Scanner()
        findings = scanner.scan_file(code, 'api.js')
        
        # Clean code should have minimal or no findings
        # (May have some from pattern matching, but should be low severity)
        critical_findings = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(critical_findings) == 0
    
    def test_repository_scan(self):
        files = {
            'server.js': "const API_KEY = 'sk-123';",
            'db.js': "db.execute('SELECT * FROM users WHERE id=' + req.query.id);",
            'config.json': '{"debug": true}',
        }
        
        scanner = Scanner()
        findings = scanner.scan_repo(files)
        
        # Should find issues across multiple files
        assert len(findings) > 0
        assert len({f.file for f in findings}) == 2  # At least 2 different files
        
        # Should be sorted by severity
        severities = [f.severity for f in findings]
        assert severities == sorted(severities, key=lambda s: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].index(s.value))


# Run tests manually
if __name__ == '__main__':
    import pytest
    pytest.main([__file__, '-v'])

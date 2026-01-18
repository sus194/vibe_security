import React, { useState } from 'react';
import axios from 'axios';
import Scanner from '@/components/Scanner';
import Results from '@/components/Results';

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

export default function Home() {
  const [repoUrl, setRepoUrl] = useState('');
  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const handleScan = async (url: string) => {
    setLoading(true);
    setError(null);
    setResults(null);

    try {
      const response = await axios.post(`${API_BASE_URL}/scan`, {
        repo_url: url,
      });
      setResults(response.data);
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to scan repository');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900">
      <div className="max-w-6xl mx-auto px-4 py-12">
        {/* Header */}
        <div className="text-center mb-12">
          <div className="flex items-center justify-center gap-3 mb-4">
            <div className="w-12 h-12 bg-gradient-to-br from-cyan-400 to-blue-500 rounded-lg flex items-center justify-center">
              <span className="text-xl font-bold text-white">⚡</span>
            </div>
            <h1 className="text-4xl font-bold text-white">VibeGuard</h1>
          </div>
          <p className="text-xl text-slate-300">
            Security Scanner for Vibe-Coded GitHub Repositories
          </p>
          <p className="text-slate-400 mt-2">
            Find common security issues introduced by fast coding practices
          </p>
        </div>

        {/* Scanner */}
        <Scanner 
          onScan={handleScan}
          loading={loading}
          error={error}
        />

        {/* Results */}
        {results && <Results data={results} />}

        {/* Info Section */}
        {!results && !loading && (
          <div className="mt-16 grid md:grid-cols-3 gap-6">
            <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-6 hover:border-cyan-500/50 transition-colors">
              <h3 className="text-lg font-semibold text-cyan-400 mb-2">🔑 Secrets Detection</h3>
              <p className="text-slate-300">
                Finds hard-coded API keys, tokens, and cloud credentials
              </p>
            </div>
            <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-6 hover:border-cyan-500/50 transition-colors">
              <h3 className="text-lg font-semibold text-cyan-400 mb-2">🧪 Input Validation</h3>
              <p className="text-slate-300">
                Detects SQL injection, command injection, and path traversal risks
              </p>
            </div>
            <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-6 hover:border-cyan-500/50 transition-colors">
              <h3 className="text-lg font-semibold text-cyan-400 mb-2">🔓 Auth & CORS</h3>
              <p className="text-slate-300">
                Identifies unsafe authentication and overly permissive CORS
              </p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

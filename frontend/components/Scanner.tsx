import React from 'react';

interface ScannerProps {
  onScan: (url: string) => void;
  loading: boolean;
  error: string | null;
}

export default function Scanner({ onScan, loading, error }: ScannerProps) {
  const [input, setInput] = React.useState('');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (input.trim()) {
      onScan(input);
    }
  };

  return (
    <div className="mb-8">
      <form onSubmit={handleSubmit} className="space-y-4">
        <div className="relative">
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="https://github.com/user/repo"
            className="w-full px-6 py-4 bg-slate-800 border border-slate-700 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500"
            disabled={loading}
          />
        </div>

        {error && (
          <div className="p-4 bg-red-500/10 border border-red-500/50 rounded-lg text-red-400">
            {error}
          </div>
        )}

        <button
          type="submit"
          disabled={loading || !input.trim()}
          className="w-full px-6 py-3 bg-gradient-to-r from-cyan-500 to-blue-500 hover:from-cyan-600 hover:to-blue-600 disabled:from-slate-600 disabled:to-slate-700 text-white font-semibold rounded-lg transition-all duration-200 disabled:cursor-not-allowed"
        >
          {loading ? (
            <span className="flex items-center justify-center gap-2">
              <span className="inline-block w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
              Scanning...
            </span>
          ) : (
            'Scan Repository'
          )}
        </button>
      </form>
    </div>
  );
}

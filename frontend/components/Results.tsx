import React, { useState } from 'react';

interface Finding {
  severity: string;
  file: string;
  line_number: number;
  issue: string;
  why: string;
  fix: string;
  category: string;
  code_snippet: string;
}

interface ResultsProps {
  data: {
    repo_url: string;
    status: string;
    findings: Finding[];
    summary: {
      total_issues: number;
      by_severity: Record<string, number>;
      by_category: Record<string, number>;
      files_scanned: number;
      risk_score: number;
    };
  };
}

const severityColors = {
  CRITICAL: { bg: 'bg-red-500/10', border: 'border-red-500/50', text: 'text-red-400', badge: 'bg-red-500' },
  HIGH: { bg: 'bg-orange-500/10', border: 'border-orange-500/50', text: 'text-orange-400', badge: 'bg-orange-500' },
  MEDIUM: { bg: 'bg-yellow-500/10', border: 'border-yellow-500/50', text: 'text-yellow-400', badge: 'bg-yellow-500' },
  LOW: { bg: 'bg-blue-500/10', border: 'border-blue-500/50', text: 'text-blue-400', badge: 'bg-blue-500' },
};

export default function Results({ data }: ResultsProps) {
  const [expandedFinding, setExpandedFinding] = useState<number | null>(null);
  const [filterSeverity, setFilterSeverity] = useState<string | null>(null);

  const filteredFindings = filterSeverity
    ? data.findings.filter((f) => f.severity === filterSeverity)
    : data.findings;

  const getRiskLabel = (score: number) => {
    if (score >= 80) return 'CRITICAL';
    if (score >= 60) return 'HIGH';
    if (score >= 40) return 'MEDIUM';
    return 'LOW';
  };

  return (
    <div className="space-y-6">
      {/* Summary */}
      <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-6">
        <div className="flex items-center justify-between mb-6">
          <div>
            <p className="text-slate-400 text-sm mb-1">Repository</p>
            <p className="text-white font-mono text-sm">{data.repo_url}</p>
          </div>
          <div className="text-right">
            <p className="text-slate-400 text-sm mb-1">Risk Score</p>
            <div className="flex items-center gap-2">
              <div className="text-4xl font-bold text-cyan-400">{data.summary.risk_score}</div>
              <span className={`px-3 py-1 rounded text-white text-sm font-semibold ${
                getRiskLabel(data.summary.risk_score) === 'CRITICAL' ? 'bg-red-500' :
                getRiskLabel(data.summary.risk_score) === 'HIGH' ? 'bg-orange-500' :
                getRiskLabel(data.summary.risk_score) === 'MEDIUM' ? 'bg-yellow-500' :
                'bg-blue-500'
              }`}>
                {getRiskLabel(data.summary.risk_score)}
              </span>
            </div>
          </div>
        </div>

        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="bg-slate-700/50 rounded p-4">
            <p className="text-slate-400 text-sm">Total Issues</p>
            <p className="text-2xl font-bold text-white">{data.summary.total_issues}</p>
          </div>
          <div className="bg-slate-700/50 rounded p-4">
            <p className="text-slate-400 text-sm">Files Scanned</p>
            <p className="text-2xl font-bold text-white">{data.summary.files_scanned}</p>
          </div>
          <div className="bg-red-500/10 border border-red-500/30 rounded p-4">
            <p className="text-red-400 text-sm">Critical</p>
            <p className="text-2xl font-bold text-red-400">{data.summary.by_severity.CRITICAL}</p>
          </div>
          <div className="bg-orange-500/10 border border-orange-500/30 rounded p-4">
            <p className="text-orange-400 text-sm">High</p>
            <p className="text-2xl font-bold text-orange-400">{data.summary.by_severity.HIGH}</p>
          </div>
        </div>
      </div>

      {/* Category Breakdown */}
      <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-6">
        <h3 className="text-lg font-semibold text-white mb-4">Issues by Category</h3>
        <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
          {Object.entries(data.summary.by_category).map(([category, count]) => (
            <div key={category} className="bg-slate-700/50 rounded p-3">
              <p className="text-slate-300 text-sm">{category}</p>
              <p className="text-xl font-bold text-cyan-400">{count}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Findings */}
      <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-6">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold text-white">Findings</h3>
          <div className="flex gap-2">
            {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((severity) => (
              <button
                key={severity}
                onClick={() => setFilterSeverity(filterSeverity === severity ? null : severity)}
                className={`px-3 py-1 rounded text-sm font-medium transition-colors ${
                  filterSeverity === severity
                    ? `${severityColors[severity as keyof typeof severityColors].badge} text-white`
                    : 'bg-slate-700 text-slate-300 hover:bg-slate-600'
                }`}
              >
                {severity}
              </button>
            ))}
          </div>
        </div>

        {filteredFindings.length === 0 ? (
          <p className="text-slate-400 text-center py-8">
            {filterSeverity ? `No ${filterSeverity} findings` : 'No findings'}
          </p>
        ) : (
          <div className="space-y-3">
            {filteredFindings.map((finding, idx) => {
              const colors = severityColors[finding.severity as keyof typeof severityColors];
              const isExpanded = expandedFinding === idx;

              return (
                <div
                  key={idx}
                  className={`border rounded-lg transition-all cursor-pointer ${colors.bg} ${colors.border} border`}
                >
                  <div
                    className="p-4 hover:bg-white/5"
                    onClick={() => setExpandedFinding(isExpanded ? null : idx)}
                  >
                    <div className="flex items-start justify-between gap-4">
                      <div className="flex-1">
                        <div className="flex items-center gap-3 mb-2">
                          <span className={`px-2 py-1 rounded text-xs font-semibold text-white ${colors.badge}`}>
                            {finding.severity}
                          </span>
                          <span className="text-slate-400 text-xs">{finding.category}</span>
                        </div>
                        <h4 className={`font-semibold ${colors.text}`}>{finding.issue}</h4>
                        <p className="text-sm text-slate-300 mt-1">
                          {finding.file}:{finding.line_number}
                        </p>
                      </div>
                      <span className="text-xl text-slate-400">{isExpanded ? '▼' : '▶'}</span>
                    </div>
                  </div>

                  {isExpanded && (
                    <div className="border-t border-current/20 p-4 space-y-3">
                      <div>
                        <p className="text-xs font-semibold text-slate-400 uppercase mb-1">Why</p>
                        <p className="text-slate-300">{finding.why}</p>
                      </div>
                      <div>
                        <p className="text-xs font-semibold text-slate-400 uppercase mb-1">Code Snippet</p>
                        <pre className="bg-slate-900 rounded p-3 text-xs text-slate-300 overflow-x-auto">
                          {finding.code_snippet}
                        </pre>
                      </div>
                      <div>
                        <p className="text-xs font-semibold text-slate-400 uppercase mb-1">Fix</p>
                        <p className="text-slate-300">{finding.fix}</p>
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}

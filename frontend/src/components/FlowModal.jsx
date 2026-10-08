import React from 'react';
import { SEVERITY_CONFIG } from '../constants';

export default function FlowModal({ flow, onClose }) {
  if (!flow) return null;

  const cfg = SEVERITY_CONFIG[flow.severity] || SEVERITY_CONFIG.Normal;

  // Sort class probabilities descending
  const sortedProbabilities = flow.probabilities
    ? Object.entries(flow.probabilities).sort((a, b) => b[1] - a[1])
    : [];

  return (
    <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
      <div className="bg-soc-900 border border-soc-700 rounded-xl max-w-2xl w-full p-6 shadow-2xl relative max-h-[90vh] overflow-y-auto">
        {/* Close icon */}
        <button
          onClick={onClose}
          className="absolute top-4 right-4 text-slate-400 hover:text-white p-1"
          aria-label="Close modal"
        >
          <svg
            width="20"
            height="20"
            className="w-5 h-5"
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
          >
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
          </svg>
        </button>

        {/* Header */}
        <div className="flex items-center gap-3 mb-4">
          <span className={`px-2.5 py-1 rounded text-xs font-bold font-mono tracking-wider ${cfg.bgBadge}`}>
            {flow.severity}
          </span>
          <h3 className="text-lg font-bold text-white font-mono">
            Flow #{flow.id} &mdash; {flow.label}
          </h3>
        </div>

        {/* 5-tuple & Core Metrics Grid */}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs font-mono bg-soc-950 p-4 rounded-lg border border-soc-800 mb-4">
          <div>
            <span className="text-slate-500 block">SOURCE ADDRESS:</span>
            <span className="text-rose-400 font-bold">
              {flow.src_ip}:{flow.src_port}
            </span>
          </div>
          <div>
            <span className="text-slate-500 block">DESTINATION ADDRESS:</span>
            <span className="text-slate-200 font-bold">
              {flow.dst_ip}:{flow.dst_port}
            </span>
          </div>
          <div>
            <span className="text-slate-500 block">TIMESTAMP:</span>
            <span className="text-slate-300">{flow.timestamp || 'N/A'}</span>
          </div>
          <div>
            <span className="text-slate-500 block">PROTOCOL / DURATION:</span>
            <span className="text-slate-300">
              {flow.protocol || 'IP'} &bull; {flow.duration_us?.toLocaleString() || 0} µs
            </span>
          </div>
          <div>
            <span className="text-slate-500 block">TOTAL PACKETS / BYTES:</span>
            <span className="text-slate-300">
              {flow.packet_count || 0} pkts &bull; {flow.byte_count?.toLocaleString() || 0} bytes
            </span>
          </div>
          <div>
            <span className="text-slate-500 block">MODEL CONFIDENCE:</span>
            <span className="text-emerald-400 font-bold">
              {flow.confidence !== null && flow.confidence !== undefined
                ? `${(flow.confidence * 100).toFixed(2)}%`
                : 'Rule Override (PSD)'}
            </span>
          </div>
        </div>

        {/* Class Probability Distribution */}
        {sortedProbabilities.length > 0 && (
          <div>
            <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-2 font-mono">
              Class Probabilities
            </h4>
            <div className="space-y-2 bg-soc-950 p-3 rounded-lg border border-soc-800">
              {sortedProbabilities.map(([cls, prob]) => {
                const isSelected = cls === flow.label;
                const percent = (prob * 100).toFixed(2);

                return (
                  <div key={cls} className="text-xs font-mono">
                    <div className="flex justify-between text-slate-300 mb-0.5">
                      <span className={isSelected ? 'text-white font-bold' : 'text-slate-400'}>
                        {cls}
                      </span>
                      <span className={isSelected ? 'text-rose-400 font-bold' : 'text-slate-400'}>
                        {percent}%
                      </span>
                    </div>
                    <div className="w-full bg-soc-800 rounded-full h-1.5 overflow-hidden">
                      <div
                        className={`h-1.5 rounded-full transition-all duration-300 ${
                          isSelected ? 'bg-rose-500' : 'bg-slate-600'
                        }`}
                        style={{ width: `${Math.max(1, prob * 100)}%` }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* Bottom Actions */}
        <div className="mt-5 flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-1.5 bg-soc-700 hover:bg-soc-600 text-white rounded-lg text-xs font-medium transition"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
}

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
    <div className="fixed inset-0 bg-black/85 z-50 flex items-center justify-center p-4 font-mono text-xs">
      <div className="bg-[#1a1a1a] border border-[#2a2a2a] max-w-2xl w-full p-4 relative max-h-[90vh] overflow-y-auto">
        {/* Header */}
        <div className="border-b border-[#2a2a2a] pb-2.5 mb-3 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span className={`px-1.5 py-0.2 text-[10px] font-bold tracking-wider ${cfg.bgBadge}`}>
              [{flow.severity.toUpperCase()}]
            </span>
            <h3 className="text-xs font-bold text-[#ffffff] uppercase tracking-wider">
              [ FLOW INSPECTION #{flow.id} ] &mdash; <span className={cfg.textClass}>{flow.label}</span>
            </h3>
          </div>

          <button
            onClick={onClose}
            className="text-[#888888] hover:text-[#ffffff] px-2 py-0.5 border border-[#2a2a2a] bg-[#0a0a0a] text-[11px]"
            aria-label="Close modal"
          >
            [X]
          </button>
        </div>

        {/* 5-tuple & Core Metrics Grid */}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs bg-[#0a0a0a] border border-[#2a2a2a] p-3 mb-3">
          <div>
            <span className="text-[#888888] block text-[10px]">SRC HOST:</span>
            <span className="text-[#ffffff] font-bold">
              {flow.src_ip}:{flow.src_port}
            </span>
          </div>
          <div>
            <span className="text-[#888888] block text-[10px]">DST HOST:</span>
            <span className="text-[#ffffff] font-bold">
              {flow.dst_ip}:{flow.dst_port}
            </span>
          </div>
          <div>
            <span className="text-[#888888] block text-[10px]">TIMESTAMP:</span>
            <span className="text-[#888888]">{flow.timestamp || 'N/A'}</span>
          </div>
          <div>
            <span className="text-[#888888] block text-[10px]">PROTO / DURATION:</span>
            <span className="text-[#888888]">
              {flow.protocol || 'IP'} &bull; {flow.duration_us?.toLocaleString() || 0} µs
            </span>
          </div>
          <div>
            <span className="text-[#888888] block text-[10px]">PACKETS / BYTES:</span>
            <span className="text-[#888888]">
              {flow.packet_count || 0} pkts &bull; {flow.byte_count?.toLocaleString() || 0} bytes
            </span>
          </div>
          <div>
            <span className="text-[#888888] block text-[10px]">PREDICTION CONFIDENCE:</span>
            <span className={flow.is_attack ? 'text-red-400 font-bold' : 'text-[#00c853] font-bold'}>
              {flow.confidence !== null && flow.confidence !== undefined
                ? `${(flow.confidence * 100).toFixed(2)}%`
                : 'Rule Override (PSD)'}
            </span>
          </div>
        </div>

        {/* Class Probability Distribution */}
        {sortedProbabilities.length > 0 && (
          <div>
            <h4 className="text-[11px] font-bold text-[#888888] uppercase tracking-wider mb-1.5">
              [ MODEL PROBABILITY MATRIX ]
            </h4>
            <div className="space-y-1.5 bg-[#0a0a0a] border border-[#2a2a2a] p-2.5">
              {sortedProbabilities.map(([cls, prob]) => {
                const isSelected = cls === flow.label;
                const percent = (prob * 100).toFixed(2);

                return (
                  <div key={cls} className="text-xs">
                    <div className="flex justify-between text-xs mb-0.5">
                      <span className={isSelected ? 'text-[#ffffff] font-bold' : 'text-[#888888]'}>
                        {cls}
                      </span>
                      <span className={isSelected ? (flow.is_attack ? 'text-red-400 font-bold' : 'text-[#00c853] font-bold') : 'text-[#888888]'}>
                        {percent}%
                      </span>
                    </div>
                    <div className="w-full bg-[#1a1a1a] border border-[#2a2a2a] h-1.5 overflow-hidden">
                      <div
                        className={`h-full ${
                          isSelected ? (flow.is_attack ? 'bg-red-500' : 'bg-[#00c853]') : 'bg-[#2a2a2a]'
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
        <div className="mt-4 flex justify-end">
          <button
            onClick={onClose}
            className="px-3 py-1 border border-[#2a2a2a] bg-[#0a0a0a] hover:border-[#00c853] hover:text-[#00c853] text-[#ffffff] transition text-xs"
          >
            [ CLOSE DIALOG ]
          </button>
        </div>
      </div>
    </div>
  );
}

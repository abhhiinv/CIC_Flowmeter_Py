import React from 'react';

export default function CriticalBanner({ alert, onDismiss }) {
  if (!alert) return null;

  return (
    <div className="bg-gradient-to-r from-red-950 via-red-900 to-red-950 border-b border-red-500/80 px-6 py-2.5 flex items-center justify-between text-xs font-mono shadow-lg flash-critical">
      <div className="flex items-center gap-3">
        <span className="w-3 h-3 rounded-full bg-red-500 animate-ping" />
        <span className="px-2 py-0.5 rounded bg-red-600 font-bold text-white uppercase tracking-wider">
          CRITICAL THREAT DETECTED
        </span>
        <span className="text-red-200">
          <strong>{alert.label}</strong> ({alert.src_ip}:{alert.src_port} &rarr; {alert.dst_ip}:{alert.dst_port})
        </span>
        {alert.confidence !== null && alert.confidence !== undefined && (
          <span className="text-red-300 bg-red-900/60 px-2 py-0.5 rounded">
            Confidence: {(alert.confidence * 100).toFixed(1)}%
          </span>
        )}
      </div>
      <button
        onClick={onDismiss}
        className="text-red-400 hover:text-white px-2 py-1 rounded bg-black/40 hover:bg-black/60 transition"
      >
        Dismiss
      </button>
    </div>
  );
}

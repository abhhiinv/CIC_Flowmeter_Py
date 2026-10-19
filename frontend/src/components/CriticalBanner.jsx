import React from 'react';

export default function CriticalBanner({ alert, onDismiss }) {
  if (!alert) return null;

  return (
    <div className="bg-[#1a1a1a] border-y border-red-500 px-4 py-2 flex flex-wrap items-center justify-between gap-2 text-xs font-mono flash-critical">
      <div className="flex flex-wrap items-center gap-2.5">
        <span className="px-1.5 py-0.5 bg-red-600 text-black font-bold uppercase tracking-wider text-[11px]">
          [! CRITICAL]
        </span>
        <span className="text-[#ffffff]">
          <strong className="text-red-400">{alert.label}</strong> ({alert.src_ip}:{alert.src_port} &rarr; {alert.dst_ip}:{alert.dst_port})
        </span>
        {alert.confidence !== null && alert.confidence !== undefined && (
          <span className="text-red-400 border border-red-500/40 bg-[#0a0a0a] px-1.5 py-0.5 text-[11px]">
            CONF: {(alert.confidence * 100).toFixed(1)}%
          </span>
        )}
      </div>
      <button
        onClick={onDismiss}
        className="text-red-400 border border-red-500/40 bg-[#0a0a0a] hover:bg-red-500 hover:text-black px-2 py-0.5 transition uppercase text-xs"
      >
        [ DISMISS ]
      </button>
    </div>
  );
}

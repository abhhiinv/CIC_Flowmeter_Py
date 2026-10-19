import React from 'react';

export default function Header({
  connected,
  interfaceName,
  soundEnabled,
  onToggleSound,
  isPaused,
  onTogglePause,
  onResetStats,
}) {
  return (
    <header className="border-b border-[#2a2a2a] bg-[#0a0a0a] sticky top-0 z-40 px-4 py-2.5 flex flex-wrap items-center justify-between gap-3 text-xs font-mono">
      {/* Left: Branding & Status */}
      <div className="flex flex-wrap items-center gap-3">
        {/* Terminal Bracket Badge & Title */}
        <div className="flex items-center gap-2">
          <span className="px-1.5 py-0.5 border border-[#00c853] text-[#00c853] bg-[#1a1a1a] font-bold tracking-wider text-[11px]">
            IDS
          </span>
          <h1 className="text-sm font-bold tracking-wider text-[#ffffff] uppercase flex items-center gap-2">
            CICFlowMeter
            <span className="text-[#888888] font-normal text-xs">
              // LIVE STREAM
            </span>
          </h1>
        </div>

        <span className="text-[#2a2a2a] hidden sm:inline">|</span>

        {/* Status indicator */}
        <div className="flex items-center gap-2">
          <span
            className={`inline-flex items-center gap-1.5 px-2 py-0.5 border text-xs font-bold tracking-wide bg-[#1a1a1a] ${
              connected
                ? 'border-[#00c853]/40 text-[#00c853]'
                : 'border-red-500/40 text-red-400'
            }`}
          >
            <span
              className={`w-1.5 h-1.5 ${
                connected ? 'bg-[#00c853] animate-pulse' : 'bg-red-500'
              }`}
            />
            {connected ? '[ LIVE ]' : '[ DISCONNECTED ]'}
          </span>

          {interfaceName && (
            <span className="px-2 py-0.5 border border-[#2a2a2a] bg-[#1a1a1a] text-[#888888] text-xs">
              IF: <span className="text-[#ffffff]">{interfaceName}</span>
            </span>
          )}
        </div>
      </div>

      {/* Right: Controls */}
      <div className="flex items-center gap-2">
        {/* Audio Toggle */}
        <button
          onClick={onToggleSound}
          className={`px-2.5 py-1 border transition flex items-center gap-1.5 bg-[#1a1a1a] ${
            soundEnabled
              ? 'border-[#00c853]/50 text-[#00c853] hover:border-[#00c853]'
              : 'border-[#2a2a2a] text-[#888888] hover:border-[#888888] hover:text-[#ffffff]'
          }`}
          title={soundEnabled ? 'Alert Audio ON' : 'Alert Audio Muted'}
        >
          <span>{soundEnabled ? '[ AUDIO: ON ]' : '[ AUDIO: MUTED ]'}</span>
        </button>

        {/* Pause / Resume Feed */}
        <button
          onClick={onTogglePause}
          className={`px-2.5 py-1 border transition flex items-center gap-1.5 bg-[#1a1a1a] ${
            isPaused
              ? 'border-yellow-500 text-yellow-400'
              : 'border-[#2a2a2a] text-[#ffffff] hover:border-[#00c853] hover:text-[#00c853]'
          }`}
        >
          <span>{isPaused ? '[ ▶ RESUME ]' : '[ || PAUSE ]'}</span>
        </button>

        {/* Reset Stats */}
        <button
          onClick={onResetStats}
          className="px-2.5 py-1 border border-[#2a2a2a] bg-[#1a1a1a] text-[#888888] hover:border-red-500 hover:text-red-400 transition"
          title="Clear current stream statistics and buffers"
        >
          [ RESET STATS ]
        </button>
      </div>
    </header>
  );
}

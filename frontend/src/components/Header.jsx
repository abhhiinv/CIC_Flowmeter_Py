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
    <header className="border-b border-soc-700 bg-soc-900/90 backdrop-blur sticky top-0 z-40 px-6 py-3.5 flex flex-wrap items-center justify-between gap-4">
      {/* Left: Branding & Status */}
      <div className="flex items-center gap-4">
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-gradient-to-tr from-rose-600 via-orange-500 to-amber-400 flex items-center justify-center font-bold text-black shadow-lg shadow-rose-900/40">
            <svg
              width="20"
              height="20"
              className="w-5 h-5 text-black"
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2.5}
                d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"
              />
            </svg>
          </div>
          <div>
            <h1 className="text-lg font-bold tracking-tight text-white flex items-center gap-2">
              CICFlowMeter{' '}
              <span className="text-xs px-2 py-0.5 rounded font-mono bg-soc-800 text-rose-400 border border-rose-500/20">
                LIVE IDS
              </span>
            </h1>
            <p className="text-xs text-slate-400">Ensemble ML & State-Aware Port Scan Detection</p>
          </div>
        </div>

        {/* Status pill & Interface */}
        <div className="flex items-center gap-2 pl-4 border-l border-soc-700">
          <span
            className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-mono font-medium ${
              connected
                ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                : 'bg-red-500/10 text-red-400 border border-red-500/30'
            }`}
          >
            <span
              className={`w-2 h-2 rounded-full ${
                connected ? 'bg-emerald-400 animate-pulse' : 'bg-red-500'
              }`}
            />
            {connected ? 'LIVE WEBSOCKET' : 'CONNECTING...'}
          </span>
          {interfaceName && (
            <span className="text-xs font-mono px-2 py-1 bg-soc-800 text-slate-300 rounded border border-soc-700">
              IF: {interfaceName}
            </span>
          )}
        </div>
      </div>

      {/* Right: Actions */}
      <div className="flex items-center gap-3">
        {/* Sound toggle */}
        <button
          onClick={onToggleSound}
          className={`p-2 rounded-lg border text-xs font-medium flex items-center gap-1.5 transition ${
            soundEnabled
              ? 'bg-soc-800 border-soc-600 text-amber-400 hover:bg-soc-700'
              : 'bg-soc-900 border-soc-800 text-slate-500 hover:bg-soc-800'
          }`}
          title={soundEnabled ? 'Alert Audio ON' : 'Alert Audio Muted'}
        >
          {soundEnabled ? (
            <>
              <svg
                width="16"
                height="16"
                className="w-4 h-4 text-amber-400"
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M15.536 8.464a5 5 0 010 7.072m2.828-9.9a9 9 0 010 12.728M5.586 15H4a1 1 0 01-1-1v-4a1 1 0 011-1h1.586l4.707-4.707C10.923 3.663 12 4.109 12 5v14c0 .891-1.077 1.337-1.707.707L5.586 15z"
                />
              </svg>
              <span>Sound ON</span>
            </>
          ) : (
            <>
              <svg
                width="16"
                height="16"
                className="w-4 h-4"
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M5.586 15H4a1 1 0 01-1-1v-4a1 1 0 011-1h1.586l4.707-4.707C10.923 3.663 12 4.109 12 5v14c0 .891-1.077 1.337-1.707.707L5.586 15z"
                />
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M17 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2"
                />
              </svg>
              <span>Muted</span>
            </>
          )}
        </button>

        {/* Pause / Resume feed */}
        <button
          onClick={onTogglePause}
          className={`px-3 py-1.5 rounded-lg border text-xs font-medium flex items-center gap-1.5 transition ${
            isPaused
              ? 'bg-amber-500/20 border-amber-500 text-amber-300'
              : 'bg-soc-800 border-soc-700 text-slate-300 hover:bg-soc-700'
          }`}
        >
          {isPaused ? (
            <>
              <svg
                width="14"
                height="14"
                className="w-3.5 h-3.5 text-amber-400"
                fill="currentColor"
                viewBox="0 0 20 20"
              >
                <path
                  fillRule="evenodd"
                  d="M10 18a8 8 0 100-16 8 8 0 000 16zM9.555 7.168A1 1 0 008 8v4a1 1 0 001.555.832l3-2a1 1 0 000-1.664l-3-2z"
                  clipRule="evenodd"
                />
              </svg>
              <span>RESUME FEED</span>
            </>
          ) : (
            <>
              <svg
                width="14"
                height="14"
                className="w-3.5 h-3.5"
                fill="currentColor"
                viewBox="0 0 20 20"
              >
                <path
                  fillRule="evenodd"
                  d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zM7 8a1 1 0 012 0v4a1 1 0 11-2 0V8zm5-1a1 1 0 00-1 1v4a1 1 0 102 0V8a1 1 0 00-1-1z"
                  clipRule="evenodd"
                />
              </svg>
              <span>PAUSE FEED</span>
            </>
          )}
        </button>

        {/* Reset stats button */}
        <button
          onClick={onResetStats}
          className="px-3 py-1.5 rounded-lg border border-soc-700 bg-soc-800 text-xs font-medium text-slate-300 hover:bg-rose-950/40 hover:border-rose-700/50 hover:text-rose-300 transition"
          title="Clear current stream statistics and buffers"
        >
          Reset Stats
        </button>
      </div>
    </header>
  );
}

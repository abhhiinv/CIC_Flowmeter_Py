export const SEVERITY_CONFIG = {
  Critical: {
    label: 'CRITICAL',
    color: '#EF4444',
    textClass: 'text-red-400',
    bgBadge: 'bg-red-500/10 text-red-400 border border-red-500/40',
    bannerBg: 'bg-red-950/60 border-red-600/80',
    dotClass: 'bg-red-500 shadow-[0_0_8px_#ef4444]',
    rowBorder: 'border-l-4 border-l-red-500',
  },
  High: {
    label: 'HIGH',
    color: '#F97316',
    textClass: 'text-orange-400',
    bgBadge: 'bg-orange-500/10 text-orange-400 border border-orange-500/40',
    bannerBg: 'bg-orange-950/60 border-orange-600/80',
    dotClass: 'bg-orange-500 shadow-[0_0_8px_#f97316]',
    rowBorder: 'border-l-4 border-l-orange-500',
  },
  Medium: {
    label: 'MEDIUM',
    color: '#EAB308',
    textClass: 'text-yellow-400',
    bgBadge: 'bg-yellow-500/10 text-yellow-400 border border-yellow-500/40',
    bannerBg: 'bg-yellow-950/60 border-yellow-600/80',
    dotClass: 'bg-yellow-500 shadow-[0_0_8px_#eab308]',
    rowBorder: 'border-l-4 border-l-yellow-500',
  },
  Normal: {
    label: 'NORMAL',
    color: '#10B981',
    textClass: 'text-emerald-400',
    bgBadge: 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30',
    bannerBg: 'bg-emerald-950/40 border-emerald-600/50',
    dotClass: 'bg-emerald-500 shadow-[0_0_8px_#10b981]',
    rowBorder: 'border-l-4 border-l-emerald-500',
  },
};

/**
 * Web Audio API synthesizer for alert beeps.
 * Critical: sawtooth (880Hz -> 659Hz -> 880Hz)
 * High: triangle (587Hz -> 440Hz)
 */
export const playAlertSound = (severity) => {
  try {
    const AudioContextClass = window.AudioContext || window.webkitAudioContext;
    if (!AudioContextClass) return;

    const audioCtx = new AudioContextClass();
    const osc = audioCtx.createOscillator();
    const gain = audioCtx.createGain();
    osc.connect(gain);
    gain.connect(audioCtx.destination);

    if (severity === 'Critical') {
      osc.type = 'sawtooth';
      osc.frequency.setValueAtTime(880, audioCtx.currentTime);
      osc.frequency.setValueAtTime(659, audioCtx.currentTime + 0.15);
      osc.frequency.setValueAtTime(880, audioCtx.currentTime + 0.3);
      gain.gain.setValueAtTime(0.12, audioCtx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.001, audioCtx.currentTime + 0.45);
      osc.start();
      osc.stop(audioCtx.currentTime + 0.45);
    } else if (severity === 'High') {
      osc.type = 'triangle';
      osc.frequency.setValueAtTime(587, audioCtx.currentTime);
      osc.frequency.setValueAtTime(440, audioCtx.currentTime + 0.15);
      gain.gain.setValueAtTime(0.08, audioCtx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.001, audioCtx.currentTime + 0.35);
      osc.start();
      osc.stop(audioCtx.currentTime + 0.35);
    }
  } catch (err) {
    // Silently handle autoplay / policy restrictions
  }
};

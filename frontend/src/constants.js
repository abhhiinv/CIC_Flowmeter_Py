export const SEVERITY_CONFIG = {
  Critical: {
    label: 'CRITICAL',
    color: '#EF4444',
    textClass: 'text-red-400',
    bgBadge: 'bg-red-950/40 text-red-400 border border-red-500/60',
    bannerBg: 'bg-[#1a1a1a] border-red-500/80',
    dotClass: 'bg-red-500',
    rowBorder: 'border-l-2 border-l-red-500',
  },
  High: {
    label: 'HIGH',
    color: '#F97316',
    textClass: 'text-orange-400',
    bgBadge: 'bg-orange-950/40 text-orange-400 border border-orange-500/60',
    bannerBg: 'bg-[#1a1a1a] border-orange-500/80',
    dotClass: 'bg-orange-500',
    rowBorder: 'border-l-2 border-l-orange-500',
  },
  Medium: {
    label: 'MEDIUM',
    color: '#EAB308',
    textClass: 'text-yellow-400',
    bgBadge: 'bg-yellow-950/40 text-yellow-400 border border-yellow-500/60',
    bannerBg: 'bg-[#1a1a1a] border-yellow-500/80',
    dotClass: 'bg-yellow-500',
    rowBorder: 'border-l-2 border-l-yellow-500',
  },
  Normal: {
    label: 'NORMAL',
    color: '#00c853',
    textClass: 'text-[#00c853]',
    bgBadge: 'bg-[#00c853]/10 text-[#00c853] border border-[#00c853]/40',
    bannerBg: 'bg-[#1a1a1a] border-[#00c853]/50',
    dotClass: 'bg-[#00c853]',
    rowBorder: 'border-l-2 border-l-[#00c853]',
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

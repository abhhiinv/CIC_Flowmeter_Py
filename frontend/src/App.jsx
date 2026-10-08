import React, { useState } from 'react';
import { useWebSocket } from './hooks/useWebSocket';
import Header from './components/Header';
import CriticalBanner from './components/CriticalBanner';
import StatCards from './components/StatCards';
import AlertFeed from './components/AlertFeed';
import SeverityPanel from './components/SeverityPanel';
import FlowTable from './components/FlowTable';
import FlowModal from './components/FlowModal';

export default function App() {
  const [isPaused, setIsPaused] = useState(false);
  const [soundEnabled, setSoundEnabled] = useState(true);
  const [selectedFlow, setSelectedFlow] = useState(null);

  const {
    connected,
    flows,
    alerts,
    stats,
    lastCriticalAlert,
    clearLastCritical,
  } = useWebSocket({ isPaused, soundEnabled });

  const handleResetStats = async () => {
    try {
      await fetch('/api/clear', { method: 'POST' });
    } catch (err) {
      console.error('Failed to reset statistics:', err);
    }
  };

  return (
    <div className="flex flex-col min-h-screen bg-soc-950 text-slate-100">
      {/* 1. Header */}
      <Header
        connected={connected}
        interfaceName={stats?.interface}
        soundEnabled={soundEnabled}
        onToggleSound={() => setSoundEnabled((prev) => !prev)}
        isPaused={isPaused}
        onTogglePause={() => setIsPaused((prev) => !prev)}
        onResetStats={handleResetStats}
      />

      {/* 2. Dismissible Critical Alert Flash Banner */}
      <CriticalBanner
        alert={lastCriticalAlert}
        onDismiss={clearLastCritical}
      />

      {/* Main Content Dashboard */}
      <main className="flex-1 p-6 space-y-6 max-w-[1700px] w-full mx-auto">
        {/* 3. Stat Cards */}
        <StatCards stats={stats} />

        {/* 4. Two-Column Threat Section */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Left: Recent Attack Alert Feed (2/3 width) */}
          <div className="lg:col-span-2">
            <AlertFeed alerts={alerts} onSelectFlow={setSelectedFlow} />
          </div>

          {/* Right: Severity Hierarchy & Top Sources (1/3 width) */}
          <div className="lg:col-span-1">
            <SeverityPanel stats={stats} />
          </div>
        </div>

        {/* 5. Full-Width Live Flow Stream Table */}
        <FlowTable flows={flows} onSelectFlow={setSelectedFlow} />
      </main>

      {/* 6. Flow Detail Modal */}
      <FlowModal
        flow={selectedFlow}
        onClose={() => setSelectedFlow(null)}
      />
    </div>
  );
}

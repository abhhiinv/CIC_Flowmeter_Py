import React, { useState, useMemo } from 'react';
import { SEVERITY_CONFIG } from '../constants';

export default function FlowTable({ flows, onSelectFlow }) {
  const [filterSeverity, setFilterSeverity] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');

  const filteredFlows = useMemo(() => {
    return flows.filter((flow) => {
      if (filterSeverity === 'ATTACKS_ONLY' && !flow.is_attack) return false;
      if (filterSeverity === 'CRITICAL' && flow.severity !== 'Critical') return false;
      if (filterSeverity === 'HIGH' && flow.severity !== 'High') return false;
      if (filterSeverity === 'MEDIUM' && flow.severity !== 'Medium') return false;
      if (filterSeverity === 'NORMAL' && flow.severity !== 'Normal') return false;

      if (searchQuery.trim()) {
        const query = searchQuery.toLowerCase();
        const matchIp =
          (flow.src_ip || '').toLowerCase().includes(query) ||
          (flow.dst_ip || '').toLowerCase().includes(query);
        const matchPort =
          String(flow.src_port || '').includes(query) ||
          String(flow.dst_port || '').includes(query);
        const matchLabel = (flow.label || '').toLowerCase().includes(query);
        return matchIp || matchPort || matchLabel;
      }
      return true;
    });
  }, [flows, filterSeverity, searchQuery]);

  const formatDuration = (us) => {
    if (us === undefined || us === null) return '0 µs';
    if (us >= 1000000) {
      return `${(us / 1000000).toFixed(2)}s`;
    }
    return `${Math.round(us).toLocaleString()} µs`;
  };

  return (
    <div className="bg-[#1a1a1a] border border-[#2a2a2a] flex flex-col font-mono text-xs">
      {/* Table Toolbar */}
      <div className="p-3 border-b border-[#2a2a2a] flex flex-wrap items-center justify-between gap-3 bg-[#151515]">
        <div className="flex items-center gap-2.5">
          <h2 className="text-xs font-bold tracking-wider text-[#ffffff] uppercase">
            [ LIVE FLOW STREAM ]
          </h2>
          <span className="text-[11px] text-[#888888]">
            BUFFER: <span className="text-[#ffffff]">{filteredFlows.length}</span> / {flows.length}
          </span>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {/* Filter tabs */}
          <div className="flex bg-[#0a0a0a] border border-[#2a2a2a] text-xs">
            {[
              { id: 'ALL', label: 'ALL' },
              { id: 'ATTACKS_ONLY', label: 'ATTACKS ONLY' },
              { id: 'CRITICAL', label: 'CRITICAL' },
              { id: 'HIGH', label: 'HIGH' },
              { id: 'MEDIUM', label: 'MEDIUM' },
              { id: 'NORMAL', label: 'NORMAL' },
            ].map((tab) => (
              <button
                key={tab.id}
                onClick={() => setFilterSeverity(tab.id)}
                className={`px-2 py-1 transition text-xs border-r border-[#2a2a2a] last:border-r-0 ${
                  filterSeverity === tab.id
                    ? 'bg-[#2a2a2a] text-[#ffffff] font-bold'
                    : 'text-[#888888] hover:text-[#ffffff]'
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>

          {/* Search box */}
          <div className="relative">
            <input
              type="text"
              placeholder="> filter IP / port / attack..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="bg-[#0a0a0a] border border-[#2a2a2a] text-[#ffffff] text-xs px-2.5 py-1 focus:outline-none focus:border-[#00c853] placeholder:text-[#888888] w-56"
            />
          </div>
        </div>
      </div>

      {/* Table Content */}
      <div className="overflow-x-auto max-h-[520px]">
        <table className="w-full text-left border-collapse text-xs">
          <thead>
            <tr className="bg-[#0a0a0a] border-b border-[#2a2a2a] text-[#888888] uppercase text-[10px] tracking-wider sticky top-0 z-20">
              <th className="py-2 px-3 font-bold border-r border-[#2a2a2a]/40">#</th>
              <th className="py-2 px-3 font-bold border-r border-[#2a2a2a]/40">TIME</th>
              <th className="py-2 px-3 font-bold border-r border-[#2a2a2a]/40">SOURCE</th>
              <th className="py-2 px-3 font-bold border-r border-[#2a2a2a]/40">DESTINATION</th>
              <th className="py-2 px-3 font-bold border-r border-[#2a2a2a]/40">PROTO</th>
              <th className="py-2 px-3 font-bold border-r border-[#2a2a2a]/40">PKTS</th>
              <th className="py-2 px-3 font-bold border-r border-[#2a2a2a]/40">DURATION</th>
              <th className="py-2 px-3 font-bold border-r border-[#2a2a2a]/40">CLASSIFICATION</th>
              <th className="py-2 px-3 font-bold border-r border-[#2a2a2a]/40">SEVERITY</th>
              <th className="py-2 px-3 font-bold">CONF</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#2a2a2a]/60">
            {filteredFlows.length === 0 ? (
              <tr>
                <td colSpan="10" className="py-10 text-center text-[#888888] text-xs">
                  [ -- NO MATCHING FLOWS BUFFERED -- ]
                </td>
              </tr>
            ) : (
              filteredFlows.map((flow) => {
                const cfg = SEVERITY_CONFIG[flow.severity] || SEVERITY_CONFIG.Normal;
                const timeStr = flow.timestamp ? (flow.timestamp.split(' ')[1] || flow.timestamp) : '--:--:--';

                return (
                  <tr
                    key={`flow-${flow.id}-${flow.epoch || flow.timestamp}`}
                    onClick={() => onSelectFlow(flow)}
                    className={`hover:bg-[#151515] transition cursor-pointer ${
                      flow.severity === 'Critical' ? 'bg-red-950/20' : ''
                    }`}
                  >
                    <td className="py-1.5 px-3 text-[#888888] font-bold border-r border-[#2a2a2a]/30">#{flow.id}</td>
                    <td className="py-1.5 px-3 text-[#888888] border-r border-[#2a2a2a]/30">{timeStr}</td>
                    <td className="py-1.5 px-3 text-[#ffffff] border-r border-[#2a2a2a]/30">
                      {flow.src_ip}:{flow.src_port}
                    </td>
                    <td className="py-1.5 px-3 text-[#ffffff] border-r border-[#2a2a2a]/30">
                      {flow.dst_ip}:{flow.dst_port}
                    </td>
                    <td className="py-1.5 px-3 text-[#888888] uppercase border-r border-[#2a2a2a]/30">{flow.protocol}</td>
                    <td className="py-1.5 px-3 text-[#ffffff] border-r border-[#2a2a2a]/30">{flow.packet_count}</td>
                    <td className="py-1.5 px-3 text-[#888888] border-r border-[#2a2a2a]/30">
                      {formatDuration(flow.duration_us)}
                    </td>
                    <td className="py-1.5 px-3 border-r border-[#2a2a2a]/30">
                      <span className={`font-bold ${cfg.textClass}`}>{flow.label}</span>
                    </td>
                    <td className="py-1.5 px-3 border-r border-[#2a2a2a]/30">
                      <span className={`px-1.5 py-0.2 text-[10px] font-bold tracking-wider ${cfg.bgBadge}`}>
                        [{cfg.label}]
                      </span>
                    </td>
                    <td className="py-1.5 px-3 text-[#888888]">
                      {flow.confidence !== null && flow.confidence !== undefined ? (
                        `${(flow.confidence * 100).toFixed(1)}%`
                      ) : (
                        <span>-</span>
                      )}
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

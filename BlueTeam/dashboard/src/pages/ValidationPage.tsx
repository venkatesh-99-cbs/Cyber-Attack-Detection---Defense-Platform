import React, { useEffect, useState } from 'react';
import { Cpu, Play, Clock } from 'lucide-react';
import { apiService } from '../services/api';
import { ValidationRecord, ReplayTimelineEvent } from '../types/validation';

export const ValidationPage: React.FC = () => {
  const [validations, setValidations] = useState<ValidationRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedValidation, setSelectedValidation] = useState<ValidationRecord | null>(null);
  const [replayTimeline, setReplayTimeline] = useState<ReplayTimelineEvent[] | null>(null);

  useEffect(() => {
    loadValidations();
  }, []);

  const loadValidations = async () => {
    setLoading(true);
    try {
      const data = await apiService.fetchValidations();
      setValidations(data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleReplay = async (val: ValidationRecord) => {
    setSelectedValidation(val);
    setReplayTimeline(null);
    try {
      const data = await apiService.fetchReplay(val.validation_id);
      setReplayTimeline(data.timeline);
    } catch (err) {
      console.error(err);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="bg-soc-panel border border-sky-500/30 rounded-lg p-5 space-y-3 shadow-sm">
        <div className="flex items-center space-x-3">
          <div className="p-2.5 bg-slate-900 border border-slate-800 rounded text-sky-400">
            <Cpu className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <h2 className="text-sm font-bold font-mono text-slate-100 uppercase tracking-wider">
                Attack-to-Defense Validation & Replay Engine
              </h2>
            </div>
            <p className="text-xs text-soc-textMuted mt-1 font-sans">
              Automated evaluation of Blue Team detection efficacy against executed attacks, including chronological sequence replay.
            </p>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Validations List */}
        <div className="bg-soc-panel border border-soc-border rounded-lg p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-soc-border pb-3">
            <h3 className="text-xs font-bold font-mono text-slate-200 uppercase tracking-wider">
              Validation History
            </h3>
            <button 
              onClick={loadValidations}
              className="text-[10px] bg-slate-800 hover:bg-slate-700 px-2 py-1 rounded text-slate-300 font-mono transition-colors"
            >
              REFRESH
            </button>
          </div>

          {loading ? (
            <div className="text-center py-8 text-slate-500 text-xs font-mono">Loading records...</div>
          ) : validations.length === 0 ? (
            <div className="text-center py-8 text-slate-500 text-xs font-mono bg-slate-900/40 rounded border border-slate-800/50">
              No validation records available.
            </div>
          ) : (
            <div className="space-y-3 max-h-[600px] overflow-y-auto pr-1 custom-scrollbar">
              {validations.map((val) => (
                <div 
                  key={val.validation_id} 
                  className={`border rounded p-3 text-xs cursor-pointer transition-colors ${
                    selectedValidation?.validation_id === val.validation_id 
                      ? 'bg-slate-800 border-sky-500/50' 
                      : 'bg-soc-bg border-soc-border hover:border-slate-600'
                  }`}
                  onClick={() => handleReplay(val)}
                >
                  <div className="flex justify-between mb-2">
                    <span className="font-mono text-slate-300">{val.event_id}</span>
                    <span className={`font-mono font-bold ${val.overall_result === 'PASS' ? 'text-emerald-400' : 'text-rose-400'}`}>
                      {val.overall_result}
                    </span>
                  </div>
                  <div className="flex items-center space-x-4 text-soc-textMuted mb-2">
                    <span className="capitalize">{val.attack_type.replace('_', ' ')}</span>
                    <span>{new Date(val.created_at).toLocaleString()}</span>
                  </div>
                  <div className="grid grid-cols-5 gap-1 text-[10px] font-mono text-center">
                    {['detection', 'risk', 'alert', 'incident', 'response'].map((stage) => {
                      const passed = val.checks[stage as keyof typeof val.checks];
                      return (
                        <div key={stage} className={`p-1 rounded border ${passed ? 'bg-emerald-950/30 border-emerald-900/50 text-emerald-500' : 'bg-rose-950/30 border-rose-900/50 text-rose-500'}`} title={stage.toUpperCase()}>
                          {stage.charAt(0).toUpperCase()}
                        </div>
                      );
                    })}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Replay Viewer */}
        <div className="bg-soc-panel border border-soc-border rounded-lg p-5 flex flex-col">
          <h3 className="text-xs font-bold font-mono text-slate-200 uppercase tracking-wider border-b border-soc-border pb-3 mb-4 flex items-center space-x-2">
            <Play className="w-4 h-4 text-sky-400" />
            <span>Lifecycle Replay</span>
          </h3>

          {!selectedValidation ? (
            <div className="flex-1 flex items-center justify-center text-slate-500 text-xs font-mono">
              Select a validation record to view its chronological sequence.
            </div>
          ) : !replayTimeline ? (
            <div className="flex-1 flex items-center justify-center text-slate-500 text-xs font-mono">
              Loading timeline...
            </div>
          ) : (
            <div className="flex-1 overflow-y-auto space-y-4 pr-2 custom-scrollbar">
              <div className="bg-slate-900/60 p-3 rounded border border-slate-800 space-y-2 mb-4">
                <p className="text-xs text-slate-300 font-mono font-bold border-b border-slate-800 pb-2">Validation Summary</p>
                <ul className="text-[11px] text-slate-400 space-y-1 font-sans">
                  {selectedValidation.reasons.map((reason, idx) => (
                    <li key={idx} className="flex items-start space-x-2">
                      <span className="text-slate-600 mt-0.5">•</span>
                      <span>{reason}</span>
                    </li>
                  ))}
                </ul>
              </div>

              <div className="relative border-l border-slate-700 ml-3 space-y-6">
                {replayTimeline.map((item, idx) => (
                  <div key={idx} className="relative pl-6">
                    <div className="absolute -left-[5px] top-1.5 w-2.5 h-2.5 rounded-full bg-slate-800 border border-sky-500"></div>
                    <div className="bg-soc-bg border border-soc-border rounded p-3 space-y-1">
                      <div className="flex items-center justify-between">
                        <span className="text-[10px] font-bold font-mono text-sky-400 uppercase tracking-wider">{item.stage}</span>
                        <span className="text-[10px] text-slate-500 font-mono flex items-center">
                          <Clock className="w-3 h-3 mr-1" />
                          {new Date(item.timestamp).toLocaleTimeString()}
                        </span>
                      </div>
                      <div className="text-xs text-slate-300 font-mono">
                        <span className="text-emerald-400 font-bold">{item.status}</span>
                        {item.rule && <span className="ml-2 text-slate-400">Rule: {item.rule}</span>}
                        {item.score !== undefined && <span className="ml-2 text-slate-400">Score: {item.score}</span>}
                        {item.mode && <span className="ml-2 text-slate-400">Mode: {item.mode}</span>}
                        {item.detail && <span className="ml-2 text-slate-400">{item.detail}</span>}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};


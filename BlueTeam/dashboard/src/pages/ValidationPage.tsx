import React, { useEffect, useState } from 'react';
import {
  Cpu,
  Play,
  Clock,
  CheckCircle2,
  XCircle,
  ShieldCheck,
  Terminal,
  Activity,
  RefreshCw,
} from 'lucide-react';
import { apiService } from '../services/api';
import { ValidationRecord, ReplayTimelineEvent } from '../types/validation';

export const ValidationPage: React.FC = () => {
  const [validations, setValidations] = useState<ValidationRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedValidation, setSelectedValidation] = useState<ValidationRecord | null>(null);
  const [replayTimeline, setReplayTimeline] = useState<ReplayTimelineEvent[] | null>(null);
  const [loadingReplay, setLoadingReplay] = useState(false);

  useEffect(() => {
    loadValidations();
  }, []);

  const loadValidations = async () => {
    setLoading(true);
    try {
      const data = await apiService.fetchValidations();
      setValidations(data || []);
      // If there are validations and none selected, auto-select the first one for presentation
      if (data && data.length > 0 && !selectedValidation) {
        handleReplay(data[0]);
      }
    } catch (err) {
      console.warn('Failed to load validations:', err);
      setValidations([]);
    } finally {
      setLoading(false);
    }
  };

  const handleReplay = async (val: ValidationRecord) => {
    setSelectedValidation(val);
    setLoadingReplay(true);
    try {
      const data = await apiService.fetchReplay(val.validation_id);
      setReplayTimeline(data?.timeline || []);
    } catch (err) {
      console.warn('Failed to fetch replay timeline:', err);
      setReplayTimeline([]);
    } finally {
      setLoadingReplay(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Executive Header Banner */}
      <div className="bg-soc-panel border border-sky-500/30 rounded-lg p-5 space-y-3 shadow-sm">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-start space-x-3.5">
            <div className="p-2.5 bg-slate-900 border border-slate-800 rounded-lg text-sky-400 shrink-0 mt-0.5">
              <Cpu className="w-6 h-6" />
            </div>
            <div>
              <div className="flex flex-wrap items-center gap-2">
                <h2 className="text-base sm:text-lg font-bold font-mono text-slate-100 uppercase tracking-wider">
                  ATTACK-TO-DEFENSE VALIDATION & REPLAY ENGINE
                </h2>
                <span className="bg-sky-950 text-sky-300 text-[10px] font-mono px-2 py-0.5 rounded border border-sky-500/30 font-semibold">
                  CORE DIFFERENTIATOR
                </span>
                <span className="bg-slate-800 text-slate-300 text-[10px] font-mono px-2 py-0.5 rounded border border-slate-700">
                  READ-ONLY REPLAY
                </span>
              </div>
              <p className="text-xs text-soc-textMuted mt-1 font-sans max-w-3xl leading-relaxed">
                Validate expected security behavior against actual persisted lifecycle results.
              </p>
            </div>
          </div>

          <div className="flex items-center space-x-2 font-mono text-xs shrink-0">
            <button
              onClick={loadValidations}
              disabled={loading}
              className="flex items-center space-x-1.5 bg-soc-bg hover:bg-slate-800 text-slate-300 border border-soc-border px-3 py-1.5 rounded transition-colors disabled:opacity-50"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin text-sky-400' : ''}`} />
              <span>Refresh Records</span>
            </button>
          </div>
        </div>
      </div>

      {/* Main 2-Column Presentation Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Validation History (5 cols on lg) */}
        <div className="lg:col-span-5 bg-soc-panel border border-soc-border rounded-lg p-5 flex flex-col h-[760px]">
          <div className="flex items-center justify-between border-b border-soc-border pb-3 mb-3 select-none">
            <div className="flex items-center space-x-2">
              <ShieldCheck className="w-4 h-4 text-emerald-400" />
              <h3 className="text-xs font-bold font-mono text-slate-200 uppercase tracking-wider">
                Validation Records ({validations.length})
              </h3>
            </div>
            <span className="text-[10px] font-mono text-slate-400">
              Audit Efficacy Logs
            </span>
          </div>

          {loading ? (
            <div className="flex-1 flex flex-col items-center justify-center py-12 text-center text-xs font-mono text-slate-400 space-y-2">
              <RefreshCw className="w-5 h-5 animate-spin text-sky-400" />
              <span>Loading validation history from SQLite...</span>
            </div>
          ) : validations.length === 0 ? (
            <div className="flex-1 flex flex-col items-center justify-center py-12 px-4 text-center text-xs font-mono text-slate-400 space-y-2">
              <Cpu className="w-8 h-8 text-slate-600 mb-1" />
              <p className="text-slate-300 font-semibold">No validation records available.</p>
              <p className="text-slate-500 max-w-xs text-[11px] font-sans">
                Post an evaluation request to <code className="text-sky-400 font-mono">POST /validation</code> with an event ID to audit its attack-to-defense lifecycle.
              </p>
            </div>
          ) : (
            <div className="flex-1 overflow-y-auto space-y-3.5 pr-1.5 custom-scrollbar">
              {validations.map((val) => {
                const isSelected = selectedValidation?.validation_id === val.validation_id;
                const isPass = val.overall_result === 'PASS';

                return (
                  <div
                    key={val.validation_id}
                    onClick={() => handleReplay(val)}
                    className={`border rounded-lg p-4 cursor-pointer transition-all shadow-sm space-y-3 ${
                      isSelected
                        ? 'bg-slate-800/90 border-sky-500 shadow-md ring-1 ring-sky-500/30'
                        : 'bg-soc-card border-soc-border hover:border-slate-600 hover:bg-soc-hover/50'
                    }`}
                  >
                    {/* Record Header */}
                    <div className="flex items-center justify-between font-mono">
                      <div className="flex items-center space-x-2">
                        <span className="bg-slate-900 text-sky-300 px-2 py-0.5 rounded text-xs font-bold border border-slate-800">
                          {val.attack_type.replace('_', ' ').toUpperCase()}
                        </span>
                        <span className="text-xs text-slate-400">{val.event_id}</span>
                      </div>

                      {/* Prominent PASS / FAIL badge */}
                      <span
                        className={`inline-flex items-center space-x-1 px-2.5 py-0.5 rounded text-xs font-bold border ${
                          isPass
                            ? 'bg-emerald-950/80 text-emerald-400 border-emerald-500/40'
                            : 'bg-rose-950/80 text-rose-400 border-rose-500/40'
                        }`}
                      >
                        {isPass ? <CheckCircle2 className="w-3.5 h-3.5" /> : <XCircle className="w-3.5 h-3.5" />}
                        <span>{val.overall_result}</span>
                      </span>
                    </div>

                    {/* 5-Stage Match Checklist */}
                    <div className="space-y-1 bg-soc-bg/80 p-2.5 rounded border border-soc-borderMuted font-mono text-[11px]">
                      {(
                        [
                          { key: 'detection', label: 'DETECTION' },
                          { key: 'risk', label: 'RISK' },
                          { key: 'alert', label: 'ALERT' },
                          { key: 'incident', label: 'INCIDENT' },
                          { key: 'response', label: 'RESPONSE' },
                        ] as const
                      ).map(({ key, label }) => {
                        const matched = val.checks[key];
                        return (
                          <div key={key} className="flex items-center justify-between py-0.5">
                            <span className="text-slate-400">{label}</span>
                            <span
                              className={`flex items-center space-x-1 font-bold ${
                                matched ? 'text-emerald-400' : 'text-rose-400'
                              }`}
                            >
                              {matched ? (
                                <>
                                  <CheckCircle2 className="w-3 h-3" />
                                  <span>MATCH</span>
                                </>
                              ) : (
                                <>
                                  <XCircle className="w-3 h-3" />
                                  <span>MISMATCH</span>
                                </>
                              )}
                            </span>
                          </div>
                        );
                      })}
                    </div>

                    {/* Footer */}
                    <div className="flex items-center justify-between text-[10px] font-mono text-soc-textMuted pt-1">
                      <span>{new Date(val.created_at).toLocaleString()}</span>
                      <span className="text-sky-400 hover:underline flex items-center space-x-1">
                        <Play className="w-3 h-3" />
                        <span>Inspect Timeline →</span>
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Right Column: Reconstructed Lifecycle Replay (7 cols on lg) */}
        <div className="lg:col-span-7 bg-soc-panel border border-soc-border rounded-lg p-5 flex flex-col h-[760px]">
          {/* Header */}
          <div className="flex items-center justify-between border-b border-soc-border pb-3 mb-4 select-none">
            <div className="flex items-center space-x-2">
              <Play className="w-4 h-4 text-sky-400" />
              <h3 className="text-xs font-bold font-mono text-slate-200 uppercase tracking-wider">
                Lifecycle Replay Timeline
              </h3>
            </div>
            {selectedValidation && (
              <span className="text-xs font-mono text-slate-400">
                Event: <strong className="text-slate-200">{selectedValidation.event_id}</strong>
              </span>
            )}
          </div>

          {!selectedValidation ? (
            <div className="flex-1 flex flex-col items-center justify-center text-center p-8 text-slate-500 font-mono text-xs space-y-2">
              <Play className="w-10 h-10 text-slate-700" />
              <p className="text-slate-300 font-semibold">No Validation Selected</p>
              <p className="text-slate-500 max-w-sm text-[11px] font-sans">
                Select a validation audit from the left column to replay and evaluate the step-by-step security lifecycle.
              </p>
            </div>
          ) : loadingReplay ? (
            <div className="flex-1 flex flex-col items-center justify-center text-center p-8 text-slate-400 font-mono text-xs space-y-2">
              <RefreshCw className="w-6 h-6 animate-spin text-sky-400" />
              <span>Reconstructing lifecycle timeline from SQLite records...</span>
            </div>
          ) : (
            <div className="flex-1 overflow-y-auto space-y-4 pr-2 custom-scrollbar">
              {/* Validation Summary Briefing Box */}
              <div className="bg-soc-bg border border-soc-border rounded-lg p-4 space-y-2 font-mono">
                <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                  <div className="text-xs font-bold text-slate-200 uppercase tracking-wider">
                    Validation Audit Assessment
                  </div>
                  <span
                    className={`px-2 py-0.5 rounded text-xs font-bold border ${
                      selectedValidation.overall_result === 'PASS'
                        ? 'bg-emerald-950 text-emerald-400 border-emerald-500/40'
                        : 'bg-rose-950 text-rose-400 border-rose-500/40'
                    }`}
                  >
                    RESULT: {selectedValidation.overall_result}
                  </span>
                </div>

                <div className="space-y-1 pt-1">
                  <span className="text-[11px] text-sky-400 uppercase tracking-wider font-bold block">
                    EXPLAINABLE FINDINGS
                  </span>
                  <ul className="text-xs text-slate-300 space-y-1 font-sans">
                    {selectedValidation.reasons.map((reason, idx) => (
                      <li key={idx} className="flex items-start space-x-2">
                        <span className="text-sky-400 font-mono">•</span>
                        <span>{reason}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              </div>

              {/* Visual Pipeline Flow Sequence */}
              <div className="bg-soc-card/80 border border-soc-border rounded-lg p-3 select-none">
                <div className="text-[10px] font-mono text-slate-400 uppercase tracking-wider mb-2">
                  Lifecycle Sequence Progression:
                </div>
                <div className="flex flex-wrap items-center gap-1.5 text-[10px] font-mono text-slate-300">
                  <span className="bg-slate-900 border border-slate-700 px-2 py-1 rounded text-sky-400 font-bold">1. EVENT</span>
                  <span className="text-slate-600">→</span>
                  <span className="bg-slate-900 border border-slate-700 px-2 py-1 rounded text-sky-400 font-bold">2. DETECTION</span>
                  <span className="text-slate-600">→</span>
                  <span className="bg-slate-900 border border-slate-700 px-2 py-1 rounded text-amber-400 font-bold">3. RISK</span>
                  <span className="text-slate-600">→</span>
                  <span className="bg-slate-900 border border-slate-700 px-2 py-1 rounded text-amber-400 font-bold">4. ALERT</span>
                  <span className="text-slate-600">→</span>
                  <span className="bg-slate-900 border border-slate-700 px-2 py-1 rounded text-rose-400 font-bold">5. INCIDENT</span>
                  <span className="text-slate-600">→</span>
                  <span className="bg-slate-900 border border-slate-700 px-2 py-1 rounded text-indigo-400 font-bold">6. RESPONSE</span>
                  <span className="text-slate-600">→</span>
                  <span className="bg-slate-900 border border-slate-700 px-2 py-1 rounded text-emerald-400 font-bold">7. VALIDATION</span>
                </div>
              </div>

              {/* Vertical Chronological Replay Timeline */}
              <div className="relative border-l-2 border-slate-700 ml-4 space-y-6 pt-2 pb-4">
                {replayTimeline && replayTimeline.length > 0 ? (
                  replayTimeline.map((item, idx) => {
                    let stageColor = 'text-sky-400 border-sky-500';
                    let badgeBg = 'bg-sky-950/40 text-sky-400 border-sky-500/30';

                    if (item.stage === 'RISK' || item.stage === 'ALERT') {
                      stageColor = 'text-amber-400 border-amber-500';
                      badgeBg = 'bg-amber-950/40 text-amber-400 border-amber-500/30';
                    } else if (item.stage === 'INCIDENT') {
                      stageColor = 'text-rose-400 border-rose-500';
                      badgeBg = 'bg-rose-950/40 text-rose-400 border-rose-500/30';
                    } else if (item.stage === 'VALIDATION') {
                      stageColor = 'text-emerald-400 border-emerald-500';
                      badgeBg = 'bg-emerald-950/40 text-emerald-400 border-emerald-500/30';
                    }

                    return (
                      <div key={idx} className="relative pl-6">
                        {/* Timeline Node Icon */}
                        <div
                          className={`absolute -left-[9px] top-1.5 w-4 h-4 rounded-full bg-slate-900 border-2 ${stageColor} flex items-center justify-center`}
                        >
                          <span className="w-1.5 h-1.5 rounded-full bg-slate-200" />
                        </div>

                        {/* Stage Card */}
                        <div className="bg-soc-card border border-soc-border hover:border-slate-700 rounded-lg p-3.5 space-y-2 shadow-sm font-mono text-xs transition-colors">
                          <div className="flex items-center justify-between border-b border-soc-borderMuted pb-2">
                            <div className="flex items-center space-x-2">
                              <span className={`px-2 py-0.5 rounded text-[11px] font-bold border uppercase tracking-wider ${badgeBg}`}>
                                {item.stage}
                              </span>
                              <span className="text-slate-200 font-bold">{item.status}</span>
                            </div>

                            <span className="text-[11px] text-slate-400 flex items-center space-x-1">
                              <Clock className="w-3.5 h-3.5 text-slate-500" />
                              <span>{new Date(item.timestamp).toLocaleTimeString()}</span>
                            </span>
                          </div>

                          {/* Stage Details */}
                          <div className="space-y-1 text-slate-300 text-xs">
                            {item.rule && (
                              <div className="flex items-center space-x-1.5">
                                <Terminal className="w-3.5 h-3.5 text-sky-400 shrink-0" />
                                <span className="text-slate-400">Triggered Rule:</span>
                                <strong className="text-sky-300">{item.rule}</strong>
                              </div>
                            )}

                            {item.score !== undefined && (
                              <div className="flex items-center space-x-1.5">
                                <Activity className="w-3.5 h-3.5 text-amber-400 shrink-0" />
                                <span className="text-slate-400">Calculated Risk Score:</span>
                                <strong className="text-amber-300">{item.score}/100</strong>
                              </div>
                            )}

                            {item.mode && (
                              <div className="flex items-center space-x-1.5">
                                <span className="text-slate-400">Defensive Response Mode:</span>
                                <strong className="text-slate-200">{item.mode}</strong>
                              </div>
                            )}

                            {item.detail && (
                              <div className="text-slate-300 font-sans text-[11px] pt-1">
                                {item.detail}
                              </div>
                            )}

                            {item.validation_id && (
                              <div className="text-[11px] text-slate-400">
                                Audit Reference ID: <span className="text-slate-300 font-mono">{item.validation_id}</span>
                              </div>
                            )}
                          </div>
                        </div>
                      </div>
                    );
                  })
                ) : (
                  <div className="pl-6 text-xs text-slate-500 font-mono">
                    No replay timeline events recorded for this lifecycle.
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

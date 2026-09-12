"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import AttackGraph from "@/components/AttackGraph";
import {
  Host,
  SecurityEvent,
  Simulation,
  HostStatus,
  EventSeverity,
  ThreatScoreResponse,
  InvestigationData,
  InvestigationResponse,
  ResponseData,
  ResponseRunResponse,
  AttackGraphNode,
  AttackGraphEdge,
  AttackGraphResponse,
} from "@/types/simulation";

const SCENARIOS = [
  {
    id: "credential_compromise",
    name: "Credential Compromise",
    target: "server-01 (10.0.1.10)",
    totalEvents: 7,
    description: "Brute force login attempts leading to privilege escalation and sensitive shadow file access.",
    badge: "IDENTITY ATTACK",
  },
  {
    id: "ransomware",
    name: "Ransomware Simulation",
    target: "server-03 (10.0.1.12)",
    totalEvents: 7,
    description: "SSH breach leading to privilege escalation, server access, and mass file encryption on server-03.",
    badge: "MALWARE",
  },
  {
    id: "data_exfiltration",
    name: "Data Exfiltration",
    target: "database (10.0.2.10)",
    totalEvents: 4,
    description: "Off-hours DB login, sensitive PII table extraction, staging dump creation, and massive outbound transfer.",
    badge: "DATA LEAK",
  },
];

const DEFAULT_HOSTS: Host[] = [
  { id: "web-server", hostname: "web-server", ip_address: "10.0.0.10", host_type: "WEB", status: "HEALTHY", criticality: "HIGH" },
  { id: "server-01", hostname: "server-01", ip_address: "10.0.1.10", host_type: "APP", status: "HEALTHY", criticality: "MEDIUM" },
  { id: "server-02", hostname: "server-02", ip_address: "10.0.1.11", host_type: "APP", status: "HEALTHY", criticality: "MEDIUM" },
  { id: "server-03", hostname: "server-03", ip_address: "10.0.1.12", host_type: "APP", status: "HEALTHY", criticality: "HIGH" },
  { id: "database", hostname: "database", ip_address: "10.0.2.10", host_type: "DATABASE", status: "HEALTHY", criticality: "CRITICAL" },
];

export default function Dashboard() {
  const [selectedScenario, setSelectedScenario] = useState<string>("ransomware");
  const [simulation, setSimulation] = useState<Simulation | null>(null);
  const [hosts, setHosts] = useState<Host[]>(DEFAULT_HOSTS);
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [threat, setThreat] = useState<ThreatScoreResponse | null>(null);
  const [isCompleted, setIsCompleted] = useState<boolean>(false);
  const [loading, setLoading] = useState<boolean>(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [investigation, setInvestigation] = useState<InvestigationData | null>(null);
  const [investigating, setInvestigating] = useState<boolean>(false);
  const [responseResult, setResponseResult] = useState<ResponseData | null>(null);
  const [responding, setResponding] = useState<boolean>(false);
  const [attackGraphNodes, setAttackGraphNodes] = useState<AttackGraphNode[]>([]);
  const [attackGraphEdges, setAttackGraphEdges] = useState<AttackGraphEdge[]>([]);

  const currentScenarioObj = SCENARIOS.find((s) => s.id === (simulation?.scenario_id || selectedScenario));
  const maxTicks = currentScenarioObj ? currentScenarioObj.totalEvents : 7;

  // Fetch Attack Graph when simulation updates or advances
  useEffect(() => {
    if (!simulation) {
      setAttackGraphNodes([]);
      setAttackGraphEdges([]);
      return;
    }

    async function fetchAttackGraph() {
      try {
        const res = await fetch(`/api/simulation/attack-graph?simulation_id=${simulation!.id}`);
        if (res.ok) {
          const data: AttackGraphResponse = await res.json();
          setAttackGraphNodes(data.nodes || []);
          setAttackGraphEdges(data.edges || []);
        }
      } catch (err) {
        console.error("Failed to fetch attack graph:", err);
      }
    }

    fetchAttackGraph();
  }, [simulation?.id, events.length]);

  // Restore simulation state on page refresh
  useEffect(() => {
    async function restoreState() {
      const savedSimId = localStorage.getItem("sentinelgraph_sim_id");
      if (!savedSimId) return;

      try {
        const res = await fetch(`/api/simulation/state?simulation_id=${savedSimId}`);
        if (res.ok) {
          const data = await res.json();
          if (data.simulation) {
            setSimulation(data.simulation);
            setHosts(data.hosts || DEFAULT_HOSTS);
            setEvents(data.events || []);
            setThreat(data.threat || null);

            if (data.simulation.scenario_id) {
              setSelectedScenario(data.simulation.scenario_id);
            }

            const targetEventsCount = SCENARIOS.find((s) => s.id === data.simulation.scenario_id)?.totalEvents || 7;
            if (data.simulation.current_tick >= targetEventsCount) {
              setIsCompleted(true);
            }
          }
        } else {
          localStorage.removeItem("sentinelgraph_sim_id");
        }
      } catch (err) {
        console.error("Failed to restore simulation state:", err);
      }
    }

    restoreState();
  }, []);

  // 1. Start Simulation
  async function handleStartSimulation() {
    setLoading(true);
    setErrorMessage(null);
    console.log("[START SIMULATION]", selectedScenario);
    try {
      const res = await fetch("/api/simulation/start", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ scenario_id: selectedScenario }),
      });

      if (!res.ok) {
        const contentType = res.headers.get("content-type");
        if (contentType?.includes("application/json")) {
          const errorData = await res.json();
          throw new Error(errorData.detail || "Failed to start simulation.");
        }
        const errorText = await res.text();
        throw new Error(errorText || `Failed to start simulation (${res.status} ${res.statusText}).`);
      }

      const data = await res.json();
      setSimulation(data.simulation);
      setHosts(data.hosts || DEFAULT_HOSTS);
      setEvents(data.events || []);
      setThreat(data.threat || null);
      setIsCompleted(false);
      setInvestigation(null);
      setResponseResult(null);

      if (data.simulation?.id) {
        localStorage.setItem("sentinelgraph_sim_id", data.simulation.id);
      }
    } catch (err: any) {
      console.error("Start simulation error:", err);
      setErrorMessage(err.message || "Backend server unavailable.");
    } finally {
      setLoading(false);
    }
  }

  // 2. Advance Step
  async function handleStepSimulation() {
    if (!simulation) return;
    setLoading(true);
    setErrorMessage(null);

    try {
      const res = await fetch("/api/simulation/step", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ simulation_id: simulation.id }),
      });

      if (!res.ok) {
        const contentType = res.headers.get("content-type");
        if (contentType?.includes("application/json")) {
          const errorData = await res.json();
          throw new Error(errorData.detail || "Failed to advance step.");
        }
        const errorText = await res.text();
        throw new Error(errorText || `Failed to advance step (${res.status} ${res.statusText}).`);
      }

      const data = await res.json();
      if (data.simulation) {
        setSimulation(data.simulation);
      }
      if (data.hosts) {
        setHosts(data.hosts);
      }
      if (data.event) {
        setEvents((prev) => [...prev, data.event]);
      }
      if (data.threat) {
        setThreat(data.threat);
      }
      if (data.completed) {
        setIsCompleted(true);
      }
    } catch (err: any) {
      console.error("Step simulation error:", err);
      setErrorMessage(err.message || "Failed to advance step.");
    } finally {
      setLoading(false);
    }
  }

  // 3. Reset Simulation
  async function handleResetSimulation() {
    if (!simulation) return;
    setLoading(true);
    setErrorMessage(null);

    try {
      const res = await fetch("/api/simulation/reset", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ simulation_id: simulation.id }),
      });

      if (!res.ok) {
        const contentType = res.headers.get("content-type");
        if (contentType?.includes("application/json")) {
          const errorData = await res.json();
          throw new Error(errorData.detail || "Failed to reset simulation.");
        }
        const errorText = await res.text();
        throw new Error(errorText || `Failed to reset simulation (${res.status} ${res.statusText}).`);
      }

      // Reset state completely so user can pick any scenario
      setSimulation(null);
      localStorage.removeItem("sentinelgraph_sim_id");
      setHosts(DEFAULT_HOSTS);
      setEvents([]);
      setThreat(null);
      setIsCompleted(false);
      setInvestigation(null);
      setResponseResult(null);
    } catch (err: any) {
      console.error("Reset simulation error:", err);
      setErrorMessage(err.message || "Failed to reset simulation.");
    } finally {
      setLoading(false);
    }
  }

  // 4. Run AI Investigation
  async function handleRunInvestigation() {
    if (!simulation) return;
    setInvestigating(true);
    setErrorMessage(null);

    try {
      const res = await fetch("/api/investigation/run", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ simulation_id: simulation.id }),
      });

      if (!res.ok) {
        const contentType = res.headers.get("content-type");
        if (contentType?.includes("application/json")) {
          const errorData = await res.json();
          throw new Error(errorData.detail || "Failed to run AI investigation.");
        }
        const errorText = await res.text();
        throw new Error(errorText || `Failed to run AI investigation (${res.status}).`);
      }

      const data: InvestigationResponse = await res.json();
      setInvestigation(data.investigation);
    } catch (err: any) {
      console.error("AI Investigation error:", err);
      setErrorMessage(err.message || "Failed to run AI investigation.");
    } finally {
      setInvestigating(false);
    }
  }

  // 5. Run AI Defensive Response
  async function handleRunResponse() {
    if (!simulation) return;
    setResponding(true);
    setErrorMessage(null);

    try {
      const res = await fetch("/api/response/run", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ simulation_id: simulation.id }),
      });

      if (!res.ok) {
        const contentType = res.headers.get("content-type");
        if (contentType?.includes("application/json")) {
          const errorData = await res.json();
          throw new Error(errorData.detail || "Failed to run defensive response.");
        }
        const errorText = await res.text();
        throw new Error(errorText || `Failed to run defensive response (${res.status}).`);
      }

      const data: ResponseRunResponse = await res.json();
      if (data.investigation) {
        setInvestigation(data.investigation);
      }
      if (data.response) {
        setResponseResult(data.response);
      }
      if (data.hosts) {
        setHosts(data.hosts);
      }
    } catch (err: any) {
      console.error("Defensive response error:", err);
      setErrorMessage(err.message || "Failed to run defensive response.");
    } finally {
      setResponding(false);
    }
  }

  // Format event type string into clean title string (e.g. MASS_FILE_MODIFICATION -> Mass file modification)
  function formatEventTypeName(evtType: string): string {
    if (!evtType) return "Unknown Event";
    return evtType
      .split("_")
      .map((word, idx) => (idx === 0 ? word.charAt(0).toUpperCase() + word.slice(1).toLowerCase() : word.toLowerCase()))
      .join(" ");
  }

  // Helper Badge Colors
  function getHostStatusBadge(status: HostStatus) {
    switch (status) {
      case "HEALTHY":
        return <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full bg-emerald-950/80 border border-emerald-800 text-emerald-400 text-xs font-mono"><span className="w-2 h-2 rounded-full bg-emerald-400" />HEALTHY</span>;
      case "SUSPICIOUS":
        return <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full bg-amber-950/80 border border-amber-800 text-amber-400 text-xs font-mono"><span className="w-2 h-2 rounded-full bg-amber-400 animate-pulse" />SUSPICIOUS</span>;
      case "COMPROMISED":
        return <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full bg-rose-950/80 border border-rose-800 text-rose-400 text-xs font-mono font-bold"><span className="w-2 h-2 rounded-full bg-rose-500 animate-ping" />COMPROMISED</span>;
      case "ISOLATED":
        return <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full bg-sky-950/80 border border-sky-800 text-sky-400 text-xs font-mono"><span className="w-2 h-2 rounded-full bg-sky-400" />ISOLATED</span>;
      default:
        return <span className="text-xs font-mono text-slate-400">{status}</span>;
    }
  }

  function getSeverityBadge(severity: string) {
    switch (severity) {
      case "LOW":
        return <span className="text-xs px-2.5 py-1 rounded bg-slate-800 text-slate-300 font-mono font-bold">LOW</span>;
      case "MEDIUM":
        return <span className="text-xs px-2.5 py-1 rounded bg-amber-950 border border-amber-800 text-amber-300 font-mono font-bold">MEDIUM</span>;
      case "HIGH":
        return <span className="text-xs px-2.5 py-1 rounded bg-orange-950 border border-orange-800 text-orange-400 font-mono font-bold">HIGH</span>;
      case "CRITICAL":
        return <span className="text-xs px-2.5 py-1 rounded bg-rose-950 border border-rose-800 text-rose-400 font-bold font-mono animate-pulse">CRITICAL</span>;
      default:
        return <span className="text-xs px-2.5 py-1 rounded bg-slate-800 text-slate-400 font-mono">{severity}</span>;
    }
  }

  const currentScore = simulation ? simulation.threat_score : 0;
  const currentSeverity = simulation ? simulation.severity : "LOW";
  const factorsList = threat?.factors || [];

  return (
    <div className="min-h-screen bg-[#090d16] text-slate-200 font-sans flex flex-col">
      {/* HEADER */}
      <header className="border-b border-slate-800 bg-slate-900/90 backdrop-blur-md px-6 py-4 flex items-center justify-between sticky top-0 z-50">
        <div className="flex items-center gap-4">
          <Link
            href="/"
            className="text-xs font-mono text-cyan-400 hover:text-cyan-300 border border-cyan-800/60 px-3 py-1.5 rounded-md bg-cyan-950/50 transition-colors"
          >
            ← BACK TO LANDING
          </Link>
          <div className="h-4 w-px bg-slate-800" />
          <h1 className="text-xl font-extrabold font-mono tracking-tight text-white">
            SENTINEL<span className="text-cyan-400">GRAPH</span> <span className="text-xs text-slate-500 font-normal">SOC WORKSPACE</span>
          </h1>
        </div>

        <div className="flex items-center gap-3 font-mono text-xs">
          <span className="text-slate-400">SYSTEM STATUS:</span>
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-emerald-950 border border-emerald-800 text-emerald-400">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            ONLINE
          </span>
        </div>
      </header>

      {/* MAIN SOC CONTENT */}
      <main className="flex-1 p-6 max-w-7xl mx-auto w-full space-y-6">
        {/* Error Alert Banner */}
        {errorMessage && (
          <div className="bg-rose-950/80 border border-rose-800 text-rose-200 p-4 rounded-lg flex items-center justify-between font-mono text-sm">
            <span>⚠️ {errorMessage}</span>
            <button onClick={() => setErrorMessage(null)} className="text-rose-400 hover:text-white font-bold">✕</button>
          </div>
        )}

        {/* TOP SECTION: SCENARIO SELECTOR */}
        <section className="space-y-3">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-mono tracking-wider text-slate-400 uppercase font-semibold">
              Select Attack Scenario
            </h2>
            {simulation && (
              <span className="text-xs font-mono text-cyan-400">
                ACTIVE SIMULATION ID: <code className="bg-slate-900 px-2 py-0.5 rounded border border-slate-800">{simulation.id}</code>
              </span>
            )}
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {SCENARIOS.map((sc) => {
              const isSelected = selectedScenario === sc.id;
              const isSelectionDisabled = !!simulation && !isCompleted;

              return (
                <div
                  key={sc.id}
                  onClick={() => {
                    if (!isSelectionDisabled) {
                      setSelectedScenario(sc.id);
                    }
                  }}
                  className={`p-5 rounded-xl border transition-all relative flex flex-col justify-between ${
                    isSelected
                      ? "bg-cyan-950/40 border-cyan-500 glow-cyan"
                      : "bg-slate-900/50 border-slate-800/80 hover:border-slate-700 hover:bg-slate-900/80 opacity-75"
                  } ${isSelectionDisabled ? "cursor-not-allowed opacity-60" : "cursor-pointer"}`}
                >
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-[10px] font-mono tracking-widest px-2 py-0.5 rounded bg-slate-800 text-slate-400 uppercase">
                        {sc.badge}
                      </span>
                      <span className="text-xs font-mono text-slate-400">
                        {sc.totalEvents} Events
                      </span>
                    </div>

                    <h3 className="text-base font-bold font-mono text-white mb-1">
                      {sc.name}
                    </h3>
                    <p className="text-xs text-slate-400 mb-4 line-clamp-2">
                      {sc.description}
                    </p>
                  </div>

                  <div className="border-t border-slate-800/80 pt-3 flex items-center justify-between text-xs font-mono text-slate-400">
                    <span>Target: <strong className="text-slate-200">{sc.target.split(" ")[0]}</strong></span>
                    {isSelected && (
                      <span className="text-cyan-400 font-bold">SELECTED ✓</span>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </section>

        {/* CONTROLS AND CURRENT METRICS ROW */}
        <section className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {/* SIMULATION CONTROLS */}
          <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 backdrop-blur-md flex flex-col justify-between">
            <h3 className="text-xs font-mono text-slate-400 tracking-wider uppercase mb-4 font-semibold">
              Simulation Controls
            </h3>

            <div className="space-y-3">
              {!simulation ? (
                <button
                  onClick={handleStartSimulation}
                  disabled={loading}
                  className="w-full py-3 rounded-lg bg-cyan-500 hover:bg-cyan-400 disabled:opacity-50 text-slate-950 font-mono font-bold tracking-wider uppercase transition-all shadow-md shadow-cyan-950"
                >
                  {loading ? "INITIALIZING..." : "[ START SIMULATION ]"}
                </button>
              ) : (
                <>
                  <div className="grid grid-cols-2 gap-3">
                    <button
                      onClick={handleStepSimulation}
                      disabled={loading || isCompleted}
                      className={`py-3 rounded-lg font-mono font-bold tracking-wider uppercase transition-all ${
                        isCompleted
                          ? "bg-slate-800 text-slate-500 cursor-not-allowed"
                          : "bg-emerald-500 hover:bg-emerald-400 text-slate-950 shadow-md shadow-emerald-950"
                      }`}
                    >
                      {loading ? "STEPPING..." : isCompleted ? "COMPLETED" : "[ STEP ]"}
                    </button>

                    <button
                      onClick={handleResetSimulation}
                      disabled={loading || investigating}
                      className="py-3 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 font-mono font-bold tracking-wider uppercase transition-all border border-slate-700"
                    >
                      [ RESET ]
                    </button>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                    <button
                      onClick={handleRunInvestigation}
                      disabled={loading || investigating || responding || events.length === 0}
                      className="py-2.5 px-2 rounded-lg bg-purple-600 hover:bg-purple-500 disabled:opacity-50 text-white font-mono text-xs font-bold tracking-wider uppercase transition-all shadow-md shadow-purple-950 flex items-center justify-center gap-1.5"
                    >
                      {investigating ? (
                        <>
                          <span className="w-2 h-2 rounded-full bg-purple-300 animate-ping" />
                          INVESTIGATING...
                        </>
                      ) : (
                        <>🤖 [ AI INVESTIGATE ]</>
                      )}
                    </button>

                    <button
                      onClick={handleRunResponse}
                      disabled={loading || responding || events.length === 0}
                      className="py-2.5 px-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-slate-950 font-mono text-xs font-bold tracking-wider uppercase transition-all shadow-md shadow-cyan-950 flex items-center justify-center gap-1.5"
                    >
                      {responding ? (
                        <>
                          <span className="w-2 h-2 rounded-full bg-cyan-300 animate-ping" />
                          PLANNING DEFENSE...
                        </>
                      ) : (
                        <>🛡️ [ DEFENSIVE RESPONSE ]</>
                      )}
                    </button>
                  </div>
                </>
              )}
            </div>

            <p className="text-[11px] font-mono text-slate-500 mt-4 text-center">
              {!simulation
                ? "Click START SIMULATION to initialize synthetic environment."
                : isCompleted
                ? "Scenario execution finished. Click RESET to restart."
                : "Click STEP to advance simulation clock by 1 tick."}
            </p>
          </div>

          {/* CURRENT SIMULATION METRICS */}
          <div className="md:col-span-2 bg-slate-900/80 border border-slate-800 rounded-xl p-5 backdrop-blur-md grid grid-cols-2 sm:grid-cols-4 gap-4 font-mono">
            <div className="bg-slate-950/70 border border-slate-800/80 p-4 rounded-lg flex flex-col justify-between">
              <span className="text-xs text-slate-500 uppercase">Scenario</span>
              <span className="text-sm font-bold text-white truncate mt-2">
                {currentScenarioObj?.name || "None"}
              </span>
            </div>

            <div className="bg-slate-950/70 border border-slate-800/80 p-4 rounded-lg flex flex-col justify-between">
              <span className="text-xs text-slate-500 uppercase">Tick Progress</span>
              <span className="text-xl font-bold text-cyan-400 mt-2">
                {simulation ? simulation.current_tick : 0} <span className="text-xs text-slate-500 font-normal">/ {maxTicks}</span>
              </span>
            </div>

            <div className="bg-slate-950/70 border border-slate-800/80 p-4 rounded-lg flex flex-col justify-between">
              <span className="text-xs text-slate-500 uppercase">Threat Score</span>
              <span className={`text-xl font-bold mt-2 ${
                currentScore >= 81 ? "text-rose-400 font-extrabold" :
                currentScore >= 61 ? "text-orange-400" :
                currentScore >= 31 ? "text-amber-400" :
                "text-emerald-400"
              }`}>
                {currentScore} <span className="text-xs text-slate-500 font-normal">/ 100</span>
              </span>
            </div>

            <div className="bg-slate-950/70 border border-slate-800/80 p-4 rounded-lg flex flex-col justify-between">
              <span className="text-xs text-slate-500 uppercase">Severity</span>
              <div className="mt-2">
                {getSeverityBadge(currentSeverity)}
              </div>
            </div>
          </div>
        </section>

        {/* BOTTOM SECTION: EVENT FEED, THREAT FACTORS, AND HOST STATUS */}
        <section className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* EVENT FEED (2/3 width) */}
          <div className="lg:col-span-2 bg-slate-900/80 border border-slate-800 rounded-xl p-5 backdrop-blur-md flex flex-col">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-4">
              <h3 className="text-xs font-mono text-slate-400 tracking-wider uppercase font-semibold flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
                Security Event Stream
              </h3>
              <span className="text-xs font-mono text-slate-500">
                {events.length} Events Captured
              </span>
            </div>

            <div className="flex-1 min-h-[300px] max-h-[420px] overflow-y-auto space-y-2 pr-1 font-mono text-xs">
              {events.length === 0 ? (
                <div className="h-full min-h-[220px] flex items-center justify-center text-slate-600 italic">
                  No events captured yet. Click [ STEP ] to advance simulation.
                </div>
              ) : (
                events.map((evt) => (
                  <div
                    key={evt.id}
                    className="p-3 rounded-lg bg-slate-950/80 border border-slate-800/80 hover:border-slate-700 transition-colors"
                  >
                    <div className="flex items-center justify-between mb-1">
                      <div className="flex items-center gap-2">
                        <span className="text-slate-500">[{evt.timestamp}]</span>
                        <span className="font-bold text-cyan-300">{evt.event_type}</span>
                      </div>
                      {getSeverityBadge(evt.severity)}
                    </div>

                    <div className="grid grid-cols-2 gap-2 text-[11px] text-slate-400 my-1">
                      <span>Source: <strong className="text-slate-300">{evt.source_ip}</strong></span>
                      <span>Target: <strong className="text-slate-300">{evt.target_host}</strong></span>
                    </div>

                    {evt.details && (
                      <div className="mt-2 text-[10px] text-slate-400 bg-slate-900/90 p-2 rounded border border-slate-800/50">
                        <code className="text-slate-300">{JSON.stringify(evt.details)}</code>
                      </div>
                    )}
                  </div>
                ))
              )}
            </div>
          </div>

          {/* RIGHT COLUMN: THREAT FACTORS & NETWORK HOST STATUS (1/3 width) */}
          <div className="space-y-6">
            {/* THREAT FACTORS CARD */}
            <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 backdrop-blur-md flex flex-col">
              <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-4">
                <h3 className="text-xs font-mono text-slate-400 tracking-wider uppercase font-semibold flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-orange-400 animate-pulse" />
                  Threat Factors
                </h3>
                <span className="text-xs font-mono text-slate-500">
                  {factorsList.length} Factors
                </span>
              </div>

              <div className="space-y-2.5 font-mono text-xs max-h-[220px] overflow-y-auto pr-1">
                {factorsList.length === 0 ? (
                  <div className="py-6 text-center text-slate-600 italic">
                    No active threat factors. Baseline score 0.
                  </div>
                ) : (
                  factorsList.map((factor, idx) => (
                    <div key={idx} className="p-2.5 rounded bg-slate-950/80 border border-slate-800/80">
                      <div className="flex items-center justify-between font-bold">
                        <span className="text-slate-200">{formatEventTypeName(factor.event_type)}</span>
                        <span className="text-rose-400">+{factor.contribution}</span>
                      </div>
                      <p className="text-[11px] text-slate-400 mt-1">{factor.reason}</p>
                    </div>
                  ))
                )}
              </div>
            </div>

            {/* HOST STATUS GRID */}
            <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 backdrop-blur-md flex flex-col">
              <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-4">
                <h3 className="text-xs font-mono text-slate-400 tracking-wider uppercase font-semibold">
                  Network Host Status
                </h3>
                <span className="text-xs font-mono text-slate-500">5 Topology Nodes</span>
              </div>

              <div className="space-y-3 font-mono">
                {hosts.map((host) => (
                  <div
                    key={host.id}
                    className={`p-3 rounded-lg border transition-colors flex items-center justify-between ${
                      host.status === "COMPROMISED"
                        ? "bg-rose-950/30 border-rose-800/80"
                        : "bg-slate-950/80 border-slate-800/80"
                    }`}
                  >
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-bold text-white">{host.hostname}</span>
                        <span className="text-[10px] px-1.5 py-0.2 rounded bg-slate-800 text-slate-400">
                          {host.host_type}
                        </span>
                      </div>
                      <span className="text-xs text-slate-500">{host.ip_address}</span>
                    </div>

                    <div>{getHostStatusBadge(host.status)}</div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </section>

        {/* ATTACK CHAIN GRAPH SECTION */}
        {events.length > 0 && (
          <section className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 backdrop-blur-md space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-xs font-mono text-slate-400 tracking-wider uppercase font-semibold flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
                Interactive Attack Chain Graph
              </h3>
              <span className="text-xs font-mono text-slate-500">
                {attackGraphNodes.length} Nodes • {attackGraphEdges.length} Edges
              </span>
            </div>
            <AttackGraph nodes={attackGraphNodes} edges={attackGraphEdges} />
          </section>
        )}

        {/* AI INVESTIGATION PANEL */}
        {(investigation || investigating) && (
          <section className="bg-slate-900/90 border border-purple-800/60 rounded-xl p-6 backdrop-blur-md space-y-6 shadow-2xl font-mono">
            {/* Panel Header */}
            <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800 pb-4">
              <div className="flex items-center gap-3">
                <span className="w-3 h-3 rounded-full bg-purple-400 animate-pulse" />
                <h2 className="text-base font-extrabold text-white tracking-wide uppercase">
                  AI SOC INVESTIGATOR REPORT
                </h2>
              </div>

              {investigation && (
                <div className="flex flex-wrap items-center gap-3 text-xs">
                  <span className="text-slate-400">CONFIDENCE:</span>
                  <span className={`px-2.5 py-1 rounded font-bold border ${
                    investigation.confidence === "HIGH"
                      ? "bg-emerald-950 border-emerald-800 text-emerald-400"
                      : investigation.confidence === "MEDIUM"
                      ? "bg-amber-950 border-amber-800 text-amber-400"
                      : "bg-slate-800 border-slate-700 text-slate-400"
                  }`}>
                    {investigation.confidence}
                  </span>

                  <span className="text-slate-400">DETERMINISTIC THREAT:</span>
                  <span className={`px-2.5 py-1 rounded font-bold border ${
                    investigation.threat.score >= 81 ? "bg-rose-950 border-rose-800 text-rose-400" :
                    investigation.threat.score >= 61 ? "bg-orange-950 border-orange-800 text-orange-400" :
                    "bg-amber-950 border-amber-800 text-amber-400"
                  }`}>
                    {investigation.threat.score}/100 ({investigation.threat.severity})
                  </span>
                </div>
              )}
            </div>

            {investigating ? (
              <div className="py-12 flex flex-col items-center justify-center space-y-3">
                <div className="w-10 h-10 border-4 border-purple-500 border-t-transparent rounded-full animate-spin" />
                <p className="text-sm font-bold text-purple-300 animate-pulse">
                  LANGGRAPH INVESTIGATOR ANALYZING SIMULATION EVENTS...
                </p>
                <p className="text-xs text-slate-500">Correlating threat signals & evaluating attack chain stages</p>
              </div>
            ) : investigation ? (
              <div className="space-y-6">
                {/* Detection & Executive Summary Grid */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="bg-slate-950/80 border border-slate-800 p-4 rounded-lg">
                    <h3 className="text-xs text-purple-400 font-bold uppercase mb-2">🔍 Detection Summary</h3>
                    <p className="text-xs text-slate-300 leading-relaxed">{investigation.detection_summary}</p>
                  </div>

                  <div className="bg-slate-950/80 border border-slate-800 p-4 rounded-lg">
                    <h3 className="text-xs text-cyan-400 font-bold uppercase mb-2">📋 Investigation Summary</h3>
                    <p className="text-xs text-slate-300 leading-relaxed">{investigation.investigation_summary}</p>
                  </div>
                </div>

                {/* Attack Chain Stage Flow */}
                <div className="bg-slate-950/80 border border-slate-800 p-4 rounded-lg space-y-3">
                  <h3 className="text-xs text-orange-400 font-bold uppercase">⚡ Attack Chain Sequence</h3>
                  <div className="flex flex-wrap items-center gap-2">
                    {investigation.attack_chain.map((item, idx) => (
                      <div key={idx} className="flex items-center gap-2">
                        <div className="bg-slate-900 border border-slate-700 px-3 py-2 rounded-lg flex flex-col">
                          <span className="text-[10px] text-slate-500 uppercase">{item.stage}</span>
                          <span className="text-xs font-bold text-slate-200 mt-0.5">{item.event_types.join(", ")}</span>
                        </div>
                        {idx < investigation.attack_chain.length - 1 && (
                          <span className="text-slate-600 font-bold">→</span>
                        )}
                      </div>
                    ))}
                  </div>
                </div>

                {/* Threat Analysis Narrative */}
                <div className="bg-slate-950/80 border border-slate-800 p-4 rounded-lg">
                  <h3 className="text-xs text-rose-400 font-bold uppercase mb-2">🛡️ Defensive Threat Analysis</h3>
                  <p className="text-xs text-slate-300 leading-relaxed">{investigation.threat_analysis}</p>
                </div>

                {/* Affected Hosts & Recommendations */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {/* Affected Hosts */}
                  <div className="bg-slate-950/80 border border-slate-800 p-4 rounded-lg space-y-2">
                    <h3 className="text-xs text-emerald-400 font-bold uppercase">🖥️ Affected Simulated Hosts</h3>
                    {investigation.affected_hosts.length === 0 ? (
                      <p className="text-xs text-slate-500 italic">No target hosts impacted.</p>
                    ) : (
                      <div className="space-y-2">
                        {investigation.affected_hosts.map((h, i) => (
                          <div key={i} className="p-2 bg-slate-900 rounded border border-slate-800 text-xs">
                            <div className="flex items-center justify-between font-bold text-slate-200">
                              <span>{h.host}</span>
                              <span className="text-[10px] text-slate-500">{h.role}</span>
                            </div>
                            <p className="text-[11px] text-slate-400 mt-1">{h.impact}</p>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>

                  {/* Safe Defensive Recommendations */}
                  <div className="bg-slate-950/80 border border-slate-800 p-4 rounded-lg space-y-2">
                    <h3 className="text-xs text-amber-400 font-bold uppercase">🛡️ Safe SOC Recommendations</h3>
                    <ul className="space-y-1.5 text-xs text-slate-300">
                      {investigation.recommendations.map((rec, i) => (
                        <li key={i} className="flex items-start gap-2">
                          <span className="text-amber-400 font-bold">•</span>
                          <span>{rec}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                </div>
              </div>
            ) : null}
          </section>
        )}

        {/* AI DEFENSIVE RESPONSE PANEL */}
        {(responseResult || responding) && (
          <section className="bg-slate-900/90 border border-cyan-800/60 rounded-xl p-6 backdrop-blur-md space-y-6 shadow-2xl font-mono">
            {/* Header & Status */}
            <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800 pb-4">
              <div className="flex items-center gap-3">
                <span className="w-3 h-3 rounded-full bg-cyan-400 animate-pulse" />
                <h2 className="text-base font-extrabold text-white tracking-wide uppercase">
                  AI DEFENSIVE RESPONSE WORKFLOW
                </h2>
              </div>
              {responseResult && (
                <span className="text-xs font-bold px-3 py-1 rounded-full bg-cyan-950 border border-cyan-800 text-cyan-400">
                  STATUS: {responseResult.status}
                </span>
              )}
            </div>

            {/* Workflow Transparency Pipeline */}
            <div className="bg-slate-950/80 border border-slate-800/80 p-4 rounded-lg">
              <span className="text-[10px] text-slate-500 uppercase tracking-widest block mb-2 font-bold">
                LANGGRAPH RESPONSE PIPELINE TRANSPARENCY
              </span>
              <div className="grid grid-cols-2 sm:grid-cols-5 gap-2 text-center text-[11px]">
                <div className="p-2 rounded bg-slate-900 border border-purple-800/60 text-purple-300 font-bold">
                  1. AI INVESTIGATION
                </div>
                <div className="p-2 rounded bg-slate-900 border border-blue-800/60 text-blue-300 font-bold">
                  2. RESPONSE PLAN
                </div>
                <div className="p-2 rounded bg-slate-900 border border-amber-800/60 text-amber-300 font-bold">
                  3. SAFETY CHECK
                </div>
                <div className="p-2 rounded bg-slate-900 border border-emerald-800/60 text-emerald-300 font-bold">
                  4. APPROVED ACTIONS
                </div>
                <div className="p-2 rounded bg-slate-900 border border-cyan-800/60 text-cyan-300 font-bold col-span-2 sm:col-span-1">
                  5. SIMULATED EXECUTION
                </div>
              </div>
            </div>

            {responding ? (
              <div className="py-12 flex flex-col items-center justify-center space-y-3">
                <div className="w-10 h-10 border-4 border-cyan-500 border-t-transparent rounded-full animate-spin" />
                <p className="text-sm font-bold text-cyan-300 animate-pulse">
                  GENERATING & VALIDATING SIMULATED DEFENSIVE PLAN...
                </p>
                <p className="text-xs text-slate-500">Checking deterministic safety allowlist & applying simulated actions</p>
              </div>
            ) : responseResult ? (
              <div className="space-y-6">
                {/* Summary narrative */}
                <div className="bg-slate-950/80 border border-slate-800 p-4 rounded-lg">
                  <h3 className="text-xs text-cyan-400 font-bold uppercase mb-2">📋 Response Execution Summary</h3>
                  <p className="text-xs text-slate-300 leading-relaxed">{responseResult.summary}</p>
                </div>

                {/* Actions Grid */}
                <div className="space-y-3">
                  <h3 className="text-xs text-slate-400 font-bold uppercase">🛡️ Proposed & Executed Actions</h3>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {responseResult.executed_actions.map((act, i) => (
                      <div key={i} className="p-4 rounded-lg bg-slate-950/80 border border-cyan-800/60 space-y-2">
                        <div className="flex items-center justify-between">
                          <span className="text-sm font-bold text-cyan-300 font-mono">{act.action_type || act.action_id}</span>
                          <span className={`text-[10px] font-bold px-2 py-0.5 rounded font-mono ${
                            act.status === "EXECUTED" ? "bg-emerald-950 text-emerald-400 border border-emerald-800" :
                            act.status === "APPROVED" ? "bg-cyan-950 text-cyan-400 border border-cyan-800" :
                            "bg-rose-950 text-rose-400 border border-rose-800"
                          }`}>
                            {act.status}
                          </span>
                        </div>
                        <div className="text-xs text-slate-300">
                          Target: <strong className="text-white">{act.target}</strong> | Priority: <span className="text-amber-400 font-bold">{act.priority}</span>
                        </div>
                        <p className="text-xs text-slate-400 leading-normal">{act.reason}</p>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Defensive Host Status Changes */}
                <div className="bg-slate-950/80 border border-slate-800 p-4 rounded-lg space-y-3">
                  <h3 className="text-xs text-emerald-400 font-bold uppercase">🖥️ Fictional Host Defense Status</h3>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    {hosts.map((h) => (
                      <div key={h.id} className="p-3 rounded bg-slate-900 border border-slate-800 flex items-center justify-between text-xs font-mono">
                        <div>
                          <span className="font-bold text-white">{h.hostname}</span>
                          <span className="text-slate-500 block text-[10px]">{h.ip_address}</span>
                        </div>
                        <div>{getHostStatusBadge(h.status)}</div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            ) : null}
          </section>
        )}
      </main>
    </div>
  );
}

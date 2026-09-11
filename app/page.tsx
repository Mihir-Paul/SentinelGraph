"use client";

import { useEffect, useState } from "react";
import Link from "next/link";

type HealthStatus = "CHECKING..." | "ONLINE" | "OFFLINE";

export default function Home() {
  const [backendStatus, setBackendStatus] = useState<HealthStatus>("CHECKING...");

  useEffect(() => {
    async function checkHealth() {
      try {
        const res = await fetch("/api/health", { cache: "no-store" });
        if (res.ok) {
          const data = await res.json();
          if (data.status === "ok") {
            setBackendStatus("ONLINE");
          } else {
            setBackendStatus("OFFLINE");
          }
        } else {
          setBackendStatus("OFFLINE");
        }
      } catch (err) {
        console.error("Health check error:", err);
        setBackendStatus("OFFLINE");
      }
    }

    checkHealth();
  }, []);

  return (
    <main className="flex-1 flex flex-col items-center justify-center p-6 relative">
      {/* Background Ambient Glow */}
      <div className="absolute top-1/4 left-1/2 -translate-x-1/2 -translate-y-1/2 w-96 h-96 bg-cyan-500/10 rounded-full blur-3xl pointer-events-none" />

      <div className="w-full max-w-3xl z-10">
        {/* Header Branding Card */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-8 backdrop-blur-md glow-cyan text-center mb-8">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-950/80 border border-cyan-800 text-cyan-400 text-xs font-mono tracking-widest uppercase mb-4">
            <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
            Security Operations Center
          </div>

          <h1 className="text-4xl md:text-6xl font-extrabold tracking-tight text-white mb-2 font-mono">
            SENTINEL<span className="text-cyan-400">GRAPH</span>
          </h1>

          <p className="text-lg md:text-xl text-slate-400 font-medium tracking-wide uppercase font-mono mb-6">
            AI CYBER DEFENSE SIMULATION
          </p>

          {/* Status Metrics Box */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 max-w-lg mx-auto mb-8 font-mono">
            <div className="bg-slate-950/70 border border-slate-800 p-4 rounded-lg flex items-center justify-between">
              <span className="text-slate-400 text-sm">System Status:</span>
              <span className="text-emerald-400 font-bold flex items-center gap-2 text-sm">
                <span className="w-2.5 h-2.5 rounded-full bg-emerald-500 animate-ping inline-block" />
                ONLINE
              </span>
            </div>

            <div className="bg-slate-950/70 border border-slate-800 p-4 rounded-lg flex items-center justify-between">
              <span className="text-slate-400 text-sm">Backend:</span>
              <span
                className={`font-bold flex items-center gap-2 text-sm ${
                  backendStatus === "ONLINE"
                    ? "text-emerald-400"
                    : backendStatus === "OFFLINE"
                    ? "text-rose-400"
                    : "text-amber-400"
                }`}
              >
                {backendStatus === "CHECKING..." && (
                  <span className="w-2.5 h-2.5 rounded-full bg-amber-400 animate-pulse inline-block" />
                )}
                {backendStatus === "ONLINE" && (
                  <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 inline-block glow-emerald" />
                )}
                {backendStatus === "OFFLINE" && (
                  <span className="w-2.5 h-2.5 rounded-full bg-rose-500 inline-block" />
                )}
                {backendStatus}
              </span>
            </div>
          </div>

          {/* Action Button: Always navigates to /dashboard */}
          <Link
            href="/dashboard"
            className="inline-block px-8 py-3 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold font-mono tracking-wider uppercase transition-all duration-200 shadow-lg shadow-cyan-950 hover:shadow-cyan-500/20 active:scale-95"
          >
            [ ENTER SOC ]
          </Link>
        </div>
      </div>
    </main>
  );
}

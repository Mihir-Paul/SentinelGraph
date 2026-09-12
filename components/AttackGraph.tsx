"use client";

import { useState } from "react";
import { AttackGraphNode, AttackGraphEdge } from "@/types/simulation";

interface AttackGraphProps {
  nodes: AttackGraphNode[];
  edges: AttackGraphEdge[];
}

export default function AttackGraph({ nodes, edges }: AttackGraphProps) {
  const [selectedNode, setSelectedNode] = useState<AttackGraphNode | null>(null);

  if (!nodes || nodes.length === 0) {
    return (
      <div className="py-12 text-center text-slate-600 font-mono text-xs italic">
        No attack graph data available. Advance simulation steps to visualize the attack topology graph.
      </div>
    );
  }

  function getNodeBadge(type: string, severity: string) {
    switch (type) {
      case "SOURCE":
        return "bg-sky-950 border-sky-700 text-sky-400";
      case "HOST":
        return "bg-indigo-950 border-indigo-700 text-indigo-300";
      case "IMPACT":
        return "bg-rose-950 border-rose-600 text-rose-300 animate-pulse font-extrabold";
      default:
        if (severity === "CRITICAL") return "bg-rose-950/90 border-rose-800 text-rose-400 font-bold";
        if (severity === "HIGH") return "bg-orange-950/90 border-orange-800 text-orange-400 font-bold";
        if (severity === "MEDIUM") return "bg-amber-950/90 border-amber-800 text-amber-300";
        return "bg-slate-800 border-slate-700 text-slate-300";
    }
  }

  return (
    <div className="space-y-4 font-mono">
      {/* ATTACK GRAPH CANVAS */}
      <div className="bg-slate-950/90 border border-slate-800/90 rounded-xl p-4 overflow-x-auto min-h-[160px] flex items-center">
        <div className="flex items-center gap-3 min-w-max py-2 px-1">
          {nodes.map((node, idx) => {
            const isSelected = selectedNode?.id === node.id;
            const isLast = idx === nodes.length - 1;

            return (
              <div key={node.id} className="flex items-center gap-3">
                {/* Node Box */}
                <div
                  onClick={() => setSelectedNode(node)}
                  className={`p-3 rounded-lg border transition-all cursor-pointer shadow-lg flex flex-col justify-between max-w-[200px] ${
                    isSelected ? "ring-2 ring-cyan-400 scale-105 z-10" : "hover:border-slate-600"
                  } ${getNodeBadge(node.type, node.severity)}`}
                >
                  <div className="flex items-center justify-between gap-2 mb-1">
                    <span className="text-[9px] tracking-wider px-1.5 py-0.5 rounded bg-black/40 text-slate-300 uppercase font-bold">
                      {node.type}
                    </span>
                    <span className="text-[9px] font-bold">{node.severity}</span>
                  </div>

                  <span className="text-xs font-bold truncate tracking-tight text-white my-1">
                    {node.label}
                  </span>

                  {node.type === "EVENT" && node.details?.timestamp && (
                    <span className="text-[10px] text-slate-400">[{node.details.timestamp}]</span>
                  )}
                </div>

                {/* Arrow Connector */}
                {!isLast && (
                  <div className="flex flex-col items-center justify-center px-1">
                    <span className="text-[9px] text-slate-500 uppercase tracking-widest font-bold mb-0.5">
                      {edges[idx]?.relationship || "→"}
                    </span>
                    <span className="text-cyan-400 font-bold text-lg leading-none">→</span>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>

      {/* SELECTED NODE INSPECTOR MODAL/POPOVER */}
      {selectedNode && (
        <div className="bg-slate-900 border border-slate-700 rounded-lg p-4 font-mono text-xs space-y-2 relative shadow-2xl">
          <div className="flex items-center justify-between border-b border-slate-800 pb-2">
            <div className="flex items-center gap-2">
              <span className="text-cyan-400 font-bold">NODE INSPECTOR:</span>
              <span className="font-bold text-white">{selectedNode.label}</span>
              <span className="text-[10px] px-2 py-0.5 rounded bg-slate-800 text-slate-300 uppercase">
                {selectedNode.type}
              </span>
            </div>
            <button
              onClick={() => setSelectedNode(null)}
              className="text-slate-400 hover:text-white font-bold"
            >
              ✕
            </button>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-[11px] py-1 text-slate-300">
            <div>Node ID: <strong className="text-slate-100">{selectedNode.id}</strong></div>
            <div>Severity: <strong className="text-slate-100">{selectedNode.severity}</strong></div>
            {selectedNode.details?.source_ip && (
              <div>Source IP: <strong className="text-slate-100">{selectedNode.details.source_ip}</strong></div>
            )}
            {selectedNode.details?.target_host && (
              <div>Target Host: <strong className="text-slate-100">{selectedNode.details.target_host}</strong></div>
            )}
          </div>

          {selectedNode.details && (
            <div className="bg-slate-950 p-2.5 rounded border border-slate-800 text-[10px] overflow-x-auto text-slate-300">
              <code className="text-cyan-300">{JSON.stringify(selectedNode.details, null, 2)}</code>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

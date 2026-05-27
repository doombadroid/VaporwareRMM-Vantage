"use client";

import { useCallback, useEffect, useState } from "react";
import AuthGuard from "@/components/AuthGuard";
import api, {
  type Command,
  type CommandList,
  type EdgeList,
  CANCELLABLE_STATES,
} from "@/lib/api";

const STATES = [
  "queued",
  "delivered_to_edge",
  "delivered_to_endpoint",
  "executing",
  "succeeded",
  "failed",
  "expired",
  "cancelled",
];

function fmtTime(unix?: number): string {
  if (!unix) return "—";
  return new Date(unix * 1000).toLocaleString();
}

export default function CommandsPage() {
  const [commands, setCommands] = useState<Command[]>([]);
  const [edges, setEdges] = useState<{ id: string; name: string }[]>([]);
  const [edgeFilter, setEdgeFilter] = useState("");
  const [stateFilter, setStateFilter] = useState("");
  const [error, setError] = useState("");
  const [modalOpen, setModalOpen] = useState(false);

  const load = useCallback(() => {
    const params = new URLSearchParams();
    if (edgeFilter) params.set("edge_id", edgeFilter);
    if (stateFilter) params.set("state", stateFilter);
    api
      .get<CommandList>("/commands?" + params.toString())
      .then((r) => setCommands(r.data.data))
      .catch((e: unknown) => setError(e instanceof Error ? e.message : "fetch failed"));
  }, [edgeFilter, stateFilter]);

  // Initial + filter-change load, plus 10s auto-refresh.
  useEffect(() => {
    load();
    const t = setInterval(load, 10_000);
    return () => clearInterval(t);
  }, [load]);

  useEffect(() => {
    // limit=200 (the backend's max page) so the filter + modal cover fleets
    // larger than the default 50-edge page (codex round 2 #4).
    api
      .get<EdgeList>("/edges?limit=200")
      .then((r) => setEdges(r.data.data.map((e) => ({ id: e.id, name: e.name || e.id }))))
      .catch(() => {
        /* edge dropdown is best-effort; filtering still works by typing */
      });
  }, []);

  const cancel = async (correlationID: string) => {
    setError("");
    try {
      await api.delete("/commands/" + encodeURIComponent(correlationID));
      load();
    } catch (e: unknown) {
      // 409 = already dispatched/terminal; surface the server message.
      const msg =
        (e as { response?: { data?: { error?: string } } })?.response?.data?.error ||
        (e instanceof Error ? e.message : "cancel failed");
      setError(msg);
    }
  };

  return (
    <AuthGuard>
      <main className="min-h-screen px-6 py-8 max-w-6xl mx-auto">
        <header className="mb-6 flex items-center justify-between">
          <div>
            <h1 className="text-xl font-semibold">Commands</h1>
            <p className="text-xs text-white/45 mt-1">
              Operator commands queued to Edge appliances. Auto-refreshes every 10s.
            </p>
          </div>
          <button
            onClick={() => setModalOpen(true)}
            className="rounded-lg bg-cyan-500/20 border border-cyan-400/30 px-3 py-1.5 text-xs text-cyan-200 hover:bg-cyan-500/30"
          >
            New command
          </button>
        </header>

        <div className="mb-4 flex gap-3 text-xs">
          <select
            value={edgeFilter}
            onChange={(e) => setEdgeFilter(e.target.value)}
            className="rounded-md bg-white/[0.04] border border-white/10 px-2 py-1.5 text-white/80"
          >
            <option value="">All edges</option>
            {edges.map((e) => (
              <option key={e.id} value={e.id}>
                {e.name}
              </option>
            ))}
          </select>
          <select
            value={stateFilter}
            onChange={(e) => setStateFilter(e.target.value)}
            className="rounded-md bg-white/[0.04] border border-white/10 px-2 py-1.5 text-white/80"
          >
            <option value="">All states</option>
            {STATES.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
        </div>

        {error && (
          <div className="mb-4 rounded-lg border border-rose-500/30 bg-rose-500/[0.05] px-4 py-3 text-xs text-rose-300">
            {error}
          </div>
        )}

        {commands.length === 0 ? (
          <div className="rounded-2xl border border-white/[0.06] bg-white/[0.02] px-6 py-12 text-center">
            <p className="text-sm text-white/65 font-medium">No commands.</p>
            <p className="mt-2 text-xs text-white/40">Queue one with “New command”.</p>
          </div>
        ) : (
          <table className="w-full text-sm border-collapse">
            <thead>
              <tr className="text-left text-[10px] uppercase tracking-wider text-white/35">
                <th className="py-2">Endpoint</th>
                <th className="py-2">Type</th>
                <th className="py-2">State</th>
                <th className="py-2">Result</th>
                <th className="py-2">Queued</th>
                <th className="py-2">Terminal</th>
                <th className="py-2" />
              </tr>
            </thead>
            <tbody>
              {commands.map((c) => (
                <tr key={c.correlation_id} className="border-t border-white/[0.04]">
                  <td className="py-2 font-mono text-white/80">{c.target_endpoint_id}</td>
                  <td className="py-2 text-white/55">{c.command_type}</td>
                  <td className="py-2">
                    <span className="text-white/80">{c.state}</span>
                  </td>
                  <td className="py-2 text-white/55">
                    {c.result_status ? `${c.result_status}${c.result_message ? `: ${c.result_message}` : ""}` : "—"}
                  </td>
                  <td className="py-2 text-white/45 text-xs">{fmtTime(c.queued_at)}</td>
                  <td className="py-2 text-white/45 text-xs">{fmtTime(c.terminal_at)}</td>
                  <td className="py-2 text-right">
                    {CANCELLABLE_STATES.includes(c.state) && (
                      <button
                        onClick={() => cancel(c.correlation_id)}
                        className="text-xs text-rose-300 hover:text-rose-200"
                      >
                        Cancel
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        {modalOpen && (
          <NewCommandModal
            edges={edges}
            onClose={() => setModalOpen(false)}
            onQueued={() => {
              setModalOpen(false);
              load();
            }}
            onError={setError}
          />
        )}
      </main>
    </AuthGuard>
  );
}

function NewCommandModal({
  edges,
  onClose,
  onQueued,
  onError,
}: {
  edges: { id: string; name: string }[];
  onClose: () => void;
  onQueued: () => void;
  onError: (msg: string) => void;
}) {
  const [edgeID, setEdgeID] = useState(edges[0]?.id ?? "");
  const [targetKind, setTargetKind] = useState<"endpoint" | "tag">("endpoint");
  const [targetValue, setTargetValue] = useState("");
  const [serviceName, setServiceName] = useState("");
  const [submitting, setSubmitting] = useState(false);

  // /edges may resolve after the modal mounts; adopt the first edge once it
  // arrives if the operator hasn't picked one, so the visible selection and
  // edgeID agree (codex round 2 #3).
  useEffect(() => {
    if (!edgeID && edges.length > 0) setEdgeID(edges[0].id);
  }, [edges, edgeID]);

  const submit = async () => {
    if (!edgeID || !targetValue || !serviceName) {
      onError("edge, target, and service name are required");
      return;
    }
    setSubmitting(true);
    try {
      await api.post("/commands", {
        edge_id: edgeID,
        // values is comma-split so an operator can target several at once.
        targets: { kind: targetKind, values: targetValue.split(",").map((v) => v.trim()).filter(Boolean) },
        command_type: "restart_service",
        command_params: { service_name: serviceName },
      });
      onQueued();
    } catch (e: unknown) {
      const msg =
        (e as { response?: { data?: { error?: string } } })?.response?.data?.error ||
        (e instanceof Error ? e.message : "enqueue failed");
      onError(msg);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60" onClick={onClose}>
      <div
        className="w-full max-w-md rounded-2xl border border-white/10 bg-[#0c0c0e] p-6"
        onClick={(e) => e.stopPropagation()}
      >
        <h2 className="text-sm font-semibold mb-4">New command</h2>
        <label className="block text-[10px] uppercase tracking-wider text-white/35 mb-1">Edge</label>
        <select
          value={edgeID}
          onChange={(e) => setEdgeID(e.target.value)}
          className="w-full mb-3 rounded-md bg-white/[0.04] border border-white/10 px-2 py-1.5 text-sm text-white/80"
        >
          {edges.length === 0 && <option value="">No edges</option>}
          {edges.map((e) => (
            <option key={e.id} value={e.id}>
              {e.name}
            </option>
          ))}
        </select>

        <label className="block text-[10px] uppercase tracking-wider text-white/35 mb-1">Target by</label>
        <div className="mb-3 flex gap-2">
          {(["endpoint", "tag"] as const).map((k) => (
            <button
              key={k}
              onClick={() => setTargetKind(k)}
              className={`flex-1 rounded-md border px-2 py-1.5 text-xs ${
                targetKind === k
                  ? "border-cyan-400/40 bg-cyan-500/15 text-cyan-200"
                  : "border-white/10 text-white/55"
              }`}
            >
              {k}
            </button>
          ))}
        </div>

        <label className="block text-[10px] uppercase tracking-wider text-white/35 mb-1">
          {targetKind === "endpoint" ? "Endpoint ID(s)" : "Tag name(s)"} (comma-separated)
        </label>
        <input
          value={targetValue}
          onChange={(e) => setTargetValue(e.target.value)}
          placeholder={targetKind === "endpoint" ? "host-abc, host-def" : "linux-prod"}
          className="w-full mb-3 rounded-md bg-white/[0.04] border border-white/10 px-2 py-1.5 text-sm text-white/80"
        />

        <label className="block text-[10px] uppercase tracking-wider text-white/35 mb-1">
          Command: restart_service — service name
        </label>
        <input
          value={serviceName}
          onChange={(e) => setServiceName(e.target.value)}
          placeholder="nginx"
          className="w-full mb-5 rounded-md bg-white/[0.04] border border-white/10 px-2 py-1.5 text-sm text-white/80"
        />

        <div className="flex justify-end gap-2">
          <button onClick={onClose} className="rounded-lg px-3 py-1.5 text-xs text-white/55 hover:text-white/80">
            Cancel
          </button>
          <button
            onClick={submit}
            disabled={submitting}
            className="rounded-lg bg-cyan-500/20 border border-cyan-400/30 px-3 py-1.5 text-xs text-cyan-200 hover:bg-cyan-500/30 disabled:opacity-50"
          >
            {submitting ? "Queuing…" : "Queue command"}
          </button>
        </div>
      </div>
    </div>
  );
}

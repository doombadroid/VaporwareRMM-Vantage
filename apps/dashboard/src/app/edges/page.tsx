"use client";

import { useEffect, useState } from "react";
import AuthGuard from "@/components/AuthGuard";
import api, { type EdgeList } from "@/lib/api";

export default function EdgesPage() {
  const [list, setList] = useState<EdgeList | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    api
      .get<EdgeList>("/edges")
      .then((r) => setList(r.data))
      .catch((e: unknown) => setError(e instanceof Error ? e.message : "fetch failed"));
  }, []);

  return (
    <AuthGuard>
      <main className="min-h-screen px-6 py-8 max-w-5xl mx-auto">
        <header className="mb-6">
          <h1 className="text-xl font-semibold">Fleet</h1>
          <p className="text-xs text-white/45 mt-1">
            Edge appliances paired to this Vantage instance.
          </p>
        </header>

        {error && (
          <div className="rounded-lg border border-rose-500/30 bg-rose-500/[0.05] px-4 py-3 text-xs text-rose-300">
            {error}
          </div>
        )}

        {list && list.data.length === 0 && (
          <div className="rounded-2xl border border-white/[0.06] bg-white/[0.02] px-6 py-12 text-center">
            <p className="text-sm text-white/65 font-medium">No Edges paired yet.</p>
            <p className="mt-2 text-xs text-white/40 max-w-md mx-auto leading-relaxed">
              Federation pairing flow lands in F2. For now, this is just the foundation —
              the database table, the API endpoint, and this empty-state view are wired
              correctly so subsequent phases can fill in the pairing UX, command routing,
              and audit checkpoints.
            </p>
            <a
              href="#"
              className="mt-4 inline-block text-xs text-cyan-300 hover:text-cyan-200"
              aria-disabled
            >
              Setup (coming in F2)
            </a>
          </div>
        )}

        {list && list.data.length > 0 && (
          <table className="w-full text-sm border-collapse">
            <thead>
              <tr className="text-left text-[10px] uppercase tracking-wider text-white/35">
                <th className="py-2">Name</th>
                <th className="py-2">Tenant</th>
                <th className="py-2">Status</th>
              </tr>
            </thead>
            <tbody>
              {list.data.map((e) => (
                <tr key={e.id} className="border-t border-white/[0.04]">
                  <td className="py-2 font-mono">{e.name || e.id}</td>
                  <td className="py-2 text-white/55">{e.tenant_id}</td>
                  <td className="py-2 text-white/55">{e.status}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </main>
    </AuthGuard>
  );
}

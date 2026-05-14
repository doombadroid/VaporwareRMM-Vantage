"use client";

import { useState, FormEvent } from "react";
import { useRouter } from "next/navigation";
import api from "@/lib/api";

type LoginResponse = { user_id: string; role: string; expires_at: number };

export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError("");
    setBusy(true);
    try {
      const { data } = await api.post<LoginResponse>("/auth/login", { email, password });
      // Track expiry client-side so AuthGuard can redirect away
      // from authed pages on stale sessions without a round-trip.
      localStorage.setItem("auth_expiry", String(data.expires_at));
      router.replace("/edges");
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : "login failed";
      setError(msg);
    } finally {
      setBusy(false);
    }
  };

  return (
    <main className="min-h-screen flex items-center justify-center px-4">
      <form onSubmit={submit} className="w-full max-w-sm space-y-4 bg-white/[0.04] border border-white/[0.08] rounded-2xl p-6">
        <div>
          <h1 className="text-lg font-semibold">VaporwareRMM Vantage</h1>
          <p className="text-xs text-white/45 mt-1">Federation control server. Sign in to manage your Edge fleet.</p>
        </div>
        <div>
          <label className="block text-[10px] uppercase tracking-wider text-white/40 mb-1">Email</label>
          <input
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
            className="w-full bg-white/[0.04] border border-white/[0.08] rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-cyan-500/40"
            autoComplete="username"
          />
        </div>
        <div>
          <label className="block text-[10px] uppercase tracking-wider text-white/40 mb-1">Password</label>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            className="w-full bg-white/[0.04] border border-white/[0.08] rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-cyan-500/40"
            autoComplete="current-password"
          />
        </div>
        {error && <p className="text-xs text-rose-400">{error}</p>}
        <button
          type="submit"
          disabled={busy}
          className="w-full bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white text-sm font-medium rounded-lg px-3 py-2 transition-colors"
        >
          {busy ? "Signing in…" : "Sign in"}
        </button>
      </form>
    </main>
  );
}

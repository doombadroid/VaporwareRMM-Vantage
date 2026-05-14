"use client";

// Client-side auth gate. Vantage's stateful sessions live in
// Postgres; the dashboard can't read the auth_token (httpOnly) so
// it tracks a separate auth_expiry value in localStorage that
// login sets and logout clears. If absent or past expiry, redirect
// to /login.
//
// Real authorization is server-side — handlers refuse on a missing
// session. AuthGuard is a UX-only check that prevents the
// dashboard from rendering authed views with stale state, not a
// security boundary.

import { useEffect } from "react";
import { useRouter } from "next/navigation";

export default function AuthGuard({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  useEffect(() => {
    const raw = typeof window !== "undefined" ? localStorage.getItem("auth_expiry") : null;
    if (!raw) {
      router.replace("/login");
      return;
    }
    const expiry = parseInt(raw, 10);
    if (!expiry || Date.now() / 1000 > expiry) {
      localStorage.removeItem("auth_expiry");
      router.replace("/login");
    }
  }, [router]);
  return <>{children}</>;
}

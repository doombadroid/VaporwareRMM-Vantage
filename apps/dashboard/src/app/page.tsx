"use client";

// Root path. If the user has an unexpired auth_expiry, send them
// to /edges. Otherwise, /login.

import { useEffect } from "react";
import { useRouter } from "next/navigation";

export default function RootPage() {
  const router = useRouter();
  useEffect(() => {
    const raw = typeof window !== "undefined" ? localStorage.getItem("auth_expiry") : null;
    const expiry = raw ? parseInt(raw, 10) : 0;
    if (expiry && Date.now() / 1000 < expiry) {
      router.replace("/edges");
    } else {
      router.replace("/login");
    }
  }, [router]);
  return null;
}

import axios from "axios";

// Axios instance for Vantage. Sends cookies with every request
// (withCredentials), reads csrf_token from document.cookie on
// state-changing methods and echoes it in X-CSRF-Token.
//
// Base URL defaults to http://localhost:9090/api/v1 for dev where
// the dashboard runs on :3001 and Vantage on :9090. In prod behind
// Caddy, the dashboard ships with NEXT_PUBLIC_API_URL=/api/v1 so
// the browser hits the same origin.

const baseURL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:9090/api/v1";

const api = axios.create({
  baseURL,
  withCredentials: true,
  headers: { "Content-Type": "application/json" },
});

api.interceptors.request.use((config) => {
  if (config.method && config.method.toUpperCase() !== "GET") {
    const csrf = readCookie("csrf_token");
    if (csrf) {
      config.headers = config.headers || {};
      config.headers["X-CSRF-Token"] = csrf;
    }
  }
  return config;
});

function readCookie(name: string): string | null {
  if (typeof document === "undefined") return null;
  const match = document.cookie.match(new RegExp("(?:^|; )" + name + "=([^;]*)"));
  return match ? decodeURIComponent(match[1]) : null;
}

export default api;

export type Edge = {
  id: string;
  name: string;
  tenant_id: string;
  status: string;
  created_at: number;
};

export type EdgeList = {
  data: Edge[];
  total: number;
  limit: number;
  offset: number;
  has_more: boolean;
};

export type User = {
  id: string;
  email: string;
  role: string;
  last_login_at?: number;
};

import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        // Minimal palette. F1 keeps the UI utilitarian — designer
        // polish is a later phase.
        ink: "#0a0a10",
        muted: "rgba(255,255,255,0.45)",
      },
    },
  },
  plugins: [],
};
export default config;

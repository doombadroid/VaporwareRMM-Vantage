import "./globals.css";
import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "VaporwareRMM Vantage",
  description: "Federation control server for VaporwareRMM Edge appliances",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}

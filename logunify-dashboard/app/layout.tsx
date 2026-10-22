import type { Metadata } from "next";
import AppShell from "@/components/AppShell";
import "./globals.css";

// A nonce-based CSP needs the HTML rendered per request, not prerendered at build time.
export const dynamic = "force-dynamic";

export const metadata: Metadata = {
  title: "LogUnify SOC Console",
  description: "Security operations dashboard for the LogUnify log pre-processing pipeline",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <body>
        <a
          href="#main"
          className="sr-only focus:not-sr-only focus:fixed focus:left-2 focus:top-2 focus:z-50 focus:rounded focus:bg-accent focus:px-3 focus:py-2 focus:text-bg"
        >
          Skip to content
        </a>
        <AppShell>{children}</AppShell>
      </body>
    </html>
  );
}

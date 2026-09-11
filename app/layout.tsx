import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "SentinelGraph | AI Cyber Defense Simulation",
  description: "AI-powered cyberattack simulation and Security Operations Center (SOC) defensive response platform",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="h-full dark">
      <body className="min-h-full flex flex-col bg-[#090d16] text-slate-100 antialiased bg-grid-pattern">
        {children}
      </body>
    </html>
  );
}

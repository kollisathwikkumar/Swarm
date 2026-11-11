import type { Metadata, Viewport } from "next";
import { JetBrains_Mono, Manrope } from "next/font/google";
import { AppShell } from "@/components/AppShell";
import "./globals.css";

const manrope = Manrope({
  subsets: ["latin"],
  variable: "--font-manrope",
  display: "swap",
});

const jetbrainsMono = JetBrains_Mono({
  subsets: ["latin"],
  variable: "--font-jetbrains-mono",
  display: "swap",
});

export const metadata: Metadata = {
  title: "Swarm — Multi-Agent Automated Code Review",
  description:
    "AI-powered multi-agent code review workbench combining Fan-Out/Fan-In DeepSeek analysis, deterministic security scanners, cross-file test mapping, and syntax-verified patches.",
};

export const viewport: Viewport = {
  colorScheme: "light dark",
};

const FOUC_SCHEME_SCRIPT = `
try {
  var pref = localStorage.getItem("rb_color_scheme");
  var meta = document.querySelector('meta[name="color-scheme"]');
  if (pref === "light" || pref === "dark") {
    if (meta) meta.content = pref;
    document.documentElement.classList.toggle("dark", pref === "dark");
    document.documentElement.setAttribute("data-theme", pref);
  } else {
    if (meta) meta.content = "light dark";
    var osDark = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
    document.documentElement.classList.toggle("dark", !!osDark);
    document.documentElement.setAttribute("data-theme", osDark ? "dark" : "light");
  }
} catch (e) {}
`;

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html
      lang="en"
      className={`${manrope.variable} ${jetbrainsMono.variable}`}
      suppressHydrationWarning
    >
      <head>
        <meta name="color-scheme" content="light dark" />
        <script dangerouslySetInnerHTML={{ __html: FOUC_SCHEME_SCRIPT }} />
      </head>
      <body>
        <AppShell>{children}</AppShell>
      </body>
    </html>
  );
}

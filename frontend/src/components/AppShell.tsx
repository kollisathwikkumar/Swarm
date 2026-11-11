"use client";

import React from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { Menu, Moon, Sun } from "lucide-react";
import { useResolvedTheme } from "@/lib/theme";
import LiquidNavbar, { NimbusIcons, type LiquidNavItem } from "@/components/ui/liquid-navbar";

const NAV_ITEMS: LiquidNavItem[] = [
  { href: "/", label: "Dashboard", icon: NimbusIcons.home, fx: "glow" },
  { href: "/repositories", label: "Repositories", icon: NimbusIcons.folder, fx: "pop" },
  { href: "/reviews/submit", label: "Submit Review", icon: NimbusIcons.plane, fx: "plane" },
  { href: "/agents", label: "Agent Activity", icon: NimbusIcons.wave, fx: "wave" },
  { href: "/patches", label: "Fix Suggestions", icon: NimbusIcons.wrench, fx: "pop" },
  { href: "/history", label: "Review History", icon: NimbusIcons.history, fx: "spin" },
  { href: "/analytics", label: "Analytics", icon: NimbusIcons.drop, fx: "drop" },
  { href: "/architecture", label: "Project Guide", icon: NimbusIcons.guide, fx: "glow" },
  { href: "/settings", label: "Settings", icon: NimbusIcons.settings, fx: "spin" },
];

function resolveActiveIndex(pathname: string): number {
  if (pathname === "/") return 0;
  if (pathname.startsWith("/repositories")) return 1;
  if (pathname.startsWith("/reviews/submit")) return 2;
  if (pathname.startsWith("/reviews/")) return 3;
  const idx = NAV_ITEMS.findIndex(
    (item) => item.href && item.href !== "/" && pathname.startsWith(item.href)
  );
  return idx >= 0 ? idx : 0;
}

export function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname() || "/";
  const { resolved, pref, toggleOpposite } = useResolvedTheme();
  const activeIndex = resolveActiveIndex(pathname);

  return (
    <div className="flex min-h-dvh flex-col">
      <a href="#main-content" className="skip-link visually-hidden">
        Skip to main content
      </a>

      {/* Sticky Top Navigation Shell with Nimbus Liquid Glass Navbar across all pages */}
      <header className="sticky top-0 z-40 border-b border-border/80 bg-background/85 backdrop-blur-md">
        <div className="mx-auto flex w-full max-w-[1480px] flex-wrap items-center justify-between gap-x-5 gap-y-3.5 px-4 py-4 md:px-6 min-[1360px]:flex-nowrap">
          {/* Brand Identity */}
          <Link
            href="/"
            className="order-1 flex shrink-0 items-center gap-2.5 rounded-xl border border-border bg-card/90 px-3 py-1.5 transition-colors hover:border-foreground/40"
          >
            <img
              src="/swarm-logo.png"
              alt="Swarm logo"
              width={28}
              height={28}
              className="h-7 w-7 shrink-0 object-contain dark:invert"
            />
            <span className="text-sm font-bold tracking-tight">Swarm</span>
          </Link>

          {/* Centered Top Liquid Glass Navbar (spacious py-1 so PAD=14 ripples never clip) */}
          <div className="order-3 flex w-full justify-center py-1 min-[1360px]:order-2 min-[1360px]:w-auto min-[1360px]:flex-1 min-[1360px]:min-w-0">
            <LiquidNavbar
              items={NAV_ITEMS}
              active={activeIndex}
              tone={resolved === "dark" ? "dark" : "light"}
            />
          </div>

          {/* Right Controls: Theme Switcher + Compact Full-Label Popover on narrower screens */}
          <div className="order-2 flex shrink-0 items-center gap-2 min-[1360px]:order-3">
            <button
              type="button"
              onClick={toggleOpposite}
              aria-label={`Switch to ${resolved === "dark" ? "light" : "dark"} theme`}
              title={pref === "system" ? `System (${resolved}) — click to toggle` : `${pref} locked — click to toggle`}
              className="flex min-h-10 min-w-10 shrink-0 items-center justify-center rounded-xl border border-border bg-card/90 text-foreground transition-colors hover:border-foreground/40"
            >
              {resolved === "dark" ? (
                <Sun className="h-4 w-4" aria-hidden="true" />
              ) : (
                <Moon className="h-4 w-4" aria-hidden="true" />
              )}
            </button>

            <button
              type="button"
              popoverTarget="rb-nav-popover"
              popoverTargetAction="toggle"
              aria-controls="rb-nav-popover"
              className="inline-flex min-h-10 items-center gap-1.5 rounded-xl border border-border bg-card/90 px-3 text-xs font-medium text-foreground transition-colors hover:border-foreground/40 min-[1081px]:hidden"
            >
              <Menu className="h-4 w-4" aria-hidden="true" />
              <span>Menu</span>
            </button>

            <nav
              id="rb-nav-popover"
              popover="auto"
              aria-label="Full navigation index"
              className="rb-nav-popover"
            >
              <p className="px-2.5 py-1.5 font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
                Swarm Routes
              </p>
              <ul className="space-y-1">
                {NAV_ITEMS.map((item, idx) => (
                  <li key={item.href || item.label}>
                    <Link
                      href={item.href || "/"}
                      aria-current={idx === activeIndex ? "page" : undefined}
                      onClick={() => {
                        const pop = document.getElementById("rb-nav-popover") as
                          | (HTMLElement & { hidePopover?: () => void })
                          | null;
                        pop?.hidePopover?.();
                      }}
                      className="nav-link flex min-h-10 items-center gap-2.5 rounded-lg px-3 py-2 text-sm text-muted-foreground transition-colors hover:bg-muted hover:text-foreground"
                    >
                      <span className="shrink-0">{item.icon}</span>
                      <span>{item.label}</span>
                    </Link>
                  </li>
                ))}
              </ul>
            </nav>
          </div>
        </div>
      </header>

      {/* Full-width Main Content */}
      <main id="main-content" tabIndex={-1} className="min-w-0 flex-1 p-4 md:p-6 lg:p-8">
        <div className="mx-auto max-w-[1440px]">{children}</div>
      </main>
    </div>
  );
}

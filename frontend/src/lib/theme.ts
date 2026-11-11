"use client";

import { useEffect, useState } from "react";

export type ColorSchemePref = "system" | "light" | "dark";

const STORAGE_KEY = "rb_color_scheme";

export function applyColorScheme(pref: ColorSchemePref) {
  if (typeof document === "undefined") return;
  const meta = document.querySelector<HTMLMetaElement>('meta[name="color-scheme"]');
  const contentVal = pref === "system" ? "light dark" : pref;
  if (meta) meta.content = contentVal;

  try {
    if (pref === "system") {
      localStorage.removeItem(STORAGE_KEY);
    } else {
      localStorage.setItem(STORAGE_KEY, pref);
    }
  } catch {
    // ignore storage errors
  }

  const osDark =
    typeof window !== "undefined" &&
    window.matchMedia?.("(prefers-color-scheme: dark)").matches;
  const resolvedDark = pref === "dark" || (pref === "system" && osDark);
  document.documentElement.classList.toggle("dark", resolvedDark);
  document.documentElement.setAttribute("data-theme", resolvedDark ? "dark" : "light");
  window.dispatchEvent(new CustomEvent("rb-theme-change", { detail: { pref, resolvedDark } }));
}

export function useResolvedTheme(): {
  pref: ColorSchemePref;
  resolved: "light" | "dark";
  setPref: (next: ColorSchemePref) => void;
  toggleOpposite: () => void;
} {
  const [pref, setPrefState] = useState<ColorSchemePref>("system");
  const [resolved, setResolved] = useState<"light" | "dark">("dark");

  useEffect(() => {
    const compute = () => {
      let stored: string | null = null;
      try {
        stored = localStorage.getItem(STORAGE_KEY);
      } catch {
        stored = null;
      }
      const nextPref: ColorSchemePref =
        stored === "light" || stored === "dark" ? stored : "system";
      const osDark = window.matchMedia?.("(prefers-color-scheme: dark)").matches ?? true;
      const isDark = nextPref === "dark" || (nextPref === "system" && osDark);
      setPrefState(nextPref);
      setResolved(isDark ? "dark" : "light");
    };

    compute();
    const mq = window.matchMedia?.("(prefers-color-scheme: dark)");
    const onChange = () => compute();
    const onStorage = (e: StorageEvent) => {
      if (e.key === STORAGE_KEY) compute();
    };
    mq?.addEventListener?.("change", onChange);
    window.addEventListener("rb-theme-change", onChange);
    window.addEventListener("storage", onStorage);
    return () => {
      mq?.removeEventListener?.("change", onChange);
      window.removeEventListener("rb-theme-change", onChange);
      window.removeEventListener("storage", onStorage);
    };
  }, []);

  const setPref = (next: ColorSchemePref) => {
    applyColorScheme(next);
  };

  const toggleOpposite = () => {
    const osDark = window.matchMedia?.("(prefers-color-scheme: dark)").matches ?? true;
    const osTheme: "light" | "dark" = osDark ? "dark" : "light";
    const target: "light" | "dark" = resolved === "dark" ? "light" : "dark";
    applyColorScheme(target === osTheme ? "system" : target);
  };

  return { pref, resolved, setPref, toggleOpposite };
}

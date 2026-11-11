"use client";

import React from "react";
import type { AgentRunItem } from "@/lib/types";

export interface WorkflowBentoProps {
  theme?: "light" | "dark" | "auto";
  brand?: string;
  tag?: string;
  title?: string;
  agentRuns?: AgentRunItem[];
  liveMessages?: Record<string, string>;
  reportCount?: number;
  findingsCount?: number;
  patchCount?: number;
  rejectedFalsePositivesCount?: number;
  scannerNames?: string[];
  timelineValues?: number[];
  timelineLabels?: string[];
  className?: string;
  style?: React.CSSProperties;
}

function clamp(v: number, a: number, b: number): number {
  return Math.min(b, Math.max(a, v));
}

function chartPaths(values: number[], w: number, h: number, pad: number) {
  const n = values.length;
  const lo = Math.min(...values);
  const hi = Math.max(...values);
  const span = hi - lo || 1;
  const pts = values.map(
    (v, i) =>
      [
        pad + (n < 2 ? 0 : (i / (n - 1)) * (w - pad * 2)),
        h - pad - ((v - lo) / span) * (h - pad * 2),
      ] as [number, number]
  );
  let line = "";
  pts.forEach(([x, y], i) => {
    if (i === 0) {
      line = "M" + x.toFixed(1) + "," + y.toFixed(1);
      return;
    }
    const [px, py] = pts[i - 1];
    const cx = (px + x) / 2;
    line +=
      " C" +
      cx.toFixed(1) +
      "," +
      py.toFixed(1) +
      " " +
      cx.toFixed(1) +
      "," +
      y.toFixed(1) +
      " " +
      x.toFixed(1) +
      "," +
      y.toFixed(1);
  });
  const area = n
    ? line +
      " L" +
      pts[n - 1][0].toFixed(1) +
      "," +
      (h - pad) +
      " L" +
      pts[0][0].toFixed(1) +
      "," +
      (h - pad) +
      " Z"
    : "";
  return { line, area, points: pts };
}

function nearestIndex(xs: number[], x: number): number {
  let best = 0;
  for (let i = 1; i < xs.length; i++) if (Math.abs(xs[i] - x) < Math.abs(xs[best] - x)) best = i;
  return best;
}

function parseTitle(s: string): { text: string; muted: boolean }[][] {
  return s.split(/\n|\\n/).map((line) => {
    const out: { text: string; muted: boolean }[] = [];
    line.split("*").forEach((text, i) => {
      if (text) out.push({ text, muted: i % 2 === 1 });
    });
    return out;
  });
}

function useInView(threshold = 0.15) {
  const ref = React.useRef<HTMLDivElement | null>(null);
  const [inView, setInView] = React.useState(false);
  React.useEffect(() => {
    const el = ref.current;
    if (!el || inView) return;
    if (typeof IntersectionObserver !== "function") {
      setInView(true);
      return;
    }
    const io = new IntersectionObserver(
      (es) => {
        if (es.some((e) => e.isIntersecting)) {
          setInView(true);
          io.disconnect();
        }
      },
      { threshold }
    );
    io.observe(el);
    return () => io.disconnect();
  }, [inView, threshold]);
  return [ref, inView] as const;
}

function Brackets() {
  return (
    <>
      <span className="ib-c ib-c-tl" aria-hidden="true" />
      <span className="ib-c ib-c-tr" aria-hidden="true" />
      <span className="ib-c ib-c-bl" aria-hidden="true" />
      <span className="ib-c ib-c-br" aria-hidden="true" />
    </>
  );
}

function Title({ text }: { text: string }) {
  return (
    <h2 className="ib-h2">
      {parseTitle(text).map((line, i) => (
        <span key={i}>
          {line.map((run, j) => (
            <React.Fragment key={j}>
              {run.muted ? (
                <span className="ib-muted" style={{ display: "inline" }}>
                  {run.text}
                </span>
              ) : (
                run.text
              )}
            </React.Fragment>
          ))}
        </span>
      ))}
    </h2>
  );
}

function ReviewMark({ size = 18 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" aria-hidden="true">
      <path
        d="M12 2.5L4 6v5.5c0 5.1 3.4 9.7 8 11 4.6-1.3 8-5.9 8-11V6l-8-3.5zm-1.1 13.3l-3.2-3.2 1.4-1.4 1.8 1.8 4.2-4.2 1.4 1.4-5.6 5.6z"
        fill="currentColor"
      />
    </svg>
  );
}

function AgentGlyph({ kind }: { kind: string }) {
  if (kind === "diff_agent") {
    return (
      <g fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
        <path d="M-5 -6h6l4 4v8h-10z" />
        <path d="M-2 0h4M0 -2v4" />
      </g>
    );
  }
  if (kind === "style_agent") {
    return (
      <g fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
        <path d="M-5 5l8-8 2 2-8 8-3 1z" />
        <path d="M1 -5l4 4" />
      </g>
    );
  }
  if (kind === "security_agent") {
    return (
      <g fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
        <path d="M0 -6.5L5.5 -4v4c0 3.5-2.3 6-5.5 7-3.2-1-5.5-3.5-5.5-7v-4z" />
      </g>
    );
  }
  return (
    <g fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M-2.5 -6h5M-1.5 -6v3.5L-5.5 5.5h11L1.5 -2.5V-6" />
    </g>
  );
}

function ScannerGlyph({ index }: { index: number }) {
  const k = index % 4;
  return (
    <g fill="none" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round">
      {k === 0 && (
        <>
          <path d="M0 -6L5 -3.5v3.5C5 3 2.8 5.2 0 6-2.8 5.2-5 3-5 0v-3.5z" />
          <path d="M-2 0l1.4 1.4 2.8-2.8" />
        </>
      )}
      {k === 1 && (
        <>
          <rect x="-5.5" y="-5" width="11" height="10" rx="1.5" />
          <path d="M-2.5 0h5M-2.5 -2.5h5M-2.5 2.5h3" />
        </>
      )}
      {k === 2 && (
        <>
          <circle cx="-1" cy="-1" r="4.2" />
          <path d="M2.2 2.2 5.8 5.8" />
        </>
      )}
      {k === 3 && (
        <>
          <path d="M-5 -5h10v10h-10z" />
          <path d="M-2 0l1.5 1.5L3 -2" />
        </>
      )}
    </g>
  );
}

function statusDotColor(status?: string): string {
  if (status === "completed") return "#22c55e";
  if (status === "running") return "#38bdf8";
  if (status === "incomplete" || status === "failed") return "#f59e0b";
  return "var(--ib-faint)";
}

function FlowCard({
  brand,
  uid,
  reduced,
  inView,
  agentRuns,
  liveMessages,
  reportCount,
  findingsCount,
  patchCount,
  rejectedCount,
}: {
  brand: string;
  uid: string;
  reduced: boolean;
  inView: boolean;
  agentRuns: AgentRunItem[];
  liveMessages: Record<string, string>;
  reportCount: number;
  findingsCount: number;
  patchCount: number;
  rejectedCount: number;
}) {
  const [side, setSide] = React.useState<"" | "left" | "right">("");
  const byName = new Map<string, AgentRunItem>();
  for (const r of agentRuns) byName.set(r.agent_name, r);

  const fanOutNodes = [
    { key: "diff_agent", label: "Diff Agent", short: "DIFF · AST", x: 52, y: 34 },
    { key: "style_agent", label: "Style Agent", short: "STYLE · SYNTAX", x: 146, y: 34 },
    { key: "security_agent", label: "Security Agent", short: "SEC · GUARDS", x: 52, y: 112 },
    { key: "test_coverage_agent", label: "Test-Coverage", short: "TEST · MAP", x: 146, y: 112 },
  ];

  const L1 = "M114,70 C190,70 212,99 258,99";
  const L2 = "M114,76 C186,76 210,119 258,119";
  const R1 = "M382,99 C414,99 422,86 452,86";
  const R2 = "M382,119 C414,119 422,134 452,134";

  const chip = (byName.get("reviewer_manager")?.status === "running"
    ? "VERIFYING"
    : brand.split(" ")[0]
  ).toUpperCase();
  const chipLong = chip.length * 6.5 > 64;
  const rays = uid + "rays";
  const glow = uid + "glow";

  const activeRunLabel = (nodeKey: string, fallback: string) => {
    const run = byName.get(nodeKey);
    const live = liveMessages[nodeKey];
    if (live) return `${fallback}: ${live.slice(0, 34)}`;
    if (!run) return fallback;
    if (run.duration_ms > 0) return `${fallback} (${run.model_used} · ${run.duration_ms}ms)`;
    return `${fallback} (${run.status})`;
  };

  return (
    <div className="ib-frame ib-frame-hover ib-wide">
      <Brackets />
      <div className="ib-card" style={{ padding: 0, overflow: "hidden" }}>
        <svg
          className="ib-diagram"
          viewBox="0 0 640 184"
          role="img"
          aria-label="Six-agent Fan-Out analysis converging into Reviewer Manager verification and verified Fix-Suggestion reports"
        >
          <defs>
            <radialGradient id={glow} cx="320" cy="110" r="190" gradientUnits="userSpaceOnUse">
              <stop offset="0" stopColor="var(--ib-raise)" stopOpacity="1" />
              <stop offset="1" stopColor="var(--ib-raise)" stopOpacity="0" />
            </radialGradient>
            <linearGradient id={rays} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0" stopColor="var(--ib-line-strong)" stopOpacity=".55" />
              <stop offset="1" stopColor="var(--ib-line-strong)" stopOpacity="0" />
            </linearGradient>
          </defs>
          <rect x="0" y="0" width="640" height="184" fill={`url(#${glow})`} />
          {[-62, -38, -14, 14, 38, 62].map((a, i) => {
            const x1 = (320 + Math.sin((a * Math.PI) / 180) * 260).toFixed(2);
            const y1 = (110 - Math.cos((a * Math.PI) / 180) * 260).toFixed(2);
            const x2 = (320 + Math.sin(((a + 7) * Math.PI) / 180) * 260).toFixed(2);
            const y2 = (110 - Math.cos(((a + 7) * Math.PI) / 180) * 260).toFixed(2);
            return (
              <path
                key={i}
                d={`M320,110 L${x1},${y1} L${x2},${y2}Z`}
                fill={`url(#${rays})`}
                opacity=".45"
              />
            );
          })}

          {/* 4 Fan-Out Analysis Engines Cluster */}
          <g onMouseEnter={() => setSide("left")} onMouseLeave={() => setSide("")}>
            <rect x="16" y="8" width="174" height="142" fill="transparent" />
            {fanOutNodes.map((n) => (
              <line
                key={"wire-" + n.key}
                x1={n.x}
                y1={n.y}
                x2="99"
                y2="73"
                stroke="var(--ib-line-strong)"
                strokeDasharray="2 3"
              />
            ))}
            <g transform="translate(86,60)">
              <rect width="26" height="26" rx="5" className="ib-node" />
              <g transform="translate(5,5)" style={{ color: "var(--ib-ink)" }}>
                <ReviewMark size={16} />
              </g>
            </g>
            {fanOutNodes.map((n) => {
              const run = byName.get(n.key);
              const tip = activeRunLabel(n.key, n.label);
              const dot = statusDotColor(run?.status);
              const pulsing = run?.status === "running" || (run?.status === "completed" && inView);
              return (
                <g key={n.key} className="ib-av" tabIndex={0} role="img" aria-label={tip}>
                  <g transform={`translate(${n.x - 13},${n.y - 13})`}>
                    <rect width="26" height="26" rx="6" className="ib-node" />
                    <g transform="translate(13,13)" style={{ color: "var(--ib-ink)" }}>
                      <AgentGlyph kind={n.key} />
                    </g>
                  </g>
                  <circle
                    cx={n.x + 11}
                    cy={n.y + 11}
                    r="3"
                    fill={dot}
                    stroke="var(--ib-paper)"
                    strokeWidth="1.2"
                    className={!reduced && pulsing ? "ib-presence" : undefined}
                  />
                  <text
                    x={n.x}
                    y={n.y + 23}
                    textAnchor="middle"
                    fontSize="6.5"
                    letterSpacing="0.7"
                    fill="var(--ib-muted)"
                    fontFamily="var(--ib-mono)"
                  >
                    {n.short}
                  </text>
                  <g className="ib-av-tip" transform={`translate(${Math.max(76, n.x)},${n.y - 20})`}>
                    <rect
                      x={-Math.min(180, tip.length * 4.5 + 14) / 2}
                      y="-9"
                      width={Math.min(180, tip.length * 4.5 + 14)}
                      height="15"
                      rx="3"
                      fill="var(--ib-inv)"
                    />
                    <text
                      x="0"
                      y="1"
                      textAnchor="middle"
                      fontSize="7"
                      fill="var(--ib-inv-ink)"
                      fontFamily="var(--ib-mono)"
                    >
                      {tip.slice(0, 36)}
                    </text>
                  </g>
                </g>
              );
            })}
          </g>

          {/* Fan-Out / Fan-In Streams */}
          {[L1, L2].map((d, i) => (
            <path
              key={d}
              d={d}
              className={"ib-flow" + (side === "left" ? " ib-flow-on" : "") + (i ? " ib-dash" : "")}
            />
          ))}
          {[R1, R2].map((d, i) => (
            <path
              key={d}
              d={d}
              className={"ib-flow" + (side === "right" ? " ib-flow-on" : "") + (i ? " ib-dash" : "")}
            />
          ))}
          {!reduced &&
            [L1, L2, R1, R2].map((d, i) => (
              <circle key={"p" + i} r="2.2" className="ib-pkt">
                <animateMotion
                  dur={`${2.2 + (i % 2) * 0.55}s`}
                  begin={`${i * 0.35}s`}
                  repeatCount="indefinite"
                  path={d}
                />
              </circle>
            ))}

          {/* Fan-In Verification Hub */}
          <g transform="translate(258,86)">
            <rect
              x="-4"
              y="-4"
              width="132"
              height="52"
              rx="8"
              fill="none"
              stroke="var(--ib-line)"
              className={reduced ? undefined : "ib-glow"}
            />
            <rect
              width="124"
              height="44"
              rx="6"
              className="ib-node"
              style={{ filter: "drop-shadow(0 6px 10px rgba(0,0,0,.08))" }}
            />
            <g transform="translate(12,14)" style={{ color: "var(--ib-ink)" }}>
              <ReviewMark size={16} />
            </g>
            <text
              x="35"
              y="22"
              fontSize="8"
              letterSpacing="1.1"
              fontWeight="700"
              fill="var(--ib-ink)"
              fontFamily="var(--ib-sans)"
              textLength={chipLong ? 66 : undefined}
              lengthAdjust={chipLong ? "spacingAndGlyphs" : undefined}
            >
              {chip}
            </text>
            <text x="35" y="32" fontSize="6.5" fill="var(--ib-muted)" fontFamily="var(--ib-mono)">
              FAN-IN GATE
            </text>
            <path d="M108 18l4 4-4 4" fill="none" stroke="var(--ib-muted)" strokeWidth="1.3" />
          </g>

          {/* Verified Report Stack + Patch Count */}
          <g onMouseEnter={() => setSide("right")} onMouseLeave={() => setSide("")}>
            {[2, 1, 0].map((k) => (
              <g
                key={k}
                transform={`translate(${452 + k * 11},${42 - k * 9})`}
                opacity={1 - k * 0.24}
              >
                <g className={"ib-sheet" + (k === 0 ? " ib-sheet-new" : "")}>
                  <rect width="142" height="104" rx="4" fill="var(--ib-raise)" stroke="var(--ib-line-strong)" />
                  {k === 0 && (
                    <>
                      <text x="10" y="16" fontSize="7" fill="var(--ib-muted)" fontFamily="var(--ib-mono)">
                        {`REPORT #${Math.max(1, reportCount)} · ${findingsCount} FINDINGS`}
                      </text>
                      <rect x="10" y="24" width="76" height="5" rx="1" fill="var(--ib-ink)" opacity=".8" />
                      <text x="10" y="38" fontSize="6.5" fill="var(--ib-soft)" fontFamily="var(--ib-mono)">
                        {`PATCHES VERIFIED: ${patchCount} · FILTERED FP: ${rejectedCount}`}
                      </text>
                      {[20, 32, 16, 28, 22, 34].map((h, j) => (
                        <rect
                          key={j}
                          x={12 + j * 13}
                          y={94 - h}
                          width="8"
                          height={h}
                          fill="var(--ib-ink)"
                          opacity={0.25 + j * 0.12}
                        />
                      ))}
                      <path d="M96 66h34M96 74h28M96 82h32" stroke="var(--ib-line-strong)" strokeWidth="2.5" />
                    </>
                  )}
                </g>
              </g>
            ))}
          </g>
        </svg>

        <div className="ib-wide-copy" style={{ padding: "0 22px 20px" }}>
          <div>
            <h3>Fan-Out Specialists + Adversarial Verification</h3>
            <p>
              Four parallel agents inspect diffs, code quality, security vulnerabilities, and cross-file
              test mappings using complete workspace files, then converge into the Reviewer Manager gate.
            </p>
          </div>
          <div>
            <h3>Syntax-Validated Patch Reports</h3>
            <p>
              Contradicted LLM hallucinations are filtered out deterministically, and Fix-Suggestion
              patches are validated by both <code>git apply --check</code> and language parsers.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

function ScannersHubCard({
  scanners,
  reduced,
}: {
  scanners: string[];
  reduced: boolean;
}) {
  const [hover, setHover] = React.useState(-1);
  const [auto, setAuto] = React.useState(0);
  const tools = scanners.length >= 4 ? scanners.slice(0, 4) : ["Semgrep + Guards", "Gitleaks + OSV", "Pytest + Test-Map", "AST + TS Syntax"];

  React.useEffect(() => {
    if (reduced || hover >= 0) return;
    const t = setInterval(() => setAuto((a) => (a + 1) % 4), 1700);
    return () => clearInterval(t);
  }, [reduced, hover]);

  const on = hover >= 0 ? hover : reduced ? -1 : auto;
  const tiles = [
    { x: 66, y: 34 },
    { x: 66, y: 116 },
    { x: 234, y: 34 },
    { x: 234, y: 116 },
  ];
  const path = (i: number) => {
    const t = tiles[i];
    const dir = t.x < 150 ? -1 : 1;
    return `M${150 + dir * 17},75 H${150 + dir * 42} V${t.y} H${t.x - dir * 15}`;
  };

  return (
    <div className="ib-frame ib-frame-hover">
      <Brackets />
      <div className="ib-card">
        <svg className="ib-diagram" viewBox="0 0 300 150" role="group" aria-label="Deterministic Scanner & Verification Engines">
          {tiles.map((_, i) => (
            <path key={i} d={path(i)} className={"ib-flow" + (on === i ? " ib-flow-on" : "")} />
          ))}
          {!reduced && on >= 0 && (
            <circle key={on} r="2.2" className="ib-pkt">
              <animateMotion dur="1.1s" repeatCount="indefinite" path={path(on)} />
            </circle>
          )}
          <g transform="translate(133,58)">
            <rect
              width="34"
              height="34"
              rx="7"
              className="ib-node"
              style={{ filter: "drop-shadow(0 4px 8px rgba(0,0,0,.08))" }}
            />
            <g transform="translate(8,8)" style={{ color: "var(--ib-ink)" }}>
              <ReviewMark size={18} />
            </g>
          </g>
          {tiles.map((t, i) => (
            <g
              key={i}
              className={"ib-tool" + (on === i ? " ib-tool-on" : "")}
              tabIndex={0}
              role="img"
              aria-label={tools[i]}
              onMouseEnter={() => setHover(i)}
              onMouseLeave={() => setHover(-1)}
              onFocus={() => setHover(i)}
              onBlur={() => setHover(-1)}
            >
              <rect x={t.x - 15} y={t.y - 15} width="30" height="30" rx="6" className="ib-node" />
              <g transform={`translate(${t.x},${t.y})`} style={{ color: "var(--ib-ink)" }}>
                <ScannerGlyph index={i} />
              </g>
              <text
                x={t.x}
                y={t.y + (t.y < 75 ? -21 : 28)}
                textAnchor="middle"
                fontSize="7.5"
                fill="var(--ib-muted)"
                fontFamily="var(--ib-mono)"
                opacity={on === i ? 1 : 0}
                style={{ transition: "opacity .25s" }}
              >
                {tools[i]}
              </text>
            </g>
          ))}
          <text x="150" y="114" textAnchor="middle" fontSize="7" fill="var(--ib-faint)" fontFamily="var(--ib-mono)">
            {on >= 0 ? `verified · ${(tools[on] ?? "").toLowerCase()}` : `${tools.length} engines online`}
          </text>
        </svg>
        <div style={{ marginTop: "auto" }}>
          <h3>Deterministic Verification Engines</h3>
          <p>
            Semgrep, Bandit, Gitleaks, OSV-Scanner, Node TS syntax parser, and cross-file test-import
            mapping anchor every Verified verdict in reproducible evidence.
          </p>
        </div>
      </div>
    </div>
  );
}

function ReviewSignalChartCard({
  values,
  labels,
  uid,
  reduced,
}: {
  values: number[];
  labels?: string[];
  uid: string;
  reduced: boolean;
}) {
  const [ref, inView] = useInView(0.25);
  const [hover, setHover] = React.useState(-1);
  const W = 300;
  const H = 130;
  const hasRealSeries = values.length > 0;
  const vals = values.length >= 2 ? values : values.length === 1 ? [values[0], values[0]] : [0, 0];
  const { line, area, points } = chartPaths(vals, W, H, 14);
  const split = Math.max(1, vals.length - 1);
  const fill = uid + "area";
  const last = points[points.length - 1];
  const i = hover >= 0 ? hover : points.length - 1;
  const p = points[i];

  const onMove = (e: React.PointerEvent<SVGSVGElement>) => {
    const r = e.currentTarget.getBoundingClientRect();
    setHover(nearestIndex(points.map((q) => q[0]), ((e.clientX - r.left) / r.width) * W));
  };

  return (
    <div className="ib-frame ib-frame-hover" ref={ref} data-in={inView}>
      <Brackets />
      <div className="ib-card">
        <svg
          className="ib-diagram ib-chart"
          viewBox={`0 0 ${W} ${H + 6}`}
          onPointerMove={onMove}
          onPointerLeave={() => setHover(-1)}
          role="img"
          aria-label="Live Review & Findings Signal Chart"
        >
          <defs>
            <linearGradient id={fill} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0" stopColor="var(--ib-ink)" stopOpacity=".14" />
              <stop offset="1" stopColor="var(--ib-ink)" stopOpacity="0" />
            </linearGradient>
          </defs>
          {[0.25, 0.5, 0.75].map((g) => (
            <line key={g} x1="14" x2={W - 14} y1={H * g} y2={H * g} stroke="var(--ib-line)" />
          ))}
          {hasRealSeries ? (
            <>
              <path d={area} fill={`url(#${fill})`} />
              <path
                d={line}
                fill="none"
                stroke="var(--ib-ink)"
                strokeWidth="1.5"
                pathLength={1}
                className="ib-line-draw"
                opacity=".88"
              />
              {points[split] && (
                <line
                  x1={points[split][0]}
                  x2={points[split][0]}
                  y1="10"
                  y2={H - 14}
                  stroke="var(--ib-line-strong)"
                  strokeDasharray="2 3"
                />
              )}
              {hover >= 0 && <line x1={p[0]} x2={p[0]} y1="8" y2={H - 14} stroke="var(--ib-ink)" strokeOpacity=".35" />}
              {!reduced && hover < 0 && (
                <circle cx={last[0]} cy={last[1]} r="7" fill="var(--ib-ink)" opacity=".15" className="ib-glow" />
              )}
              <circle cx={p[0]} cy={p[1]} r="3.2" fill="var(--ib-raise)" stroke="var(--ib-ink)" strokeWidth="1.5" />
              <g transform={`translate(${clamp(p[0], 48, W - 48)},${p[1] < 34 ? p[1] + 22 : p[1] - 12})`}>
                <rect x="-38" y="-11" width="76" height="15" rx="2" fill="var(--ib-inv)" />
                <text x="0" y="-1" textAnchor="middle" fontSize="7.2" fill="var(--ib-inv-ink)" fontFamily="var(--ib-mono)">
                  {`${labels?.[i] || `run ${i + 1}`}: ${vals[i]}`}
                </text>
              </g>
            </>
          ) : (
            <text x={W / 2} y={H / 2} textAnchor="middle" fontSize="8.5" fill="var(--ib-muted)" fontFamily="var(--ib-mono)">
              NO RECORDED RUNS YET (ZERO FAKE METRICS)
            </text>
          )}
        </svg>
        <div style={{ marginTop: "auto" }}>
          <h3>Real-Time Verification Telemetry</h3>
          <p>
            Scrub across live database review runs to inspect findings density and model decisions—100%
            computed from recorded runs with zero synthetic placeholder data.
          </p>
        </div>
      </div>
    </div>
  );
}

export default function SmartWorkflowAutomation({
  theme = "auto",
  brand = "SWARM",
  tag = "6-Agent Orchestration",
  title = "Smart *Workflow*\nAutomation",
  agentRuns = [],
  liveMessages = {},
  reportCount = 0,
  findingsCount = 0,
  patchCount = 0,
  rejectedFalsePositivesCount = 0,
  scannerNames = ["Semgrep + Guards", "Gitleaks + OSV", "Pytest + Test-Map", "AST + TS Syntax"],
  timelineValues = [],
  timelineLabels,
  className = "",
  style,
}: WorkflowBentoProps) {
  const uid = "ib" + React.useId().replace(/[^a-zA-Z0-9]/g, "");
  const [dark, setDark] = React.useState(theme === "dark");
  const [reduced, setReduced] = React.useState(false);

  React.useEffect(() => {
    const sync = () => {
      const motionReduced =
        typeof window !== "undefined" &&
        window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
      setReduced(Boolean(motionReduced));
      if (theme === "dark" || theme === "light") {
        setDark(theme === "dark");
        return;
      }
      const attr = document.documentElement.getAttribute("data-theme");
      if (attr === "dark" || attr === "light") {
        setDark(attr === "dark");
      } else {
        setDark(Boolean(window.matchMedia?.("(prefers-color-scheme: dark)").matches));
      }
    };
    sync();
    const mq = window.matchMedia?.("(prefers-color-scheme: dark)");
    const mm = window.matchMedia?.("(prefers-reduced-motion: reduce)");
    mq?.addEventListener?.("change", sync);
    mm?.addEventListener?.("change", sync);
    window.addEventListener("rb-theme-change", sync);
    return () => {
      mq?.removeEventListener?.("change", sync);
      mm?.removeEventListener?.("change", sync);
      window.removeEventListener("rb-theme-change", sync);
    };
  }, [theme]);

  const [featRef, featIn] = useInView(0.1);

  return (
    <div className={"ib-root " + className} data-theme={dark ? "dark" : "light"} style={style}>
      <div className="ib-shell">
        <section className="ib-sec" aria-labelledby={uid + "feat"}>
          <div className="ib-reveal" ref={featRef} data-in={featIn}>
            <div className="ib-head" id={uid + "feat"}>
              {tag && <span className="ib-tag">{tag}</span>}
              <Title text={title} />
            </div>
            <div className="ib-bento">
              <FlowCard
                brand={brand}
                uid={uid}
                reduced={reduced}
                inView={featIn}
                agentRuns={agentRuns}
                liveMessages={liveMessages}
                reportCount={reportCount}
                findingsCount={findingsCount}
                patchCount={patchCount}
                rejectedCount={rejectedFalsePositivesCount}
              />
              <ScannersHubCard scanners={scannerNames} reduced={reduced} />
              <ReviewSignalChartCard
                values={timelineValues}
                labels={timelineLabels}
                uid={uid}
                reduced={reduced}
              />
            </div>
          </div>
        </section>
      </div>
    </div>
  );
}

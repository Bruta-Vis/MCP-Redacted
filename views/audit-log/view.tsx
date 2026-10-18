/** Privacy audit trail: what the gateway redacted before results reached the model. */
import { ThemeProvider, useCallTool, useToolContext } from "mcp-use/react";
import { useState } from "react";
import "./view.css";

type Output = NonNullable<ReturnType<typeof useToolContext<"show-audit-log">>["toolOutput"]>;
type Entry = Output["entries"][number];

const KIND_STYLE: Record<string, string> = {
  EMAIL: "bg-sky-100 text-sky-800 dark:bg-sky-500/15 dark:text-sky-300",
  PHONE: "bg-violet-100 text-violet-800 dark:bg-violet-500/15 dark:text-violet-300",
  SSN: "bg-rose-100 text-rose-800 dark:bg-rose-500/15 dark:text-rose-300",
  CREDIT_CARD: "bg-rose-100 text-rose-800 dark:bg-rose-500/15 dark:text-rose-300",
  SECRET: "bg-red-100 text-red-800 dark:bg-red-500/15 dark:text-red-300",
  IP_ADDRESS: "bg-amber-100 text-amber-800 dark:bg-amber-500/15 dark:text-amber-300",
  PERSON_NAME: "bg-emerald-100 text-emerald-800 dark:bg-emerald-500/15 dark:text-emerald-300",
  ADDRESS: "bg-teal-100 text-teal-800 dark:bg-teal-500/15 dark:text-teal-300",
  DATE_OF_BIRTH: "bg-teal-100 text-teal-800 dark:bg-teal-500/15 dark:text-teal-300",
  TERM: "bg-orange-100 text-orange-800 dark:bg-orange-500/15 dark:text-orange-300",
};
const kindStyle = (kind: string) =>
  KIND_STYLE[kind] ?? "bg-zinc-100 text-zinc-700 dark:bg-white/10 dark:text-zinc-300";

const TOKEN = /(\[[A-Z]+(?:_[A-Z]+)*_\d+\])/g;

function Highlighted({ text }: { text: string }) {
  return (
    <>
      {text.split(TOKEN).map((part, i) => {
        if (i % 2 === 0) return <span key={i}>{part}</span>;
        const kind = part.slice(1, part.lastIndexOf("_"));
        return (
          <mark key={i} className={`rounded px-1 font-semibold ${kindStyle(kind)}`}>
            {part}
          </mark>
        );
      })}
    </>
  );
}

function Stat({ label, value, tone }: { label: string; value: number; tone?: "warn" }) {
  return (
    <div className="rounded-xl border border-zinc-200 px-3 py-2 dark:border-white/10">
      <div
        className={`text-xl font-semibold tabular-nums ${
          tone === "warn" && value > 0 ? "text-rose-600 dark:text-rose-400" : "text-zinc-900 dark:text-zinc-50"
        }`}
      >
        {value}
      </div>
      <div className="text-[11px] tracking-wide text-zinc-500 uppercase dark:text-zinc-400">{label}</div>
    </div>
  );
}

function EntryRow({ entry, defaultOpen }: { entry: Entry; defaultOpen?: boolean }) {
  const [open, setOpen] = useState(defaultOpen ?? false);
  const time = new Date(entry.at).toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hourCycle: "h23",
  });
  const counts = entry.findings.reduce<Record<string, number>>((acc, f) => {
    acc[f.kind] = (acc[f.kind] ?? 0) + 1;
    return acc;
  }, {});

  return (
    <li className="border-t border-zinc-100 first:border-t-0 dark:border-white/5">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        aria-expanded={open}
        className="flex w-full cursor-pointer items-center gap-3 bg-transparent px-1 py-2.5 text-left hover:bg-zinc-50 dark:hover:bg-white/5"
      >
        <span className="w-16 shrink-0 font-mono text-xs whitespace-nowrap text-zinc-400 tabular-nums">{time}</span>
        <span className="min-w-0 flex-1 truncate font-mono text-[13px] text-zinc-900 dark:text-zinc-100">
          <span className="text-zinc-400">{entry.upstream} › </span>
          {entry.target}
        </span>
        <span className="hidden gap-1 sm:flex">
          {Object.entries(counts).map(([kind, n]) => (
            <span key={kind} className={`rounded-full px-2 py-0.5 text-[10px] font-semibold ${kindStyle(kind)}`}>
              {kind.replace(/_/g, " ").toLowerCase()} {n}
            </span>
          ))}
        </span>
        {entry.rehydrated > 0 && (
          <span
            title="Tokens in the model's arguments were swapped for real values before calling the upstream"
            className="rounded-full border border-zinc-300 px-2 py-0.5 text-[10px] text-zinc-600 dark:border-white/15 dark:text-zinc-300"
          >
            ↺ {entry.rehydrated}
          </span>
        )}
        <span className="w-14 shrink-0 text-right text-xs text-zinc-400 tabular-nums">{entry.latencyMs} ms</span>
        <span
          className={`h-2 w-2 shrink-0 rounded-full ${entry.status === "ok" ? "bg-emerald-500" : "bg-rose-500"}`}
          aria-label={entry.status}
        />
      </button>
      {open && (
        <div className="space-y-2 px-1 pb-3">
          {entry.findings.length > 0 ? (
            <div className="flex flex-wrap gap-1.5">
              {entry.findings.map((f, i) => (
                <span key={i} className={`rounded-md px-1.5 py-0.5 font-mono text-[11px] ${kindStyle(f.kind)}`}>
                  {f.token}
                  {f.path && <span className="opacity-60"> @ {f.path}</span>}
                </span>
              ))}
            </div>
          ) : (
            <p className="m-0 text-xs text-zinc-500">Nothing sensitive found in this payload.</p>
          )}
          <div>
            <div className="mb-1 text-[11px] tracking-wide text-zinc-500 uppercase">What the model received</div>
            <pre className="m-0 max-h-56 overflow-auto rounded-lg bg-zinc-50 p-3 font-mono text-[12px] leading-relaxed whitespace-pre-wrap text-zinc-800 dark:bg-white/5 dark:text-zinc-200">
              <Highlighted text={entry.preview || "(empty)"} />
            </pre>
          </div>
        </div>
      )}
    </li>
  );
}

export default function AuditLogView() {
  const view = useToolContext<"show-audit-log">();
  const refresh = useCallTool("show-audit-log");

  const data: Output | undefined = refresh.data?.structuredContent ?? view.toolOutput;

  return (
    <ThemeProvider>
      <main className="audit-root bg-white p-4 text-zinc-900 sm:p-5 dark:bg-zinc-950 dark:text-zinc-100">
        <header className="mb-4 flex items-start justify-between gap-3">
          <div>
            <h1 className="m-0 text-base font-semibold">Privacy audit</h1>
            <p className="m-0 mt-0.5 text-xs text-zinc-500 dark:text-zinc-400">
              Redacted on the gateway before reaching the model. Original values are never stored or shown.
            </p>
          </div>
          <button
            type="button"
            disabled={refresh.isPending || view.status === "pending"}
            onClick={() => void refresh.callTool({ limit: 50 }).catch(() => {})}
            className="shrink-0 cursor-pointer rounded-lg border border-zinc-300 bg-transparent px-3 py-1.5 text-xs font-medium hover:bg-zinc-50 disabled:cursor-not-allowed disabled:opacity-50 dark:border-white/15 dark:hover:bg-white/5"
          >
            {refresh.isPending ? "Refreshing…" : "Refresh"}
          </button>
        </header>

        {view.status === "error" && !data && (
          <p className="text-sm text-rose-600">Could not load the audit log: {view.error.message}</p>
        )}
        {refresh.error && <p className="text-sm text-rose-600">{refresh.error.message}</p>}

        {!data && view.status === "pending" && (
          <div className="grid animate-pulse grid-cols-2 gap-2 sm:grid-cols-4">
            {[0, 1, 2, 3].map((i) => (
              <div key={i} className="h-14 rounded-xl bg-zinc-100 dark:bg-white/5" />
            ))}
          </div>
        )}

        {data && (
          <>
            <section className="grid grid-cols-2 gap-2 sm:grid-cols-4">
              <Stat label="Calls audited" value={data.summary.calls} />
              <Stat label="Values redacted" value={data.summary.redactions} />
              <Stat label="Tokens rehydrated" value={data.summary.rehydrated} />
              <Stat label="Errors" value={data.summary.errors} tone="warn" />
            </section>

            <section className="mt-3 flex flex-wrap items-center gap-1.5">
              {data.upstreams.map((u) => (
                <span
                  key={u.namespace}
                  title={u.error ?? `${u.tools} tools over ${u.transport}`}
                  className="inline-flex items-center gap-1.5 rounded-full border border-zinc-200 px-2.5 py-0.5 text-[11px] dark:border-white/10"
                >
                  <span
                    className={`h-1.5 w-1.5 rounded-full ${u.status === "connected" ? "bg-emerald-500" : "bg-rose-500"}`}
                  />
                  {u.namespace}
                  <span className="text-zinc-400">
                    {u.status === "connected" ? `${u.tools} tools` : "unavailable"}
                  </span>
                </span>
              ))}
              {Object.entries(data.summary.byKind).map(([kind, n]) => (
                <span key={kind} className={`rounded-full px-2 py-0.5 text-[11px] font-medium ${kindStyle(kind)}`}>
                  {kind.replace(/_/g, " ").toLowerCase()} · {n}
                </span>
              ))}
            </section>

            <section className="mt-4">
              {data.entries.length === 0 ? (
                <p className="rounded-xl border border-dashed border-zinc-300 p-6 text-center text-sm text-zinc-500 dark:border-white/15">
                  No calls yet. Ask for something from a proxied tool, then refresh.
                </p>
              ) : (
                <ul className="m-0 list-none p-0">
                  {data.entries.map((e, i) => (
                    <EntryRow key={e.id} entry={e} defaultOpen={i === 0} />
                  ))}
                </ul>
              )}
            </section>
          </>
        )}
      </main>
    </ThemeProvider>
  );
}

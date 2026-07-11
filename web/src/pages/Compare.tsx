import { useState, useEffect } from "react";
import { useParams, Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { ArrowLeft, Plus, Minus, TrendingUp, TrendingDown } from "lucide-react";
import { api, Scan, DiffSummary } from "@/lib/api";
import { Panel, SectionTitle, Spinner, ErrorState, EmptyState, SeverityChip } from "@/components/ui";

export function Compare() {
  const { id = "" } = useParams();
  const scans = useQuery({ queryKey: ["asset-scans", id], queryFn: () => api.get<Scan[]>(`/assets/${id}/scans`) });
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");

  useEffect(() => {
    const list = scans.data;
    if (list && list.length && !to) {
      setTo(list[0].id);
      if (list.length > 1) setFrom(list[1].id);
    }
  }, [scans.data, to]);

  const diff = useQuery({
    queryKey: ["diff", id, from, to],
    queryFn: () => api.get<DiffSummary>(`/assets/${id}/diff?from=${from}&to=${to}`),
    enabled: !!to,
  });

  if (scans.isLoading) return <div className="p-8"><Spinner label="Loading scans…" /></div>;
  if (scans.error) return <ErrorState message={(scans.error as Error).message} />;
  const list = scans.data || [];

  const label = (s: Scan) => `${new Date(s.started_at).toLocaleString()} · ${s.status}${s.score != null ? ` · ${s.score}` : ""}`;

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <Link to={`/assets/${id}`} className="btn-ghost rounded-md p-1.5"><ArrowLeft size={18} /></Link>
        <SectionTitle eyebrow="What changed" title="Compare scans" />
      </div>

      {list.length < 2 ? (
        <Panel><EmptyState title="Not enough scans to compare" hint="Run at least two scans of this asset to see a structured diff." /></Panel>
      ) : (
        <>
          <div className="grid gap-3 sm:grid-cols-2">
            <div>
              <label className="label">From (baseline)</label>
              <select className="input" value={from} onChange={(e) => setFrom(e.target.value)}>
                <option value="">— none (first scan) —</option>
                {list.map((s) => <option key={s.id} value={s.id}>{label(s)}</option>)}
              </select>
            </div>
            <div>
              <label className="label">To (current)</label>
              <select className="input" value={to} onChange={(e) => setTo(e.target.value)}>
                {list.map((s) => <option key={s.id} value={s.id}>{label(s)}</option>)}
              </select>
            </div>
          </div>

          {diff.isLoading && <Spinner label="Computing diff…" />}
          {diff.data && <DiffView d={diff.data} />}
        </>
      )}
    </div>
  );
}

function DiffView({ d }: { d: DiffSummary }) {
  const scoreUp = d.score_delta > 0;
  return (
    <div className="space-y-6">
      <div className="grid gap-3 sm:grid-cols-3">
        <Panel className="p-4">
          <div className="eyebrow">Score change</div>
          <div className={`mt-1 flex items-center gap-2 metric text-2xl font-semibold ${d.score_delta === 0 ? "text-muted" : scoreUp ? "text-ok" : "text-crit"}`}>
            {d.score_delta !== 0 && (scoreUp ? <TrendingUp size={20} /> : <TrendingDown size={20} />)}
            {d.score_from ?? "—"} → {d.score_to ?? "—"}
            <span className="text-base">({d.score_delta > 0 ? "+" : ""}{d.score_delta})</span>
          </div>
        </Panel>
        <Panel className="p-4"><div className="eyebrow">Grade</div><div className="mt-1 metric text-2xl font-semibold text-ink">{d.grade_from || "—"} → {d.grade_to || "—"}</div></Panel>
        <Panel className="p-4"><div className="eyebrow">Reachability</div><div className="mt-1 text-2xl font-semibold">{d.went_offline ? <span className="text-crit">Went offline</span> : d.came_online ? <span className="text-ok">Came online</span> : <span className="text-muted">{d.online ? "Online" : "Offline"}</span>}</div></Panel>
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <Panel className="p-4">
          <SectionTitle eyebrow={`${d.added.length} new`} title="Appeared" />
          {d.added.length === 0 ? <div className="py-6 text-center text-sm text-muted">Nothing new.</div> : (
            <div className="space-y-1.5">
              {d.added.map((c, i) => (
                <div key={i} className="flex items-center gap-2 rounded-lg border border-ok/20 bg-ok/5 px-3 py-2">
                  <Plus size={14} className="text-ok" />
                  <span className="chip bg-line-2 uppercase text-faint">{c.kind}</span>
                  <span className="metric flex-1 truncate text-sm text-ink">{c.key}</span>
                  {c.severity && c.severity !== "info" && <SeverityChip severity={c.severity} />}
                </div>
              ))}
            </div>
          )}
        </Panel>
        <Panel className="p-4">
          <SectionTitle eyebrow={`${d.removed.length} gone`} title="Resolved" />
          {d.removed.length === 0 ? <div className="py-6 text-center text-sm text-muted">Nothing resolved.</div> : (
            <div className="space-y-1.5">
              {d.removed.map((c, i) => (
                <div key={i} className="flex items-center gap-2 rounded-lg border border-line bg-canvas/40 px-3 py-2">
                  <Minus size={14} className="text-faint" />
                  <span className="chip bg-line-2 uppercase text-faint">{c.kind}</span>
                  <span className="metric flex-1 truncate text-sm text-muted line-through">{c.key}</span>
                </div>
              ))}
            </div>
          )}
        </Panel>
      </div>

      {d.cvss_changed.length > 0 && (
        <Panel className="p-4">
          <SectionTitle eyebrow={`${d.cvss_changed.length} changed`} title="CVSS changes" />
          <div className="space-y-1.5">
            {d.cvss_changed.map((c, i) => (
              <div key={i} className="flex items-center gap-3 rounded-lg border border-line bg-canvas/40 px-3 py-2">
                <span className="metric flex-1 text-sm text-ink">{c.key}</span>
                <span className="metric text-sm text-muted">{c.from_cvss.toFixed(1)} → <span className={c.to_cvss > c.from_cvss ? "text-crit" : "text-ok"}>{c.to_cvss.toFixed(1)}</span></span>
              </div>
            ))}
          </div>
        </Panel>
      )}
    </div>
  );
}

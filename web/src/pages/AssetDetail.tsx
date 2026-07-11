import { useState } from "react";
import { useParams, Link } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { Play, GitCompare, ArrowLeft, ShieldCheck, Camera, Database, Network, FileWarning, ScrollText } from "lucide-react";
import { api, Asset, Scan, ScanDetail, ScorePoint, Finding } from "@/lib/api";
import { Panel, SectionTitle, Spinner, ErrorState, EmptyState, GradeBadge, ScoreText, SeverityChip } from "@/components/ui";
import { useToast } from "@/components/toast";
import { timeAgo, severityColor } from "@/lib/format";

function findingsByKind(findings: Finding[], kind: string) {
  return findings.filter((f) => f.kind === kind);
}

export function AssetDetail() {
  const { id = "" } = useParams();
  const qc = useQueryClient();
  const toast = useToast();
  const [rawOpen, setRawOpen] = useState(false);

  const asset = useQuery({ queryKey: ["asset", id], queryFn: () => api.get<Asset>(`/assets/${id}`) });
  const scans = useQuery({ queryKey: ["asset-scans", id], queryFn: () => api.get<Scan[]>(`/assets/${id}/scans`) });
  const history = useQuery({ queryKey: ["score-history", id], queryFn: () => api.get<ScorePoint[]>(`/assets/${id}/score-history`) });

  const latestId = scans.data?.[0]?.id;
  const detail = useQuery({
    queryKey: ["scan", latestId],
    queryFn: () => api.get<ScanDetail>(`/scans/${latestId}`),
    enabled: !!latestId,
  });

  const scan = useMutation({
    mutationFn: () => api.post(`/assets/${id}/scan`),
    onSuccess: () => {
      toast("success", "Scan complete");
      qc.invalidateQueries({ queryKey: ["asset-scans", id] });
      qc.invalidateQueries({ queryKey: ["score-history", id] });
    },
    onError: (e: Error) => toast("error", e.message),
  });

  if (asset.isLoading) return <div className="p-8"><Spinner label="Loading asset…" /></div>;
  if (asset.error) return <ErrorState message={(asset.error as Error).message} />;
  const a = asset.data!;
  const latest = scans.data?.[0];
  const findings = detail.data?.findings || [];

  const ports = findingsByKind(findings, "port");
  const cves = findingsByKind(findings, "cve").sort((x, y) => y.cvss - x.cvss);
  const weaknesses = findings.filter((f) => ["weakness", "smb_share", "mqtt_topic", "cert"].includes(f.kind));
  const screenshots = findingsByKind(findings, "screenshot");

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <Link to="/assets" className="btn-ghost rounded-md p-1.5"><ArrowLeft size={18} /></Link>
          <div>
            <div className="eyebrow">{a.type}{a.label ? ` · ${a.label}` : ""}</div>
            <h1 className="metric text-2xl font-semibold text-ink">{a.value}</h1>
          </div>
        </div>
        <div className="flex gap-2">
          <Link to={`/assets/${id}/compare`} className="btn"><GitCompare size={15} /> Compare</Link>
          <button className="btn btn-primary" onClick={() => scan.mutate()} disabled={scan.isPending}><Play size={15} /> {scan.isPending ? "Scanning…" : "Scan now"}</button>
        </div>
      </div>

      {/* Posture header */}
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <Panel className="flex items-center gap-4 p-4">
          <GradeBadge grade={latest?.grade} size="lg" />
          <div>
            <div className="eyebrow">Security score</div>
            <div className="metric text-3xl font-semibold"><ScoreText score={latest?.score} /></div>
            {latest?.score_delta != null && latest.score_delta !== 0 && (
              <div className={`text-xs ${latest.score_delta < 0 ? "text-crit" : "text-ok"}`}>{latest.score_delta > 0 ? "+" : ""}{latest.score_delta} since last scan</div>
            )}
          </div>
        </Panel>
        <Panel className="p-4"><div className="eyebrow">Highest CVSS</div><div className="mt-2 metric text-3xl font-semibold text-high">{latest?.highest_cvss ? latest.highest_cvss.toFixed(1) : "—"}</div></Panel>
        <Panel className="p-4"><div className="eyebrow">CVEs</div><div className="mt-2 metric text-3xl font-semibold text-ink">{latest?.cve_count ?? 0}{latest?.critical_count ? <span className="ml-1 text-base text-crit">{latest.critical_count} critical</span> : null}</div></Panel>
        <Panel className="p-4"><div className="eyebrow">Open ports</div><div className="mt-2 metric text-3xl font-semibold text-ink">{latest?.open_ports_count ?? 0}</div><div className="mt-1 text-xs text-faint">{latest ? `${latest.status} · ${timeAgo(latest.started_at)}` : "not scanned"}</div></Panel>
      </div>

      {!latest && (
        <Panel><EmptyState icon={<ShieldCheck size={26} />} title="Not scanned yet" hint="Run a scan to pull this asset's posture from Shodan." action={<button className="btn btn-primary mt-2" onClick={() => scan.mutate()} disabled={scan.isPending}><Play size={15} /> Scan now</button>} /></Panel>
      )}

      {latest && (
        <>
          {/* Score history */}
          <Panel className="p-4">
            <SectionTitle eyebrow="Trend" title="Score history" />
            {(history.data?.length || 0) < 2 ? (
              <div className="py-8 text-center text-sm text-muted">Not enough history yet — scores plot over time as scans accumulate.</div>
            ) : (
              <ResponsiveContainer width="100%" height={180}>
                <LineChart data={history.data} margin={{ top: 6, right: 6, left: -22, bottom: 0 }}>
                  <XAxis dataKey="at" tickFormatter={(v) => new Date(v).toLocaleDateString(undefined, { month: "short", day: "numeric" })} tick={{ fill: "#5c6a7d", fontSize: 11 }} tickLine={false} axisLine={{ stroke: "#1f2a38" }} />
                  <YAxis domain={[0, 100]} tick={{ fill: "#5c6a7d", fontSize: 11 }} tickLine={false} axisLine={false} />
                  <Tooltip contentStyle={{ background: "#111823", border: "1px solid #1f2a38", borderRadius: 8, color: "#e7ecf3" }} labelFormatter={(v) => new Date(v).toLocaleString()} />
                  <Line type="monotone" dataKey="score" stroke="#2fd4bb" strokeWidth={2} dot={false} />
                </LineChart>
              </ResponsiveContainer>
            )}
          </Panel>

          <div className="grid gap-6 lg:grid-cols-2">
            {/* CVEs */}
            <Panel className="p-4">
              <SectionTitle eyebrow={`${cves.length} found`} title="CVEs" />
              {cves.length === 0 ? <div className="py-6 text-center text-sm text-muted">No CVEs detected.</div> : (
                <div className="max-h-80 space-y-1.5 overflow-y-auto pr-1">
                  {cves.map((c) => (
                    <div key={c.id} className="flex items-center justify-between gap-2 rounded-lg border border-line bg-canvas/40 px-3 py-2">
                      <div className="flex items-center gap-2">
                        <a href={`https://nvd.nist.gov/vuln/detail/${c.key}`} target="_blank" rel="noreferrer" className="metric text-sm text-ink hover:text-signal">{c.key}</a>
                        {(c.detail?.verified as boolean) && <span className="chip bg-signal/15 text-signal">verified</span>}
                      </div>
                      <span className={`metric text-sm font-semibold ${severityColor(c.severity)}`}>{c.cvss ? c.cvss.toFixed(1) : "—"}</span>
                    </div>
                  ))}
                </div>
              )}
            </Panel>

            {/* Ports */}
            <Panel className="p-4">
              <SectionTitle eyebrow={`${ports.length} open`} title="Open ports" />
              {ports.length === 0 ? <div className="py-6 text-center text-sm text-muted">No open ports observed.</div> : (
                <div className="flex flex-wrap gap-2">
                  {ports.map((p) => (
                    <span key={p.id} className="chip border border-line-2 bg-canvas text-ink"><Network size={12} className="text-faint" /> {p.key}</span>
                  ))}
                </div>
              )}
            </Panel>
          </div>

          {/* Weaknesses */}
          <Panel className="p-4">
            <SectionTitle eyebrow={`${weaknesses.length} findings`} title="Weaknesses & exposures" />
            {weaknesses.length === 0 ? <div className="py-6 text-center text-sm text-muted">No weaknesses detected.</div> : (
              <div className="grid gap-2 sm:grid-cols-2">
                {weaknesses.map((w) => (
                  <div key={w.id} className="flex items-start gap-3 rounded-lg border border-line bg-canvas/40 px-3 py-2.5">
                    {w.kind === "smb_share" ? <Database size={16} className="mt-0.5 text-high" /> : w.kind === "cert" ? <FileWarning size={16} className="mt-0.5 text-med" /> : <ShieldCheck size={16} className="mt-0.5 text-crit" />}
                    <div className="min-w-0 flex-1">
                      <div className="metric truncate text-sm text-ink">{w.key}</div>
                      {w.target_ip && <div className="text-xs text-faint">{w.target_ip}</div>}
                    </div>
                    <SeverityChip severity={w.severity} />
                  </div>
                ))}
              </div>
            )}
          </Panel>

          {/* Screenshots */}
          {screenshots.length > 0 && (
            <Panel className="p-4">
              <SectionTitle eyebrow={`${screenshots.length} services`} title="Screenshot services" />
              <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-4">
                {screenshots.map((s) => (
                  <div key={s.id} className="rounded-lg border border-line bg-canvas p-3 text-center">
                    <Camera size={22} className={`mx-auto ${(s.detail?.remote_desktop as boolean) ? "text-crit" : "text-muted"}`} />
                    <div className="metric mt-2 text-sm text-ink">{s.key.replace("screenshot:", "port ")}</div>
                    {(s.detail?.remote_desktop as boolean) && <div className="mt-1 chip bg-crit/15 text-crit">remote desktop</div>}
                  </div>
                ))}
              </div>
            </Panel>
          )}

          {/* Scan history + raw */}
          <Panel>
            <div className="flex items-center justify-between px-4 pt-4">
              <SectionTitle eyebrow="History" title="Scans" />
              <button className="btn" onClick={() => setRawOpen((v) => !v)}><ScrollText size={15} /> {rawOpen ? "Hide" : "View"} raw report</button>
            </div>
            {rawOpen && (
              <div className="mx-4 mb-4 max-h-96 overflow-auto rounded-lg border border-line bg-canvas p-3">
                <pre className="metric whitespace-pre-wrap break-all text-xs text-muted">{JSON.stringify(detail.data?.scan.raw_json ?? {}, null, 2)}</pre>
              </div>
            )}
            <div className="overflow-x-auto">
              <table className="w-full min-w-[560px]">
                <thead><tr className="border-y border-line"><th className="th">Started</th><th className="th">Status</th><th className="th">Score</th><th className="th">CVEs</th><th className="th">Ports</th></tr></thead>
                <tbody>
                  {(scans.data || []).map((s) => (
                    <tr key={s.id} className="border-b border-line/60">
                      <td className="td text-muted">{new Date(s.started_at).toLocaleString()}</td>
                      <td className="td"><span className={`chip ${s.status === "ok" ? "bg-ok/15 text-ok" : s.status === "partial" ? "bg-med/15 text-med" : "bg-crit/15 text-crit"}`}>{s.status}</span></td>
                      <td className="td"><ScoreText score={s.score} /></td>
                      <td className="td metric text-muted">{s.cve_count}</td>
                      <td className="td metric text-muted">{s.open_ports_count}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Panel>
        </>
      )}
    </div>
  );
}

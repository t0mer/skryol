import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { Area, AreaChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { Radar, ShieldAlert, Bug, Gauge, Play } from "lucide-react";
import { api, Dashboard as Dash } from "@/lib/api";
import { GradeBadge, ScoreText, Spinner, ErrorState, EmptyState, Panel, SectionTitle } from "@/components/ui";
import { timeAgo } from "@/lib/format";
import { useToast } from "@/components/toast";

function StatTile({ icon, label, value, hint, tone }: { icon: React.ReactNode; label: string; value: React.ReactNode; hint?: string; tone?: string }) {
  return (
    <Panel className="p-4">
      <div className="flex items-center justify-between">
        <div className="eyebrow">{label}</div>
        <div className={tone || "text-faint"}>{icon}</div>
      </div>
      <div className="mt-2 metric text-3xl font-semibold text-ink">{value}</div>
      {hint && <div className="mt-1 text-xs text-muted">{hint}</div>}
    </Panel>
  );
}

const gradeOrder = ["A", "B", "C", "D", "F"];
const gradeHex: Record<string, string> = { A: "#2fd4bb", B: "#5aa9f0", C: "#e7c14b", D: "#f79445", F: "#f0546a" };

export function Dashboard() {
  const qc = useQueryClient();
  const toast = useToast();
  const { data, isLoading, error } = useQuery({
    queryKey: ["dashboard"],
    queryFn: () => api.get<Dash>("/dashboard"),
    refetchInterval: 60000,
  });

  const scanAll = useMutation({
    mutationFn: () => api.post<{ ok: number; total: number }>("/scan"),
    onSuccess: (r) => {
      toast("success", `Fleet scan complete: ${r.ok}/${r.total} assets ok`);
      qc.invalidateQueries({ queryKey: ["dashboard"] });
    },
    onError: (e: Error) => toast("error", e.message),
  });

  if (isLoading) return <div className="p-8"><Spinner label="Loading dashboard…" /></div>;
  if (error) return <ErrorState message={(error as Error).message} />;
  if (!data) return null;

  const ranked = [...data.assets].sort((a, b) => (a.score ?? 999) - (b.score ?? 999));

  return (
    <div className="space-y-6">
      <SectionTitle
        eyebrow="Fleet overview"
        title="Attack surface at a glance"
        action={
          <button className="btn btn-primary" onClick={() => scanAll.mutate()} disabled={scanAll.isPending}>
            <Play size={15} /> {scanAll.isPending ? "Scanning…" : "Scan all"}
          </button>
        }
      />

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <StatTile icon={<Radar size={18} />} label="Monitored assets" value={data.total_assets} hint={`${data.enabled_assets} enabled · ${data.scanned_assets} scanned`} />
        <StatTile icon={<Gauge size={18} />} label="Avg score" value={data.average_score ? data.average_score.toFixed(0) : "—"} tone="text-signal" hint="across scored assets" />
        <StatTile icon={<ShieldAlert size={18} />} label="Critical issues" value={data.critical_issues} tone={data.critical_issues ? "text-crit" : "text-faint"} />
        <StatTile icon={<Bug size={18} />} label="Total CVEs" value={data.total_cves} tone={data.total_cves ? "text-high" : "text-faint"} />
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        <Panel className="p-4 lg:col-span-2">
          <SectionTitle eyebrow="30-day fleet trend" title="Average security score" />
          {data.trend.length === 0 ? (
            <EmptyState title="No trend yet" hint="Score history appears once assets have been scanned over multiple days." />
          ) : (
            <ResponsiveContainer width="100%" height={220}>
              <AreaChart data={data.trend} margin={{ top: 6, right: 6, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="g" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#2fd4bb" stopOpacity={0.4} />
                    <stop offset="100%" stopColor="#2fd4bb" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="date" tick={{ fill: "#5c6a7d", fontSize: 11 }} tickLine={false} axisLine={{ stroke: "#1f2a38" }} />
                <YAxis domain={[0, 100]} tick={{ fill: "#5c6a7d", fontSize: 11 }} tickLine={false} axisLine={false} />
                <Tooltip contentStyle={{ background: "#111823", border: "1px solid #1f2a38", borderRadius: 8, color: "#e7ecf3" }} />
                <Area type="monotone" dataKey="avg_score" stroke="#2fd4bb" strokeWidth={2} fill="url(#g)" />
              </AreaChart>
            </ResponsiveContainer>
          )}
        </Panel>

        <Panel className="p-4">
          <SectionTitle eyebrow="Distribution" title="Grades" />
          <div className="space-y-3 pt-1">
            {gradeOrder.map((g) => {
              const n = data.grade_distribution[g] || 0;
              const max = Math.max(1, ...gradeOrder.map((x) => data.grade_distribution[x] || 0));
              return (
                <div key={g} className="flex items-center gap-3">
                  <span className="metric w-4 font-bold" style={{ color: gradeHex[g] }}>{g}</span>
                  <div className="h-2.5 flex-1 overflow-hidden rounded-full bg-canvas">
                    <div className="h-full rounded-full" style={{ width: `${(n / max) * 100}%`, background: gradeHex[g] }} />
                  </div>
                  <span className="metric w-6 text-right text-sm text-muted">{n}</span>
                </div>
              );
            })}
          </div>
        </Panel>
      </div>

      <Panel>
        <div className="px-4 pt-4">
          <SectionTitle eyebrow="Ranked by risk" title="Assets" />
        </div>
        {ranked.length === 0 ? (
          <EmptyState title="No assets yet" hint="Add IPs, domains, or CIDR ranges to start monitoring." action={<Link to="/assets" className="btn btn-primary mt-2">Add an asset</Link>} />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[640px]">
              <thead>
                <tr className="border-y border-line">
                  <th className="th">Asset</th>
                  <th className="th">Grade</th>
                  <th className="th">Score</th>
                  <th className="th">Highest CVSS</th>
                  <th className="th">CVEs</th>
                  <th className="th">Ports</th>
                  <th className="th">Last scan</th>
                </tr>
              </thead>
              <tbody>
                {ranked.map((a) => (
                  <tr key={a.asset_id} className="border-b border-line/60 hover:bg-panel-2/50">
                    <td className="td">
                      <Link to={`/assets/${a.asset_id}`} className="group flex flex-col">
                        <span className="metric text-ink group-hover:text-signal">{a.value}</span>
                        <span className="text-xs text-faint">{a.label || a.type}</span>
                      </Link>
                    </td>
                    <td className="td"><GradeBadge grade={a.grade} size="sm" /></td>
                    <td className="td"><ScoreText score={a.score} /></td>
                    <td className="td metric text-muted">{a.highest_cvss ? a.highest_cvss.toFixed(1) : "—"}</td>
                    <td className="td metric text-muted">{a.cve_count}{a.critical_count > 0 && <span className="ml-1 text-crit">({a.critical_count} crit)</span>}</td>
                    <td className="td metric text-muted">{a.open_ports_count}</td>
                    <td className="td text-xs text-faint">{timeAgo(a.last_scanned_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
    </div>
  );
}

import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Plus, Pencil, Trash2, Bell, BellRing } from "lucide-react";
import { api, AlertRule, AlertEvent, Channel, Asset } from "@/lib/api";
import { Panel, SectionTitle, Spinner, ErrorState, EmptyState, Toggle, SeverityChip } from "@/components/ui";
import { Modal } from "@/components/Modal";
import { useToast } from "@/components/toast";
import { timeAgo } from "@/lib/format";

const conditions: { value: string; label: string; param?: "cvss" | "points" | "grade" }[] = [
  { value: "new_open_port", label: "New open port" },
  { value: "new_cve", label: "New CVE", param: "cvss" },
  { value: "cve_cvss_at_least", label: "New CVE with CVSS ≥ X", param: "cvss" },
  { value: "score_drop_at_least", label: "Score dropped by ≥ N", param: "points" },
  { value: "grade_drops_below", label: "Grade drops below", param: "grade" },
  { value: "default_password_detected", label: "Default password detected" },
  { value: "new_screenshot_service", label: "New screenshot service (VNC/RDP)" },
  { value: "new_smb_share", label: "New SMB share" },
  { value: "new_exposed_database", label: "New exposed database" },
  { value: "cert_expired_or_selfsigned", label: "Certificate expired / self-signed" },
  { value: "asset_offline", label: "Asset went offline" },
  { value: "asset_online", label: "Asset came online" },
  { value: "scan_failed", label: "Scan failed" },
];

const condLabel = (v: string) => conditions.find((c) => c.value === v)?.label || v;

interface Form {
  id?: string;
  scope: "global" | "asset";
  asset_id: string;
  condition: string;
  enabled: boolean;
  severity: string;
  cooldown_seconds: number;
  channel_ids: string[];
  paramValue: string;
}

const empty: Form = { scope: "global", asset_id: "", condition: "new_cve", enabled: true, severity: "high", cooldown_seconds: 3600, channel_ids: [], paramValue: "7.0" };

export function Alerts() {
  const qc = useQueryClient();
  const toast = useToast();
  const [form, setForm] = useState<Form | null>(null);

  const rules = useQuery({ queryKey: ["rules"], queryFn: () => api.get<AlertRule[]>("/rules") });
  const channels = useQuery({ queryKey: ["channels"], queryFn: () => api.get<Channel[]>("/channels") });
  const assets = useQuery({ queryKey: ["assets"], queryFn: () => api.get<Asset[]>("/assets") });
  const events = useQuery({ queryKey: ["alert-events"], queryFn: () => api.get<AlertEvent[]>("/alerts/events?limit=50"), refetchInterval: 30000 });

  const save = useMutation({
    mutationFn: (f: Form) => {
      const cond = conditions.find((c) => c.value === f.condition);
      const params: Record<string, unknown> = {};
      if (cond?.param === "cvss") params[f.condition === "new_cve" ? "min_cvss" : "cvss"] = parseFloat(f.paramValue) || 0;
      if (cond?.param === "points") params.points = parseInt(f.paramValue) || 0;
      if (cond?.param === "grade") params.grade = f.paramValue || "B";
      const body = {
        scope: f.scope,
        asset_id: f.scope === "asset" ? f.asset_id : "",
        condition: f.condition,
        enabled: f.enabled,
        severity: f.severity,
        cooldown_seconds: f.cooldown_seconds,
        channel_ids: f.channel_ids,
        params,
      };
      return f.id ? api.put(`/rules/${f.id}`, body) : api.post("/rules", body);
    },
    onSuccess: () => {
      toast("success", form?.id ? "Rule updated" : "Rule created");
      qc.invalidateQueries({ queryKey: ["rules"] });
      setForm(null);
    },
    onError: (e: Error) => toast("error", e.message),
  });

  const remove = useMutation({
    mutationFn: (id: string) => api.del(`/rules/${id}`),
    onSuccess: () => { toast("success", "Rule deleted"); qc.invalidateQueries({ queryKey: ["rules"] }); },
    onError: (e: Error) => toast("error", e.message),
  });

  if (rules.isLoading) return <div className="p-8"><Spinner label="Loading alerts…" /></div>;
  if (rules.error) return <ErrorState message={(rules.error as Error).message} />;

  const cond = form ? conditions.find((c) => c.value === form.condition) : undefined;
  const chMap = new Map((channels.data || []).map((c) => [c.id, c]));

  return (
    <div className="space-y-6">
      <SectionTitle eyebrow="Rules & routing" title="Alerts" action={<button className="btn btn-primary" onClick={() => setForm(empty)}><Plus size={15} /> New rule</button>} />

      <Panel>
        {(rules.data?.length || 0) === 0 ? (
          <EmptyState icon={<Bell size={26} />} title="No alert rules" hint="Create rules that fire on new CVEs, open ports, score drops, default passwords, and more — routed to your notification channels." action={<button className="btn btn-primary mt-2" onClick={() => setForm(empty)}><Plus size={15} /> New rule</button>} />
        ) : (
          <div className="divide-y divide-line">
            {rules.data!.map((r) => (
              <div key={r.id} className="flex flex-wrap items-center gap-3 p-4">
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <span className="font-medium text-ink">{condLabel(r.condition)}</span>
                    <SeverityChip severity={r.severity} />
                    {!r.enabled && <span className="chip bg-line-2 text-faint">disabled</span>}
                  </div>
                  <div className="mt-1 text-xs text-faint">
                    {r.scope === "global" ? "All assets" : "Single asset"} · cooldown {Math.round(r.cooldown_seconds / 60)}m · {r.channel_ids.length} channel{r.channel_ids.length === 1 ? "" : "s"}
                    {r.channel_ids.length > 0 && <> → {r.channel_ids.map((id) => chMap.get(id)?.label || "?").join(", ")}</>}
                  </div>
                </div>
                <div className="flex gap-1">
                  <button className="btn-ghost rounded-md p-1.5" onClick={() => setForm({
                    id: r.id, scope: r.scope, asset_id: r.asset_id || "", condition: r.condition,
                    enabled: r.enabled, severity: r.severity, cooldown_seconds: r.cooldown_seconds,
                    channel_ids: r.channel_ids, paramValue: String((r.params?.cvss ?? r.params?.min_cvss ?? r.params?.points ?? r.params?.grade ?? "") as string),
                  })}><Pencil size={15} /></button>
                  <button className="btn-ghost rounded-md p-1.5 hover:text-crit" onClick={() => confirm("Delete this rule?") && remove.mutate(r.id)}><Trash2 size={15} /></button>
                </div>
              </div>
            ))}
          </div>
        )}
      </Panel>

      <Panel>
        <div className="px-4 pt-4"><SectionTitle eyebrow="Audit log" title="Recent firings" /></div>
        {(events.data?.length || 0) === 0 ? (
          <EmptyState icon={<BellRing size={24} />} title="No alerts fired yet" hint="Firings appear here after a scan matches a rule." />
        ) : (
          <div className="max-h-96 divide-y divide-line overflow-y-auto">
            {events.data!.map((e) => (
              <div key={e.id} className="flex items-center gap-3 px-4 py-2.5 text-sm">
                <SeverityChip severity={e.severity} />
                <span className="flex-1 text-ink">{condLabel(e.condition)}</span>
                <span className="text-xs text-faint">{timeAgo(e.fired_at)}</span>
                <span className="metric text-xs text-muted">{Object.values(e.delivered || {}).filter((v) => v === "ok").length}/{Object.keys(e.delivered || {}).length} sent</span>
              </div>
            ))}
          </div>
        )}
      </Panel>

      <Modal open={!!form} onClose={() => setForm(null)} title={form?.id ? "Edit rule" : "New alert rule"} wide>
        {form && (
          <form className="space-y-4" onSubmit={(e) => { e.preventDefault(); save.mutate(form); }}>
            <div className="grid gap-4 sm:grid-cols-2">
              <div>
                <label className="label">Condition</label>
                <select className="input" value={form.condition} onChange={(e) => setForm({ ...form, condition: e.target.value })}>
                  {conditions.map((c) => <option key={c.value} value={c.value}>{c.label}</option>)}
                </select>
              </div>
              {cond?.param && (
                <div>
                  <label className="label">{cond.param === "cvss" ? "Minimum CVSS" : cond.param === "points" ? "Points dropped" : "Grade threshold"}</label>
                  {cond.param === "grade" ? (
                    <select className="input" value={form.paramValue} onChange={(e) => setForm({ ...form, paramValue: e.target.value })}>
                      {["A", "B", "C", "D"].map((g) => <option key={g} value={g}>{g}</option>)}
                    </select>
                  ) : (
                    <input className="input metric" value={form.paramValue} onChange={(e) => setForm({ ...form, paramValue: e.target.value })} placeholder={cond.param === "cvss" ? "7.0" : "10"} />
                  )}
                </div>
              )}
            </div>

            <div className="grid gap-4 sm:grid-cols-2">
              <div>
                <label className="label">Scope</label>
                <select className="input" value={form.scope} onChange={(e) => setForm({ ...form, scope: e.target.value as "global" | "asset" })}>
                  <option value="global">All assets (global)</option>
                  <option value="asset">Single asset</option>
                </select>
              </div>
              {form.scope === "asset" && (
                <div>
                  <label className="label">Asset</label>
                  <select className="input" value={form.asset_id} onChange={(e) => setForm({ ...form, asset_id: e.target.value })} required>
                    <option value="">— select —</option>
                    {(assets.data || []).map((a) => <option key={a.id} value={a.id}>{a.value}</option>)}
                  </select>
                </div>
              )}
            </div>

            <div className="grid gap-4 sm:grid-cols-2">
              <div>
                <label className="label">Severity</label>
                <select className="input" value={form.severity} onChange={(e) => setForm({ ...form, severity: e.target.value })}>
                  {["critical", "high", "medium", "low", "info"].map((s) => <option key={s} value={s}>{s}</option>)}
                </select>
              </div>
              <div>
                <label className="label">Cooldown (minutes)</label>
                <input className="input metric" type="number" min={0} value={Math.round(form.cooldown_seconds / 60)} onChange={(e) => setForm({ ...form, cooldown_seconds: (parseInt(e.target.value) || 0) * 60 })} />
              </div>
            </div>

            <div>
              <label className="label">Route to channels</label>
              {(channels.data?.length || 0) === 0 ? (
                <div className="rounded-lg border border-line-2 bg-canvas/40 px-3 py-2 text-xs text-muted">No channels yet — add one under Settings → Notifications.</div>
              ) : (
                <div className="flex flex-wrap gap-2">
                  {channels.data!.map((c) => {
                    const on = form.channel_ids.includes(c.id);
                    return (
                      <button key={c.id} type="button" onClick={() => setForm({ ...form, channel_ids: on ? form.channel_ids.filter((x) => x !== c.id) : [...form.channel_ids, c.id] })}
                        className={`chip border px-3 py-1.5 ${on ? "border-signal-dim bg-signal/10 text-signal" : "border-line-2 text-muted"}`}>
                        {c.label || c.type}
                      </button>
                    );
                  })}
                </div>
              )}
            </div>

            <label className="flex items-center gap-2.5 text-sm text-muted"><Toggle checked={form.enabled} onChange={(v) => setForm({ ...form, enabled: v })} /> Enabled</label>

            <div className="flex justify-end gap-2 pt-2">
              <button type="button" className="btn" onClick={() => setForm(null)}>Cancel</button>
              <button type="submit" className="btn btn-primary" disabled={save.isPending}>{save.isPending ? "Saving…" : "Save rule"}</button>
            </div>
          </form>
        )}
      </Modal>
    </div>
  );
}

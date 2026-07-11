import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Plus, Trash2, Pencil, RefreshCw, Send, KeyRound, Bell, SlidersHorizontal, Server } from "lucide-react";
import { api, ShodanKey, Channel, ChannelType, ChannelConfig, Settings, ScoringWeights } from "@/lib/api";
import { Panel, SectionTitle, Spinner, Toggle } from "@/components/ui";
import { Modal } from "@/components/Modal";
import { useToast } from "@/components/toast";
import { healthColor, timeAgo } from "@/lib/format";

export function SettingsPage() {
  return (
    <div className="space-y-6">
      <SectionTitle eyebrow="Configuration" title="Settings" />
      <ShodanKeys />
      <Channels />
      <ScoringWeightsCard />
      <RuntimeInfo />
    </div>
  );
}

// ---------- Shodan keys ----------
function ShodanKeys() {
  const qc = useQueryClient();
  const toast = useToast();
  const [modal, setModal] = useState<{ id?: string; label: string; secret: string; enabled: boolean } | null>(null);
  const keys = useQuery({ queryKey: ["keys"], queryFn: () => api.get<ShodanKey[]>("/shodan/keys") });

  const save = useMutation({
    mutationFn: (m: { id?: string; label: string; secret: string; enabled: boolean }) =>
      m.id ? api.put(`/shodan/keys/${m.id}`, m) : api.post("/shodan/keys", m),
    onSuccess: () => { toast("success", "Key saved"); qc.invalidateQueries({ queryKey: ["keys"] }); setModal(null); },
    onError: (e: Error) => toast("error", e.message),
  });
  const remove = useMutation({ mutationFn: (id: string) => api.del(`/shodan/keys/${id}`), onSuccess: () => { toast("success", "Key removed"); qc.invalidateQueries({ queryKey: ["keys"] }); } });
  const refresh = useMutation({ mutationFn: (id: string) => api.post(`/shodan/keys/${id}/refresh`), onSuccess: () => { toast("success", "Credits refreshed"); qc.invalidateQueries({ queryKey: ["keys"] }); }, onError: (e: Error) => toast("error", e.message) });

  return (
    <Panel>
      <div className="flex items-center justify-between px-4 pt-4">
        <SectionTitle eyebrow="Shodan" title="API keys" />
        <div className="flex gap-2">
          <button className="btn" onClick={() => keys.data?.[0] && refresh.mutate(keys.data[0].id)} disabled={refresh.isPending || !keys.data?.length}><RefreshCw size={14} className={refresh.isPending ? "animate-spin" : ""} /> Refresh credits</button>
          <button className="btn btn-primary" onClick={() => setModal({ label: "", secret: "", enabled: true })}><Plus size={15} /> Add key</button>
        </div>
      </div>
      <div className="p-4">
        {keys.isLoading ? <Spinner /> : (keys.data?.length || 0) === 0 ? (
          <div className="rounded-lg border border-dashed border-line-2 p-6 text-center text-sm text-muted">
            <KeyRound className="mx-auto mb-2 text-faint" /> No Shodan keys. Add at least one to run scans.
          </div>
        ) : (
          <div className="space-y-2">
            {keys.data!.map((k) => (
              <div key={k.id} className="flex flex-wrap items-center gap-3 rounded-lg border border-line bg-canvas/40 px-3 py-2.5">
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <span className="font-medium text-ink">{k.label || "unlabeled"}</span>
                    <span className={`chip ${healthColor(k.health)}`}>{k.health}</span>
                    {!k.enabled && <span className="chip bg-line-2 text-faint">disabled</span>}
                  </div>
                  <div className="mt-0.5 metric text-xs text-faint">
                    {k.query_credits.toLocaleString()} query · {k.scan_credits.toLocaleString()} scan credits{k.plan && ` · ${k.plan}`} · used {timeAgo(k.last_used_at)}
                  </div>
                  {k.last_error && <div className="text-xs text-crit">{k.last_error}</div>}
                </div>
                <div className="flex gap-1">
                  <button className="btn-ghost rounded-md p-1.5" onClick={() => setModal({ id: k.id, label: k.label, secret: "", enabled: k.enabled })}><Pencil size={15} /></button>
                  <button className="btn-ghost rounded-md p-1.5 hover:text-crit" onClick={() => confirm("Remove this key?") && remove.mutate(k.id)}><Trash2 size={15} /></button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      <Modal open={!!modal} onClose={() => setModal(null)} title={modal?.id ? "Edit key" : "Add Shodan key"}>
        {modal && (
          <form className="space-y-4" onSubmit={(e) => { e.preventDefault(); save.mutate(modal); }}>
            <div><label className="label">Label</label><input className="input" value={modal.label} onChange={(e) => setModal({ ...modal, label: e.target.value })} placeholder="Primary key" /></div>
            <div><label className="label">API key {modal.id && <span className="text-faint">(leave blank to keep)</span>}</label><input className="input metric" type="password" value={modal.secret} onChange={(e) => setModal({ ...modal, secret: e.target.value })} placeholder="shodan api key" autoComplete="off" /></div>
            <label className="flex items-center gap-2.5 text-sm text-muted"><Toggle checked={modal.enabled} onChange={(v) => setModal({ ...modal, enabled: v })} /> Enabled</label>
            <div className="flex justify-end gap-2"><button type="button" className="btn" onClick={() => setModal(null)}>Cancel</button><button type="submit" className="btn btn-primary" disabled={save.isPending}>Save</button></div>
          </form>
        )}
      </Modal>
    </Panel>
  );
}

// ---------- Channels ----------
const channelTypes: { value: ChannelType; label: string }[] = [
  { value: "shoutrrr", label: "Shoutrrr (Slack, Telegram, email, webhook…)" },
  { value: "greenapi", label: "GreenAPI WhatsApp" },
  { value: "whatsapp_web", label: "WhatsApp Web (self-hosted)" },
];

interface ChForm { id?: string; type: ChannelType; label: string; enabled: boolean; config: ChannelConfig; }

function Channels() {
  const qc = useQueryClient();
  const toast = useToast();
  const [form, setForm] = useState<ChForm | null>(null);
  const channels = useQuery({ queryKey: ["channels"], queryFn: () => api.get<Channel[]>("/channels") });

  const save = useMutation({
    mutationFn: (f: ChForm) => (f.id ? api.put(`/channels/${f.id}`, f) : api.post("/channels", f)),
    onSuccess: () => { toast("success", "Channel saved"); qc.invalidateQueries({ queryKey: ["channels"] }); setForm(null); },
    onError: (e: Error) => toast("error", e.message),
  });
  const remove = useMutation({ mutationFn: (id: string) => api.del(`/channels/${id}`), onSuccess: () => { toast("success", "Channel removed"); qc.invalidateQueries({ queryKey: ["channels"] }); } });
  const test = useMutation({
    mutationFn: (f: ChForm) => (f.id ? api.post(`/channels/${f.id}/test`) : api.post("/channels/test", { type: f.type, config: f.config })),
    onSuccess: () => toast("success", "Test message sent"),
    onError: (e: Error) => toast("error", e.message),
  });

  const set = (patch: Partial<ChannelConfig>) => form && setForm({ ...form, config: { ...form.config, ...patch } });

  return (
    <Panel>
      <div className="flex items-center justify-between px-4 pt-4">
        <SectionTitle eyebrow="Notifications" title="Channels" />
        <button className="btn btn-primary" onClick={() => setForm({ type: "shoutrrr", label: "", enabled: true, config: {} })}><Plus size={15} /> Add channel</button>
      </div>
      <div className="p-4">
        {channels.isLoading ? <Spinner /> : (channels.data?.length || 0) === 0 ? (
          <div className="rounded-lg border border-dashed border-line-2 p-6 text-center text-sm text-muted"><Bell className="mx-auto mb-2 text-faint" /> No channels. Add one to receive alerts.</div>
        ) : (
          <div className="space-y-2">
            {channels.data!.map((c) => (
              <div key={c.id} className="flex items-center gap-3 rounded-lg border border-line bg-canvas/40 px-3 py-2.5">
                <div className="flex-1">
                  <div className="flex items-center gap-2"><span className="font-medium text-ink">{c.label || c.type}</span><span className="chip bg-line-2 text-faint">{c.type}</span>{!c.enabled && <span className="chip bg-line-2 text-faint">disabled</span>}</div>
                </div>
                <div className="flex gap-1">
                  <button className="btn-ghost rounded-md p-1.5" title="Send test" onClick={() => test.mutate({ id: c.id, type: c.type, label: c.label, enabled: c.enabled, config: {} })}><Send size={15} /></button>
                  <button className="btn-ghost rounded-md p-1.5" onClick={() => setForm({ id: c.id, type: c.type, label: c.label, enabled: c.enabled, config: {} })}><Pencil size={15} /></button>
                  <button className="btn-ghost rounded-md p-1.5 hover:text-crit" onClick={() => confirm("Remove this channel?") && remove.mutate(c.id)}><Trash2 size={15} /></button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      <Modal open={!!form} onClose={() => setForm(null)} title={form?.id ? "Edit channel" : "Add channel"}>
        {form && (
          <form className="space-y-4" onSubmit={(e) => { e.preventDefault(); save.mutate(form); }}>
            <div><label className="label">Provider</label><select className="input" value={form.type} onChange={(e) => setForm({ ...form, type: e.target.value as ChannelType, config: {} })} disabled={!!form.id}>{channelTypes.map((t) => <option key={t.value} value={t.value}>{t.label}</option>)}</select></div>
            <div><label className="label">Name</label><input className="input" value={form.label} onChange={(e) => setForm({ ...form, label: e.target.value })} placeholder="Security team Slack" /></div>

            {form.type === "shoutrrr" && (
              <div><label className="label">Shoutrrr URL</label><input className="input metric" value={form.config.url || ""} onChange={(e) => set({ url: e.target.value })} placeholder="slack://token@channel" /></div>
            )}
            {form.type === "greenapi" && (
              <div className="grid gap-3 sm:grid-cols-2">
                <div><label className="label">Instance ID</label><input className="input metric" value={form.config.instance_id || ""} onChange={(e) => set({ instance_id: e.target.value })} /></div>
                <div><label className="label">Token</label><input className="input metric" type="password" value={form.config.token || ""} onChange={(e) => set({ token: e.target.value })} /></div>
                <div><label className="label">Recipient phone</label><input className="input metric" value={form.config.phone || ""} onChange={(e) => set({ phone: e.target.value })} placeholder="972501234567" /></div>
                <div><label className="label">API URL (optional)</label><input className="input metric" value={form.config.api_url || ""} onChange={(e) => set({ api_url: e.target.value })} placeholder="https://api.green-api.com" /></div>
              </div>
            )}
            {form.type === "whatsapp_web" && (
              <div className="grid gap-3 sm:grid-cols-2">
                <div><label className="label">Base URL</label><input className="input metric" value={form.config.base_url || ""} onChange={(e) => set({ base_url: e.target.value })} placeholder="http://localhost:3000" /></div>
                <div><label className="label">Recipient phone</label><input className="input metric" value={form.config.phone || ""} onChange={(e) => set({ phone: e.target.value })} /></div>
                <div><label className="label">Username (optional)</label><input className="input" value={form.config.username || ""} onChange={(e) => set({ username: e.target.value })} /></div>
                <div><label className="label">Password (optional)</label><input className="input" type="password" value={form.config.password || ""} onChange={(e) => set({ password: e.target.value })} /></div>
              </div>
            )}

            <label className="flex items-center gap-2.5 text-sm text-muted"><Toggle checked={form.enabled} onChange={(v) => setForm({ ...form, enabled: v })} /> Enabled</label>

            <div className="flex justify-between gap-2 pt-2">
              <button type="button" className="btn" onClick={() => test.mutate(form)} disabled={test.isPending}><Send size={14} /> Send test</button>
              <div className="flex gap-2"><button type="button" className="btn" onClick={() => setForm(null)}>Cancel</button><button type="submit" className="btn btn-primary" disabled={save.isPending}>Save</button></div>
            </div>
          </form>
        )}
      </Modal>
    </Panel>
  );
}

// ---------- Scoring weights ----------
const weightLabels: { key: keyof ScoringWeights; label: string }[] = [
  { key: "cve_critical", label: "CVE critical" },
  { key: "cve_high", label: "CVE high" },
  { key: "cve_medium", label: "CVE medium" },
  { key: "cve_low", label: "CVE low" },
  { key: "verified_multiplier", label: "Verified ×" },
  { key: "default_password", label: "Default password" },
  { key: "remote_desktop", label: "Remote desktop" },
  { key: "exposed_database", label: "Exposed database" },
  { key: "anonymous_smb", label: "Anonymous SMB" },
  { key: "smb_share", label: "SMB share" },
  { key: "cert_issue", label: "Cert issue" },
  { key: "weak_tls", label: "Weak TLS" },
  { key: "mqtt_exposed", label: "MQTT exposed" },
  { key: "sensitive_port", label: "Sensitive port" },
];

function ScoringWeightsCard() {
  const qc = useQueryClient();
  const toast = useToast();
  const settings = useQuery({ queryKey: ["settings"], queryFn: () => api.get<Settings>("/settings") });
  const [draft, setDraft] = useState<ScoringWeights | null>(null);
  const w = draft || settings.data?.scoring_weights;

  const save = useMutation({
    mutationFn: (weights: ScoringWeights) => api.put<Settings>("/settings", { scoring_weights: weights }),
    onSuccess: () => { toast("success", "Scoring weights saved"); qc.invalidateQueries({ queryKey: ["settings"] }); setDraft(null); },
    onError: (e: Error) => toast("error", e.message),
  });

  return (
    <Panel className="p-4">
      <SectionTitle eyebrow="Deterministic model" title="Scoring weights" action={draft ? <button className="btn btn-primary" onClick={() => save.mutate(draft)} disabled={save.isPending}>Save</button> : undefined} />
      <p className="mb-4 text-xs text-muted">Score starts at 100; each finding subtracts its weight. Verified CVEs are multiplied. Grades: A ≥ 90, B ≥ 80, C ≥ 70, D ≥ 60, F below.</p>
      {!w ? <Spinner /> : (
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-4">
          {weightLabels.map(({ key, label }) => (
            <div key={key}>
              <label className="label">{label}</label>
              <input className="input metric" type="number" step="0.5" value={w[key]} onChange={(e) => setDraft({ ...w, [key]: parseFloat(e.target.value) || 0 })} />
            </div>
          ))}
        </div>
      )}
    </Panel>
  );
}

// ---------- Runtime ----------
function RuntimeInfo() {
  const settings = useQuery({ queryKey: ["settings"], queryFn: () => api.get<Settings>("/settings") });
  const s = settings.data;
  const row = (label: string, value: React.ReactNode) => (
    <div className="flex items-center justify-between border-b border-line/60 py-2 last:border-0"><span className="text-sm text-muted">{label}</span><span className="metric text-sm text-ink">{value}</span></div>
  );
  return (
    <Panel className="p-4">
      <SectionTitle eyebrow="Runtime" title="Instance" />
      {!s ? <Spinner /> : (
        <div className="grid gap-x-8 sm:grid-cols-2">
          {row("Version", s.version)}
          {row("Scan schedule", <span className="text-faint">{s.schedule}</span>)}
          {row("Max hosts / asset", s.max_hosts_per_asset)}
          {row("Max concurrency", s.max_concurrency)}
          {row("Retention", s.retention_days === 0 ? "keep all" : `${s.retention_days} days`)}
          {row("Encryption", s.encryption_configured ? <span className="text-ok">configured</span> : <span className="text-crit">not set</span>)}
          {row("Authentication", s.auth_enabled ? <span className="text-ok">enabled</span> : <span className="text-med">open</span>)}
        </div>
      )}
      <div className="mt-3 flex items-center gap-2 text-xs text-faint"><Server size={13} /> Schedule, retention, and concurrency are set via config/env and shown read-only. <SlidersHorizontal size={13} className="ml-2" /> Scoring weights are editable above.</div>
    </Panel>
  );
}

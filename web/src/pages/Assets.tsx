import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { Plus, Play, Pencil, Trash2, Radar } from "lucide-react";
import { api, Asset, AssetType } from "@/lib/api";
import { Panel, SectionTitle, Spinner, ErrorState, EmptyState, Toggle } from "@/components/ui";
import { Modal } from "@/components/Modal";
import { useToast } from "@/components/toast";
import { timeAgo } from "@/lib/format";

const types: { value: AssetType; label: string; hint: string }[] = [
  { value: "ip", label: "IP address", hint: "A single IPv4 or IPv6 address" },
  { value: "fqdn", label: "Hostname (FQDN)", hint: "Resolved to IPs each scan" },
  { value: "domain", label: "Domain", hint: "Subdomains enumerated via Shodan DNS" },
  { value: "cidr", label: "CIDR range", hint: "Expanded to member hosts (bounded)" },
];

interface Form {
  id?: string;
  type: AssetType;
  value: string;
  label: string;
  notes: string;
  enabled: boolean;
  rescan: boolean;
}

const empty: Form = { type: "ip", value: "", label: "", notes: "", enabled: true, rescan: false };

export function Assets() {
  const qc = useQueryClient();
  const toast = useToast();
  const [form, setForm] = useState<Form | null>(null);

  const { data, isLoading, error } = useQuery({ queryKey: ["assets"], queryFn: () => api.get<Asset[]>("/assets") });

  const save = useMutation({
    mutationFn: (f: Form) =>
      f.id
        ? api.put<Asset>(`/assets/${f.id}`, f)
        : api.post<Asset>("/assets", f),
    onSuccess: () => {
      toast("success", form?.id ? "Asset updated" : "Asset added");
      qc.invalidateQueries({ queryKey: ["assets"] });
      setForm(null);
    },
    onError: (e: Error) => toast("error", e.message),
  });

  const remove = useMutation({
    mutationFn: (id: string) => api.del(`/assets/${id}`),
    onSuccess: () => {
      toast("success", "Asset removed");
      qc.invalidateQueries({ queryKey: ["assets"] });
    },
    onError: (e: Error) => toast("error", e.message),
  });

  const scan = useMutation({
    mutationFn: (id: string) => api.post(`/assets/${id}/scan`),
    onSuccess: () => {
      toast("success", "Scan complete");
      qc.invalidateQueries({ queryKey: ["assets"] });
    },
    onError: (e: Error) => toast("error", e.message),
  });

  if (isLoading) return <div className="p-8"><Spinner label="Loading assets…" /></div>;
  if (error) return <ErrorState message={(error as Error).message} />;
  const assets = data || [];

  return (
    <div className="space-y-6">
      <SectionTitle
        eyebrow="Monitored"
        title="Assets"
        action={<button className="btn btn-primary" onClick={() => setForm(empty)}><Plus size={15} /> Add asset</button>}
      />

      <Panel>
        {assets.length === 0 ? (
          <EmptyState icon={<Radar size={28} />} title="No assets monitored" hint="Add an IP, hostname, domain, or CIDR range to begin watching its external attack surface." action={<button className="btn btn-primary mt-2" onClick={() => setForm(empty)}><Plus size={15} /> Add asset</button>} />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[680px]">
              <thead>
                <tr className="border-b border-line">
                  <th className="th">Asset</th>
                  <th className="th">Type</th>
                  <th className="th">Enabled</th>
                  <th className="th">Rescan</th>
                  <th className="th">Updated</th>
                  <th className="th text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {assets.map((a) => (
                  <tr key={a.id} className="border-b border-line/60 hover:bg-panel-2/50">
                    <td className="td">
                      <Link to={`/assets/${a.id}`} className="group flex flex-col">
                        <span className="metric text-ink group-hover:text-signal">{a.value}</span>
                        {a.label && <span className="text-xs text-faint">{a.label}</span>}
                      </Link>
                    </td>
                    <td className="td"><span className="chip bg-line-2 uppercase text-muted">{a.type}</span></td>
                    <td className="td">{a.enabled ? <span className="text-ok">●</span> : <span className="text-faint">○</span>}</td>
                    <td className="td text-muted">{a.rescan ? "on" : "—"}</td>
                    <td className="td text-xs text-faint">{timeAgo(a.updated_at)}</td>
                    <td className="td">
                      <div className="flex items-center justify-end gap-1">
                        <button className="btn-ghost rounded-md p-1.5" title="Scan now" onClick={() => scan.mutate(a.id)} disabled={scan.isPending}><Play size={15} /></button>
                        <button className="btn-ghost rounded-md p-1.5" title="Edit" onClick={() => setForm({ ...a })}><Pencil size={15} /></button>
                        <button className="btn-ghost rounded-md p-1.5 hover:text-crit" title="Delete" onClick={() => confirm(`Remove ${a.value}?`) && remove.mutate(a.id)}><Trash2 size={15} /></button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      <Modal open={!!form} onClose={() => setForm(null)} title={form?.id ? "Edit asset" : "Add asset"}>
        {form && (
          <form
            className="space-y-4"
            onSubmit={(e) => {
              e.preventDefault();
              save.mutate(form);
            }}
          >
            <div>
              <label className="label">Type</label>
              <div className="grid grid-cols-2 gap-2">
                {types.map((t) => (
                  <button
                    key={t.value}
                    type="button"
                    onClick={() => setForm({ ...form, type: t.value })}
                    className={`rounded-lg border px-3 py-2 text-left text-sm transition-colors ${form.type === t.value ? "border-signal-dim bg-signal/10 text-ink" : "border-line-2 text-muted hover:border-line-2 hover:text-ink"}`}
                  >
                    <div className="font-medium">{t.label}</div>
                    <div className="text-[11px] text-faint">{t.hint}</div>
                  </button>
                ))}
              </div>
            </div>
            <div>
              <label className="label">Value</label>
              <input className="input metric" value={form.value} onChange={(e) => setForm({ ...form, value: e.target.value })} placeholder={form.type === "cidr" ? "10.0.0.0/24" : form.type === "ip" ? "8.8.8.8" : "example.com"} required autoFocus />
            </div>
            <div>
              <label className="label">Label (optional)</label>
              <input className="input" value={form.label} onChange={(e) => setForm({ ...form, label: e.target.value })} placeholder="Production edge" />
            </div>
            <div className="flex items-center gap-6">
              <label className="flex items-center gap-2.5 text-sm text-muted">
                <Toggle checked={form.enabled} onChange={(v) => setForm({ ...form, enabled: v })} /> Enabled
              </label>
              <label className="flex items-center gap-2.5 text-sm text-muted">
                <Toggle checked={form.rescan} onChange={(v) => setForm({ ...form, rescan: v })} /> On-demand rescan
              </label>
            </div>
            <div className="flex justify-end gap-2 pt-2">
              <button type="button" className="btn" onClick={() => setForm(null)}>Cancel</button>
              <button type="submit" className="btn btn-primary" disabled={save.isPending}>{save.isPending ? "Saving…" : "Save"}</button>
            </div>
          </form>
        )}
      </Modal>
    </div>
  );
}

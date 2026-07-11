import { ReactNode } from "react";
import clsx from "clsx";
import { gradeColor, scoreColor, severityBg } from "@/lib/format";

export function Panel({ className, children }: { className?: string; children: ReactNode }) {
  return <div className={clsx("panel", className)}>{children}</div>;
}

export function SectionTitle({ eyebrow, title, action }: { eyebrow?: string; title: string; action?: ReactNode }) {
  return (
    <div className="mb-4 flex items-end justify-between gap-3">
      <div>
        {eyebrow && <div className="eyebrow mb-1">{eyebrow}</div>}
        <h2 className="text-lg font-semibold tracking-tight text-ink">{title}</h2>
      </div>
      {action}
    </div>
  );
}

export function GradeBadge({ grade, size = "md" }: { grade?: string; size?: "sm" | "md" | "lg" }) {
  const dims = size === "lg" ? "h-14 w-14 text-3xl" : size === "sm" ? "h-7 w-7 text-sm" : "h-10 w-10 text-xl";
  return (
    <div
      className={clsx(
        "flex items-center justify-center rounded-lg border border-line-2 bg-canvas font-mono font-bold",
        dims,
        gradeColor(grade),
      )}
      title={grade ? `Grade ${grade}` : "Not scored"}
    >
      {grade || "–"}
    </div>
  );
}

export function ScoreText({ score, className }: { score?: number; className?: string }) {
  return (
    <span className={clsx("metric font-semibold", scoreColor(score), className)}>
      {score == null ? "—" : score}
    </span>
  );
}

export function SeverityChip({ severity }: { severity: string }) {
  return <span className={clsx("chip capitalize", severityBg(severity))}>{severity}</span>;
}

export function Spinner({ label }: { label?: string }) {
  return (
    <div className="flex items-center gap-3 text-muted">
      <div className="h-4 w-4 animate-sweep rounded-full border-2 border-line-2 border-t-signal" />
      {label && <span className="text-sm">{label}</span>}
    </div>
  );
}

export function EmptyState({ icon, title, hint, action }: { icon?: ReactNode; title: string; hint?: string; action?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 px-6 py-16 text-center">
      {icon && <div className="text-faint">{icon}</div>}
      <div className="text-ink">{title}</div>
      {hint && <div className="max-w-sm text-sm text-muted">{hint}</div>}
      {action}
    </div>
  );
}

export function ErrorState({ message }: { message: string }) {
  return (
    <div className="panel p-6">
      <div className="text-sm text-crit">Something went wrong</div>
      <div className="mt-1 text-sm text-muted">{message}</div>
    </div>
  );
}

export function Toggle({ checked, onChange, label }: { checked: boolean; onChange: (v: boolean) => void; label?: string }) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      onClick={() => onChange(!checked)}
      className={clsx(
        "relative inline-flex h-6 w-11 shrink-0 items-center rounded-full border transition-colors",
        checked ? "border-signal-dim bg-signal/30" : "border-line-2 bg-canvas",
      )}
      title={label}
    >
      <span
        className={clsx(
          "inline-block h-4 w-4 transform rounded-full transition-transform",
          checked ? "translate-x-6 bg-signal" : "translate-x-1 bg-faint",
        )}
      />
    </button>
  );
}

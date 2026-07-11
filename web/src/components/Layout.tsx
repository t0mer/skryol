import { ReactNode, useState } from "react";
import { NavLink, useLocation } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { LayoutDashboard, Radar, Bell, Settings, Menu, X, KeyRound } from "lucide-react";
import { api, ShodanKey } from "@/lib/api";
import clsx from "clsx";

const nav = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard, end: true },
  { to: "/assets", label: "Assets", icon: Radar },
  { to: "/alerts", label: "Alerts", icon: Bell },
  { to: "/settings", label: "Settings", icon: Settings },
];

function KeyHealth() {
  const { data } = useQuery({
    queryKey: ["keys"],
    queryFn: () => api.get<ShodanKey[]>("/shodan/keys"),
    refetchInterval: 60000,
  });
  const keys = data || [];
  const healthy = keys.filter((k) => k.enabled && k.health === "healthy").length;
  const credits = keys.reduce((s, k) => s + (k.query_credits || 0), 0);
  const anyBad = keys.some((k) => k.enabled && (k.health === "invalid" || k.health === "exhausted"));
  return (
    <div className="flex items-center gap-2 font-mono text-xs">
      <KeyRound size={14} className={anyBad ? "text-crit" : keys.length ? "text-ok" : "text-faint"} />
      <span className={anyBad ? "text-crit" : "text-muted"}>
        {healthy}/{keys.length || 0} keys
      </span>
      <span className="hidden text-faint sm:inline">· {credits.toLocaleString()} credits</span>
    </div>
  );
}

export function Layout({ children }: { children: ReactNode }) {
  const [open, setOpen] = useState(false);
  const loc = useLocation();

  const sidebar = (
    <nav className="flex h-full flex-col gap-1 p-3">
      <div className="mb-4 flex items-center gap-2.5 px-2 py-1">
        <div className="relative flex h-8 w-8 items-center justify-center rounded-md border border-signal-dim bg-signal/10">
          <div className="absolute h-6 w-6 animate-sweep rounded-full border-t border-signal/60" />
          <Radar size={16} className="text-signal" />
        </div>
        <div>
          <div className="font-semibold leading-none tracking-tight text-ink">Skryol</div>
          <div className="eyebrow mt-1">attack surface</div>
        </div>
      </div>
      {nav.map((n) => (
        <NavLink
          key={n.to}
          to={n.to}
          end={n.end}
          onClick={() => setOpen(false)}
          className={({ isActive }) =>
            clsx(
              "flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition-colors",
              isActive
                ? "bg-signal/10 text-signal shadow-[inset_2px_0_0_0] shadow-signal"
                : "text-muted hover:bg-panel-2 hover:text-ink",
            )
          }
        >
          <n.icon size={17} />
          {n.label}
        </NavLink>
      ))}
      <div className="mt-auto px-3 pt-4 text-[11px] text-faint">
        External attack-surface monitor
        <br />
        powered by Shodan.
      </div>
    </nav>
  );

  return (
    <div className="flex min-h-screen">
      {/* Desktop sidebar */}
      <aside className="hidden w-60 shrink-0 border-r border-line bg-panel/60 lg:block">
        <div className="sticky top-0 h-screen">{sidebar}</div>
      </aside>

      {/* Mobile slide-over */}
      {open && (
        <div className="fixed inset-0 z-40 lg:hidden">
          <div className="absolute inset-0 bg-canvas/70 backdrop-blur-sm" onClick={() => setOpen(false)} />
          <aside className="absolute left-0 top-0 h-full w-60 border-r border-line bg-panel">{sidebar}</aside>
        </div>
      )}

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-30 flex items-center justify-between gap-3 border-b border-line bg-canvas/80 px-4 py-3 backdrop-blur-md lg:px-6">
          <div className="flex items-center gap-3">
            <button className="btn-ghost rounded-md p-1.5 lg:hidden" onClick={() => setOpen(true)} aria-label="Open menu">
              <Menu size={18} />
            </button>
            <span className="text-sm font-medium capitalize text-muted">
              {loc.pathname === "/" ? "Dashboard" : loc.pathname.split("/")[1]}
            </span>
          </div>
          <KeyHealth />
        </header>
        <main className="mx-auto w-full max-w-7xl flex-1 p-4 lg:p-6">{children}</main>
      </div>

      {/* Escape hatch on mobile overlay */}
      {open && (
        <button className="fixed right-4 top-3 z-50 text-muted lg:hidden" onClick={() => setOpen(false)} aria-label="Close menu">
          <X size={20} />
        </button>
      )}
    </div>
  );
}

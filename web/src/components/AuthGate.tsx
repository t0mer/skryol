import { ReactNode, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Radar, LogIn } from "lucide-react";
import { api } from "@/lib/api";
import { Spinner } from "./ui";

interface AuthMe {
  auth_required: boolean;
  authenticated: boolean;
}

export function AuthGate({ children }: { children: ReactNode }) {
  const { data, isLoading } = useQuery({
    queryKey: ["auth-me"],
    queryFn: () => api.get<AuthMe>("/auth/me"),
    retry: false,
  });

  if (isLoading) {
    return <div className="flex h-screen items-center justify-center"><Spinner label="Loading…" /></div>;
  }
  if (data && data.auth_required && !data.authenticated) {
    return <Login />;
  }
  return <>{children}</>;
}

function Login() {
  const qc = useQueryClient();
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setBusy(true);
    try {
      await api.post("/auth/login", { username, password });
      await qc.invalidateQueries();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Login failed");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex min-h-screen items-center justify-center p-4">
      <form onSubmit={submit} className="panel w-full max-w-sm animate-fade-in p-6">
        <div className="mb-6 flex items-center gap-3">
          <div className="relative flex h-10 w-10 items-center justify-center rounded-md border border-signal-dim bg-signal/10">
            <div className="absolute h-7 w-7 animate-sweep rounded-full border-t border-signal/60" />
            <Radar size={18} className="text-signal" />
          </div>
          <div>
            <div className="text-lg font-semibold tracking-tight text-ink">Skryol</div>
            <div className="eyebrow">sign in to continue</div>
          </div>
        </div>
        <div className="space-y-3">
          <div>
            <label className="label">Username</label>
            <input className="input" value={username} onChange={(e) => setUsername(e.target.value)} autoFocus autoComplete="username" />
          </div>
          <div>
            <label className="label">Password</label>
            <input className="input" type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" />
          </div>
          {error && <div className="text-sm text-crit">{error}</div>}
          <button className="btn btn-primary w-full" type="submit" disabled={busy}>
            <LogIn size={15} /> {busy ? "Signing in…" : "Sign in"}
          </button>
        </div>
      </form>
    </div>
  );
}

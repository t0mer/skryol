export function timeAgo(iso?: string): string {
  if (!iso) return "never";
  const d = new Date(iso).getTime();
  if (Number.isNaN(d)) return "never";
  const secs = Math.floor((Date.now() - d) / 1000);
  if (secs < 60) return "just now";
  const mins = Math.floor(secs / 60);
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  if (days < 30) return `${days}d ago`;
  return new Date(iso).toLocaleDateString();
}

export function gradeColor(grade?: string): string {
  switch (grade) {
    case "A":
      return "text-ok";
    case "B":
      return "text-low";
    case "C":
      return "text-med";
    case "D":
      return "text-high";
    case "F":
      return "text-crit";
    default:
      return "text-faint";
  }
}

export function severityColor(sev: string): string {
  switch (sev) {
    case "critical":
      return "text-crit";
    case "high":
      return "text-high";
    case "medium":
      return "text-med";
    case "low":
      return "text-low";
    default:
      return "text-muted";
  }
}

export function severityBg(sev: string): string {
  switch (sev) {
    case "critical":
      return "bg-crit/15 text-crit";
    case "high":
      return "bg-high/15 text-high";
    case "medium":
      return "bg-med/15 text-med";
    case "low":
      return "bg-low/15 text-low";
    default:
      return "bg-line-2 text-muted";
  }
}

export function scoreColor(score?: number): string {
  if (score == null) return "text-faint";
  if (score >= 90) return "text-ok";
  if (score >= 80) return "text-low";
  if (score >= 70) return "text-med";
  if (score >= 60) return "text-high";
  return "text-crit";
}

export function healthColor(health: string): string {
  switch (health) {
    case "healthy":
      return "bg-ok/15 text-ok";
    case "cooling":
      return "bg-med/15 text-med";
    case "exhausted":
    case "invalid":
      return "bg-crit/15 text-crit";
    default:
      return "bg-line-2 text-muted";
  }
}

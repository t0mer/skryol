/** @type {import('tailwindcss').Config} */
export default {
  darkMode: "class",
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        // Observatory canvas.
        canvas: "#0a0e14",
        panel: "#111823",
        "panel-2": "#161f2c",
        line: "#1f2a38",
        "line-2": "#2a3949",
        ink: "#e7ecf3",
        muted: "#8996a8",
        faint: "#5c6a7d",
        // Signal accent (skry teal).
        signal: {
          DEFAULT: "#2fd4bb",
          dim: "#1f9c8a",
          glow: "#5ce7d3",
        },
        // Severity scale.
        crit: "#f0546a",
        high: "#f79445",
        med: "#e7c14b",
        low: "#5aa9f0",
        ok: "#2fd4bb",
      },
      fontFamily: {
        sans: [
          "Inter var",
          "Inter",
          "ui-sans-serif",
          "system-ui",
          "-apple-system",
          "Segoe UI",
          "Roboto",
          "sans-serif",
        ],
        mono: [
          "ui-monospace",
          "JetBrains Mono",
          "SFMono-Regular",
          "Menlo",
          "Consolas",
          "monospace",
        ],
      },
      boxShadow: {
        panel: "0 1px 0 0 rgba(255,255,255,0.02) inset, 0 8px 24px -12px rgba(0,0,0,0.6)",
        glow: "0 0 0 1px rgba(47,212,187,0.25), 0 0 24px -6px rgba(47,212,187,0.35)",
      },
      keyframes: {
        "fade-in": {
          from: { opacity: "0", transform: "translateY(4px)" },
          to: { opacity: "1", transform: "translateY(0)" },
        },
        sweep: {
          "0%": { transform: "rotate(0deg)" },
          "100%": { transform: "rotate(360deg)" },
        },
      },
      animation: {
        "fade-in": "fade-in 0.3s ease-out both",
        sweep: "sweep 4s linear infinite",
      },
    },
  },
  plugins: [],
};

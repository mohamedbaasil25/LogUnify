import type { Config } from "tailwindcss";

// Palette matches the dark theme of the existing logunify.html console.
const config: Config = {
  content: ["./app/**/*.{ts,tsx}", "./components/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        bg: "#0b1016",
        panel: "#121a22",
        panel2: "#18222c",
        line: "#25323e",
        fg: "#e3eaf1",
        mute: "#8a9aa9",
        accent: "#7ba3ff",
        crit: "#ff7266",
        warn: "#f0b34a",
        ok: "#5fd394",
      },
      fontFamily: {
        sans: ['"IBM Plex Sans"', "system-ui", "-apple-system", '"Segoe UI"', "sans-serif"],
        mono: ['"JetBrains Mono"', "ui-monospace", "Consolas", "monospace"],
      },
    },
  },
  plugins: [],
};

export default config;

"use client";

import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  BarElement,
  Title,
  Tooltip,
  Legend,
  ArcElement,
  PointElement,
  LineElement,
  Filler,
} from "chart.js";

// Register all Chart.js components once at the module level
ChartJS.register(
  CategoryScale,
  LinearScale,
  BarElement,
  Title,
  Tooltip,
  Legend,
  ArcElement,
  PointElement,
  LineElement,
  Filler,
);

export const DARK_DEFAULTS = {
  responsive: true,
  maintainAspectRatio: false,
  plugins: {
    legend: {
      labels: {
        color: "#888",
        font: { family: "SF Mono, Fira Code, Consolas, monospace", size: 11 },
      },
    },
    tooltip: {
      backgroundColor: "#111",
      borderColor: "#333",
      borderWidth: 1,
      titleColor: "#c0c0c0",
      bodyColor: "#888",
      titleFont: { family: "SF Mono, Fira Code, Consolas, monospace" },
      bodyFont: { family: "SF Mono, Fira Code, Consolas, monospace" },
    },
  },
  scales: {
    x: {
      ticks: {
        color: "#888",
        font: { family: "SF Mono, Fira Code, Consolas, monospace", size: 10 },
      },
      grid: { color: "#1a1a1a" },
      border: { color: "#1a1a1a" },
    },
    y: {
      ticks: {
        color: "#888",
        font: { family: "SF Mono, Fira Code, Consolas, monospace", size: 10 },
      },
      grid: { color: "#1a1a1a" },
      border: { color: "#1a1a1a" },
    },
  },
};

export const SEV_COLORS: Record<string, string> = {
  critical: "#ff4444",
  high: "#ff8800",
  medium: "#f0c040",
  low: "#4488ff",
  unknown: "#555555",
};

export { ChartJS };

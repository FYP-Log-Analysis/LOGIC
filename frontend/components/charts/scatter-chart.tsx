"use client";

import { Scatter } from "react-chartjs-2";
import "@/components/charts/setup";
import { DARK_DEFAULTS } from "@/components/charts/setup";

interface ScatterPoint {
  x: number | string;
  y: number;
  label?: string;
}

interface ScatterDataset {
  label: string;
  data: ScatterPoint[];
  color?: string;
  pointRadius?: number;
}

interface ScatterChartProps {
  title?: string;
  datasets: ScatterDataset[];
  xLabel?: string;
  yLabel?: string;
  height?: number;
}

export default function ScatterChart({
  title,
  datasets,
  xLabel,
  yLabel,
  height = 300,
}: ScatterChartProps) {
  const chartData = {
    datasets: datasets.map((ds) => ({
      label: ds.label,
      data: ds.data.map((p) => ({ x: p.x as number, y: p.y })),
      backgroundColor: ds.color ?? "#4488ff",
      pointRadius: ds.pointRadius ?? 4,
      pointHoverRadius: 6,
    })),
  };

  const options = {
    ...DARK_DEFAULTS,
    plugins: {
      ...DARK_DEFAULTS.plugins,
      title: title
        ? {
            display: true,
            text: title,
            color: "#888",
            font: {
              family: "SF Mono, Fira Code, Consolas, monospace",
              size: 12,
              weight: 400 as const,
            },
            padding: { bottom: 12 },
          }
        : { display: false },
    },
    scales: {
      x: {
        ...DARK_DEFAULTS.scales.x,
        title: xLabel
          ? { display: true, text: xLabel, color: "#555" }
          : { display: false },
        type: "linear" as const,
      },
      y: {
        ...DARK_DEFAULTS.scales.y,
        title: yLabel
          ? { display: true, text: yLabel, color: "#555" }
          : { display: false },
      },
    },
  };

  return (
    <div style={{ height, width: "100%" }}>
      <Scatter data={chartData} options={options} />
    </div>
  );
}

"use client";

import { Line } from "react-chartjs-2";
import "@/components/charts/setup";
import { DARK_DEFAULTS } from "@/components/charts/setup";

interface LineDataset {
  label: string;
  data: number[];
  color?: string;
  fill?: boolean;
}

interface LineChartProps {
  title?: string;
  labels: string[];
  datasets: LineDataset[];
  yLabel?: string;
  threshold?: number;
  thresholdLabel?: string;
  height?: number;
}

export default function LineChart({
  title,
  labels,
  datasets,
  yLabel,
  threshold,
  thresholdLabel,
  height = 280,
}: LineChartProps) {
  const chartData = {
    labels,
    datasets: [
      ...datasets.map((ds) => ({
        label: ds.label,
        data: ds.data,
        borderColor: ds.color ?? "#4488ff",
        backgroundColor: ds.fill
          ? `${ds.color ?? "#4488ff"}22`
          : "transparent",
        fill: ds.fill ?? false,
        borderWidth: 1.5,
        pointRadius: 3,
        pointHoverRadius: 5,
        tension: 0.15,
      })),
      // Threshold annotation line as a dataset
      ...(threshold !== undefined
        ? [
            {
              label: thresholdLabel ?? `Threshold (${threshold})`,
              data: Array(labels.length).fill(threshold),
              borderColor: "#aaaaaa",
              borderDash: [6, 3],
              borderWidth: 1,
              pointRadius: 0,
              fill: false,
            },
          ]
        : []),
    ],
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
      ...DARK_DEFAULTS.scales,
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
      <Line data={chartData} options={options} />
    </div>
  );
}

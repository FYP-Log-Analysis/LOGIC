"use client";

import { Doughnut } from "react-chartjs-2";
import "@/components/charts/setup";
import { DARK_DEFAULTS } from "@/components/charts/setup";

interface PieChartProps {
  title?: string;
  labels: string[];
  values: number[];
  colors?: string[];
  height?: number;
}

const DEFAULT_COLORS = [
  "#4a8a4a",
  "#4a4a8a",
  "#8a6a4a",
  "#8a4a4a",
  "#6a4a8a",
  "#4a7a8a",
  "#8a8a4a",
  "#7a4a4a",
];

export default function PieChart({
  title,
  labels,
  values,
  colors,
  height = 260,
}: PieChartProps) {
  const data = {
    labels,
    datasets: [
      {
        data: values,
        backgroundColor: colors ?? DEFAULT_COLORS.slice(0, labels.length),
        borderColor: "#0d0d0d",
        borderWidth: 2,
      },
    ],
  };

  const options = {
    ...DARK_DEFAULTS,
    scales: {}, // no scales for pie
    plugins: {
      ...DARK_DEFAULTS.plugins,
      legend: {
        position: "bottom" as const,
        labels: {
          color: "#888",
          font: { family: "SF Mono, Fira Code, Consolas, monospace", size: 10 },
          padding: 12,
        },
      },
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
            padding: { bottom: 8 },
          }
        : { display: false },
    },
  };

  return (
    <div style={{ height, width: "100%" }}>
      <Doughnut data={data} options={options} />
    </div>
  );
}

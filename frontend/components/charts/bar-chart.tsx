"use client";

import { Bar } from "react-chartjs-2";
import "@/components/charts/setup";
import { DARK_DEFAULTS } from "@/components/charts/setup";

interface BarChartProps {
  title?: string;
  labels: string[];
  values: number[];
  color?: string | string[];
  horizontal?: boolean;
  height?: number;
}

export default function BarChart({
  title,
  labels,
  values,
  color = "#4a4a8a",
  horizontal = false,
  height = 260,
}: BarChartProps) {
  const data = {
    labels,
    datasets: [
      {
        data: values,
        backgroundColor: Array.isArray(color) ? color : color,
        borderWidth: 0,
      },
    ],
  };

  const options = {
    ...DARK_DEFAULTS,
    indexAxis: horizontal ? ("y" as const) : ("x" as const),
    plugins: {
      ...DARK_DEFAULTS.plugins,
      legend: { display: false },
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
  };

  return (
    <div style={{ height, width: "100%" }}>
      <Bar data={data} options={options} />
    </div>
  );
}

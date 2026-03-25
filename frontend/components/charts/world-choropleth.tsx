"use client";

import { WorldMap, type DataItem, type ISOCode } from "react-svg-worldmap";

export interface GeoCountryDatum {
  country_code: string;
  country_name: string;
  detection_count: number;
  critical_count?: number;
  high_count?: number;
  medium_count?: number;
  low_count?: number;
}

interface WorldChoroplethProps {
  countries: GeoCountryDatum[];
}

export default function WorldChoropleth({ countries }: WorldChoroplethProps) {
  const data: DataItem<number>[] = countries
    .filter((item) => item.country_code && item.country_code !== "ZZ")
    .map((item) => ({
      country: item.country_code.toUpperCase() as ISOCode,
      value: item.detection_count,
    }));

  if (!data.length) {
    return (
      <div
        style={{
          minHeight: 280,
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          color: "#555",
          fontSize: 12,
          border: "1px dashed #2a2a2a",
          borderRadius: 4,
          background: "radial-gradient(circle at 30% 20%, #161616 0%, #0d0d0d 70%)",
        }}
      >
        No geolocated detections available yet.
      </div>
    );
  }

  return (
    <div
      style={{
        minHeight: 280,
        background: "radial-gradient(circle at 30% 20%, #161616 0%, #0d0d0d 70%)",
        border: "1px solid #1e1e1e",
        borderRadius: 4,
        padding: 12,
      }}
    >
      <WorldMap
        color="#d97706"
        backgroundColor="transparent"
        borderColor="#2d2d2d"
        size="responsive"
        data={data}
        tooltipBgColor="#0d0d0d"
        tooltipTextColor="#e8e8e8"
        title="Detection Density by Country"
        valueSuffix=" detections"
      />
    </div>
  );
}

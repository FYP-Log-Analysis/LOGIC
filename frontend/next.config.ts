import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  reactCompiler: true,
  output: 'standalone',
  env: {
    API_BASE_URL: process.env.API_BASE_URL || 'http://localhost:4000',
  },
};

export default nextConfig;

import path from "node:path";
import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  output: "standalone",
  outputFileTracingRoot: path.join(__dirname),
  poweredByHeader: false,
  reactStrictMode: true,
  async rewrites() {
    const backend = (
      process.env.NERUTON_SERVER_URL || "http://127.0.0.1:8080"
    ).replace(/\/+$/, "");

    return [
      {
        source: "/_neruton/:path*",
        destination: `${backend}/_neruton/:path*`,
      },
      {
        source: "/t/:path*",
        destination: `${backend}/t/:path*`,
      },
    ];
  },
};

export default nextConfig;

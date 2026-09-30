/** @type {import('next').NextConfig} */
const API = process.env.LOGUNIFY_API_URL ?? "http://localhost:8000";

const nextConfig = {
  reactStrictMode: true,
  // Same-origin proxy to the FastAPI backend: no CORS, and the backend URL never reaches the browser.
  async rewrites() {
    return [{ source: "/api/:path*", destination: `${API}/api/:path*` }];
  },
};

export default nextConfig;

/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  output: "standalone", // self-contained server for the container image
  compress: false, // gzip buffers Server-Sent Events; terminate compression at the reverse proxy instead
  // The backend proxy is a runtime route handler (app/api/[...path]/route.ts), not a rewrite: LOGUNIFY_API_URL is read at start-up.
};

export default nextConfig;

/** @type {import('next').NextConfig} */
const securityHeaders = [
  { key: "X-Frame-Options", value: "DENY" },
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "Referrer-Policy", value: "no-referrer" },
  { key: "Permissions-Policy", value: "geolocation=(), camera=(), microphone=(), payment=()" },
  { key: "Cross-Origin-Opener-Policy", value: "same-origin" },
  { key: "Cross-Origin-Resource-Policy", value: "same-origin" },
  // The Content-Security-Policy (with a per-request nonce) is set in middleware.ts.
];

const nextConfig = {
  reactStrictMode: true,
  poweredByHeader: false, // do not advertise the framework
  output: "standalone", // self-contained server for the container image
  compress: false, // gzip buffers Server-Sent Events; terminate compression at the reverse proxy instead
  async headers() {
    return [{ source: "/:path*", headers: securityHeaders }];
  },
  // The backend proxy is a runtime route handler (app/api/[...path]/route.ts), not a rewrite: LOGUNIFY_API_URL is read at start-up.
};

export default nextConfig;

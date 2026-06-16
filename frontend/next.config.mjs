/** @type {import('next').NextConfig} */
const nextConfig = {
  output: 'standalone',
  experimental: {
    proxyTimeout: 600_000,
  },
  httpAgentOptions: {
    keepAlive: true,
  },
  async rewrites() {
    const backend = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'
    return [
      { source: '/api/:path*', destination: `${backend}/api/:path*` },
      { source: '/health', destination: `${backend}/health` },
    ]
  },
}

export default nextConfig

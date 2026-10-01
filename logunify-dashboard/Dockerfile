# syntax=docker/dockerfile:1.7
# LogUnify SOC dashboard: Next.js standalone server, non-root. The backend URL is read at START (LOGUNIFY_API_URL), not baked in.
ARG NODE_IMAGE=node:22-alpine

FROM ${NODE_IMAGE} AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund

FROM ${NODE_IMAGE} AS build
WORKDIR /app
ENV NEXT_TELEMETRY_DISABLED=1
COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN npm run build

FROM ${NODE_IMAGE}
WORKDIR /app
ENV NODE_ENV=production NEXT_TELEMETRY_DISABLED=1 PORT=3000 HOSTNAME=0.0.0.0 LOGUNIFY_API_URL=http://backend:8000
COPY --from=build --chown=node:node /app/.next/standalone ./
COPY --from=build --chown=node:node /app/.next/static ./.next/static
USER node
EXPOSE 3000
HEALTHCHECK --interval=15s --timeout=4s --start-period=15s --retries=4 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:3000/').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"]
CMD ["node", "server.js"]

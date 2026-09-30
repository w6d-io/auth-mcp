# Build stage
FROM node:22-alpine AS builder

WORKDIR /app

COPY package*.json tsconfig.json ./
RUN npm ci

COPY src ./src
RUN npm run build

# Production stage
FROM node:22-alpine AS production

# The commit the image is built from; CI passes it (the metadata action sets the same label).
ARG REVISION=unknown
LABEL org.opencontainers.image.source="https://github.com/w6d-io/auth-mcp" \
      org.opencontainers.image.revision="${REVISION}"

WORKDIR /app

COPY package*.json ./
RUN npm ci --omit=dev && npm cache clean --force

COPY --from=builder /app/dist ./dist

RUN addgroup -g 1001 -S nodejs && adduser -S nodejs -u 1001 -G nodejs
# Numeric, so Kubernetes can verify runAsNonRoot without a runAsUser.
USER 1001:1001

ENV NODE_ENV=production PORT=3100

EXPOSE 3100

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3100/healthz', (r) => process.exit(r.statusCode === 200 ? 0 : 1))"

CMD ["node", "dist/server.js"]

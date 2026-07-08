# Build stage
FROM node:20-alpine AS builder
WORKDIR /app

# Copy local dependency package
COPY db-guard/node ./db-guard/node
# Copy proxy package
COPY db-proxy ./db-proxy

# Install and build db-guard
WORKDIR /app/db-guard/node
RUN npm ci
RUN npm run build

# Install and build db-proxy
WORKDIR /app/db-proxy
RUN npm ci
RUN npm run build

# Production stage
FROM node:20-alpine
WORKDIR /app

# Copy built packages from builder
COPY --from=builder /app/db-guard/node /app/db-guard/node
COPY --from=builder /app/db-proxy /app/db-proxy

WORKDIR /app/db-proxy

# Expose default DB-Proxy port
EXPOSE 54320

# Start proxy in non-interactive CLI mode by default
CMD ["node", "dist/index.js", "--non-interactive"]

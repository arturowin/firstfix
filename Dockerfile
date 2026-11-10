# One image for api, worker and migrate; compose picks the command.
FROM node:22-alpine

WORKDIR /app
ENV NODE_ENV=production

COPY package.json package-lock.json .npmrc ./
# Dev dependencies are needed only to bundle the UI (esbuild); pruned afterwards.
RUN npm ci --include=dev --ignore-scripts --no-audit --no-fund

COPY tsconfig.json ./
COPY migrations ./migrations
COPY scripts ./scripts
COPY src ./src
RUN node scripts/build-web.ts && npm prune --omit=dev --ignore-scripts --no-audit --no-fund

USER node
EXPOSE 3000
CMD ["node", "src/api/main.ts"]

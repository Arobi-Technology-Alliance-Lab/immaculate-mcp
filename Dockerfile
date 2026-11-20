FROM node:22-alpine

WORKDIR /app

COPY package.json LICENSE glama.json server.json ./
COPY src ./src

USER node

ENV NODE_ENV=production
ENV AROBI_MCP_URL=https://aura-genesis.org/api/v1/mcp

ENTRYPOINT ["node", "/app/src/index.mjs"]

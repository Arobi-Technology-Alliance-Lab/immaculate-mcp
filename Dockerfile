FROM node:22-alpine

WORKDIR /app

COPY package.json LICENSE glama.json server.json ./
COPY src ./src

USER node

ENV NODE_ENV=production

ENTRYPOINT ["node", "/app/src/index.mjs"]

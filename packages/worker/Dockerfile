ARG NODE_VERSION="18.16"
ARG ALPINE_VERSION="3.18"

FROM node:${NODE_VERSION}-alpine${ALPINE_VERSION} AS node_base

FROM node_base AS builder_base

RUN npm install pnpm -g

FROM node_base AS runner_base

# Install docker
RUN apk upgrade --update-cache --available && \
  apk add openssl git docker docker-cli-compose curl && \
  rm -rf /var/cache/apk/*

FROM builder_base AS builder

WORKDIR /app

COPY ./pnpm-lock.yaml ./
COPY ./pnpm-workspace.yaml ./
COPY ./patches ./patches
RUN pnpm fetch --no-scripts

COPY ./packages ./packages

RUN pnpm install -r --prefer-offline 

COPY ./packages/cli/build.js ./packages/cli/build.js
COPY ./packages/cli/src ./packages/cli/src
COPY ./packages/cli/package.json ./packages/cli/package.json
COPY ./packages/cli/assets ./packages/cli/assets

RUN pnpm -r build --filter @runtipi/cli

FROM runner_base AS app

WORKDIR /app

ENV NODE_ENV=production

COPY --from=builder /app/packages/cli/dist .
COPY --from=builder /app/packages/cli/assets ./assets

CMD ["node", "index.js", "start"]


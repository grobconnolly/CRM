# Finlete CRM — cloud image
FROM node:22-slim

# curl is required: the server uses it to fetch FanGraphs / MLB Pipeline data
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
# data.jso[n] is a glob so the build also works from git, where data.json is ignored;
# a fresh volume just starts empty and fills on the first rank sync
COPY server.js data.jso[n] ./
COPY public ./public
COPY sources ./sources

# Data lives on a persistent volume mounted at /data (seeded from data.json on first run)
ENV DATA_DIR=/data

CMD ["node", "server.js"]

# Backup runner with the client tools for PostgreSQL, MongoDB and MySQL/MariaDB.
FROM node:22-alpine

# pg_dump must be >= the server's major version (build with --build-arg PG_CLIENT=postgresql18-client for PG 18)
ARG PG_CLIENT=postgresql17-client
RUN apk add --no-cache tini ${PG_CLIENT} mariadb-client mongodb-tools ca-certificates tzdata

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force
COPY bin ./bin
COPY src ./src
COPY examples ./examples
COPY .env.example ./

# config + state live in /config (mount it); temp files in /tmp (mount a big volume for large DBs)
WORKDIR /config
ENV NODE_ENV=production DBBACKUP_CONFIG=/config/dbbackup.config.json
RUN chown node:node /config
USER node

ENTRYPOINT ["/sbin/tini", "--", "node", "/app/bin/dbbackup.js"]
CMD ["daemon"]

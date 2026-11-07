# DEMO ONLY. Intentionally un-hardened so the dockerfile check has findings.
FROM node:latest
ARG NPM_TOKEN=npm_FAKEdemotoken000000000000000000000000
ADD https://example.com/setup.sh /setup.sh
RUN curl https://get.example.com/install | sh
COPY . /app
CMD ["node", "/app/dist/app.js"]

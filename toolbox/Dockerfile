# Crenel toolbox: nuclei, katana and trufflehog, and nothing else.
#
#   crenel tools build        (or: docker build -t crenel-toolbox:0.1.0 toolbox/)
#
# Every input is pinned: base images by digest, release archives by the sha256
# published in each project's checksums file, the nuclei templates by the
# sha256 of their tagged release. The nuclei templates are filtered at build
# time (nuclei-filter.mjs): only non-intrusive, GET/HEAD-only http templates
# stay in the image. No exploitation tool (no sqlmap, no brute forcer).
#
# The image has no network policy of its own: Crenel runs it on an internal
# Docker network whose only exit is Crenel's scoped egress proxy. See
# docs/TOOLBOX.md.

ARG ALPINE=alpine:3.22@sha256:bfe7ceb9f09ec0566c48fb93356e45a47a00be5a1dd14fa5b909e7709c66b034
ARG NODE=node:22.23.4-slim@sha256:5ec23b7c622b00547753bc6ffd78085dd868a68aeb41c8e0a1418f033e13d96d

# ---- fetch: download and verify the official release archives ----
FROM ${ALPINE} AS fetch
ARG TARGETARCH
ARG NUCLEI_VERSION=3.11.1
ARG KATANA_VERSION=1.8.0
ARG TRUFFLEHOG_VERSION=3.99.8
ARG TEMPLATES_VERSION=10.5.1
WORKDIR /dl
RUN set -eu; \
    case "${TARGETARCH:-amd64}" in \
      amd64) NUCLEI_SHA=ea63d4ae232808cd7c6bc00d0142428e231fab59dae01042246097d195835ab6; \
             KATANA_SHA=cb027ae99d0757061b70c07a15c7a80f62c5a535ab52c4a329f80c4b0a7309d2; \
             TRUFFLEHOG_SHA=7c3b02f160f28929a467e29e20fba98746e0729f6e37c3c25761e4f8789abe08 ;; \
      arm64) NUCLEI_SHA=8044e3d9768ba0a744b2872c1a87e813006f013da97ca9f50f7661a4203bec07; \
             KATANA_SHA=80e269210727a855511ffac8dfb01297b2344742acec71a35e8ba4a67a90f0f2; \
             TRUFFLEHOG_SHA=a0382d83dd58c967af5dd0175cc732c62c836ab1d15dc9ae71b01a2d3f0911b2 ;; \
      *) echo "unsupported arch ${TARGETARCH}"; exit 1 ;; \
    esac; \
    A="${TARGETARCH:-amd64}"; \
    GH=https://github.com; \
    wget -q -O nuclei.zip "$GH/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${A}.zip"; \
    wget -q -O katana.zip "$GH/projectdiscovery/katana/releases/download/v${KATANA_VERSION}/katana_${KATANA_VERSION}_linux_${A}.zip"; \
    wget -q -O trufflehog.tgz "$GH/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VERSION}/trufflehog_${TRUFFLEHOG_VERSION}_linux_${A}.tar.gz"; \
    wget -q -O templates.tgz "$GH/projectdiscovery/nuclei-templates/archive/refs/tags/v${TEMPLATES_VERSION}.tar.gz"; \
    printf '%s  %s\n' \
      "$NUCLEI_SHA" nuclei.zip \
      "$KATANA_SHA" katana.zip \
      "$TRUFFLEHOG_SHA" trufflehog.tgz \
      30fe1cfaced4635f886e4a2673641bba86998dceec28e468274524e789aa56eb templates.tgz \
      | sha256sum -c -; \
    mkdir -p bin templates; \
    unzip -q -o nuclei.zip nuclei -d bin; \
    unzip -q -o katana.zip katana -d bin; \
    tar -xzf trufflehog.tgz -C bin trufflehog; \
    tar -xzf templates.tgz -C templates --strip-components=1; \
    chmod 0755 bin/*

# ---- filter: delete every nuclei template that is not on the allowlist ----
FROM ${NODE} AS filter
COPY --from=fetch /dl/templates /templates
COPY nuclei-filter.mjs /filter/nuclei-filter.mjs
RUN node /filter/nuclei-filter.mjs /templates && find /templates -type d -empty -delete

# ---- final image ----
FROM ${ALPINE}
RUN apk add --no-cache ca-certificates=20261020-r0 socat=1.8.1.3-r0 \
 && addgroup -g 65532 crenel && adduser -D -H -u 65532 -G crenel -h /tmp/home crenel
COPY --from=fetch /dl/bin/nuclei /dl/bin/katana /dl/bin/trufflehog /usr/local/bin/
COPY --from=filter /templates /opt/nuclei-templates
COPY entrypoint.sh /usr/local/bin/crenel-entrypoint
RUN chmod 0755 /usr/local/bin/crenel-entrypoint && chmod -R a-w /opt/nuclei-templates
LABEL org.opencontainers.image.title="crenel-toolbox" \
      org.opencontainers.image.description="nuclei (filtered templates), katana, trufflehog for Crenel; network only through Crenel's egress proxy" \
      org.opencontainers.image.licenses="MIT"
ENV HOME=/tmp/home \
    NUCLEI_TEMPLATES=/opt/nuclei-templates \
    DISABLE_NUCLEI_TEMPLATES_PUBLIC_DOWNLOAD=true \
    DISABLE_NUCLEI_TEMPLATES_GITHUB_DOWNLOAD=true
USER 65532:65532
WORKDIR /tmp
ENTRYPOINT ["/usr/local/bin/crenel-entrypoint"]

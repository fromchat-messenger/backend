#
# Custom Caddy built with:
# - Rate limit plugin
#
# Site snippets under additions/ are NOT baked into the image.
# Mount them at runtime (compose bind-mount or anonymous VOLUME).
#

FROM caddy:2-builder AS builder
RUN xcaddy build \
      --with github.com/mholt/caddy-ratelimit

FROM caddy:2

COPY --from=builder /usr/bin/caddy /usr/bin/caddy
COPY Caddyfile /etc/caddy/Caddyfile

RUN mkdir -p /etc/caddy/additions
VOLUME /etc/caddy/additions

# Trailhead server image. Generation does NOT run in this container: with TRAILHEAD_SANDBOX=command the
# worker launches each run in a separate isolated sandbox (see deploy/sandbox/README.md).
FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
ARG TRAILHEAD_GIT_SHA=dev
ENV TRAILHEAD_GIT_SHA=${TRAILHEAD_GIT_SHA}
RUN cargo build --release --locked --bin trailhead

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates git bash python3 docker.io \
    && rm -rf /var/lib/apt/lists/* && useradd --system --home /app trailhead
WORKDIR /app
COPY --from=build /src/target/release/trailhead /usr/local/bin/trailhead
COPY web ./web
COPY agent.toml ./agent.toml
COPY deploy/sandbox ./deploy/sandbox
USER trailhead
ENV TRAILHEAD_BIND=0.0.0.0:8080 TRAILHEAD_WEB_DIR=/app/web TRAILHEAD_AGENT_TOML=/app/agent.toml
EXPOSE 8080
CMD ["trailhead", "serve"]

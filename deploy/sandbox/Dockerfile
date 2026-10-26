# The generation sandbox image: Rust toolchain + the Claude Agent SDK CLI, nothing else.
# Build: docker build -t ghcr.io/shashirsb/agentreksdb-trailhead-sandbox:main deploy/sandbox
FROM rust:1-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends nodejs npm python3 git \
    && rm -rf /var/lib/apt/lists/* \
    && npm install -g @anthropic-ai/claude-code \
    && rustup component add clippy rustfmt \
    && useradd --create-home sandbox
COPY run.sh /opt/trailhead/run.sh
USER sandbox
ENV HOME=/home/sandbox CARGO_HOME=/tmp/cargo

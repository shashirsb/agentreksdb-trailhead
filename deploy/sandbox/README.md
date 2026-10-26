# Generation sandbox

Each intent is generated in its own throwaway sandbox. The worker only ever sees what comes back:
`out/base`, `out/patch`, `out/transcript.jsonl`, `out/cost_usd`, `out/image_digest`.

| File | Runs where | Job |
| --- | --- | --- |
| `launch.sh` | worker host (`TRAILHEAD_SANDBOX_COMMAND`) | clones the target repo, starts the locked-down container |
| `run.sh` | inside the sandbox | runs the pinned model headless (`claude -p --bare`), writes the patch |
| `Dockerfile` | build once | the sandbox image (Rust + Claude Agent SDK CLI) |
| `fake-model.sh` | tests only | deterministic stand-in that edits the test app without calling a model |

## One-time network setup (Docker profile)

```bash
docker network create --internal trailhead-sandbox          # no route to the internet
docker run -d --name model-proxy --network bridge \
  -e ANTHROPIC_API_KEY -v $PWD/agent.toml:/app/agent.toml \
  trailhead trailhead model-proxy --bind 0.0.0.0:8888
docker network connect trailhead-sandbox model-proxy         # the proxy is the sandbox's only door
docker build -t ghcr.io/shashirsb/agentreksdb-trailhead-sandbox:main deploy/sandbox
```

Then on the worker: `TRAILHEAD_SANDBOX=command TRAILHEAD_SANDBOX_COMMAND=deploy/sandbox/launch.sh`.

## What the isolation guarantees

- The real API key lives only in the proxy; the sandbox holds a placeholder.
- The proxy forwards only `POST /v1/messages` and only for the pinned model in `agent.toml`.
- No other egress: crates must be vendored in the target repo (`CARGO_NET_OFFLINE=true`).
- No signing key exists anywhere near the sandbox: commits are signed later by `.github/workflows/commit.yml`.
- Limits: 8 CPUs, 16 GB, 4096 processes, read-only root, all capabilities dropped, 45-minute wall clock (worker).

## Moving to Firecracker

For untrusted public traffic, run `run.sh` in a Firecracker microVM per intent (own kernel; AI-written
`unsafe` code and `build.rs` scripts cannot reach the host kernel). Keep the same contract: mount the run
directory, give the VM a tap device whose only route is the model proxy, read `out/` when it exits.

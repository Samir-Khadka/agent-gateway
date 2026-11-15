# Deploying Agent Gateway

## Local (fastest)

```bash
pip install -r requirements.txt
# in one terminal: the demo tool server (the thing being protected)
uvicorn gateway.demo_server:create_demo_server --factory --port 8001
# in another: the gateway
GATEWAY_ADMIN_KEY=demo-admin-secret \
  uvicorn gateway.server:app --port 8000
```

Then open the dashboard at `http://127.0.0.1:8000/admin/dashboard`
(with the admin key) and the policy editor at
`http://127.0.0.1:8000/admin/editor`.

## Docker

```bash
docker build -t agent-gateway .
docker run -p 8000:8000 -e GATEWAY_ADMIN_KEY=$(openssl rand -hex 32) \
  agent-gateway
```

## Render (free tier)

`render.yaml` is a Blueprint: connect this repo in the Render
dashboard and it creates the web service. Set `GATEWAY_KEYS` in the
dashboard (JSON, agent key -> agent id) and point `UPSTREAM_URL` at
your own MCP tool server instead of the demo server.

**Note (Nov 2026):** Samir's Render workspace is suspended until
1 Dec (the free 750-hour budget is exhausted), so a live Render
deploy waits until then. The Docker and local paths work now.

## What a real deployment needs

- **A persistent disk** for `./data` (audit log, taint, approvals).
  On Render free the disk is ephemeral — a restart loses the log.
  Attach a disk, or ship the audit log to object storage.
- **Your own tool server** as `UPSTREAM_URL`. The demo server is
  a stand-in: it has four tools and one of them returns an
  injected instruction on purpose.
- **A real admin key** (`GATEWAY_ADMIN_KEY`), long and random,
  never committed.
- **HTTPS** in front of the gateway (Render provides it; for Docker,
  put a reverse proxy in front). Agent keys and the admin key travel
  in headers — never send them over plain HTTP.

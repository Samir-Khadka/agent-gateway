# Agent Gateway — one container, two processes: the demo tool
# server (the thing being protected) and the gateway itself.
# For a real deployment, point UPSTREAM_URL at your own MCP server
# instead of the demo server.
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY gateway/ gateway/
COPY policies/ policies/
COPY demo.py .
ENV PYTHONUNBUFFERED=1
ENV UPSTREAM_URL=http://127.0.0.1:8001/mcp
EXPOSE 8000
CMD ["sh", "-c", "uvicorn gateway.demo_server:create_demo_server --factory --host 0.0.0.0 --port 8001 & exec uvicorn gateway.server:app --host 0.0.0.0 --port 8000"]

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /app/app/uploads \
    && chmod +x /app/docker-entrypoint.sh

ENV TBMCP_MCP_SERVER_URL=http://127.0.0.1:5002/mcp

EXPOSE 5001 5002

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD python - <<'PY' || exit 1
import socket, sys
def check(port):
    s = socket.socket()
    s.settimeout(2)
    try:
        s.connect(("127.0.0.1", port))
        return True
    except Exception:
        return False
    finally:
        s.close()
if not (check(5001) and check(5002)):
    sys.exit(1)
PY

CMD ["/app/docker-entrypoint.sh"]

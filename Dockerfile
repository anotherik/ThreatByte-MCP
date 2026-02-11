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

CMD ["/app/docker-entrypoint.sh"]

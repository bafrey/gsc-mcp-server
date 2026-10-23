FROM ghcr.io/astral-sh/uv:python3.13-bookworm-slim
WORKDIR /app

COPY pyproject.toml uv.lock README.md LICENSE ./
RUN uv sync --frozen --no-cache --no-install-project --no-dev

COPY gsc_server.py app.py ./
ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    GSC_CONFIG_DIR=/tmp/mcp-gsc

CMD ["python", "app.py"]

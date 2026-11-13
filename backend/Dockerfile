FROM python:3.12-slim
COPY --from=ghcr.io/astral-sh/uv:0.13.8 /uv /usr/local/bin/uv
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PATH="/app/.venv/bin:$PATH"
WORKDIR /app
COPY backend/pyproject.toml backend/uv.lock ./
RUN uv sync --frozen --no-dev && useradd --system --uid 10001 appuser
COPY --chown=appuser:appuser backend/app ./app
COPY --chown=appuser:appuser backend/migrations ./migrations
COPY --chown=appuser:appuser backend/alembic.ini ./
COPY --chown=appuser:appuser samples ./samples
USER appuser
EXPOSE 8000
CMD ["uvicorn", "app.api:app", "--host", "0.0.0.0", "--port", "8000", "--no-proxy-headers"]

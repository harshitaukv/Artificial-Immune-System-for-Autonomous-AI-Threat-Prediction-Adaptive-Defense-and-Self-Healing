# ---------- Stage 1: build the React dashboard ----------
FROM node:22-slim AS frontend
WORKDIR /build
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm install --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

# ---------- Stage 2: runtime ----------
FROM python:3.11-slim AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    ASTRASEC_ARTIFACTS=/app/artifacts

WORKDIR /app

RUN apt-get update \
 && apt-get install -y --no-install-recommends curl \
 && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt ./backend/requirements.txt
RUN pip install -r backend/requirements.txt

COPY backend/ ./backend/
COPY tests/ ./tests/
COPY pytest.ini ./
COPY --from=frontend /build/dist ./frontend/dist

# Train once at build time so the image ships ready to serve. Comment this out
# and mount a volume at /app/artifacts if you prefer to train separately.
RUN cd backend && python -m astrasec.train --samples 30000 --cv 0

RUN useradd --create-home --uid 10001 astrasec \
 && chown -R astrasec:astrasec /app
USER astrasec

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
  CMD curl -fsS http://localhost:8000/api/health || exit 1

WORKDIR /app/backend
CMD ["python", "-m", "uvicorn", "astrasec.api:app", "--host", "0.0.0.0", "--port", "8000"]

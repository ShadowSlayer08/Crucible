# CRUCIBLE — Trial by fire for AI.
# Multi-stage image: build a wheel, then a slim non-root runtime with the
# `crucible` console script on PATH (CLI + PDF + web dashboard extras).
#
#   docker build -t crucible:3.0.0 .
#   docker run --rm crucible:3.0.0 --version
#   docker run --rm -v "$PWD/reports:/app/reports" crucible:3.0.0 \
#       --mode vapt --endpoint https://api.openai.com --api-key "$KEY" --model gpt-4o
#   docker run --rm -p 8000:8000 crucible:3.0.0 --serve --serve-host 0.0.0.0
#
# Authorized testing only. See SECURITY.md.

# ── build ────────────────────────────────────────────────────────────────────
FROM python:3.12-slim AS build
ENV PIP_NO_CACHE_DIR=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /src
COPY . /src
RUN python -m pip install --upgrade pip build \
 && python -m build --wheel --outdir /dist

# ── runtime ──────────────────────────────────────────────────────────────────
FROM python:3.12-slim AS runtime

LABEL org.opencontainers.image.title="CRUCIBLE" \
      org.opencontainers.image.description="Trial by fire for AI — black-box offensive testing for LLM / agentic systems." \
      org.opencontainers.image.source="https://github.com/ShadowSlayer08/Crucible" \
      org.opencontainers.image.version="3.0.0" \
      org.opencontainers.image.licenses="LicenseRef-Source-Available"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# Install the built wheel with the server + pdf + docs extras.
# (browser/Playwright is intentionally omitted — it pulls a full Chromium.)
COPY --from=build /dist/*.whl /tmp/
RUN pip install --upgrade pip \
 && pip install "$(ls /tmp/*.whl)[server,pdf]" \
 && rm -rf /tmp/*.whl

# Non-root runtime user; reports land in a mountable volume.
RUN useradd --create-home --uid 10001 crucible \
 && mkdir -p /app/reports && chown -R crucible:crucible /app
USER crucible
WORKDIR /app
VOLUME ["/app/reports"]

# Web dashboard port (only used with `--serve --serve-host 0.0.0.0`).
EXPOSE 8000

ENTRYPOINT ["crucible"]
CMD ["--help"]

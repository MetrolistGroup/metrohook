FROM ghcr.io/astral-sh/uv:debian AS builder

WORKDIR /app

COPY requirements.txt ./

RUN uv venv /app/.venv && \
    uv pip install --python /app/.venv/bin/python -r requirements.txt

FROM ghcr.io/astral-sh/uv:debian

WORKDIR /app

COPY --from=builder /app/.venv /app/.venv
COPY . .

ENV PYTHONUNBUFFERED=1 \
    PATH="/app/.venv/bin:$PATH"

CMD ["uv", "run", "main.py"]

FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /app/uploads

EXPOSE 5000

ENV PYTHONUNBUFFERED=1

# Optional env vars:
# VT_API_KEY        — VirusTotal API key for hash reputation lookups
# PHISH_API_KEY     — Require X-API-Key header on API endpoints
# PHISH_SECRET      — Flask session secret (defaults to random per-process)

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--timeout", "120", "app:app"]

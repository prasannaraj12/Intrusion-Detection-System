# Python 3.11 Slim base for AegisNIDS Layer 1 Inference Service
FROM python:3.11-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=off \
    PIP_DISABLE_PIP_VERSION_CHECK=on

# Install system dependencies (OpenMP for LightGBM, libpcap)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libgomp1 libpcap-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Hardening Phase 13: Non-root execution user
RUN useradd -m -u 10001 aegisuser

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN chown -R aegisuser:aegisuser /app

USER aegisuser

EXPOSE 5000

CMD ["python", "run.py"]

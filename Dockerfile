FROM python:3.12-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY main.py .
COPY middleware.py .
COPY database.py .
COPY cli.py .
COPY secrets.json.example secrets.json.example

# Persistent data directory for vault.db
RUN mkdir -p /app/data
ENV AGENT_VAULT_APP_DIR=/app/data

# Non-root user for security
RUN useradd -m -u 1000 appuser && chown -R appuser:appuser /app
USER appuser

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')" || exit 1

# Run with secrets from mounted volume
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]

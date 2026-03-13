FROM python:3.12-slim

WORKDIR /workspace

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY app ./app
COPY cli.py .
COPY entrypoint.sh .
COPY secrets.json.example secrets.json.example

# Persistent data directory for vault.db
RUN mkdir -p /app/data
ENV AGENT_VAULT_APP_DIR=/app/data

# Non-root user for security
RUN chmod +x /workspace/entrypoint.sh && useradd -m -u 1000 appuser && chown -R appuser:appuser /workspace /app/data
USER appuser

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')" || exit 1

# Run bootstrap then API server
CMD ["/workspace/entrypoint.sh"]

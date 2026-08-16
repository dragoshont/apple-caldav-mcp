FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src

RUN pip install --no-cache-dir .

# Brokered mode receives only caller credentials. Guarded direct mode receives
# the Apple ID + app-specific password from a runtime secret store. Neither mode
# bakes credentials into the image or argv.
EXPOSE 8080
ENV APPLE_MCP_HTTP_PORT=8080 HOME=/tmp

# Run as a non-root numeric uid (defense in depth; the k8s securityContext pins
# the same). Numeric USER avoids the useradd-on-reserved-uid quirk.
USER 1000

HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=3).status==200 else 1)"

CMD ["apple-caldav-mcp"]

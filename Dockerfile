FROM alpine:3.20

# Install runtime dependencies
RUN apk add --no-cache python3 py3-pip nginx curl unzip jq bash tzdata

# Install build dependencies needed for Pillow and psutil
RUN apk add --no-cache --virtual .build-deps \
    gcc musl-dev python3-dev zlib-dev jpeg-dev freetype-dev linux-headers

WORKDIR /app
COPY requirements.txt .

# Install Python dependencies
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt \
    && apk del .build-deps

# Install Xray-core
RUN curl -fsSL -o xray.zip "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip" && \
    unzip xray.zip -d /usr/local/bin/ && \
    chmod +x /usr/local/bin/xray && \
    rm xray.zip

# Copy application files
COPY . /app

# Copy nginx config
COPY nginx.conf /etc/nginx/nginx.conf

# Runtime defaults (override in Railway → Variables as needed)
# Railway injects $PORT automatically; nginx listens on it, panel stays on 10000.
ENV PYTHONUNBUFFERED=1 \
    PANEL_PORT=10000 \
    STANNG_DATA_DIR=/app/data \
    PANEL_NAME="ALOO PANEL" \
    TELEGRAM_CONTACT="https://t.me/ITSESMAT"

# Entrypoint setup + writable dirs (data volume mounts here on Railway)
RUN chmod +x /app/entrypoint.sh \
    && mkdir -p /app/data /var/log/nginx /var/run

VOLUME ["/app/data"]

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://127.0.0.1:10000/health || exit 1

CMD ["/app/entrypoint.sh"]

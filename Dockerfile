FROM alpine:3.20

# Install runtime dependencies
RUN apk add --no-cache \
    python3 \
    py3-pip \
    nginx \
    curl \
    unzip \
    jq \
    bash \
    tzdata

# Install build dependencies needed for Pillow and psutil
RUN apk add --no-cache --virtual .build-deps \
    gcc \
    musl-dev \
    python3-dev \
    zlib-dev \
    jpeg-dev \
    freetype-dev \
    linux-headers

WORKDIR /app

# Copy requirements first for better Docker cache
COPY requirements.txt .

# Install Python dependencies
RUN pip3 install \
    --no-cache-dir \
    --break-system-packages \
    -r requirements.txt \
    && apk del .build-deps

# Install Xray-core
RUN curl -fsSL \
    -o /tmp/xray.zip \
    "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip" \
    && unzip /tmp/xray.zip -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/xray \
    && rm -f /tmp/xray.zip

# Copy application files
COPY . /app

# Copy nginx configuration
COPY nginx.conf /etc/nginx/nginx.conf

# Runtime environment
ENV PYTHONUNBUFFERED=1 \
    PANEL_PORT=10000 \
    STANNG_DATA_DIR=/app/data \
    PANEL_NAME="ALOO PANEL" \
    TELEGRAM_CONTACT="https://t.me/ITSESMAT"

# Create required directories
# IMPORTANT:
# Do NOT use Docker VOLUME here.
# Railway Volumes must be configured from Railway dashboard.
RUN chmod +x /app/entrypoint.sh \
    && mkdir -p /app/data \
    && mkdir -p /var/log/nginx \
    && mkdir -p /var/run \
    && mkdir -p /run/nginx

# Railway will route traffic to the port defined by $PORT.
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s \
    --timeout=5s \
    --start-period=20s \
    --retries=3 \
    CMD curl -fsS http://127.0.0.1:10000/health || exit 1

# Start application
CMD ["/app/entrypoint.sh"]

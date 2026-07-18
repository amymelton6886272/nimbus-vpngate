FROM debian:12-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    VPNGATE_DATA_DIR=/app/vpngate_data \
    LOCAL_PROXY_HOST=0.0.0.0 \
    LOCAL_PROXY_PORT=7928 \
    UI_HOST=0.0.0.0 \
    UI_PORT=8787 \
    CONNECTION_ENABLED=true

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    iproute2 \
    iputils-ping \
    net-tools \
    openvpn \
    procps \
    python3 \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY vpngate_manager.py proxy_server.py vpn_utils.py README.md LICENSE /app/
COPY docker/entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh \
 && mkdir -p /app/vpngate_data

EXPOSE 7928 8787

ENTRYPOINT ["/entrypoint.sh"]

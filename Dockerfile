FROM python:3.12-slim

# for Docker CLI and nmap
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        nmap \
        docker.io \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN pip install --no-cache-dir

# config and data directories
RUN mkdir -p /root/.config/so-ops /app/data

# Default config path
ENV SO_OPS_CONFIG=/root/.config/so-ops/config.toml
ENV SO_OPS_DATA_DIR=/app/data
 
ENTRYPOINT ["so-ops"]
CMD ["--help"]
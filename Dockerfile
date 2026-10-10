# Image légère de Dave : Python 3.12 slim, aucune dépendance système ajoutée.
FROM python:3.12-slim
LABEL org.opencontainers.image.title="dave" \
      org.opencontainers.image.description="Security audit for self-hosted AI stacks" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later"
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 DAVE_INSTALL_METHOD=docker
WORKDIR /src
COPY pyproject.toml README.md ./
COPY dave ./dave
RUN pip install --no-cache-dir . && rm -rf /src /root/.cache \
 && useradd --uid 10001 --create-home dave && mkdir -p /work
USER dave
WORKDIR /work
ENTRYPOINT ["dave"]

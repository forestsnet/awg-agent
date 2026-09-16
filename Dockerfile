# Базовый образ — официальный от Amnezia: в нём уже лежат amneziawg-go,
# awg и awg-quick нужных версий. Тег прибит: `latest` у базы означал бы,
# что протокол на сервере клиента меняется сам по себе.
FROM amneziavpn/amneziawg-go:3.1.20260828

RUN apk add --no-cache python3 py3-pip iptables ip6tables dumb-init

WORKDIR /app
COPY requirements.txt ./
RUN python3 -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir --upgrade pip \
    && /opt/venv/bin/pip install --no-cache-dir -r requirements.txt

COPY agent/ ./agent/
COPY web/ ./web/

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    WG_PATH=/etc/amnezia/amneziawg

EXPOSE 51820/udp
EXPOSE 51821/tcp

# exec, чтобы uvicorn получил сигналы от dumb-init напрямую и контейнер
# останавливался за секунду, а не по таймауту.
CMD ["/usr/bin/dumb-init", "sh", "-c", "exec uvicorn agent.main:app --host ${WEBUI_HOST:-0.0.0.0} --port ${PORT:-51821} --no-access-log"]

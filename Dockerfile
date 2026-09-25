# Базовый образ — официальный от Amnezia: в нём уже лежат amneziawg-go,
# awg и awg-quick нужных версий. Тег прибит: `latest` у базы означал бы,
# что протокол на сервере клиента меняется сам по себе.
FROM amneziavpn/amneziawg-go:3.1.20260828

# nftables — торрент-блокировщику (nft-таблица btguard). Без утилиты nft он не поднимался
# вовсе: в базовом образе только iptables, а ошибка тонула в логе.
RUN apk add --no-cache python3 py3-pip iptables ip6tables nftables dumb-init

WORKDIR /app
COPY requirements.txt ./
RUN python3 -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir --upgrade pip \
    && /opt/venv/bin/pip install --no-cache-dir -r requirements.txt

COPY agent/ ./agent/
COPY web/ ./web/

# Хэш коммита приезжает из CI: в панели видно, какая именно сборка
# крутится на сервере. Без него «обновил» и «обновилось» не различить.
ARG BUILD_SHA=dev
ENV AGENT_BUILD=${BUILD_SHA} \
    PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    WG_PATH=/etc/amnezia/amneziawg

EXPOSE 51820/udp
EXPOSE 51821/tcp

# exec, чтобы uvicorn получил сигналы от dumb-init напрямую и контейнер
# останавливался за секунду, а не по таймауту.
CMD ["/usr/bin/dumb-init", "sh", "-c", "exec uvicorn agent.main:app --host ${WEBUI_HOST:-0.0.0.0} --port ${PORT:-51821} --no-access-log"]

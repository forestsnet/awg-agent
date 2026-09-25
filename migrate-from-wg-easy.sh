#!/usr/bin/env bash
# Плавная миграция amnezia-wg-easy / wg-easy → awg-agent, без перевыпуска клиентских конфигов.
#
# Переносит ключи, PSK, адреса и ПАРАМЕТРЫ ОБФУСКАЦИИ (Jc/Jmin/Jmax/S1..S4/H1..H4) из wg0.json,
# а из окружения старого контейнера — порты, подсеть, DNS и пароль панели: уже розданные конфиги
# продолжают работать, пароль панели у бота остаётся верным. Старый контейнер только
# останавливается, не удаляется: откат мгновенный.
#
# Агент встаёт так же, как его ставит бот (vpn-agent-install): каталог
# /opt/vpn-agent/<awg|wg>-agent-N/ с .env и docker-compose.yml, контейнер <awg|wg>-agent-N.
# Тогда его обновляет vpn-agent-update — кнопка «Обновить агент» в боте и панели.
#
#   sudo ./migrate-from-wg-easy.sh --dry-run     разведать и показать план, ничего не менять
#   sudo ./migrate-from-wg-easy.sh               мигрировать (спросит подтверждение)
#   sudo ./migrate-from-wg-easy.sh --yes         мигрировать без вопросов
#   sudo ./migrate-from-wg-easy.sh --rollback    вернуться на старую панель
#
# Опции: --old <контейнер>       какой контейнер переносить (иначе — автопоиск)
#        --old-port <порт>       порт веб-панели старого контейнера: выбрать из нескольких
#        --proto awg|wg          иначе — по образу (amnezia-wg-easy → awg, wg-easy → wg)
#        --dir <каталог>         каталог экземпляра агента (иначе первый свободный
#                                /opt/vpn-agent/<proto>-agent-N)
#        --image <образ>         по умолчанию ghcr.io/forestsnet/awg-agent:latest
#        --password <пароль>     пароль панели: нужен, если у старой панели нет PASSWORD_HASH
#                                (только PASSWORD); с ним же проверяется вход после переезда
#        --allow-reissue         переносить и без параметров обфускации в wg0.json (клиентам
#                                AmneziaWG тогда нужны новые конфиги) — без флага отказ
#
# Для бота: в режиме --dry-run строки «PLAN ключ=значение», в конце любого режима —
# «RESULT ok …» или «RESULT fail причина».
set -euo pipefail

IMAGE="ghcr.io/forestsnet/awg-agent:latest"
BASE_DIR="/opt/vpn-agent"
# Неудачные и откаченные экземпляры — рядом, а не внутри BASE_DIR: vpn-agent-update
# обновляет каждый каталог с docker-compose.yml в BASE_DIR и споткнулся бы о них.
ATTIC="/opt/vpn-agent.attic"
DIR=""
OLD=""
OLD_PORT=""
PROTO=""
PASSWORD=""
MODE=apply
ASSUME_YES=0
ALLOW_REISSUE=0

say(){ printf '\033[1m[migrate]\033[0m %s\n' "$*"; }
die(){ printf '\033[1;31m[migrate] %s\033[0m\n' "$*" >&2; echo "RESULT fail $*"; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) MODE=dry ;;
    --rollback) MODE=rollback ;;
    --yes|-y) ASSUME_YES=1 ;;
    --allow-reissue) ALLOW_REISSUE=1 ;;
    --old) shift; OLD=${1-} ;;
    --old=*) OLD=${1#*=} ;;
    --old-port) shift; OLD_PORT=${1-} ;;
    --old-port=*) OLD_PORT=${1#*=} ;;
    --proto) shift; PROTO=${1-} ;;
    --proto=*) PROTO=${1#*=} ;;
    --dir) shift; DIR=${1-} ;;
    --dir=*) DIR=${1#*=} ;;
    --image) shift; IMAGE=${1-} ;;
    --image=*) IMAGE=${1#*=} ;;
    --password) shift; PASSWORD=${1-} ;;
    --password=*) PASSWORD=${1#*=} ;;
    -h|--help) sed -n '2,31p' "$0"; exit 0 ;;
    *) die "неизвестный аргумент: $1" ;;
  esac; shift
done

[ "$(id -u)" = 0 ] || die "нужен root"
command -v docker >/dev/null || die "нужен docker"
docker compose version >/dev/null 2>&1 || die "нужен docker compose (плагин)"
command -v python3 >/dev/null || die "нужен python3 (разбор wg0.json)"
command -v curl >/dev/null || die "нужен curl"

# Поднять старую панель и убедиться, что она ОТВЕЧАЕТ, а не просто «запущена»:
# контейнер без своих портов (их держит агент) тоже числится запущенным.
old_back() {  # old_back <контейнер> <порт веб-панели>
  docker start "$1" >/dev/null 2>&1 || return 1
  for _ in $(seq 1 30); do
    code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "http://127.0.0.1:$2/api/session" || true)
    case "$code" in 200|401) return 0 ;; esac
    sleep 2
  done
  return 1
}

# Погасить экземпляр агента: compose down и контейнер по имени — на случай, если compose
# уже не узнаёт свой проект.
agent_down() {  # agent_down <каталог экземпляра>
  docker compose -f "$1/docker-compose.yml" --env-file "$1/.env" down >/dev/null 2>&1 || true
  docker rm -f "$(basename "$1")" >/dev/null 2>&1 || true
}

# ── Откат ───────────────────────────────────────────────────────────
# Экземпляр, созданный миграцией, помечен файлом migrated-from (имя старого контейнера).
# При откате метка снимается: иначе следующий откат нашёл бы и этот каталог.
if [ "$MODE" = rollback ]; then
  found=0
  for mark in "$BASE_DIR"/*/migrated-from; do
    [ -f "$mark" ] || continue
    inst=$(dirname "$mark"); old=$(cat "$mark")
    [ -n "$DIR" ] && [ "$inst" != "$DIR" ] && continue
    [ -n "$OLD" ] && [ "$old" != "$OLD" ] && continue
    port=$(sed -n 's/^PORT=\([0-9]*\).*/\1/p' "$inst/.env" 2>/dev/null | head -1)
    agent_down "$inst"
    mv "$mark" "$mark.rolled-back"
    mkdir -p "$ATTIC"
    mv "$inst" "$ATTIC/$(basename "$inst").rolled-back-$(date +%s)"
    old_back "$old" "${port:-51821}" || die "агент $(basename "$inst") остановлен, но старая панель $old не отвечает — проверь вручную"
    say "откат: $(basename "$inst") остановлен, $old запущен и отвечает"
    found=1
  done
  [ "$found" = 1 ] || die "не нашёл экземпляр агента, созданный миграцией (метка migrated-from)"
  echo "RESULT ok rollback"
  exit 0
fi

# ── Какой контейнер переносим ───────────────────────────────────────
candidates() {
  docker ps -a --format '{{.Names}}\t{{.Image}}' \
    | awk -F'\t' '$2 ~ /(amnezia-wg-easy|wg-easy)/ && $2 !~ /awg-agent/ {print $1}'
}
env_of() {  # env_of <контейнер> <переменная>
  docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$1" \
    | awk -F= -v k="$2" '$1==k{sub(/^[^=]*=/,""); print; exit}'
}
if [ -z "$OLD" ] && [ -n "$OLD_PORT" ]; then
  for name in $(candidates); do
    if docker inspect -f '{{json .HostConfig.PortBindings}}' "$name" | grep -q "\"HostPort\":\"$OLD_PORT\"" \
       || [ "$(env_of "$name" PORT)" = "$OLD_PORT" ]; then
      OLD=$name; break
    fi
  done
  [ -n "$OLD" ] || die "старой панели на порту $OLD_PORT нет (контейнер amnezia-wg-easy/wg-easy не найден)"
fi
if [ -z "$OLD" ]; then
  n=$(candidates | grep -c . || true)
  [ "$n" -ge 1 ] || die "контейнер amnezia-wg-easy/wg-easy не найден — это не панель wg-easy"
  [ "$n" -eq 1 ] || die "контейнеров старой панели несколько ($n) — укажи --old или --old-port"
  OLD=$(candidates)
fi
docker inspect "$OLD" >/dev/null 2>&1 || die "контейнер $OLD не существует"
OLD_IMAGE=$(docker inspect -f '{{.Config.Image}}' "$OLD")
if [ -z "$PROTO" ]; then
  case "$OLD_IMAGE" in *amnezia*) PROTO=awg ;; *) PROTO=wg ;; esac
fi
[ "$PROTO" = awg ] || [ "$PROTO" = wg ] || die "--proto: awg или wg"
say "старая панель: $OLD ($OLD_IMAGE), протокол $PROTO"

# ── wg0.json старой панели ──────────────────────────────────────────
SRCDIR=""
while read -r src dst; do
  [ -n "$src" ] || continue
  case "$dst" in /etc/wireguard|/etc/amnezia/amneziawg) [ -f "$src/wg0.json" ] && { SRCDIR=$src; break; } ;; esac
done < <(docker inspect -f '{{range .Mounts}}{{.Source}} {{.Destination}}{{println}}{{end}}' "$OLD")
if [ -z "$SRCDIR" ]; then
  while read -r src; do
    [ -n "$src" ] && [ -f "$src/wg0.json" ] && { SRCDIR=$src; break; }
  done < <(docker inspect -f '{{range .Mounts}}{{.Source}}{{println}}{{end}}' "$OLD")
fi
if [ -z "$SRCDIR" ]; then
  for src in $(docker inspect -f '{{range .Mounts}}{{.Source}} {{end}}' "$OLD"); do
    [ -f "$src/wg-easy.db" ] && die "wg-easy 15+ хранит клиентов в SQLite (wg-easy.db) — такую панель переносить не умеем"
  done
  die "не нашёл wg0.json в томах $OLD"
fi
WG0="$SRCDIR/wg0.json"

read -r NCLIENTS HASOBF HASS34 < <(python3 - "$WG0" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
s = d.get("server") or {}
obf = all(str(s.get(k) if s.get(k) is not None else "").strip() != ""
          for k in ("jc", "jmin", "jmax", "s1", "s2", "h1", "h2", "h3", "h4"))
def num(v):
    try:
        return int(str(v).strip() or 0)
    except ValueError:
        return 0
s34 = bool(num(s.get("s3")) or num(s.get("s4")))
print(len(d.get("clients") or {}), "yes" if obf else "no", "yes" if s34 else "no")
PY
)
[ -n "${NCLIENTS:-}" ] || die "wg0.json не разобрался: $WG0"
if [ "$PROTO" = awg ]; then
  say "клиентов в wg0.json: $NCLIENTS · обфускация: $([ "$HASOBF" = yes ] && echo есть || echo НЕТ)$([ "$HASS34" = yes ] && echo ' (с S3/S4)')"
  if [ "$HASOBF" != yes ] && [ "$ALLOW_REISSUE" != 1 ]; then
    die "в wg0.json нет параметров обфускации — после переезда клиентам AmneziaWG нужны новые конфиги; если это и нужно — --allow-reissue"
  fi
else
  say "клиентов в wg0.json: $NCLIENTS (WireGuard, обфускации нет)"
fi

# ── Окружение старой панели ─────────────────────────────────────────
WG_HOST=$(env_of "$OLD" WG_HOST)
WG_PORT=$(env_of "$OLD" WG_PORT); WG_PORT=${WG_PORT:-51820}
WG_CONFIG_PORT=$(env_of "$OLD" WG_CONFIG_PORT); WG_CONFIG_PORT=${WG_CONFIG_PORT:-$WG_PORT}
UI_PORT=$(env_of "$OLD" PORT); UI_PORT=${UI_PORT:-51821}
WEBUI_HOST=$(env_of "$OLD" WEBUI_HOST); WEBUI_HOST=${WEBUI_HOST:-0.0.0.0}
WG_DEFAULT_ADDRESS=$(env_of "$OLD" WG_DEFAULT_ADDRESS); WG_DEFAULT_ADDRESS=${WG_DEFAULT_ADDRESS:-10.8.0.x}
WG_DEFAULT_DNS=$(env_of "$OLD" WG_DEFAULT_DNS)
WG_ALLOWED_IPS=$(env_of "$OLD" WG_ALLOWED_IPS)
WG_PERSISTENT_KEEPALIVE=$(env_of "$OLD" WG_PERSISTENT_KEEPALIVE)
WG_MTU=$(env_of "$OLD" WG_MTU)
OLD_HASH=$(env_of "$OLD" PASSWORD_HASH)
OLD_PLAIN=$(env_of "$OLD" PASSWORD)
[ -n "$WG_HOST" ] || die "у старой панели не задан WG_HOST"
if [ -n "$OLD_HASH" ]; then PASS_MODE="hash"
elif [ -n "$PASSWORD" ] || [ -n "$OLD_PLAIN" ]; then PASS_MODE="plain"
else die "у старой панели нет ни PASSWORD_HASH, ни PASSWORD — передай --password"
fi

if [ -z "$DIR" ]; then
  i=1
  while [ -e "$BASE_DIR/$PROTO-agent-$i" ]; do i=$((i+1)); done
  DIR="$BASE_DIR/$PROTO-agent-$i"
fi
[ -e "$DIR/docker-compose.yml" ] && die "каталог $DIR уже занят другим экземпляром агента"
for mark in "$BASE_DIR"/*/migrated-from; do
  [ -f "$mark" ] && [ "$(cat "$mark")" = "$OLD" ] && die "$OLD уже переведён на агента: $(dirname "$mark")"
done
# Порты старой панели не должны держать чужие контейнеры (например, уже работающий агент).
busy=$(docker ps --format '{{.Names}}\t{{.Ports}}' | awk -F'\t' -v old="$OLD" -v w=":$WG_PORT->" -v u=":$UI_PORT->" \
  '$1 != old && (index($2, w) || index($2, u)) {print $1}' | head -1)
[ -z "$busy" ] || die "порт $WG_PORT/$UI_PORT занят контейнером $busy — сервер уже переведён или порт чужой"
NAME=$(basename "$DIR")
COMPOSE="$DIR/docker-compose.yml"
say "порт WG: $WG_PORT · веб-панель: $UI_PORT · подсеть: $WG_DEFAULT_ADDRESS · экземпляр: $NAME"

if [ "$MODE" = dry ]; then
  echo "PLAN container=$OLD"
  echo "PLAN image=$OLD_IMAGE"
  echo "PLAN proto=$PROTO"
  echo "PLAN clients=$NCLIENTS"
  echo "PLAN obfuscation=$([ "$PROTO" = wg ] && echo none || echo "$HASOBF")"
  echo "PLAN s3s4=$HASS34"
  echo "PLAN wg_port=$WG_PORT"
  echo "PLAN ui_port=$UI_PORT"
  echo "PLAN address=$WG_DEFAULT_ADDRESS"
  echo "PLAN password=$PASS_MODE"
  echo "PLAN dir=$DIR"
  echo "PLAN agent_image=$IMAGE"
  say "=== DRY-RUN: ничего не менялось ==="
  say "шаги: копия wg0.json → docker stop $OLD (не удаляя) → $NAME на тех же портах → /api/health → при сбое откат"
  echo "RESULT ok dry-run"
  exit 0
fi

# ── Подтверждение ───────────────────────────────────────────────────
if [ "$ASSUME_YES" != 1 ]; then
  printf '\033[1m[migrate]\033[0m Остановить %s и поднять агента %s на порту %s? [y/N] ' "$OLD" "$NAME" "$WG_PORT"
  read -r ans; case "$ans" in y|Y|yes) ;; *) die "отменено"; esac
fi

# ── Образ и пароль ──────────────────────────────────────────────────
say "тяну образ $IMAGE"
docker pull -q "$IMAGE" >/dev/null 2>&1 || docker image inspect "$IMAGE" >/dev/null 2>&1 \
  || die "образ $IMAGE не скачался"
if [ "$PASS_MODE" = hash ]; then
  HASH=$OLD_HASH
else
  # bcrypt считает сам образ агента: на сервере не нужны ни htpasswd, ни python-bcrypt.
  HASH=$(docker run --rm --entrypoint python3 "$IMAGE" -c \
    'import bcrypt,sys;print(bcrypt.hashpw(sys.argv[1].encode(),bcrypt.gensalt()).decode())' \
    "${PASSWORD:-$OLD_PLAIN}") || die "не посчитался хэш пароля"
fi
HASH_YAML=${HASH//\$/\$\$}

# ── Каталог экземпляра ──────────────────────────────────────────────
install -d -m750 "$DIR/data"
cp -a "$WG0" "$DIR/data/wg0.json"          # источник для legacy-импорта; оригинал нетронут
echo "$OLD" > "$DIR/migrated-from"
{
  echo "VPN_PROTO=$PROTO"
  echo "WG_HOST=$WG_HOST"
  echo "WG_PORT=$WG_PORT"
  echo "WG_CONFIG_PORT=$WG_CONFIG_PORT"
  echo "PORT=$UI_PORT"
  echo "WEBUI_HOST=$WEBUI_HOST"
  echo "WG_DEFAULT_ADDRESS=$WG_DEFAULT_ADDRESS"
  [ -n "$WG_DEFAULT_DNS" ] && echo "WG_DEFAULT_DNS=$WG_DEFAULT_DNS"
  [ -n "$WG_ALLOWED_IPS" ] && echo "WG_ALLOWED_IPS=$WG_ALLOWED_IPS"
  [ -n "$WG_PERSISTENT_KEEPALIVE" ] && echo "WG_PERSISTENT_KEEPALIVE=$WG_PERSISTENT_KEEPALIVE"
  [ -n "$WG_MTU" ] && echo "WG_MTU=$WG_MTU"
  # Новые клиенты — в наборе старых (2.0): парк однородный, старые приложения подключаются.
  [ "$PROTO" = awg ] && echo "AWG_PROTO=2"
  true
} > "$DIR/.env"
chmod 600 "$DIR/.env"

cat > "$COMPOSE" <<YML
services:
  agent:
    image: $IMAGE
    container_name: $NAME
    env_file: .env
    environment:
      # Не в .env: там доллары из bcrypt-хэша съедает интерполяция.
      PASSWORD_HASH: "$HASH_YAML"
    volumes:
      - ./data:/etc/amnezia/amneziawg
    ports:
      - "${WG_PORT}:${WG_PORT}/udp"
      - "${UI_PORT}:${UI_PORT}/tcp"
    cap_add:
      - NET_ADMIN
      - SYS_MODULE
      - NET_RAW
    sysctls:
      net.ipv4.conf.all.src_valid_mark: "1"
      net.ipv4.ip_forward: "1"
    devices:
      - /dev/net/tun:/dev/net/tun
    restart: unless-stopped
YML
say "экземпляр записан: $DIR"

rollback_now() {
  say "⚠ $1 — ОТКАТ"
  docker logs --tail 30 "$NAME" 2>&1 | sed 's/^/    /' >&2 || true
  agent_down "$DIR"
  mv "$DIR/migrated-from" "$DIR/migrated-from.failed" 2>/dev/null || true
  mkdir -p "$ATTIC"
  mv "$DIR" "$ATTIC/$(basename "$DIR").failed-$(date +%s)"
  old_back "$OLD" "$UI_PORT" || die "миграция не удалась ($1), и СТАРАЯ ПАНЕЛЬ $OLD НЕ ОТВЕЧАЕТ — проверь сервер вручную"
  die "миграция откатена ($1), работает $OLD"
}

# ── Переключение: стоп старой (не удаляем — для отката), старт агента ─
docker stop "$OLD" >/dev/null
say "старая панель остановлена (контейнер сохранён: docker start $OLD)"
docker compose -f "$COMPOSE" --env-file "$DIR/.env" up -d >/dev/null 2>&1 || rollback_now "docker compose up не отработал"

# ── Проверка ────────────────────────────────────────────────────────
ok=""
for _ in $(seq 1 45); do
  h=$(curl -fsS --max-time 3 "http://127.0.0.1:${UI_PORT}/api/health" 2>/dev/null || true)
  case "$h" in *'"up":true'*) ok=$h; break ;; esac
  sleep 2
done
[ -n "$ok" ] || rollback_now "агент не поднял интерфейс (/api/health)"
GOT=$(printf '%s' "$ok" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("clients","?"))' 2>/dev/null || echo '?')
[ "$GOT" = "$NCLIENTS" ] || rollback_now "клиентов $GOT, а в старой панели было $NCLIENTS"
# Параметры обфускации на живом интерфейсе агента — те же, что у старой панели. Иначе
# рукопожатие ещё проходит (S1/S2), а трафик — нет (S3/S4): «подключается, интернета нет»
# у всех клиентов разом. Так было бы с образом агента старее импорта S3/S4.
if [ "$PROTO" = awg ] && [ "$HASOBF" = yes ]; then
  LIVE=$(docker exec "$NAME" awg show wg0 2>/dev/null || true)
  MISMATCH=$(python3 - "$WG0" "$LIVE" <<'PY'
import json, re, sys
want = json.load(open(sys.argv[1])).get("server") or {}
live = dict(re.findall(r"^\s*(jc|jmin|jmax|s[1-4]|h[1-4]):\s*(\S+)", sys.argv[2], re.M))
def num(v):
    try:
        return int(str(v).strip() or 0)
    except ValueError:
        return str(v).strip()
bad = [k for k in ("jc", "jmin", "jmax", "s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4")
       if num(want.get(k)) != num(live.get(k, 0))]
print(",".join(bad))
PY
)
  [ -z "$MISMATCH" ] || rollback_now "параметры обфускации на агенте не совпали со старыми ($MISMATCH) — нужен образ агента новее"
fi
if [ -n "${PASSWORD:-$OLD_PLAIN}" ]; then
  body=$(python3 -c 'import json,sys;print(json.dumps({"password":sys.argv[1]}))' "${PASSWORD:-$OLD_PLAIN}")
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 -X POST \
    "http://127.0.0.1:${UI_PORT}/api/session" -H 'Content-Type: application/json' --data-binary "$body" || true)
  [ "$code" = 200 ] || rollback_now "пароль панели не принимается (HTTP $code)"
fi
say "✅ агент жив: клиентов $GOT, как было; порты и пароль прежние"
say "откат при необходимости: $0 --rollback"
echo "RESULT ok proto=$PROTO clients=$GOT dir=$DIR container=$NAME ui_port=$UI_PORT wg_port=$WG_PORT"

#!/usr/bin/env bash
# Плавная миграция amnezia-wg-easy → awg-agent, без перевыпуска клиентских конфигов.
#
# Переносит ключи, PSK, адреса и ПАРАМЕТРЫ ОБФУСКАЦИИ (Jc/S1/H1..H4) из wg0.json, а также
# окружение старого контейнера (имена переменных у панелей совпадают) и держит protocol 2.0 —
# поэтому уже розданные конфиги продолжают работать. Старый контейнер не удаляется: откат мгновенный.
#
#   sudo ./migrate-from-wg-easy.sh --dry-run     разведать и показать план, ничего не менять
#   sudo ./migrate-from-wg-easy.sh               мигрировать (спросит подтверждение)
#   sudo ./migrate-from-wg-easy.sh --yes         мигрировать без вопросов
#   sudo ./migrate-from-wg-easy.sh --rollback    вернуться на amnezia-wg-easy
#
# Опции: --old <контейнер> (иначе автопоиск), --dir <путь> (данные awg-agent, по умолч. /opt/awg-agent),
#        --image <образ> (по умолч. ghcr.io/forestsnet/awg-agent:latest).
set -euo pipefail

IMAGE="ghcr.io/forestsnet/awg-agent:latest"
DIR="/opt/awg-agent"
OLD=""
MODE=apply
ASSUME_YES=0

say(){ printf '\033[1m[migrate]\033[0m %s\n' "$*"; }
die(){ printf '\033[1;31m[migrate] %s\033[0m\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) MODE=dry ;;
    --rollback) MODE=rollback ;;
    --yes|-y) ASSUME_YES=1 ;;
    --old) shift; OLD=${1-} ;;
    --old=*) OLD=${1#*=} ;;
    --dir) shift; DIR=${1-} ;;
    --dir=*) DIR=${1#*=} ;;
    --image) shift; IMAGE=${1-} ;;
    --image=*) IMAGE=${1#*=} ;;
    -h|--help) sed -n '2,17p' "$0"; exit 0 ;;
    *) die "неизвестный аргумент: $1" ;;
  esac; shift
done

[ "$(id -u)" = 0 ] || die "нужен root"
command -v docker >/dev/null || die "нужен docker"
DC="docker compose"; docker compose version >/dev/null 2>&1 || DC="docker-compose"
command -v ${DC%% *} >/dev/null || die "нужен docker compose"

COMPOSE="$DIR/docker-compose.yml"

# ── Откат ───────────────────────────────────────────────────────────
if [ "$MODE" = rollback ]; then
  [ -f "$COMPOSE" ] && $DC -f "$COMPOSE" down || true
  # поднять первый остановленный amnezia-wg-easy
  cand=$(docker ps -a --filter "ancestor=" --format '{{.Names}} {{.Image}}' 2>/dev/null | awk '/amnezia-wg-easy/{print $1; exit}')
  [ -z "$cand" ] && cand=$(docker ps -a --format '{{.Names}} {{.Image}}' | awk '/amnezia-wg-easy/{print $1; exit}')
  [ -n "$cand" ] || die "старый контейнер amnezia-wg-easy не найден для отката"
  docker start "$cand" >/dev/null
  say "откат: awg-agent остановлен, $cand запущен"
  exit 0
fi

# ── Автопоиск старого контейнера ────────────────────────────────────
if [ -z "$OLD" ]; then
  OLD=$(docker ps -a --format '{{.Names}}\t{{.Image}}' | awk -F'\t' '/amnezia-wg-easy/{print $1; exit}')
  [ -n "$OLD" ] || die "контейнер amnezia-wg-easy не найден — укажи через --old"
fi
docker inspect "$OLD" >/dev/null 2>&1 || die "контейнер $OLD не существует"
say "старая панель: $OLD ($(docker inspect -f '{{.Config.Image}}' "$OLD"))"

# ── Данные старой панели: путь к wg0.json ───────────────────────────
SRCDIR=$(docker inspect -f '{{range .Mounts}}{{if eq .Destination "/etc/wireguard"}}{{.Source}}{{end}}{{end}}' "$OLD")
[ -n "$SRCDIR" ] || SRCDIR=$(docker inspect -f '{{range .Mounts}}{{.Source}}{{println}}{{end}}' "$OLD" | while read -r m; do [ -f "$m/wg0.json" ] && echo "$m" && break; done)
[ -n "$SRCDIR" ] && [ -f "$SRCDIR/wg0.json" ] || die "не нашёл wg0.json в томах $OLD"
WG0="$SRCDIR/wg0.json"

# ── Разбор wg0.json: клиенты + наличие параметров обфускации ────────
read -r NCLIENTS HASOBF < <(python3 - "$WG0" <<'PY'
import json,sys
d=json.load(open(sys.argv[1])); s=d.get("server",{})
obf=all(s.get(k) is not None for k in ("jc","jmin","jmax","s1","s2","h1","h2","h3","h4"))
print(len(d.get("clients") or {}), "yes" if obf else "no")
PY
)
say "клиентов в wg0.json: $NCLIENTS · параметры обфускации: $([ "$HASOBF" = yes ] && echo есть || echo НЕТ)"
[ "$HASOBF" = yes ] || say "⚠ параметров обфускации нет — клиентам понадобится новый конфиг после миграции"

# ── Окружение старой панели (имена переменных те же, что у agent) ───
mapfile -t OLDENV < <(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$OLD" \
  | grep -E '^(WG_|PASSWORD_HASH=|PORT=|AWG_)')
getenv(){ printf '%s\n' "${OLDENV[@]}" | awk -F= -v k="$1" '$1==k{sub(/^[^=]*=/,"");print;exit}'; }
WG_PORT=$(getenv WG_PORT); WG_PORT=${WG_PORT:-51820}
WEB_PORT=$(getenv PORT); WEB_PORT=${WEB_PORT:-51821}
say "порт WG: $WG_PORT · веб-панель: $WEB_PORT · подсеть: $(getenv WG_DEFAULT_ADDRESS)"

if [ "$MODE" = dry ]; then
  say "=== DRY-RUN, план ==="
  echo "  образ:        $IMAGE"
  echo "  данные:       $DIR/data  (сюда ляжет копия $WG0)"
  echo "  compose:      $COMPOSE"
  echo "  порты:        ${WG_PORT}/udp, ${WEB_PORT}/tcp"
  echo "  env (перенос): $(printf '%s ' "${OLDENV[@]}" | sed -E 's/PASSWORD_HASH=[^ ]*/PASSWORD_HASH=<hash>/; s/WG_HOST=[^ ]*/WG_HOST=<ip>/')"
  echo "  + AWG_PROTO=2 (совместимость 2.0, клиенты не перевыпускаются)"
  echo "  шаги: docker stop $OLD → $DC up -d → проверка /api/health → при сбое авто-откат"
  exit 0
fi

# ── Подтверждение ───────────────────────────────────────────────────
if [ "$ASSUME_YES" != 1 ]; then
  printf '\033[1m[migrate]\033[0m Остановить %s и поднять awg-agent на порту %s? [y/N] ' "$OLD" "$WG_PORT"
  read -r ans; case "$ans" in y|Y|yes) ;; *) die "отменено"; esac
fi

# ── Подготовка каталога awg-agent ───────────────────────────────────
install -d -m750 "$DIR/data"
cp -a "$WG0" "$DIR/data/wg0.json"                       # источник для legacy-импорта
say "wg0.json скопирован в $DIR/data (оригинал в $SRCDIR нетронут)"

# agent.env — значения передаются в контейнер как есть (env_file не интерполирует $ в bcrypt-хэше)
{
  printf '%s\n' "${OLDENV[@]}"
  grep -q '^AWG_PROTO=' <(printf '%s\n' "${OLDENV[@]}") || echo "AWG_PROTO=2"
} > "$DIR/agent.env"
chmod 600 "$DIR/agent.env"

cat > "$COMPOSE" <<YML
services:
  awg:
    image: $IMAGE
    container_name: awg-agent
    restart: unless-stopped
    env_file: [agent.env]
    volumes:
      - ./data:/etc/amnezia/amneziawg
    ports:
      - "${WG_PORT}:${WG_PORT}/udp"
      - "${WEB_PORT}:${WEB_PORT}/tcp"
    cap_add: [NET_ADMIN, SYS_MODULE, NET_RAW]
    sysctls:
      net.ipv4.conf.all.src_valid_mark: "1"
      net.ipv4.ip_forward: "1"
    devices:
      - /dev/net/tun:/dev/net/tun
YML
say "compose записан: $COMPOSE"

# ── Переключение: стоп старой (не удаляем — для отката), старт новой ─
docker stop "$OLD" >/dev/null
say "старая панель остановлена (контейнер сохранён для отката: docker start $OLD)"
$DC -f "$COMPOSE" pull -q 2>/dev/null || true
$DC -f "$COMPOSE" up -d

# ── Проверка ────────────────────────────────────────────────────────
ok=""
for i in $(seq 1 30); do
  h=$(curl -fsS --max-time 3 "http://127.0.0.1:${WEB_PORT}/api/health" 2>/dev/null || true)
  if [ -n "$h" ]; then ok=$h; break; fi
  sleep 1
done
if [ -z "$ok" ]; then
  say "⚠ agent не ответил на /api/health — ОТКАТ"
  $DC -f "$COMPOSE" down || true
  docker start "$OLD" >/dev/null
  die "миграция откатена, работает $OLD. Логи: docker logs awg-agent"
fi
GOT=$(printf '%s' "$ok" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("clients","?"))' 2>/dev/null || echo '?')
say "agent жив: клиентов $GOT (в старой панели было $NCLIENTS)"
[ "$GOT" = "$NCLIENTS" ] && say "✅ число клиентов совпало" || say "⚠ число клиентов отличается — проверь логи"
say "готово. Откат при необходимости: sudo $0 --rollback"

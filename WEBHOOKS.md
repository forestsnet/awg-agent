# Вебхуки торрент-блокировщика

И `native-torrent-blocker`, и встроенный блокировщик `awg-agent` шлют отчёт о пойманном торренте **в том же формате, что и Remnawave** (`torrent_blocker.report`) — существующий бот принимает их без правок.

Отчёт уходит, когда клиент словил блокировку торрента (nft-дроп DHT/uTP/tracker — по IPv4 и IPv6), с кулдауном на клиента 1 час. Если вебхук не настроен — блокировка работает, отчёты не шлются.

Если задан бан (`block_duration` > 0), клиент на это время теряет весь доступ — как `blocked` в Remnawave; `blockDuration` и `willUnblockAt` в отчёте — про него. При `block_duration` = 0 режутся только торрент-пакеты: `blockDuration: 0`, `willUnblockAt: null`.

## Запрос

`POST` на заданный URL, тело — JSON, заголовки:

| Заголовок | Значение |
|---|---|
| `Content-Type` | `application/json` |
| `X-Remnawave-Signature` | `HMAC-SHA256(тело, secret)` в hex |
| `X-Remnawave-Timestamp` | ISO-время отчёта (совпадает с `timestamp` в теле) |
| `User-Agent` | `Remnawave` |

Подпись считается по **сырым байтам тела** тем же секретом, что задан при установке (`--webhook-secret` / в модалке агента). Проверять — обязательно: это единственное, что отличает настоящий отчёт от подделки.

## Тело

```json
{
  "scope": "torrent_blocker",
  "event": "torrent_blocker.report",
  "timestamp": "2026-09-25T01:45:59Z",
  "data": {
    "node": { "name": "awg-de-1" },
    "user": {
      "id": "123456789",
      "username": "iphone-artem",
      "telegramId": "123456789",
      "email": "user@example.com"
    },
    "report": {
      "actionReport": {
        "blocked": true,
        "ip": "10.8.0.5",
        "blockDuration": 3600,
        "willUnblockAt": "2026-09-25T02:45:59Z",
        "userId": "123456789",
        "processedAt": "2026-09-25T01:45:59Z"
      },
      "xrayReport": {
        "email": "iphone-artem",
        "protocol": "fsnt-torrent-blocker",
        "network": "udp",
        "source": "10.8.0.5",
        "destination": null,
        "routeTarget": "btguard",
        "outboundTag": "fsnt-torrent-blocker",
        "inboundTag": "wireguard",
        "ts": 1790300759
      }
    }
  }
}
```

### Поля

- `data.node.name` — имя ноды (задаётся при установке).
- `data.user.telegramId` / `data.user.email` — контакты клиента, если заданы при создании или в модалке (иначе `null`). По ним бот сразу знает, кому писать.
- `data.user.username` — имя клиента (в awg-agent), в standalone — pubkey/адрес.
- `actionReport.ip` — адрес клиента в туннеле (v4 или его v6-зеркало), по нему же и бан.
- `actionReport.blockDuration` — срок бана, сек (0 — бана нет); `willUnblockAt` — когда снимется (`null` без бана).
- `xrayReport.protocol` = `fsnt-torrent-blocker` — метка наших срабатываний (у нативного Remnawave здесь `bittorrent`). По ней в панели/боте отличают источник.
- `xrayReport.destination` — у WG обычно `null` (детект по set нарушителей, без адреса пира); у standalone с чтением kernel-лога может быть заполнен.

## Проверка подписи

**Python:**
```python
import hmac, hashlib
def verify(raw_body: bytes, signature: str, secret: str) -> bool:
    expected = hmac.new(secret.encode(), raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)
```

**Node.js:**
```js
const crypto = require('crypto');
function verify(rawBody, signature, secret) {
  const expected = crypto.createHmac('sha256', secret).update(rawBody).digest('hex');
  return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(signature));
}
```

Важно: подпись считается по **сырому телу до JSON-парсинга**. Во фреймворках бери «raw body», а не пересобранный из объекта JSON.

## Что делать боту

То же, что и с нативным `torrent_blocker.report` Remnawave: залогировать, уведомить, при повторах — отключить клиента (в awg-agent — `POST /api/wireguard/client/{id}/disable`; в панели Remnawave — перевести в DISABLED). Блокировку торрент-трафика и бан делает nft на ноде и без бота — вебхук нужен для реакции на нарушителя. Снять бан досрочно — `POST /api/wireguard/client/{id}/unban`.

## Управление блокировщиком и логами

Вкл/выкл блокировщика (глобально и для клиента), контакты для отчётов и
персональные логи клиента — по API агента. Список эндпоинтов — в README,
раздел «Своё сверх amnezia-wg-easy: блокировщик, контакты, логи».

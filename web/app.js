/* Панель агента AmneziaWG.
 *
 * Без фреймворка и сборки: три файла, один запрос на каждый, работает
 * сразу. Список обновляется раз в секунду, поэтому строки не
 * перерисовываются целиком — меняем только те узлы, где текст реально
 * другой. Иначе на каждом тике слетает выделение и закрывается
 * переименование.
 *
 * Иконки — lucide (ISC), вшиты путями: тянуть ради полутора десятков
 * значков библиотеку с CDN на сервер клиента незачем.
 */

const ICONS = {
  shield: '<path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/>',
  search: '<circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/>',
  plus: '<path d="M5 12h14"/><path d="M12 5v14"/>',
  users: '<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/>',
  wifi: '<path d="M12 20h.01"/><path d="M8.5 16.429a5 5 0 0 1 7 0"/><path d="M5 12.859a10 10 0 0 1 14 0"/><path d="M2 8.82a15 15 0 0 1 20 0"/>',
  down: '<path d="M12 5v14"/><path d="m19 12-7 7-7-7"/>',
  up: '<path d="M12 19V5"/><path d="m5 12 7-7 7 7"/>',
  qr: '<rect width="5" height="5" x="3" y="3" rx="1"/><rect width="5" height="5" x="16" y="3" rx="1"/><rect width="5" height="5" x="3" y="16" rx="1"/><path d="M21 16h-3a2 2 0 0 0-2 2v3"/><path d="M21 21v.01"/><path d="M12 7v3a2 2 0 0 1-2 2H7"/><path d="M3 12h.01"/><path d="M12 3h.01"/><path d="M12 16v.01"/><path d="M16 12h1"/><path d="M21 12v.01"/><path d="M12 21v-1"/>',
  power: '<path d="M12 2v10"/><path d="M18.4 6.6a9 9 0 1 1-12.77.04"/>',
  trash: '<path d="M3 6h18"/><path d="M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6"/><path d="M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2"/><path d="M10 11v6"/><path d="M14 11v6"/>',
  close: '<path d="M18 6 6 18"/><path d="m6 6 12 12"/>',
  copy: '<rect width="14" height="14" x="8" y="8" rx="2"/><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/>',
  download: '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="m7 10 5 5 5-5"/><path d="M12 15V3"/>',
  logout: '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><path d="m16 17 5-5-5-5"/><path d="M21 12H9"/>',
  alert: '<path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3"/><path d="M12 9v4"/><path d="M12 17h.01"/>',
  check: '<path d="M20 6 9 17l-5-5"/>',
  sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2v2"/><path d="M12 20v2"/><path d="m4.93 4.93 1.41 1.41"/><path d="m17.66 17.66 1.41 1.41"/><path d="M2 12h2"/><path d="M20 12h2"/><path d="m6.34 17.66-1.41 1.41"/><path d="m19.07 4.93-1.41 1.41"/>',
  moon: '<path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9"/>',
};

const icon = (name, size = 18) =>
  `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor"
     stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${ICONS[name] || ''}</svg>`;

// Значки, расставленные в разметке: подставляем один раз при загрузке.
function paintIcons(root = document) {
  root.querySelectorAll('[data-icon]').forEach((el) => {
    el.innerHTML = icon(el.dataset.icon, Number(el.dataset.size) || 18);
    el.removeAttribute('data-icon');
  });
}

const $ = (id) => document.getElementById(id);

const state = {
  clients: [], filter: '', timer: null,
  prev: new Map(), totals: { rx: 0, tx: 0, at: 0 }, confirm: null,
};

/* ── Транспорт ──────────────────────────────────────────────────── */

async function api(path, options = {}) {
  const res = await fetch(path, { headers: { 'Content-Type': 'application/json' }, ...options });
  if (res.status === 401) { showLogin(); throw new Error('Не авторизован'); }
  if (!res.ok) {
    let msg = `Ошибка ${res.status}`;
    try { msg = (await res.json()).error || msg; } catch (e) { /* пусто */ }
    throw new Error(msg);
  }
  return res.status === 204 ? null : res.json();
}

/* ── Мелочи ─────────────────────────────────────────────────────── */

function toast(text, kind = '') {
  const el = document.createElement('div');
  el.className = `toast ${kind}`;
  el.innerHTML = `<span class="ic">${icon(kind === 'err' ? 'alert' : 'check', 16)}</span><span></span>`;
  el.lastElementChild.textContent = text;
  $('toasts').appendChild(el);
  setTimeout(() => { el.style.opacity = '0'; setTimeout(() => el.remove(), 220); }, 3200);
}

const fmtBytes = (n) => {
  if (!n) return '0 Б';
  const u = ['Б', 'КБ', 'МБ', 'ГБ', 'ТБ'];
  const i = Math.min(Math.floor(Math.log(n) / Math.log(1024)), u.length - 1);
  return `${(n / 1024 ** i).toFixed(i ? 1 : 0)} ${u[i]}`;
};

const fmtAgo = (iso) => {
  if (!iso) return 'не подключался';
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return `${Math.round(s)} с назад`;
  if (s < 3600) return `${Math.round(s / 60)} мин назад`;
  if (s < 86400) return `${Math.round(s / 3600)} ч назад`;
  return `${Math.round(s / 86400)} дн назад`;
};

// «Онлайн» — хендшейк не старше трёх минут: keepalive 25 секунд, две
// пропущенные попытки ещё не значат, что клиент отвалился.
const isLive = (iso) => !!iso && (Date.now() - new Date(iso).getTime()) < 180000;
const initials = (name) => (name || '?').trim().slice(0, 2).toUpperCase();

// Цвет аватара выводим из имени: одно и то же имя — один и тот же цвет,
// глазу проще найти нужную строку. Оттенок держим в палитре акцента.
function avatarStyle(name) {
  let h = 0;
  for (const ch of name || '') h = (h * 31 + ch.charCodeAt(0)) % 360;
  return { bg: `hsl(${h} 72% 92%)`, fg: `hsl(${h} 58% 34%)` };
}

const setText = (el, value) => { if (el && el.textContent !== value) el.textContent = value; };

/* ── Тема ───────────────────────────────────────────────────────── */

function currentTheme() {
  return document.documentElement.getAttribute('data-theme') === 'dark' ? 'dark' : 'light';
}
function paintThemeButton() {
  $('theme-btn').innerHTML = icon(currentTheme() === 'dark' ? 'sun' : 'moon', 18);
}
$('theme-btn').addEventListener('click', () => {
  const next = currentTheme() === 'dark' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', next);
  localStorage.setItem('theme', next);
  paintThemeButton();
});

/* ── Экраны ─────────────────────────────────────────────────────── */

function showLogin() {
  $('app').classList.add('hidden');
  $('login').classList.remove('hidden');
  stopPolling();
  setTimeout(() => $('password').focus(), 40);
}

function showApp() {
  $('login').classList.add('hidden');
  $('app').classList.remove('hidden');
  refresh();
  startPolling();
}

$('login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  $('login-error').textContent = '';
  try {
    await api('/api/session', {
      method: 'POST',
      body: JSON.stringify({ password: $('password').value, remember: true }),
    });
    $('password').value = '';
    showApp();
  } catch (err) {
    $('login-error').textContent =
      err.message === 'Не авторизован' ? 'Неверный пароль' : err.message;
  }
});

$('logout-btn').addEventListener('click', async () => {
  await fetch('/api/session', { method: 'DELETE' });
  showLogin();
});

/* ── Данные ─────────────────────────────────────────────────────── */

async function refresh() {
  try {
    const [clients, health] = await Promise.all([
      api('/api/wireguard/client'), api('/api/health'),
    ]);
    state.clients = clients;
    renderHealth(health);
    render();
  } catch (err) {
    if (err.message !== 'Не авторизован') console.error(err);
  }
}

function startPolling() {
  stopPolling();
  // Только при открытой вкладке: фоновая не должна долбить сервер.
  state.timer = setInterval(() => {
    if (document.visibilityState === 'visible') refresh();
  }, 1000);
}
function stopPolling() { if (state.timer) clearInterval(state.timer); state.timer = null; }
document.addEventListener('visibilitychange', () => {
  if (document.visibilityState === 'visible' && state.timer) refresh();
});

/* ── Отрисовка ──────────────────────────────────────────────────── */

function renderHealth(h) {
  const bits = [h.interface, `протокол ${h.protocol ?? '—'}`];
  if (h.header_protection) bits.push('header protection');
  if (h.random_trailers) bits.push('random trailers');
  if (h.disable_cookies) bits.push('cookies off');
  setText($('server-info'), bits.join(' · '));
  $('iface-state').classList.toggle('down', !h.up);
  setText($('iface-text'), h.up ? 'интерфейс поднят' : 'интерфейс не поднят');
}

function renderStats() {
  const now = Date.now();
  const rx = state.clients.reduce((a, c) => a + (c.transferRx || 0), 0);
  const tx = state.clients.reduce((a, c) => a + (c.transferTx || 0), 0);
  setText($('s-total'), String(state.clients.length));
  setText($('s-online'), String(state.clients.filter((c) => isLive(c.latestHandshakeAt)).length));
  setText($('s-rx'), fmtBytes(rx));
  setText($('s-tx'), fmtBytes(tx));

  const dt = (now - state.totals.at) / 1000;
  if (state.totals.at && dt > 0.2) {
    setText($('s-rx-rate'), `${fmtBytes(Math.max(0, rx - state.totals.rx) / dt)}/с`);
    setText($('s-tx-rate'), `${fmtBytes(Math.max(0, tx - state.totals.tx) / dt)}/с`);
  }
  state.totals = { rx, tx, at: now };
}

function rowTemplate(id) {
  const row = document.createElement('div');
  row.className = 'row';
  row.dataset.id = id;
  row.innerHTML = `
    <div class="who">
      <div class="avatar"></div>
      <div style="min-width:0">
        <div class="name" data-act="rename" title="Нажмите, чтобы переименовать"></div>
        <div class="meta"></div>
      </div>
    </div>
    <div class="shake"><span class="pill"></span><span class="ago"></span></div>
    <div class="traffic">
      <div class="col">
        <span class="val">${icon('down', 15)}<span class="rx"></span></span>
        <span class="rate rx-rate"></span>
      </div>
      <div class="col">
        <span class="val">${icon('up', 15)}<span class="tx"></span></span>
        <span class="rate tx-rate"></span>
      </div>
    </div>
    <div class="row-actions">
      <button class="icon" data-act="qr" title="QR и конфиг">${icon('qr', 17)}</button>
      <button class="icon" data-act="toggle">${icon('power', 17)}</button>
      <button class="icon warn" data-act="del" title="Удалить">${icon('trash', 17)}</button>
    </div>`;
  return row;
}

function render() {
  const q = state.filter.trim().toLowerCase();
  const list = q
    ? state.clients.filter((c) =>
        c.name.toLowerCase().includes(q) || (c.address || '').includes(q))
    : state.clients;

  $('empty').classList.toggle('hidden', state.clients.length > 0);

  const box = $('rows');
  const now = Date.now();
  const seen = new Set();

  list.forEach((c, index) => {
    seen.add(c.id);
    let row = box.querySelector(`.row[data-id="${c.id}"]`);
    if (!row) { row = rowTemplate(c.id); box.appendChild(row); }
    if (box.children[index] !== row) box.insertBefore(row, box.children[index] || null);

    row.classList.toggle('off', !c.enabled);
    const avatar = row.querySelector('.avatar');
    setText(avatar, initials(c.name));
    const tone = avatarStyle(c.name);
    if (avatar.style.background !== tone.bg) {
      avatar.style.background = tone.bg;
      avatar.style.color = tone.fg;
    }

    const nameEl = row.querySelector('.name');
    if (!nameEl.querySelector('input')) setText(nameEl, c.name);
    setText(row.querySelector('.meta'), c.address + (c.endpoint ? ` · ${c.endpoint}` : ''));
    row.querySelector('.pill').classList.toggle('live', isLive(c.latestHandshakeAt));
    setText(row.querySelector('.ago'), fmtAgo(c.latestHandshakeAt));
    setText(row.querySelector('.rx'), fmtBytes(c.transferRx));
    setText(row.querySelector('.tx'), fmtBytes(c.transferTx));

    // Скорость считаем из разницы счётчиков: отдельной ручки нет, а
    // лишний запрос раз в секунду тут ни к чему.
    const prev = state.prev.get(c.id);
    if (prev && now > prev.at) {
      const dt = (now - prev.at) / 1000;
      const rxr = Math.max(0, (c.transferRx || 0) - prev.rx) / dt;
      const txr = Math.max(0, (c.transferTx || 0) - prev.tx) / dt;
      setText(row.querySelector('.rx-rate'), rxr > 256 ? `${fmtBytes(rxr)}/с` : '');
      setText(row.querySelector('.tx-rate'), txr > 256 ? `${fmtBytes(txr)}/с` : '');
    }
    state.prev.set(c.id, { rx: c.transferRx || 0, tx: c.transferTx || 0, at: now });

    const toggle = row.querySelector('[data-act="toggle"]');
    toggle.title = c.enabled ? 'Выключить' : 'Включить';
    toggle.classList.toggle('warn', c.enabled);
  });

  for (const row of [...box.children]) {
    if (!seen.has(row.dataset.id)) row.remove();
  }
  renderStats();
}

/* ── Действия ───────────────────────────────────────────────────── */

$('search').addEventListener('input', (e) => { state.filter = e.target.value; render(); });

const openModal = (id) => $(id).classList.remove('hidden');
const closeModal = (id) => $(id).classList.add('hidden');

document.addEventListener('click', (e) => {
  const closer = e.target.closest('[data-close]');
  if (closer) closer.closest('.modal').classList.add('hidden');
  if (e.target.classList.contains('modal')) e.target.classList.add('hidden');
});
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') document.querySelectorAll('.modal').forEach((m) => m.classList.add('hidden'));
});

$('add-btn').addEventListener('click', () => {
  $('create-name').value = '';
  openModal('create-modal');
  setTimeout(() => $('create-name').focus(), 40);
});

$('create-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const name = $('create-name').value.trim();
  if (!name) return;
  try {
    await api('/api/wireguard/client', { method: 'POST', body: JSON.stringify({ name }) });
    closeModal('create-modal');
    toast(`Клиент «${name}» создан`);
    await refresh();
  } catch (err) { toast(err.message, 'err'); }
});

function askConfirm(title, text, okText, onOk) {
  $('confirm-title').textContent = title;
  $('confirm-text').textContent = text;
  $('confirm-ok').textContent = okText;
  state.confirm = onOk;
  openModal('confirm-modal');
}
$('confirm-ok').addEventListener('click', async () => {
  const fn = state.confirm;
  closeModal('confirm-modal');
  state.confirm = null;
  if (fn) await fn();
});

$('rows').addEventListener('click', async (e) => {
  const el = e.target.closest('[data-act]');
  if (!el) return;
  const id = el.closest('.row').dataset.id;
  const client = state.clients.find((c) => c.id === id);
  if (!client) return;

  try {
    if (el.dataset.act === 'qr') return openQr(client);
    if (el.dataset.act === 'rename') return startRename(el, client);
    if (el.dataset.act === 'toggle') {
      await api(`/api/wireguard/client/${id}/${client.enabled ? 'disable' : 'enable'}`,
        { method: 'POST' });
      toast(client.enabled ? `«${client.name}» выключен` : `«${client.name}» включён`);
      return refresh();
    }
    if (el.dataset.act === 'del') {
      return askConfirm(
        `Удалить «${client.name}»?`,
        'Конфиг перестанет работать сразу. Восстановить его нельзя — только выдать новый.',
        'Удалить',
        async () => {
          await api(`/api/wireguard/client/${id}`, { method: 'DELETE' });
          toast(`«${client.name}» удалён`);
          refresh();
        },
      );
    }
  } catch (err) { toast(err.message, 'err'); }
});

/* Переименование прямо в строке: модалка ради одного поля — лишний шаг. */
function startRename(nameEl, client) {
  if (nameEl.querySelector('input')) return;
  const input = document.createElement('input');
  input.value = client.name;
  input.maxLength = 120;
  nameEl.textContent = '';
  nameEl.appendChild(input);
  input.focus();
  input.select();

  const finish = async (save) => {
    const value = input.value.trim();
    nameEl.textContent = client.name;
    if (!save || !value || value === client.name) return;
    try {
      await api(`/api/wireguard/client/${client.id}/name`,
        { method: 'PUT', body: JSON.stringify({ name: value }) });
      toast('Имя изменено');
      refresh();
    } catch (err) { toast(err.message, 'err'); }
  };
  input.addEventListener('blur', () => finish(true));
  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') { e.preventDefault(); input.blur(); }
    if (e.key === 'Escape') { e.preventDefault(); finish(false); }
  });
}

async function openQr(client) {
  $('qr-name').textContent = client.name;
  $('qr-download').href = `/api/wireguard/client/${client.id}/configuration`;
  $('qr-body').innerHTML = '<span class="muted">…</span>';
  openModal('qr-modal');
  const res = await fetch(`/api/wireguard/client/${client.id}/qrcode.svg`);
  $('qr-body').innerHTML = await res.text();
  $('qr-copy').onclick = async () => {
    const conf = await fetch(`/api/wireguard/client/${client.id}/configuration`).then((r) => r.text());
    try {
      await navigator.clipboard.writeText(conf);
      toast('Конфиг в буфере');
    } catch (err) {
      toast('Браузер не дал доступ к буферу — скачайте файлом', 'err');
    }
  };
}

/* ── Старт ──────────────────────────────────────────────────────── */

paintIcons();
paintThemeButton();
(async () => {
  try {
    const s = await fetch('/api/session').then((r) => r.json());
    s.authenticated ? showApp() : showLogin();
  } catch (e) { showLogin(); }
})();

/* Панель агента.
 *
 * Без фреймворка и сборки намеренно: файл отдаётся одним запросом и
 * работает сразу. Список перерисовывается точечно — строки, которые не
 * изменились, не трогаем, иначе на обновлении статистики раз в секунду
 * дёргается выделение и пропадает фокус.
 */
const api = async (path, options = {}) => {
  const res = await fetch(path, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  });
  if (res.status === 401) { showLogin(); throw new Error('Не авторизован'); }
  if (!res.ok) {
    let msg = 'Ошибка ' + res.status;
    try { msg = (await res.json()).error || msg; } catch (e) { /* пусто */ }
    throw new Error(msg);
  }
  return res.status === 204 ? null : res.json();
};

const $ = (id) => document.getElementById(id);
const state = { clients: [], filter: '', timer: null };

/* ── Экраны ─────────────────────────────────────────────────────── */

function showLogin() {
  $('app').classList.add('hidden');
  $('login').classList.remove('hidden');
  stopPolling();
  setTimeout(() => $('password').focus(), 50);
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
    $('login-error').textContent = err.message === 'Не авторизован'
      ? 'Неверный пароль' : err.message;
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
      api('/api/wireguard/client'),
      api('/api/health'),
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
  // Раз в секунду и только когда вкладка открыта: фоновая вкладка не
  // должна держать сервер запросами.
  state.timer = setInterval(() => {
    if (document.visibilityState === 'visible') refresh();
  }, 1000);
}
function stopPolling() { if (state.timer) clearInterval(state.timer); state.timer = null; }

/* ── Отрисовка ──────────────────────────────────────────────────── */

function renderHealth(h) {
  $('iface-dot').classList.toggle('up', !!h.up);
  const bits = [h.interface, 'протокол ' + (h.protocol || '—')];
  if (h.header_protection) bits.push('header protection');
  if (h.random_trailers) bits.push('random trailers');
  if (h.disable_cookies) bits.push('cookies off');
  $('server-info').textContent = bits.join(' · ');
}

const fmtBytes = (n) => {
  if (!n) return '0';
  const units = ['Б', 'КБ', 'МБ', 'ГБ', 'ТБ'];
  const i = Math.min(Math.floor(Math.log(n) / Math.log(1024)), units.length - 1);
  return (n / Math.pow(1024, i)).toFixed(i ? 1 : 0) + ' ' + units[i];
};

const fmtAgo = (iso) => {
  if (!iso) return 'никогда';
  const sec = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (sec < 60) return Math.round(sec) + ' с назад';
  if (sec < 3600) return Math.round(sec / 60) + ' мин назад';
  if (sec < 86400) return Math.round(sec / 3600) + ' ч назад';
  return Math.round(sec / 86400) + ' дн назад';
};

const isLive = (iso) => iso && (Date.now() - new Date(iso).getTime()) < 3 * 60 * 1000;

function render() {
  const q = state.filter.trim().toLowerCase();
  const list = q
    ? state.clients.filter((c) =>
        c.name.toLowerCase().includes(q) || (c.address || '').includes(q))
    : state.clients;

  $('empty').classList.toggle('hidden', list.length > 0);
  $('table').classList.toggle('hidden', list.length === 0);

  const rows = $('rows');
  const seen = new Set();
  for (const c of list) {
    seen.add(c.id);
    let tr = rows.querySelector(`tr[data-id="${c.id}"]`);
    if (!tr) {
      tr = document.createElement('tr');
      tr.dataset.id = c.id;
      tr.innerHTML = `
        <td><span class="name"><span class="pill"></span><span class="label"></span></span></td>
        <td class="addr"></td>
        <td class="shake muted"></td>
        <td class="num rx"></td>
        <td class="num tx"></td>
        <td><div class="row-actions">
          <button class="ghost" data-act="qr">QR</button>
          <button class="ghost" data-act="toggle"></button>
          <button class="ghost danger" data-act="del">Удалить</button>
        </div></td>`;
      rows.appendChild(tr);
    }
    tr.classList.toggle('off', !c.enabled);
    tr.querySelector('.label').textContent = c.name;
    tr.querySelector('.pill').classList.toggle('live', isLive(c.latestHandshakeAt));
    tr.querySelector('.addr').textContent = c.address;
    tr.querySelector('.shake').textContent = fmtAgo(c.latestHandshakeAt);
    tr.querySelector('.rx').textContent = fmtBytes(c.transferRx);
    tr.querySelector('.tx').textContent = fmtBytes(c.transferTx);
    tr.querySelector('[data-act="toggle"]').textContent = c.enabled ? 'Выключить' : 'Включить';
  }
  for (const tr of [...rows.children]) {
    if (!seen.has(tr.dataset.id)) tr.remove();
  }
}

/* ── Действия ───────────────────────────────────────────────────── */

$('search').addEventListener('input', (e) => { state.filter = e.target.value; render(); });

$('add-btn').addEventListener('click', async () => {
  const name = prompt('Имя клиента');
  if (!name) return;
  try {
    await api('/api/wireguard/client', { method: 'POST', body: JSON.stringify({ name }) });
    refresh();
  } catch (err) { alert(err.message); }
});

$('rows').addEventListener('click', async (e) => {
  const btn = e.target.closest('button[data-act]');
  if (!btn) return;
  const id = btn.closest('tr').dataset.id;
  const client = state.clients.find((c) => c.id === id);
  if (!client) return;
  try {
    if (btn.dataset.act === 'qr') return openQr(client);
    if (btn.dataset.act === 'toggle') {
      await api(`/api/wireguard/client/${id}/${client.enabled ? 'disable' : 'enable'}`,
        { method: 'POST' });
    }
    if (btn.dataset.act === 'del') {
      if (!confirm(`Удалить ${client.name}? Конфиг перестанет работать сразу.`)) return;
      await api(`/api/wireguard/client/${id}`, { method: 'DELETE' });
    }
    refresh();
  } catch (err) { alert(err.message); }
});

async function openQr(client) {
  $('qr-name').textContent = client.name;
  $('qr-download').href = `/api/wireguard/client/${client.id}/configuration`;
  $('qr-body').innerHTML = '<span class="muted">…</span>';
  $('qr-modal').classList.remove('hidden');
  const res = await fetch(`/api/wireguard/client/${client.id}/qrcode.svg`);
  $('qr-body').innerHTML = await res.text();
}

$('qr-modal').addEventListener('click', (e) => {
  if (e.target.id === 'qr-modal' || e.target.dataset.close !== undefined) {
    $('qr-modal').classList.add('hidden');
  }
});
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') $('qr-modal').classList.add('hidden');
});

/* ── Старт ──────────────────────────────────────────────────────── */

(async () => {
  try {
    const s = await fetch('/api/session').then((r) => r.json());
    s.authenticated ? showApp() : showLogin();
  } catch (e) { showLogin(); }
})();

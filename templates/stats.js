// Paths and referrers are attacker-controlled, so this page only renders them via textContent.
const $ = (id) => document.getElementById(id);
// Storage can be unavailable (private windows, blocked site data); the page still works without it.
const load = (key) => { try { return localStorage.getItem(key) || ''; } catch { return ''; } };
const save = (key, value) => { try { localStorage.setItem(key, value); return true; } catch { return false; } };
const domain = () => $('domain').value.trim().replace(/\.$/, '').toLowerCase();
const tokenKey = (name) => `afwd-stats-token:${name}`;
const hex = async (text) => [...new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text)))]
  .map((b) => b.toString(16).padStart(2, '0')).join('');

const loadToken = () => {
  const token = domain() ? load(tokenKey(domain())) : '';
  $('token').value = token;
  $('token-source').textContent = token
    ? 'Token loaded from this browser.'
    : 'No token stored in this browser for this domain. Create one above or paste an existing token.';
};
$('domain').value = load('afwd-stats-domain');
$('domain').oninput = () => { $('setup').hidden = true; $('generated').textContent = ''; loadToken(); };
$('token').oninput = () => { $('token-source').textContent = ''; };
loadToken();

$('generate').onclick = async () => {
  const name = domain();
  if (!name) {
    $('domain').reportValidity();
    return;
  }
  const replaced = load(tokenKey(name));
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  const token = btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  $('new-token').textContent = token;
  $('record-name').textContent = `_afwd-stats.${name}`;
  $('record-value').textContent = `v=afwdstats1 h=${await hex(token)}`;
  $('setup').hidden = false;
  const stored = save(tokenKey(name), token) && save('afwd-stats-domain', name);
  $('generated').textContent = !stored
    ? 'Could not store the token in this browser. Copy it now.'
    : replaced
      ? 'Stored in this browser. This replaced the previous token; its DNS record keeps working until you delete it.'
      : 'Stored in this browser.';
  loadToken();
  if (!stored) $('token').value = token;
};

for (const button of document.querySelectorAll('[data-copy]')) {
  button.onclick = async () => {
    const label = button.textContent;
    try {
      await navigator.clipboard.writeText($(button.dataset.copy).textContent);
      button.textContent = 'Copied';
    } catch {
      button.textContent = 'Copy failed, select the text manually';
    }
    setTimeout(() => { button.textContent = label; }, 2000);
  };
}

const sum = (pairs) => [...pairs.reduce((map, [key, n]) => map.set(key, (map.get(key) || 0) + n), new Map())];
const section = (title, rows) => {
  const heading = document.createElement('h3');
  heading.textContent = title;
  const table = document.createElement('table');
  table.className = 'bars';
  const max = Math.max(1, ...rows.map(([, n]) => n));
  for (const [label, n] of rows) {
    const row = table.insertRow();
    row.insertCell().textContent = label;
    row.insertCell().textContent = n;
    const bar = document.createElement('div');
    bar.className = 'bar';
    bar.style.width = `${(100 * n) / max}%`;
    row.insertCell().append(bar);
  }
  $('result').append(heading, rows.length ? table : 'No data yet.');
};
$('view').onsubmit = async (event) => {
  event.preventDefault();
  const name = domain();
  const token = $('token').value.trim();
  const result = $('result');
  if (!name) {
    $('domain').reportValidity();
    return;
  }
  result.textContent = 'Loading...';
  let response;
  try {
    response = await fetch(`/api/stats/${encodeURIComponent(name)}`, { headers: { Authorization: `Bearer ${token}` } });
  } catch (error) {
    result.textContent = `Could not load statistics: ${error.message}`;
    return;
  }
  if (response.status === 401) {
    result.textContent = 'The token does not match a DNS record for this domain. Check the record, or wait for DNS to update.';
    return;
  }
  if (!response.ok) {
    result.textContent = `Error ${response.status}`;
    return;
  }
  // A pasted token that works is remembered for next time.
  save(tokenKey(name), token);
  save('afwd-stats-domain', name);
  loadToken();
  const data = await response.json();
  result.replaceChildren();
  section('Hits per day (UTC)', sum(data.hits.map(([hour, , n]) => [new Date(hour * 1000).toISOString().slice(0, 10), n])));
  section('Status', sum(data.hits.map(([, status, n]) => [status, n])).sort((a, b) => b[1] - a[1]));
  section('Top paths', data.paths);
  section('Top referrers', data.referrers);
};

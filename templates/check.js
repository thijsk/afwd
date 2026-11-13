// Record builder and domain checker. Check results contain DNS data controlled by
// the domain owner, so they are only rendered via textContent.
const $ = (id) => document.getElementById(id);
const form = $('builder');
const list = (value) => value.split(',').filter(Boolean);
const ipv4 = list(form.dataset.ipv4);
const ipv6 = list(form.dataset.ipv6);
const SAMPLE = '/blog/post?x=1';

const domain = () => $('b-domain').value.trim().replace(/\.$/, '').toLowerCase();

// Returns the normalised destination URL, or an error message.
const destination = () => {
  const value = $('b-dest').value.trim();
  if (!value) return { error: '' };
  let url;
  try {
    url = new URL(/^[a-z][a-z0-9+.-]*:/i.test(value) ? value : `https://${value}`);
  } catch {
    return { error: 'The destination is not a valid URL.' };
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') return { error: 'The destination must start with http:// or https://.' };
  return { url };
};

// Mirrors redirect_url in src/redirect.rs for the preview.
const preview = (url, name, preserve, append) => {
  const target = new URL(url.href);
  if (preserve) {
    const sample = new URL(SAMPLE, 'http://x');
    target.pathname = target.pathname.replace(/\/+$/, '') + sample.pathname;
    target.search = sample.search;
    return target.href;
  }
  if (append) {
    const [prefix, ...fragment] = target.href.split('#');
    return prefix + encodeURIComponent(name) + (fragment.length ? `#${fragment.join('#')}` : '');
  }
  target.search = '';
  return target.href;
};

const copyButton = (text) => {
  const button = document.createElement('button');
  button.type = 'button';
  button.textContent = 'Copy';
  button.onclick = async () => {
    try {
      await navigator.clipboard.writeText(text);
      button.textContent = 'Copied';
    } catch {
      button.textContent = 'Select manually';
    }
    setTimeout(() => { button.textContent = 'Copy'; }, 2000);
  };
  return button;
};

const build = () => {
  const name = domain();
  const preserve = $('b-preserve').checked;
  $('b-append').disabled = preserve;
  const append = !preserve && $('b-append').checked;
  const dest = destination();
  const missing = [!name && 'your domain', !dest.url && !dest.error && 'the destination'].filter(Boolean);
  $('b-message').textContent = dest.error || (missing.length ? `Fill in ${missing.join(' and ')} to get your DNS records.` : '');
  $('b-message').hidden = !$('b-message').textContent;
  $('b-output').hidden = !name || !dest.url;
  $('check').disabled = !name;
  if ($('b-output').hidden) return;

  const type = $('b-type').value;
  const txt = ['v=afwd1', preserve && 'preserve=y', append && 'append=y', type !== '302' && `type=${type}`, `dest=${dest.url.href}`]
    .filter(Boolean).join(' ');
  const records = [
    ...ipv4.map((address) => [name, 'A', address]),
    ...ipv6.map((address) => [name, 'AAAA', address]),
    [name, 'TXT', txt],
  ];
  if ($('b-wildcard').checked) records.push([`*.${name}`, 'CNAME', name]);

  const body = $('b-records');
  body.replaceChildren();
  for (const [host, kind, value] of records) {
    const row = body.insertRow();
    row.insertCell().textContent = host;
    row.insertCell().textContent = kind;
    const cell = row.insertCell();
    cell.className = 'mono';
    cell.textContent = value;
    row.insertCell().append(copyButton(value));
  }
  $('b-from').textContent = `http://${name}${SAMPLE}`;
  $('b-to').textContent = `${preview(dest.url, name, preserve, append)} (${type})`;
};

const result = (state, title, detail) => {
  const item = document.createElement('li');
  item.className = state;
  const heading = document.createElement('strong');
  heading.textContent = title;
  item.append(heading);
  if (detail) {
    const text = document.createElement('div');
    text.textContent = detail;
    item.append(text);
  }
  $('checks').append(item);
};

const check = async () => {
  const name = domain();
  if (!name) return;
  const checks = $('checks');
  checks.replaceChildren();
  $('check').disabled = true;
  try {
    const response = await fetch(`/api/check/${encodeURIComponent(name)}`, { cache: 'no-store' });
    if (!response.ok) throw new Error(response.status === 400 ? `${name} is not a valid domain name.` : await response.text() || `Error ${response.status}`);
    const data = await response.json();

    const foreign = data.addresses.filter(([, ours]) => ours === false).map(([address]) => address);
    if (!data.addresses.length) {
      result('bad', 'The domain does not point at AFWD', 'No A or AAAA records were found. Add the records above.');
    } else if (foreign.length === data.addresses.length) {
      result('bad', 'The domain does not point at AFWD', `It points at ${foreign.join(', ')}. Replace these records with the A and AAAA records above.`);
    } else if (foreign.length) {
      result('bad', 'Some addresses do not belong to AFWD', `Remove these records: ${foreign.join(', ')}`);
    } else if (data.addresses.some(([, ours]) => ours === null)) {
      result('unknown', 'The domain has addresses', data.addresses.map(([address]) => address).join(', '));
    } else {
      result('good', 'The domain points at AFWD', data.addresses.map(([address]) => address).join(', '));
    }

    if (!data.record) {
      result('bad', 'No AFWD TXT record', `Add a TXT record for ${data.domain} that starts with v=afwd1.`);
    } else if (data.error) {
      result('bad', 'The AFWD TXT record is invalid', `${data.error}\n${data.record}`);
    } else {
      result('good', 'The AFWD TXT record is valid', data.record);
    }

    if (data.redirect) {
      result('good', `Redirects with ${data.redirect.status}`, `${data.redirect.from} → ${data.redirect.location}`);
    }
    if (data.certificate === false) {
      result('unknown', 'HTTPS is disabled', 'The record contains cert=no, so no certificate is requested.');
    } else if (data.certificate && data.addresses.length && !foreign.length) {
      result('good', 'HTTPS certificate allowed', `Visit https://${data.domain}/ so certificate setup can start.`);
    }
  } catch (error) {
    result('bad', 'Could not check the domain', error.message);
  } finally {
    $('check').disabled = !domain();
  }
};

form.oninput = build;
form.onsubmit = (event) => event.preventDefault();
$('check').onclick = check;

// The "not configured" page links here as /#check=example.com.
const linked = new URLSearchParams(location.hash.slice(1)).get('check');
if (linked) {
  $('b-domain').value = linked;
  build();
  $('setup').scrollIntoView();
  check();
} else {
  build();
}

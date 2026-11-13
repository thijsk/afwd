// Hero demo and live numbers. In a block so its names do not clash with check.js.
{
  const byId = (id) => document.getElementById(id);

  // Each example matches what src/redirect.rs does with the record.
  const examples = [
    {
      txt: 'v=afwd1 preserve=y type=308 dest=https://new.example/',
      from: 'old-brand.example/blog/post?x=1',
      status: '308',
      to: 'new.example/blog/post?x=1',
      caption: 'Keep the path and query string',
    },
    {
      txt: 'v=afwd1 dest=https://www.example.net/',
      from: 'example.com/anything',
      status: '302',
      to: 'www.example.net/',
      caption: 'Send every request to one page',
    },
    {
      txt: 'v=afwd1 type=perm append=y dest=https://parking.example/?domain=',
      from: 'for-sale.example/',
      status: '301',
      to: 'parking.example/?domain=for-sale.example',
      caption: 'Tell the destination which domain was visited',
    },
  ];

  const demo = document.querySelector('.demo');
  const show = (example) => {
    byId('demo-txt').textContent = example.txt;
    byId('demo-from').textContent = example.from;
    byId('demo-status').textContent = example.status;
    byId('demo-to').textContent = example.to;
    byId('demo-caption').textContent = example.caption;
  };
  const still = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  if (!still) {
    let index = 0;
    setInterval(() => {
      if (document.hidden) return;
      demo.classList.add('switching');
      setTimeout(() => {
        index = (index + 1) % examples.length;
        show(examples[index]);
        demo.classList.remove('switching');
      }, 250);
    }, 4500);
  }

  fetch('/api/summary')
    .then((response) => (response.ok ? response.json() : Promise.reject()))
    .then(({ requests, domains }) => {
      if (!requests) return;
      const compact = new Intl.NumberFormat('en', { notation: 'compact', compactDisplay: 'long', maximumFractionDigits: 1 });
      const proof = byId('proof');
      const strong = (text) => Object.assign(document.createElement('strong'), { textContent: text });
      proof.replaceChildren(
        strong(compact.format(requests)),
        ' requests forwarded for ',
        strong(domains.toLocaleString('en')),
        ` domain${domains === 1 ? '' : 's'} in the last 90 days`,
      );
      proof.hidden = false;
    })
    .catch(() => {});
}

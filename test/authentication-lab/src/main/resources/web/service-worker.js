self.addEventListener('install', event => event.waitUntil(self.skipWaiting()));
self.addEventListener('activate', event => event.waitUntil(self.clients.claim()));
self.addEventListener('fetch', event => {
  const target = new URL(event.request.url);
  if (!target.pathname.endsWith('/surface/sw/token')) return;
  const script = new URL(self.location.href);
  const root = script.pathname.slice(0, script.pathname.lastIndexOf('/') + 1);
  const upstream = new URL(root + 'surface/token', script.origin);
  upstream.searchParams.set('kind', 'worker');
  upstream.searchParams.set('generation', script.searchParams.get('generation'));
  event.respondWith(fetch(upstream.href, {credentials: 'include'}));
});

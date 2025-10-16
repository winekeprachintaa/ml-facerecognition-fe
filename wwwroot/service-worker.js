const CACHE = 'qr-scan-v17';
const PRECACHE = [
    './',
    './index.html',
    './scanner.html',
    './admin.html',
    './face-api.html',
    './js/auth.js',
    './js/face-api-page.js',
    './manifest.json',
    './users.json',
    './icons/logo.png',
    './models/best.onnx',
];

self.addEventListener('install', (event) => {
    event.waitUntil(caches.open(CACHE).then(c => c.addAll(PRECACHE)));
});

self.addEventListener('activate', (event) => {
    event.waitUntil(
        caches.keys().then(keys =>
            Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k))))
    );
});

self.addEventListener('fetch', (event) => {
    const req = event.request;
    if (req.mode === 'navigate') {
        event.respondWith((async () => {
            try {
                return await fetch(req);
            } catch {
                const cache = await caches.open(CACHE);
                const cached = await cache.match(req);
                return cached || cache.match('./index.html');
            }
        })());
        return;
    }

    event.respondWith(
        caches.match(req).then(cached =>
            cached || fetch(req).then(res => {
                const clone = res.clone();
                caches.open(CACHE).then(c => c.put(req, clone));
                return res;
            })
        )
    );
});

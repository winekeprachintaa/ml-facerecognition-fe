const CACHE = 'qr-scan-v27';
const PRECACHE = [
    './',
    './index.html',
    './scanner.html',
    './admin.html',
    './js/auth.js',
    './manifest.json',
    './users.json',
    './icons/logo.png',
    './models/best.onnx',
    './models/tiny_face_detector_model-weights_manifest.json',
    './models/tiny_face_detector_model-shard1.bin',
];

// --- INSTALL ---
self.addEventListener('install', (event) => {
    event.waitUntil(
        caches.open(CACHE).then((c) => c.addAll(PRECACHE))
    );
    self.skipWaiting();
});

// --- ACTIVATE ---
self.addEventListener('activate', (event) => {
    event.waitUntil(
        caches.keys().then((keys) =>
            Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k)))
        )
    );
    self.clients.claim();
});

// --- FETCH ---
self.addEventListener('fetch', (event) => {
    const req = event.request;
    const url = new URL(req.url);

    // 1) Jangan intercept non-GET (POST/PUT/DELETE, dsb)
    if (req.method !== 'GET') {
        event.respondWith(fetch(req));
        return;
    }

    // 2) Jangan cache rute proxy/API (meski GET)
    if (url.pathname.startsWith('/proxy/')) {
        event.respondWith(fetch(req));
        return;
    }

    // 3) Cache-first untuk GET same-origin
    event.respondWith(
        caches.match(req).then((cached) => {
            if (cached) return cached;

            return fetch(req).then((res) => {
                // Cache hanya jika:
                // - request GET
                // - response OK
                // - tipe basic (same-origin) atau cors dari origin yang sama
                // - BUKAN opaque/error
                const okToCache =
                    req.method === 'GET' &&
                    res &&
                    res.ok &&
                    (res.type === 'basic' || (res.type === 'cors' && url.origin === self.location.origin));

                if (okToCache) {
                    const clone = res.clone();
                    caches.open(CACHE).then((c) => c.put(req, clone)).catch(() => { });
                }

                return res;
            }).catch(() => {
                // Fallback offline untuk navigasi
                if (req.mode === 'navigate') {
                    return caches.match('./index.html');
                }
                // atau biarkan gagal
                return Promise.reject(new Error('Network error and no cache.'));
            });
        })
    );
});

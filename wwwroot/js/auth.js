// auth.js (merge users.json + localStorage, dukung it/iterations, network-first + no-store)
window.Auth = (function () {
    const USERS_KEY = 'qrizin_users_local_v1';
    const SESSION_KEY = 'qrizin_session_v1';

    // --- utils ---
    function b64url(bytes) {
        let bin = '';
        for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
        return btoa(bin).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
    }
    function textEnc(s) { return new TextEncoder().encode(s); }
    function base64ToBytes(b64like) {
        const b64 = (b64like || '').replace(/-/g, '+').replace(/_/g, '/');
        const pad = b64.length % 4 ? '='.repeat(4 - (b64.length % 4)) : '';
        const bin = atob(b64 + pad);
        return Uint8Array.from(bin, c => c.charCodeAt(0));
    }

    async function pbkdf2(password, saltB64Like, iterations = 150000) {
        const salt = base64ToBytes(saltB64Like);
        const keyMat = await crypto.subtle.importKey('raw', textEnc(password), 'PBKDF2', false, ['deriveBits']);
        const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, keyMat, 256);
        return b64url(new Uint8Array(bits)); // base64url
    }

    function getLocalUsers() {
        try { return JSON.parse(localStorage.getItem(USERS_KEY) || '[]'); } catch { return []; }
    }
    function setLocalUsers(u) { localStorage.setItem(USERS_KEY, JSON.stringify(u)); }

    // Selalu coba /users.json dulu (aman utk PWA/route), pakai cache-buster agar tidak ketipu SW/HTTP cache
    async function loadFileUsers() {
        const bust = Date.now();
        const tryUrls = [`/users.json?v=${bust}`, `./users.json?v=${bust}`];
        for (const url of tryUrls) {
            try {
                const res = await fetch(url, { cache: 'no-store' });
                if (res.ok) {
                    const data = await res.json();
                    if (Array.isArray(data)) return data;
                }
            } catch { /* lanjut url berikut */ }
        }
        return [];
    }

    function setSession(obj) { sessionStorage.setItem(SESSION_KEY, JSON.stringify(obj)); }
    function getSession() { try { return JSON.parse(sessionStorage.getItem(SESSION_KEY)); } catch { return null; } }
    const normId = s => (s || '').trim().toUpperCase();

    // === LOGIN: merge users.json + localStorage (lokal override jika ID sama) ===
    async function login(id, password) {
        if (!id || !password) return false;

        const file = await loadFileUsers();   // dari users.json
        const local = getLocalUsers();         // dari localStorage

        const byId = new Map();
        for (const u of (Array.isArray(file) ? file : [])) byId.set(normId(u.id), u);
        for (const u of (Array.isArray(local) ? local : [])) byId.set(normId(u.id), u); // lokal override

        const u = byId.get(normId(id));
        if (!u || !u.salt || !u.hash) return false;

        const iterations = Number(u.it ?? u.iterations ?? 150000);
        const hash = await pbkdf2(password, u.salt, iterations);
        if (hash !== u.hash) return false;

        setSession({ id: u.id, role: u.role });
        return true;
    }

    // Tambah user lokal tetap ada
    async function addLocalUser(id, password, role = 'scanner') {
        if (!id || !password) throw new Error('ID & password wajib.');
        const users = getLocalUsers();
        if (users.find(u => normId(u.id) === normId(id)))
            throw new Error('ID sudah ada di lokal.');
        const saltBytes = new Uint8Array(16); crypto.getRandomValues(saltBytes);
        const salt = b64url(saltBytes);
        const hash = await pbkdf2(password, salt, 150000);
        users.push({ id, role, salt, hash, it: 150000, alg: 'PBKDF2-SHA256' });
        setLocalUsers(users);
        return true;
    }

    return { login, addLocalUser, getSession };
})();

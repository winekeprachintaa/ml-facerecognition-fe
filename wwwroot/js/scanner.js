// ================== CONFIG  ==================
window.QR_CFG = window.QR_CFG || {};

// ===== Engine Face Detection =====
const ENGINE = 'faceapi'; // 'faceapi' | 'onnx' | 'none'
const FACEAPI_MODELS_URL = './models';     // folder model face-api
const MODEL_URL = 'models/best.onnx';      // jika nanti pakai onnx

// Sembunyikan warning kernel duplikat TensorFlow.js
const _warn = console.warn;
console.warn = function (...args) {
    if (typeof args[0] === 'string' && args[0].includes("kernel") && args[0].includes("already registered")) return;
    _warn.apply(console, args);
};

// State face-api
let _noDetectSince = 0;   // timestamp ms ketika mulai tidak ada deteksi
let faReady = false;
let faOpts = null;             // TinyFaceDetectorOptions
let faBusy = false;
let fdRunningEvery = 6;        // jalankan deteksi tiap N frame
let _fdFrame = 0;

window.QR_CFG.PUBLIC_KEY_PEM = window.QR_CFG.PUBLIC_KEY_PEM || `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEST+CuutOqfMDM3w3uB3ewzrmgHFj
fzTShYZBlcbR1Z6qdpC8l3IiYVW+RmSsHaq8S7zdBSzDT5JTUuNgBtMTOA==
-----END PUBLIC KEY-----`;
if (typeof window.QR_CFG.ENFORCE_ID_MATCH === 'undefined') {
    window.QR_CFG.ENFORCE_ID_MATCH = false; // cocokkan id QR dengan user login (kecuali admin)
}

(function () {
    'use strict';

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

    function init() {
        const video = document.getElementById('video');
        const canvas = document.getElementById('qrCanvas');
        const faceCanvas = document.getElementById('faceCanvas');
        // context dibuat let karena nanti akan di-assign ulang setelah sync DPR
        let ctx = canvas.getContext('2d', { willReadFrequently: true });
        let fctx = faceCanvas.getContext('2d');
        const startBtn = document.getElementById('startCamBtn');
        const stopBtn = document.getElementById('stopCamBtn');
        const uploadBtn = document.getElementById('uploadBtn');
        const fileInput = document.getElementById('fileInput');
        const resultText = document.getElementById('resultText');
        const parsedJson = document.getElementById('parsedJson');

        const SESSION = window.Auth?.getSession?.() || null;
        if (SESSION?.role === 'admin' || SESSION?.role === 'scanner') window.QR_CFG.ENFORCE_ID_MATCH = false;
        let stream = null, rafId = null, scanning = false;
        const enc = new TextEncoder();

        // ====== Popup + cooldown scan ======
        const AUTO_CLOSE_MS = 2400;
        let scanBlockedUntil = 0;

        const pop = document.getElementById('scan-pop');
        const ttl = document.getElementById('scan-pop-title');
        const text = document.getElementById('scan-pop-text');
        const okBtn = document.getElementById('scan-pop-ok');

        function showResultModal(isValid, heading, msgText) {
            // status & isi
            pop.classList.remove('valid', 'invalid', 'hidden', 'show');
            pop.classList.add(isValid ? 'valid' : 'invalid');
            ttl.textContent = heading ?? (isValid ? 'VALID' : 'INVALID!');
            text.textContent = msgText ?? '';

            // mainkan bunyi (opsional)
            const s = isValid ? okS : ngS;
            if (s && typeof s.play === 'function') s.play().catch(() => { });

            // tampilkan & blok scanning sementara
            pop.classList.add('show');
            scanBlockedUntil = Date.now() + AUTO_CLOSE_MS;

            const close = () => {
                pop.classList.remove('show');
                setTimeout(() => pop.classList.add('hidden'), 160);
            };

            const t = setTimeout(close, AUTO_CLOSE_MS);
            okBtn?.addEventListener('click', () => { clearTimeout(t); close(); }, { once: true });
        }

        const setStatus = (t, cls) => {
            resultText.textContent = t;
            resultText.className = 'small' + (cls ? ' ' + cls : '');
        };
        const sleep = (ms) => new Promise(r => setTimeout(r, ms));

        function b64urlToBytes(b64u) {
            const b64 = (b64u || '').replace(/-/g, '+').replace(/_/g, '/');
            const pad = b64.length % 4 ? '='.repeat(4 - (b64.length % 4)) : '';
            const bin = atob(b64 + pad);
            const out = new Uint8Array(bin.length);
            for (let i = 0; i < out.length; i++) out[i] = bin.charCodeAt(i);
            return out;
        }
        function b64ToBytes(b64) {
            const bin = atob(b64);
            const out = new Uint8Array(bin.length);
            for (let i = 0; i < out.length; i++) out[i] = bin.charCodeAt(i);
            return out;
        }
        function pemToBuf(pem) {
            const b64 = pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
            return b64ToBytes(b64).buffer;
        }
        async function importSpki(pem) {
            return crypto.subtle.importKey('spki', pemToBuf(pem),
                { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
        }
        function rawSigToDer(raw) {
            if (!(raw instanceof Uint8Array) || raw.length !== 64) throw new Error('RAW harus 64B');
            const r = raw.slice(0, 32), s = raw.slice(32);
            const trim = x => { let i = 0; while (i < x.length - 1 && x[i] === 0) i++; return x.slice(i); };
            const intDer = x => {
                let v = trim(x);
                if (v[0] & 0x80) { const z = new Uint8Array(v.length + 1); z[0] = 0; z.set(v, 1); v = z; }
                const out = new Uint8Array(2 + v.length); out[0] = 0x02; out[1] = v.length; out.set(v, 2); return out;
            };
            const rDer = intDer(r), sDer = intDer(s), len = rDer.length + sDer.length;
            const seq = new Uint8Array(2 + len); seq[0] = 0x30; seq[1] = len; seq.set(rDer, 2); seq.set(sDer, 2 + rDer.length);
            return seq;
        }
        function normalizeToJson(text) {
            const s = (text || '').trim();
            if (!s) return s;
            if (s.startsWith('{')) return s;
            const p = s.split('|');
            if (p.length >= 3) {
                const [id, date, ...rest] = p; const token = rest.join('|');
                return JSON.stringify({ id, date, token });
            }
            return s;
        }
        function buildSigCandidates(token) {
            const out = [];
            try { out.push(b64urlToBytes(token)); } catch { }
            try { out.push(b64ToBytes(token)); } catch { }
            try {
                const raw = b64urlToBytes(token);
                if (raw.length === 64) {
                    out.push(rawSigToDer(raw));
                    const swap = new Uint8Array(64); swap.set(raw.slice(32), 0); swap.set(raw.slice(0, 32), 32);
                    out.push(rawSigToDer(swap));
                }
            } catch { }
            const uniq = [], seen = new Set();
            for (const u8 of out) {
                if (!(u8 instanceof Uint8Array)) continue;
                const key = `${u8.length}:${u8[0]}`;
                if (!seen.has(key)) { uniq.push(u8); seen.add(key); }
            }
            return uniq;
        }
        async function verifySignature(obj) {
            const pem = (window.QR_CFG && window.QR_CFG.PUBLIC_KEY_PEM) || '';
            if (!pem || !obj || !obj.token) return null;
            const pub = await importSpki(pem);
            const canon = x => String(x ?? '').trim();
            const msgBytes = enc.encode(`${canon(obj.id)}|${canon(obj.date)}`);
            const candidates = buildSigCandidates(obj.token);
            for (const sig of candidates) {
                try {
                    const ok = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, pub, sig, msgBytes);
                    if (ok) { obj._verified_with = `DER(len=${sig.length})`; return true; }
                } catch { }
            }
            return false;
        }
        function todayISO() {
            const d = new Date(), pad = n => String(n).padStart(2, '0');
            return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
        }
        function validateRules(obj) {
            const reasons = [], canon = x => String(x ?? '').trim();
            const qrId = canon(obj.id), qrDate = canon(obj.date);

            if (!qrId || !/^[A-Za-z0-9._-]{3,}$/.test(qrId)) reasons.push('ID tidak valid / kosong.');
            if (!/^\d{4}-\d{2}-\d{2}$/.test(qrDate)) reasons.push('Format tanggal harus YYYY-MM-DD.');
            else if (qrDate !== todayISO()) reasons.push('Tanggal bukan hari ini (token harian).');

            // ❌ tidak ada cek kecocokan dengan SESSION.id
            return { ok: reasons.length === 0, reasons };
        }

        async function handleDecodedText(decodedText) {
            try {
                const normalized = normalizeToJson(decodedText);
                if (!normalized || normalized[0] !== '{') {
                    setStatus('QR bukan JSON.', 'invalid');
                    parsedJson.textContent = decodedText || '';
                    return;
                }

                let obj;
                try {
                    obj = JSON.parse(normalized);
                } catch {
                    setStatus('QR JSON tidak valid.', 'invalid');
                    parsedJson.textContent = normalized;
                    return;
                }

                // 1) aturan bisnis
                const rules = validateRules(obj);

                // 2) verifikasi kripto
                const vcrypto = await verifySignature(obj);

                // 3) Keputusan
                let label = '';
                let cls = 'invalid';

                if (vcrypto === null) {
                    label = 'QR terbaca — verifikasi dimatikan (PUBLIC_KEY kosong).';
                } else if (vcrypto !== true) {
                    label = 'QR Izin Kerja Tidak Valid — Signature INVALID.';
                } else if (!rules.ok) {
                    label = 'QR Izin Kerja Tidak Valid — Data Tidak Sesuai Aturan.';
                    if (rules.reasons?.length) label += ` ${rules.reasons[0]}`;
                } else {
                    label = 'QR Izin Kerja Valid.';
                    cls = 'valid';
                }
                setStatus(label, cls);

                // popup
                const isValid = (cls === 'valid');
                showResultModal(isValid, isValid ? 'VALID' : 'INVALID!');

                // debug ringkas
                if (obj?.id && obj?.date) {
                    console.debug('[QR]', `${obj.id}|${obj.date}`, '→', obj._verified_with || '(unverified)');
                }
            } catch (e) {
                console.error(e);
                setStatus('Terjadi kesalahan saat memproses QR.', 'invalid');
            }
        }

        // ===== Helpers sinkron DPR
        function syncCanvas(cnv, cssW, cssH) {
            const dpr = window.devicePixelRatio || 1;
            cnv.style.width = cssW + 'px';
            cnv.style.height = cssH + 'px';
            const needW = Math.round(cssW * dpr);
            const needH = Math.round(cssH * dpr);
            if (cnv.width !== needW || cnv.height !== needH) {
                cnv.width = needW; cnv.height = needH;
            }
            const c = cnv.getContext('2d', { willReadFrequently: cnv === canvas });
            c.setTransform(dpr, 0, 0, dpr, 0, 0);
            return c;
        }

        // ===== Face-api init
        async function initFaceApi() {
            if (faReady) return;

            await faceapi.nets.tinyFaceDetector.loadFromUri(FACEAPI_MODELS_URL);

            const t = faceapi.tf || window.tf;
            if (!t) throw new Error('TensorFlowJS tidak ditemukan');

            // deteksi perangkat mobile sederhana
            const ua = navigator.userAgent.toLowerCase();
            const isMobile = /iphone|ipad|ipod|android/.test(ua);

            // urutan backend (mobile cenderung WASM dulu)
            const order = isMobile ? ['wasm', 'webgl', 'cpu'] : ['webgl', 'wasm', 'cpu'];

            let picked = null;
            for (const b of order) {
                try {
                    await t.setBackend(b);
                    await t.ready();
                    picked = t.getBackend?.() || b;
                    break;
                } catch (_) { /* coba berikutnya */ }
            }
            console.log('[faceapi] backend =', picked);

            faOpts = new faceapi.TinyFaceDetectorOptions({
                inputSize: isMobile ? 224 : 320,   // lebih ringan di HP
                scoreThreshold: 0.5
            });

            faReady = true;
        }


        // ===== Camera
        async function startCamera() {
            try {
                if (!navigator.mediaDevices?.getUserMedia) throw new Error('getUserMedia tidak didukung');

                // gunakan var luar (supaya stop bisa menghentikan)
                stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' } });
                video.srcObject = stream;

                await new Promise(res => {
                    if (video.readyState >= 1) res();
                    else video.addEventListener('loadedmetadata', () => res(), { once: true });
                });
                await video.play();

                // load engine di background
                if (ENGINE === 'faceapi') initFaceApi().catch(e => console.warn('init faceapi err', e));
                if (ENGINE === 'onnx') initFaceModel?.().catch?.(e => console.warn('init onnx err', e));

                startBtn.disabled = true;
                stopBtn.disabled = false;
                scanning = true;
                scanLoop();
            } catch (e) {
                console.error(e);
                alert('Gagal akses kamera: ' + (e.message || e));
            }
        }
        function stopCamera() {
            scanning = false; if (rafId) cancelAnimationFrame(rafId);
            if (stream) { stream.getTracks().forEach(t => t.stop()); stream = null; }
            startBtn.disabled = false; stopBtn.disabled = true;
            fctx.clearRect(0, 0, faceCanvas.width, faceCanvas.height);
        }

        async function scanLoop() {
            if (!scanning) return;
            try {
                if (video.readyState >= 2) {
                    const w = video.videoWidth, h = video.videoHeight;
                    if (w && h) {
                        // sinkron DPR + ctx terbaru
                        ctx = syncCanvas(canvas, w, h);
                        fctx = syncCanvas(faceCanvas, w, h);

                        // gambar frame video ke qrCanvas
                        ctx.drawImage(video, 0, 0, w, h);

                        // ========= FACE DETECTION =========
                        _fdFrame = (_fdFrame + 1) | 0;

                        if (ENGINE === 'faceapi' && faReady && !faBusy && (_fdFrame % fdRunningEvery === 0)) {
                            faBusy = true;
                            try {
                                const detections = await faceapi.detectAllFaces(video, faOpts); // array of {box:{x,y,width,height}, score}

                                const t = faceapi.tf || window.tf;
                                const count = detections?.length || 0;

                                // watchdog: jika 0 deteksi selama > 3 detik dan backend bukan 'wasm' → pindah ke wasm
                                const nowTs = performance.now();
                                if (count === 0) {
                                    if (!_noDetectSince) _noDetectSince = nowTs;
                                    if (nowTs - _noDetectSince > 3000 && t?.getBackend?.() !== 'wasm') {
                                        try { await t.setBackend('wasm'); await t.ready(); console.log('[faceapi] switched → wasm'); }
                                        catch { }
                                        _noDetectSince = 0; // reset
                                    }
                                } else {
                                    _noDetectSince = 0;
                                }

                                // Konversi ke format boxes {x1,y1,x2,y2,conf}
                                const boxes = (detections || []).map(d => ({
                                    x1: d.box.x,
                                    y1: d.box.y,
                                    x2: d.box.x + d.box.width,
                                    y2: d.box.y + d.box.height,
                                    conf: d.score ?? 0
                                }));

                                // Gambar kotak (STROKE saja; TANPA fill)
                                drawFaces(fctx, boxes);

                                // === Kirim 1 crop terbaik ke API (throttle) ===
                                const bestWithLabel = await maybeSendTopFace(canvas, boxes);
                                if (bestWithLabel && bestWithLabel.label) {
                                    lastApiLabel = String(bestWithLabel.label || 'Unknown');
                                    lastApiExpire = performance.now() + 5000;
                                    // gambar ulang dengan label pada kotak terbaik
                                    drawFaces(fctx, boxes.map(b => b === bestWithLabel ? bestWithLabel : b));
                                }
                            } catch (e) {
                                console.warn('face-api detect error:', e);
                            } finally {
                                faBusy = false;
                            }
                        }
                        // ========= END FACE DETECTION =========

                        // ===== QR decode dari buffer aktual (hi-DPI friendly)
                        const qrW = canvas.width, qrH = canvas.height; // buffer size
                        const img = ctx.getImageData(0, 0, qrW, qrH);
                        const code = window.jsQR ? jsQR(img.data, qrW, qrH) : null;
                        if (Date.now() >= scanBlockedUntil && code && code.data) {
                            await handleDecodedText(code.data);
                        }
                    }
                }
            } catch (e) {
                console.warn('scanLoop error:', e);
            } finally {
                rafId = requestAnimationFrame(scanLoop);
            }
        }

        function chooseFile() { fileInput.click(); }
        function readFileAsImage(file) {
            return new Promise((resolve, reject) => {
                const img = new Image(); img.onload = () => resolve(img); img.onerror = reject;
                const fr = new FileReader(); fr.onload = () => { img.src = fr.result; }; fr.onerror = reject; fr.readAsDataURL(file);
            });
        }
        async function handleFile(file) {
            try {
                const img = await readFileAsImage(file);
                const w = img.naturalWidth, h = img.naturalHeight;
                canvas.width = w; canvas.height = h; canvas.style.display = 'none';
                ctx.drawImage(img, 0, 0, w, h);
                const data = ctx.getImageData(0, 0, w, h);
                const code = window.jsQR ? jsQR(data.data, w, h) : null;
                if (code && code.data) { await handleDecodedText(code.data); }
                else setStatus('QR tidak terdeteksi pada gambar.', 'invalid');
            } catch (e) { console.error(e); setStatus('Gagal membaca gambar.', 'invalid'); }
        }

        startBtn.addEventListener('click', startCamera);
        stopBtn.addEventListener('click', stopCamera);
        uploadBtn.addEventListener('click', chooseFile);
        fileInput.addEventListener('change', e => { const f = e.target.files && e.target.files[0]; if (f) handleFile(f); });
        window.addEventListener('pagehide', stopCamera);
    }

    // ===== API Face Classification (konfigurasi) =====
    // --- state pengen warna garis ---
    let recogBusy = false;               // true saat masih kirim/menunggu API
    let lastApiLabel = "";               // label terakhir dari API (mis. "Abdullah" / "Unknown")
    let lastApiExpire = 0;               // sampai kapan label ditampilkan (ms)
    const API_BASE = 'https://192.168.100.181:8080';   // ganti ke https:// jika web kamu https
    const API_ROUTE = '/api/v1/recognition/check';     // contoh endpoint; sesuaikan dg API kamu
    const API_TYPE = 'multipart';                     // 'multipart' | 'base64'
    const API_FIELD = 'file';                          // nama field file utk multipart
    const API_MIN_INTERVAL_MS = 900;                  // throttle panggilan API
    let apiBusy = false, apiLastTs = 0;
    const FACE_BOX_SCALE = 1.25;   // 1.0 = asli, 1.25 = diperbesar 25%
    const FACE_BOX_PAD = 14;     // padding tetap (px CSS) tiap sisi
    const FACE_BOX_KEEP_SQUARE = false; // true kalau mau persegi



    // ====== Face Detect (ONNX) ======
    let fdSession = null;
    let fdInputSize = 640;
    let fdRunningEveryOnnx = 6; // (biarkan beda nama agar tidak bentrok)
    let _fdFrameOnnx = 0, fdBusyOnnx = false;

    async function initFaceModel() {
        if (fdSession) return;
        console.time('onnx-load');
        fdSession = await ort.InferenceSession.create(MODEL_URL, {
            executionProviders: ['wasm'],
            graphOptimizationLevel: 'all'
        });
        console.timeEnd('onnx-load');
        console.log('ONNX inputs:', fdSession.inputNames, 'outputs:', fdSession.outputNames);

        const dummy = new ort.Tensor('float32', new Float32Array(fdInputSize * fdInputSize * 3), [1, 3, fdInputSize, fdInputSize]);
        try {
            const feeds = {};
            feeds[fdSession.inputNames?.[0] ?? 'images'] = dummy;
            await fdSession.run(feeds);
        } catch { }
    }

    function letterbox(srcCanvas, size) {
        const s = size, ctx2 = document.createElement('canvas').getContext('2d');
        ctx2.canvas.width = s; ctx2.canvas.height = s;
        const iw = srcCanvas.width, ih = srcCanvas.height;
        const r = Math.min(s / iw, s / ih);
        const nw = Math.round(iw * r), nh = Math.round(ih * r);
        const dx = Math.floor((s - nw) / 2), dy = Math.floor((s - nh) / 2);
        ctx2.fillStyle = '#000'; ctx2.fillRect(0, 0, s, s);
        ctx2.drawImage(srcCanvas, 0, 0, iw, ih, dx, dy, nw, nh);
        return { canvas: ctx2.canvas, r, dx, dy, size: s };
    }

    function toTensorCHW(canvas) {
        const { width: w, height: h } = canvas;
        const data = canvas.getContext('2d').getImageData(0, 0, w, h).data;
        const float = new Float32Array(3 * w * h);
        let i = 0, p = 0;
        for (let y = 0; y < h; y++) {
            for (let x = 0; x < w; x++, i += 4, p++) {
                const r = data[i] / 255, g = data[i + 1] / 255, b = data[i + 2] / 255;
                float[p] = r;
                float[p + w * h] = g;
                float[p + 2 * w * h] = b;
            }
        }
        return new ort.Tensor('float32', float, [1, 3, h, w]);
    }

    let _loggedDims = false;
    function postprocessGeneric(tensor, meta) {
        const dims = tensor.dims;
        if (!_loggedDims) { console.log('ONNX output dims:', dims); _loggedDims = true; }

        const D = dims, data = tensor.data;
        const TH = 0.25, S = meta.size || 640;
        const boxes = [];

        // ===== Layout A: [1, N, 6] => [x1, y1, x2, y2, conf, cls] =====
        if (D.length === 3 && D[0] === 1 && D[2] === 6) {
            const N = D[1], C = D[2];
            for (let i = 0; i < N; i++) {
                const off = i * C;
                let x1l = data[off + 0], y1l = data[off + 1];
                let x2l = data[off + 2], y2l = data[off + 3];
                let conf = data[off + 4];

                if (!Number.isFinite(conf) || conf < 0.25) continue;

                const S = meta.size || 640;
                const maybeNorm =
                    Math.max(Math.abs(x1l), Math.abs(y1l), Math.abs(x2l), Math.abs(y2l)) <= 1.5;
                if (maybeNorm) {
                    x1l *= S; y1l *= S; x2l *= S; y2l *= S;
                }

                if (x2l < x1l) [x1l, x2l] = [x2l, x1l];
                if (y2l < y1l) [y1l, y2l] = [y2l, y1l];

                const { r, dx, dy, srcW, srcH } = meta;
                let x1 = (x1l - dx) / r, y1 = (y1l - dy) / r;
                let x2 = (x2l - dx) / r, y2 = (y2l - dy) / r;

                x1 = Math.max(0, Math.min(srcW, x1));
                y1 = Math.max(0, Math.min(srcH, y1));
                x2 = Math.max(0, Math.min(srcW, x2));
                y2 = Math.max(0, Math.min(srcH, y2));
                if ((x2 - x1) < 2 || (y2 - y1) < 2) continue;

                boxes.push({ x1, y1, x2, y2, conf });
            }
            const kept = nms(boxes, 0.45);
            if ((window.__dbg_cnt = (window.__dbg_cnt || 0) + 1) % 15 === 0) {
                if (kept[0]) console.log('dbg box:', kept[0]);
            }
            return kept;
        }

        // Layout B: [1, C, N] / [1, N, C]
        const isCN = (D.length === 3 && D[0] === 1 && D[1] > 6);
        const isNC = (D.length === 3 && D[0] === 1 && D[2] > 6);
        if (isCN || isNC) {
            const C = isCN ? D[1] : D[2];
            const N = isCN ? D[2] : D[1];
            for (let i = 0; i < N; i++) {
                const off = isCN ? i : i * C;
                const get = (k) => isCN ? data[k * N + i] : data[off + k];

                let cx = get(0), cy = get(1), w = get(2), h = get(3);
                let conf = get(4);
                let maxCls = 0; for (let k = 5; k < C; k++) if (get(k) > maxCls) maxCls = get(k);
                conf = Math.max(conf, maxCls);
                if (!Number.isFinite(conf) || conf < TH) continue;

                const maybeNorm = Math.max(Math.abs(cx), Math.abs(cy), Math.abs(w), Math.abs(h)) <= 1.5;
                if (maybeNorm) { cx *= S; cy *= S; w *= S; h *= S; }

                const x1l = cx - w / 2, y1l = cy - h / 2, x2l = cx + w / 2, y2l = cy + h / 2;
                const { r, dx, dy, srcW, srcH } = meta;
                let x1 = (x1l - dx) / r, y1 = (y1l - dy) / r;
                let x2 = (x2l - dx) / r, y2 = (y2l - dy) / r;

                let lx1 = Math.max(0, Math.min(srcW, Math.min(x1, x2)));
                let lx2 = Math.max(0, Math.min(srcW, Math.max(x1, x2)));
                let ly1 = Math.max(0, Math.min(srcH, Math.min(y1, y2)));
                let ly2 = Math.max(0, Math.min(srcH, Math.max(y1, y2)));
                if ((lx2 - lx1) < 2 || (ly2 - ly1) < 2) continue;
                boxes.push({ x1: lx1, y1: ly1, x2: lx2, y2: ly2, conf });
            }
            return nms(boxes, 0.45);
        }

        console.warn('Unknown output layout:', dims);
        return [];
    }

    function nms(boxes, iouThresh = 0.45) {
        boxes.sort((a, b) => b.conf - a.conf);
        const keep = [];
        const iou = (a, b) => {
            const x1 = Math.max(a.x1, b.x1), y1 = Math.max(a.y1, b.y1);
            const x2 = Math.min(a.x2, b.x2), y2 = Math.min(a.y2, b.y2);
            const inter = Math.max(0, x2 - x1) * Math.max(0, y2 - y1);
            const areaA = (a.x2 - a.x1) * (a.y2 - a.y1);
            const areaB = (b.x2 - b.x1) * (b.y2 - b.y1);
            return inter / (areaA + areaB - inter + 1e-6);
        };
        while (boxes.length) {
            const a = boxes.shift();
            keep.push(a);
            boxes = boxes.filter(b => iou(a, b) < iouThresh);
        }
        return keep;
    }

    function drawFaces(fctx, boxes) {
        fctx.clearRect(0, 0, fctx.canvas.width, fctx.canvas.height);
        if (!boxes || !boxes.length) return;

        const now = performance.now();
        const stroke = recogBusy ? '#3b82f6' : '#22c55e';

        // ukuran CSS (bukan buffer); koordinat bbox kita selama ini di CSS px
        const dpr = window.devicePixelRatio || 1;
        const cssW = (fctx.canvas.width / dpr);
        const cssH = (fctx.canvas.height / dpr);

        fctx.save();
        fctx.lineWidth = 4;
        fctx.strokeStyle = stroke;
        if (recogBusy) fctx.setLineDash([8, 8]); else fctx.setLineDash([]);

        for (const b of boxes) {
            // ==== PERBESAR DI TEMPAT (tanpa helper) ====
            let x1 = Math.min(b.x1, b.x2), y1 = Math.min(b.y1, b.y2);
            let x2 = Math.max(b.x1, b.x2), y2 = Math.max(b.y1, b.y2);
            let w = Math.max(1, x2 - x1), h = Math.max(1, y2 - y1);
            const cx = x1 + w / 2, cy = y1 + h / 2;

            // skala & padding
            let newW = w * FACE_BOX_SCALE + 2 * FACE_BOX_PAD;
            let newH = h * FACE_BOX_SCALE + 2 * FACE_BOX_PAD;
            if (FACE_BOX_KEEP_SQUARE) { const s = Math.max(newW, newH); newW = newH = s; }

            // pusat tetap, clamp ke batas layar (CSS)
            x1 = Math.max(0, Math.min(cssW, cx - newW / 2));
            y1 = Math.max(0, Math.min(cssH, cy - newH / 2));
            x2 = Math.max(0, Math.min(cssW, cx + newW / 2));
            y2 = Math.max(0, Math.min(cssH, cy + newH / 2));

            // gambar stroke
            const x = x1, y = y1, W = Math.max(1, x2 - x1), H = Math.max(1, y2 - y1);
            fctx.strokeRect(x, y, W, H);

            const labelToShow = b.label || ((now < lastApiExpire && lastApiLabel) ? lastApiLabel : '');
            if (labelToShow) drawLabel(fctx, x, y, labelToShow);

            // optional: simpan koordinat hasil expand agar konsisten dipakai tempat lain (tidak wajib)
            b._ex_x1 = x1; b._ex_y1 = y1; b._ex_x2 = x2; b._ex_y2 = y2;
        }

        fctx.restore();
    }


    // Badge label sederhana (background gelap, teks putih)
    function drawLabel(ctx, x, y, text) {
        ctx.save();
        ctx.font = '600 16px system-ui, Arial';
        const padX = 8, padY = 6;
        const metrics = ctx.measureText(text);
        const w = Math.ceil(metrics.width) + padX * 2;
        const h = 22 + (padY - 6);
        const bx = x, by = Math.max(0, y - h - 8);

        ctx.fillStyle = 'rgba(17, 24, 39, .9)';  // #111827 semi
        ctx.strokeStyle = 'rgba(255,255,255,.25)';
        ctx.lineWidth = 1.5;
        ctx.beginPath();
        if (ctx.roundRect) ctx.roundRect(bx, by, w, h, 6); else ctx.rect(bx, by, w, h);
        ctx.fill();
        ctx.stroke();

        ctx.fillStyle = '#fff';
        ctx.fillText(text, bx + padX, by + h - padY);
        ctx.restore();
    }

    // ======================[ PERBAIKAN CROP ]======================

    // Konversi & clamp koordinat bbox (CSS pixels) -> buffer pixels.
    function clampRoundBox(b, bufW, bufH, sx = 1, sy = 1, mirrored = false) {
        // b: {x1,y1,x2,y2} pada ruang CSS pixel (yang sama untuk overlay)
        let x1 = Math.min(b.x1, b.x2) * sx;
        let y1 = Math.min(b.y1, b.y2) * sy;
        let x2 = Math.max(b.x1, b.x2) * sx;
        let y2 = Math.max(b.y1, b.y2) * sy;

        // clamp ke buffer
        x1 = Math.max(0, Math.min(bufW, x1));
        y1 = Math.max(0, Math.min(bufH, y1));
        x2 = Math.max(0, Math.min(bufW, x2));
        y2 = Math.max(0, Math.min(bufH, y2));

        let w = Math.max(1, Math.round(x2 - x1));
        let h = Math.max(1, Math.round(y2 - y1));
        let x = Math.round(x1), y = Math.round(y1);

        // Jika sumber video dimirror secara visual (CSS transform: scaleX(-1))
        if (mirrored) x = (bufW - x) - w;

        return { x, y, w, h };
    }

    // Crop dari frame-canvas -> Blob, dengan konversi CSS→buffer otomatis
    function cropFaceToBlob(srcCanvas, box, type = 'image/jpeg', quality = 0.9, mirrored = false) {
        // Hitung skala antara CSS pixel & buffer pixel
        // style.width/height ada dalam "px", contoh "1280px"
        const cssW = parseFloat(srcCanvas.style.width) || srcCanvas.width;
        const cssH = parseFloat(srcCanvas.style.height) || srcCanvas.height;
        const bufW = srcCanvas.width;
        const bufH = srcCanvas.height;
        const scaleX = bufW / cssW;
        const scaleY = bufH / cssH;

        const { x, y, w, h } = clampRoundBox(box, bufW, bufH, scaleX, scaleY, mirrored);

        // OffscreenCanvas jika ada (lebih cepat), fallback <canvas>
        const tmp = (typeof OffscreenCanvas !== 'undefined')
            ? new OffscreenCanvas(w, h)
            : Object.assign(document.createElement('canvas'), { width: w, height: h });

        const c2 = tmp.getContext('2d');
        c2.drawImage(srcCanvas, x, y, w, h, 0, 0, w, h);

        if (tmp.convertToBlob) return tmp.convertToBlob({ type, quality });
        return new Promise(resolve => tmp.toBlob(resolve, type, quality));
    }

    // =============================================================

    function downloadBlob(blob, filename = 'download.jpg') {
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;            // nama file lokal
        document.body.appendChild(a);     // Safari iOS kadang perlu di-DOM
        a.click();
        a.remove();
        URL.revokeObjectURL(url);         // bersih-bersih
    }

    async function callApiWithBlob(blob) {
        // gunakan proxy/URL milikmu
        downloadBlob(blob, 'face.jpg'); // untuk debugging, bisa dihapus
        const url = '/proxy/api/v1/recognition/check';
        const fd = new FormData();
        fd.append('file', blob, 'face.jpg');

        recogBusy = true;
        try {
            const res = await fetch(url, { method: 'POST', body: fd, cache: 'no-store' });
            if (!res.ok) throw new Error('API fail ' + res.status);
            const json = await res.json();
            return json;
        } finally {
            recogBusy = false;
        }
    }

    function parseApiLabel(json) {
        const label =
            json?.data?.entity?.label ??
            json?.data?.label ??
            json?.label ??
            'Unknown';

        let score;
        const d = json?.data?.distance;
        if (typeof d === 'number' && isFinite(d)) score = Math.max(0, Math.min(1, 1 / (1 + d)));
        return { label, score };
    }

    async function maybeSendTopFace(canvasForCrop, boxes) {
        const now = Date.now();
        if (apiBusy || now - apiLastTs < API_MIN_INTERVAL_MS) return null;
        if (!boxes || !boxes.length) return null;

        const best = boxes.reduce((a, b) => (a.conf > b.conf ? a : b));

        try {
            apiBusy = true; apiLastTs = now;

            // ==== PERBESAR DI TEMPAT (inline) ====
            const dpr = window.devicePixelRatio || 1;
            const cssW = (canvasForCrop.width / dpr);
            const cssH = (canvasForCrop.height / dpr);

            let x1 = Math.min(best.x1, best.x2), y1 = Math.min(best.y1, best.y2);
            let x2 = Math.max(best.x1, best.x2), y2 = Math.max(best.y1, best.y2);
            let w = Math.max(1, x2 - x1), h = Math.max(1, y2 - y1);
            const cx = x1 + w / 2, cy = y1 + h / 2;

            let newW = w * FACE_BOX_SCALE + 2 * FACE_BOX_PAD;
            let newH = h * FACE_BOX_SCALE + 2 * FACE_BOX_PAD;
            if (FACE_BOX_KEEP_SQUARE) { const s = Math.max(newW, newH); newW = newH = s; }

            x1 = Math.max(0, Math.min(cssW, cx - newW / 2));
            y1 = Math.max(0, Math.min(cssH, cy - newH / 2));
            x2 = Math.max(0, Math.min(cssW, cx + newW / 2));
            y2 = Math.max(0, Math.min(cssH, cy + newH / 2));

            const expanded = { x1, y1, x2, y2, conf: best.conf, label: best.label };

            // crop pakai koordinat yg sudah diperbesar (cropFaceToBlob tetap)
            const blob = await cropFaceToBlob(canvasForCrop, expanded);

            const json = await callApiWithBlob(blob);
            const { label } = parseApiLabel(json);
            lastApiLabel = String(label || 'Unknown');
            lastApiExpire = performance.now() + 5000;

            expanded.label = lastApiLabel;   // supaya drawFaces bisa tampilkan label spesifik
            return expanded;
        } catch (e) {
            console.warn('API error:', e);
            lastApiLabel = 'Unknown';
            lastApiExpire = performance.now() + 3000;
            return null;
        } finally {
            apiBusy = false;
        }
    }


})();

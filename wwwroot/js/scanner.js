// ================== CONFIG  ==================
window.QR_CFG = window.QR_CFG || {};
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

            // mainkan bunyi (jika ada), tapi JANGAN pakai `catch {}` (keyword)
            const s = isValid ? okS : ngS;
            if (s && typeof s.play === 'function') {
                // play() mengembalikan Promise; aman ditangani .catch(() => {})
                s.play().catch(() => { });
            }

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

                // 1) aturan bisnis (cek format, tanggal hari ini, ENFORCE_ID_MATCH, dll.)
                const rules = validateRules(obj);

                // 2) verifikasi kriptografi (true | false | null jika PUBLIC_KEY kosong)
                const vcrypto = await verifySignature(obj);

                // 3) Keputusan & pesan:
                //    -> INVALID jika SALAH SATU gagal (signature ATAU rules)
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

                // TAMPILKAN MODAL + auto scan ulang (tanpa refresh)
                const isValid = (cls === 'valid');
                showResultModal(isValid, isValid ? 'VALID' : 'INVALID!');

                // 4) tampilkan JSON + alasan aturan (jika ada)
                //parsedJson.textContent = JSON.stringify(
                //    rules.ok ? obj : { ...obj, _rules: rules.reasons },
                //    null, 2
                //);

                // 5) debug ringkas
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

        // ===== Camera
        async function startCamera() {
            try {
                if (!navigator.mediaDevices?.getUserMedia) throw new Error('getUserMedia tidak didukung');
                stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' } });
                video.srcObject = stream;

                await new Promise(res => {
                    const onMeta = () => { video.removeEventListener('loadedmetadata', onMeta); res(); };
                    if (video.readyState >= 1) res(); else video.addEventListener('loadedmetadata', onMeta, { once: true });
                });
                await video.play();

                // load model di background
                initFaceModel().catch(e => console.warn('init model err', e));

                startBtn.disabled = true; stopBtn.disabled = false; scanning = true;
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
                        // sinkron DPR kedua kanvas + ambil ctx terbaru
                        ctx = syncCanvas(canvas, w, h);
                        fctx = syncCanvas(faceCanvas, w, h);

                        // gambar frame video ke qrCanvas
                        ctx.drawImage(video, 0, 0, w, h);

                        // ===== FACE DETECTION (throttle tiap N frame)
                        _fdFrame = (_fdFrame + 1) | 0;
                        if (fdSession && !fdBusy && (_fdFrame % fdRunningEvery === 0)) {
                            fdBusy = true;
                            try {
                                const lb = letterbox(canvas, fdInputSize);
                                lb.srcW = w; lb.srcH = h;

                                const input = toTensorCHW(lb.canvas);
                                const feeds = {};
                                const inputName = (fdSession.inputNames && fdSession.inputNames[0]) || 'images';
                                feeds[inputName] = input;

                                const outMap = await fdSession.run(feeds);

                                let outTensor = null;
                                for (const k of Object.keys(outMap)) {
                                    const t = outMap[k], d = t?.dims;
                                    if (d && d.length === 3 && d[0] === 1 && d[2] === 6) { outTensor = t; break; }
                                }
                                if (!outTensor) outTensor = outMap[Object.keys(outMap)[0]];

                                const boxes = postprocessGeneric(outTensor, lb);
                                drawFaces(fctx, boxes); // gambar di overlay
                            } catch (e) {
                                console.warn('FD run error', e);
                            } finally {
                                fdBusy = false;
                            }
                        }

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

    // ====== Face Detect (ONNX) ======
    const MODEL_URL = 'models/best.onnx';
    let fdSession = null;
    let fdInputSize = 640;
    let fdRunningEvery = 6;
    let _fdFrame = 0, fdBusy = false;

    async function initFaceModel() {
        if (fdSession) return;
        console.time('onnx-load');
        fdSession = await ort.InferenceSession.create(MODEL_URL, {
            executionProviders: ['wasm'],
            graphOptimizationLevel: 'all'
        });
        console.timeEnd('onnx-load');
        console.log('ONNX inputs:', fdSession.inputNames, 'outputs:', fdSession.outputNames);

        // warmup (non-fatal jika nama input beda)
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
                // BACA SEBAGAI KOTAK SUDUT: x1,y1,x2,y2
                let x1l = data[off + 0], y1l = data[off + 1];
                let x2l = data[off + 2], y2l = data[off + 3];
                let conf = data[off + 4];

                if (!Number.isFinite(conf) || conf < 0.25) continue;

                // jika output ternormalisasi (0..1), skala ke piksel letterbox S
                const S = meta.size || 640;
                const maybeNorm =
                    Math.max(Math.abs(x1l), Math.abs(y1l), Math.abs(x2l), Math.abs(y2l)) <= 1.5;
                if (maybeNorm) {
                    x1l *= S; y1l *= S; x2l *= S; y2l *= S;
                }

                // pastikan urutan min->max
                if (x2l < x1l) [x1l, x2l] = [x2l, x1l];
                if (y2l < y1l) [y1l, y2l] = [y2l, y1l];

                // unletterbox ke koordinat video
                const { r, dx, dy, srcW, srcH } = meta;
                let x1 = (x1l - dx) / r, y1 = (y1l - dy) / r;
                let x2 = (x2l - dx) / r, y2 = (y2l - dy) / r;

                // clamp & buang kotak terlalu kecil
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
        fctx.save();
        fctx.lineWidth = Math.max(2, Math.round(Math.min(fctx.canvas.width, fctx.canvas.height) / 200));
        fctx.strokeStyle = '#22c55e';
        fctx.fillStyle = 'rgba(34,197,94,.18)';
        for (const b of boxes) {
            const x = Math.min(b.x1, b.x2), y = Math.min(b.y1, b.y2);
            const w = Math.max(1, Math.abs(b.x2 - b.x1));
            const h = Math.max(1, Math.abs(b.y2 - b.y1));
            fctx.strokeRect(x, y, w, h);
            fctx.fillRect(x, y, w, h);
        }
        fctx.restore();
    }
})();

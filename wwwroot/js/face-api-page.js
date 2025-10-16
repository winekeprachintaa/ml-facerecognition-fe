(function () {
    'use strict';

    const DEFAULT_CFG = {
        modelRoot: './models/face-api',
        inputSize: 320,
        scoreThreshold: 0.5,
        matchThreshold: 0.55,
        everyNthFrame: 2
    };

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init, { once: true });
    } else {
        init();
    }

    function init() {
        const faceapi = window.faceapi;
        if (!faceapi) {
            console.error('face-api tidak tersedia di window.');
            return;
        }

        const cfg = Object.assign({}, DEFAULT_CFG, window.FaceApiConfig || {});
        cfg.modelRoot = cfg.modelRoot || DEFAULT_CFG.modelRoot;
        cfg.inputSize = Math.max(128, Math.floor(Number(cfg.inputSize) || DEFAULT_CFG.inputSize));
        cfg.scoreThreshold = Math.min(Math.max(Number(cfg.scoreThreshold) || DEFAULT_CFG.scoreThreshold, 0.1), 0.9);
        cfg.matchThreshold = Math.max(0.1, Number(cfg.matchThreshold) || DEFAULT_CFG.matchThreshold);
        cfg.everyNthFrame = Math.max(1, Math.round(Number(cfg.everyNthFrame) || DEFAULT_CFG.everyNthFrame));

        const video = document.getElementById('video');
        const overlay = document.getElementById('overlay');
        const startBtn = document.getElementById('startBtn');
        const stopBtn = document.getElementById('stopBtn');
        const markBtn = document.getElementById('markBtn');
        const clearBtn = document.getElementById('clearBtn');
        const statusLine = document.getElementById('statusLine');
        const debugLog = document.getElementById('debugLog');
        const ctx = overlay.getContext('2d');

        const state = {
            stream: null,
            running: false,
            modelsReady: false,
            loadingModels: false,
            frameCounter: 0,
            references: [],
            matcher: null,
            lastDetections: [],
            debugLines: []
        };

        const detectionOpts = new faceapi.TinyFaceDetectorOptions({
            inputSize: cfg.inputSize,
            scoreThreshold: cfg.scoreThreshold
        });

        startBtn.addEventListener('click', handleStart);
        stopBtn.addEventListener('click', handleStop);
        markBtn.addEventListener('click', handleMarkReference);
        clearBtn.addEventListener('click', handleClearReference);
        window.addEventListener('pagehide', handleStop);

        updateButtons();
        setStatus('Menunggu kamera dinyalakan.');

        async function handleStart() {
            if (state.running) return;
            try {
                await ensureModels();
            } catch (err) {
                console.error(err);
                setStatus(`Gagal memuat model face-api: ${err?.message || err}`);
                return;
            }

            if (!navigator.mediaDevices?.getUserMedia) {
                setStatus('Browser tidak mendukung akses kamera (getUserMedia).');
                return;
            }

            try {
                state.stream = await navigator.mediaDevices.getUserMedia({
                    video: { facingMode: 'user', width: { ideal: 640 } },
                    audio: false
                });
            } catch (err) {
                console.error(err);
                setStatus(`Tidak bisa mengakses kamera: ${err?.message || err}`);
                return;
            }

            video.srcObject = state.stream;
            await video.play().catch(() => {});

            state.running = true;
            state.frameCounter = cfg.everyNthFrame - 1;
            setStatus('Kamera aktif. Memulai deteksi wajah…');
            updateButtons();
            detectLoop();
        }

        function handleStop() {
            state.running = false;
            if (state.stream) {
                state.stream.getTracks().forEach(t => t.stop());
                state.stream = null;
            }
            video.srcObject = null;
            ctx.clearRect(0, 0, overlay.width, overlay.height);
            setStatus('Kamera dihentikan.');
            updateButtons();
        }

        async function handleMarkReference() {
            if (!state.running || !state.modelsReady) {
                setStatus('Mulai kamera dan tunggu model selesai dimuat.');
                return;
            }
            setStatus('Mengambil deskriptor wajah…');
            try {
                const result = await faceapi
                    .detectSingleFace(video, detectionOpts)
                    .withFaceLandmarks()
                    .withFaceDescriptor();

                if (!result) {
                    setStatus('Tidak ada wajah jelas di kamera.');
                    return;
                }

                const defaultLabel = `Rujukan-${state.references.length + 1}`;
                const label = (prompt('Label untuk wajah ini?', defaultLabel) || defaultLabel).trim();
                if (!label) {
                    setStatus('Penyimpanan rujukan dibatalkan.');
                    return;
                }

                const descriptor = new Float32Array(result.descriptor);
                state.references.push({ label, descriptor });
                rebuildMatcher();
                updateButtons();
                setStatus(`Wajah “${label}” disimpan (${state.references.length} total).`);
            } catch (err) {
                console.error(err);
                setStatus(`Gagal mengambil deskriptor wajah: ${err?.message || err}`);
            }
        }

        function handleClearReference() {
            state.references = [];
            state.matcher = null;
            updateButtons();
            setStatus('Seluruh rujukan dihapus.');
        }

        async function ensureModels() {
            if (state.modelsReady || state.loadingModels) return;
            state.loadingModels = true;
            setStatus('Memuat model face-api…');
            updateButtons();
            const loads = [
                faceapi.nets.tinyFaceDetector.loadFromUri(cfg.modelRoot),
                faceapi.nets.faceLandmark68Net.loadFromUri(cfg.modelRoot),
                faceapi.nets.faceRecognitionNet.loadFromUri(cfg.modelRoot)
            ];
            try {
                await Promise.all(loads);
                state.modelsReady = true;
                setStatus('Model face-api siap. Siap menyalakan kamera.');
            } finally {
                state.loadingModels = false;
                updateButtons();
            }
        }

        function rebuildMatcher() {
            if (!state.references.length) {
                state.matcher = null;
                return;
            }
            const labeled = state.references.map(r =>
                new faceapi.LabeledFaceDescriptors(r.label, [r.descriptor])
            );
            state.matcher = new faceapi.FaceMatcher(labeled, cfg.matchThreshold);
        }

        async function detectLoop() {
            if (!state.running) return;
            state.frameCounter = (state.frameCounter + 1) % cfg.everyNthFrame;
            if (state.frameCounter === 0) {
                await runDetection();
            }
            requestAnimationFrame(detectLoop);
        }

        async function runDetection() {
            if (!state.modelsReady) return;

            const ready = video.readyState >= 2 && video.videoWidth && video.videoHeight;
            if (!ready) return;

            if (!syncOverlayDimensions()) return;

            let results = [];
            try {
                results = await faceapi
                    .detectAllFaces(video, detectionOpts)
                    .withFaceLandmarks()
                    .withFaceDescriptors();
            } catch (err) {
                console.error(err);
                setStatus(`Kesalahan membaca wajah: ${err?.message || err}`);
                return;
            }

            const dims = { width: overlay.width, height: overlay.height };
            const resized = faceapi.resizeResults(results, dims);

            ctx.clearRect(0, 0, overlay.width, overlay.height);

            const matched = [];
            for (let i = 0; i < resized.length; i++) {
                const det = resized[i];
                let label = `Score ${(det.detection.score * 100).toFixed(1)}%`;

                if (state.matcher) {
                    const match = state.matcher.findBestMatch(results[i].descriptor);
                    label = match.label === 'unknown'
                        ? `Tidak dikenal (${match.distance.toFixed(2)})`
                        : `${match.label} (${match.distance.toFixed(2)})`;
                }

                drawBox(det.detection.box, label);
                matched.push(label);
            }

            state.lastDetections = matched;
            setStatus(resized.length
                ? `Terdeteksi ${resized.length} wajah.`
                : 'Tidak ada wajah terdeteksi.');
            appendDebug(matched.length ? matched.join('\n') : '—');
        }

        function drawBox(box, label) {
            ctx.save();
            ctx.strokeStyle = '#2563eb';
            ctx.lineWidth = 3;
            ctx.strokeRect(box.x, box.y, box.width, box.height);

            if (label) {
                const padding = 4;
                const fontSize = 15;
                ctx.font = `${fontSize}px system-ui, Arial`;
                ctx.textBaseline = 'top';
                const textWidth = ctx.measureText(label).width;
                const labelHeight = fontSize + padding * 2;
                let rectX = box.x;
                let rectY = box.y - labelHeight;
                if (rectY < 0) rectY = box.y + box.height;
                if (rectX + textWidth + padding * 2 > overlay.width) {
                    rectX = Math.max(0, overlay.width - (textWidth + padding * 2));
                }
                if (rectY + labelHeight > overlay.height) {
                    rectY = Math.max(0, overlay.height - labelHeight);
                }

                ctx.fillStyle = 'rgba(37, 99, 235, 0.85)';
                ctx.fillRect(rectX, rectY, textWidth + padding * 2, labelHeight);

                ctx.fillStyle = '#fff';
                ctx.fillText(label, rectX + padding, rectY + padding);
            }
            ctx.restore();
        }

        function syncOverlayDimensions() {
            const { videoWidth: w, videoHeight: h } = video;
            if (!w || !h) return false;
            if (overlay.width !== w) overlay.width = w;
            if (overlay.height !== h) overlay.height = h;
            faceapi.matchDimensions(overlay, { width: w, height: h });
            return true;
        }

        function updateButtons() {
            startBtn.disabled = state.running || state.loadingModels;
            stopBtn.disabled = !state.running;
            markBtn.disabled = !state.running || state.loadingModels || !state.modelsReady;
            clearBtn.disabled = !state.references.length;
        }

        function setStatus(text) {
            if (statusLine) statusLine.textContent = text;
        }

        function appendDebug(text) {
            if (!debugLog) return;
            if (!text || text === '—') {
                state.debugLines.push(`[${timestamp()}] Tidak ada wajah.`);
            } else {
                state.debugLines.push(`[${timestamp()}] ${text}`);
            }
            if (state.debugLines.length > 6) state.debugLines.splice(0, state.debugLines.length - 6);
            debugLog.hidden = false;
            debugLog.textContent = state.debugLines.join('\n');
        }

        function timestamp() {
            return new Date().toLocaleTimeString('id-ID', { hour12: false });
        }
    }
})();

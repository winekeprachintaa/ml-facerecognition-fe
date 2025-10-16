// Admin: generate token + QR (single) atau master batch dari CSV
(function () {
    const $ = (id) => document.getElementById(id);
    const priPemEl = $('priPem');
    const workerIdEl = $('workerId');
    const workDateEl = $('workDate');
    const qrJsonEl = $('qrJson');
    const genBtn = $('genBtn');
    const copyBtn = $('copyBtn');
    const pngBtn = $('pngBtn');
    const qrcodeEl = $('qrcode');

    // set default date = today
    workDateEl.value = new Date().toISOString().slice(0, 10);

    let qr; const renderQR = (txt) => {
        qrcodeEl.innerHTML = '';
        qr = new QRCode(qrcodeEl, { text: txt, width: 256, height: 256 });
    };

    async function signIdDate(id, date) {
        const pri = await CryptoUtils.importPrivateKeyPem(priPemEl.value);
        const msg = CryptoUtils.textEnc(`${id}|${date}`);
        return await CryptoUtils.signP256(pri, msg);
    }

    genBtn.onclick = async () => {
        try {
            const id = workerIdEl.value.trim();
            const date = workDateEl.value.trim();
            if (!id || !date) throw new Error('ID/Tanggal kosong');

            const token = await signIdDate(id, date);
            const obj = { id, date, token };
            const txt = JSON.stringify(obj);
            qrJsonEl.value = txt;
            renderQR(txt);
        } catch (e) { alert(e?.message || e); }
    };

    copyBtn.onclick = () => {
        navigator.clipboard.writeText(qrJsonEl.value || '').then(() => alert('Disalin'));
    };

    pngBtn.onclick = () => {
        // ambil canvas dari QRCode lib
        const img = qrcodeEl.querySelector('img');
        const cvs = qrcodeEl.querySelector('canvas');
        let dataUrl;
        if (img && img.src) dataUrl = img.src;
        else if (cvs) dataUrl = cvs.toDataURL('image/png');
        if (!dataUrl) return alert('QR belum dibuat');
        const a = document.createElement('a');
        a.href = dataUrl; a.download = 'qr.png'; a.click();
    };

    // ===== Master QR dari CSV =====
    const csvFileEl = $('csvFile');
    const genMasterBtn = $('genMasterBtn');

    const parseCSV = (text) => {
        // sangat sederhana: split baris, koma
        const lines = text.trim().split(/\r?\n/);
        const rows = lines.map(l => l.split(',').map(s => s.trim()));
        return rows;
    };

    genMasterBtn.onclick = async () => {
        try {
            const file = csvFileEl.files?.[0];
            if (!file) return alert('Pilih file CSV dulu');
            const text = await file.text();
            const rows = parseCSV(text); // [ [id,date,token], ... ]
            if (!rows.length) throw new Error('CSV kosong');

            // Jika seluruh date sama → simpan di header (data.date)
            const dates = new Set(rows.map(r => r[1]));
            const headerDate = (dates.size === 1) ? rows[0][1] : null;

            const entries = rows.map(r => {
                const id = (r[0] || '').trim();
                const date = (r[1] || '').trim();
                const token = (r[2] || '').trim();
                if (!id || !token) throw new Error('Baris tidak lengkap (butuh id & token)');
                return headerDate ? [id, token] : [id, token, date];
            });

            const payload = headerDate
                ? { type: 'batch', date: headerDate, entries }
                : { type: 'batch', entries };

            const txt = JSON.stringify(payload);
            qrJsonEl.value = txt;
            renderQR(txt);
        } catch (e) { alert(e?.message || e); }
    };

    // ===== Pair test (opsional, jalankan manual dari console) =====
    // (async () => {
    //   const pri = await CryptoUtils.importPrivateKeyPem(priPemEl.value);
    //   const pub = await CryptoUtils.importPublicKeyPem(`-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----`);
    //   const msg = CryptoUtils.textEnc('Pekerja1|2025-09-23');
    //   const sig = await CryptoUtils.signP256(pri, msg);
    //   console.log('PAIR MATCH ?', await CryptoUtils.verifyP256(pub, msg, sig));
    // })();
})();

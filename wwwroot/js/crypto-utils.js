// Utilitas crypto untuk ECDSA P-256 (SHA-256) + helper PEM/Base64
const CryptoUtils = (() => {
    const textEnc = (s) => new TextEncoder().encode(s);
    const textDec = (b) => new TextDecoder().decode(b);

    const b64ToBytes = (b64) => {
        const bin = atob(b64);
        const arr = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
        return arr;
    };
    const bytesToB64 = (u8) => {
        let bin = ''; for (let i = 0; i < u8.length; i++) bin += String.fromCharCode(u8[i]);
        return btoa(bin);
    };

    const pemToBuf = (pem, label) => {
        // label: 'PRIVATE KEY' atau 'PUBLIC KEY'
        const re = new RegExp(`-----BEGIN ${label}-----([\\s\\S]+?)-----END ${label}-----`);
        const m = (pem || '').trim().match(re);
        if (!m) throw new Error(`PEM tidak valid: header/footer tidak ditemukan (${label})`);
        const base64 = m[1].replace(/\s+/g, '');
        return b64ToBytes(base64).buffer;
    };

    const importPrivateKeyPem = async (pem) => {
        const pkcs8 = pemToBuf(pem, 'PRIVATE KEY');
        return await crypto.subtle.importKey(
            'pkcs8', pkcs8,
            { name: 'ECDSA', namedCurve: 'P-256' },
            true, ['sign']
        );
    };

    const importPublicKeyPem = async (pem) => {
        const spki = pemToBuf(pem, 'PUBLIC KEY');
        return await crypto.subtle.importKey(
            'spki', spki,
            { name: 'ECDSA', namedCurve: 'P-256' },
            true, ['verify']
        );
    };

    const signP256 = async (privateKey, data) => {
        const sig = await crypto.subtle.sign(
            { name: 'ECDSA', hash: 'SHA-256' },
            privateKey, data
        );
        return bytesToB64(new Uint8Array(sig));
    };

    const verifyP256 = async (publicKey, data, b64sig) => {
        const sig = b64ToBytes(b64sig);
        return await crypto.subtle.verify(
            { name: 'ECDSA', hash: 'SHA-256' },
            publicKey, sig, data
        );
    };

    return { textEnc, textDec, importPrivateKeyPem, importPublicKeyPem, signP256, verifyP256 };
})();

/* global nacl */
(async () => {
  const hex = h => Uint8Array.from(h.match(/../g), b => parseInt(b, 16));
  const CHUNK_SALT = new TextEncoder().encode('chunk-salt');

  // ────────────────────────────────────────────────────────────────────────────
  // 1. HKDF‑based sub‑key derivation (depends on index + nonce)
  // ────────────────────────────────────────────────────────────────────────────
  async function deriveSubKeyWithNonce(masterRaw, idx, nonce) {
    const ikm = await crypto.subtle.importKey('raw', masterRaw, 'HKDF', false, ['deriveBits']);

    const idxBuf = new Uint8Array(8);
    new DataView(idxBuf.buffer).setBigUint64(0, BigInt(idx), false);

    const info = new Uint8Array([
      ...new TextEncoder().encode('chunk-'),
      ...idxBuf,
      ...nonce
    ]);

    const bits = await crypto.subtle.deriveBits(
      { name: 'HKDF', hash: 'SHA-256', salt: CHUNK_SALT, info },
      ikm,
      256
    );
    return crypto.subtle.importKey('raw', bits, { name: 'AES-CTR', length: 256 }, false, ['decrypt']);
  }

  // ────────────────────────────────────────────────────────────────────────────
  // 2. ECDH key‑exchange + derive master AES‑CTR key
  // ────────────────────────────────────────────────────────────────────────────
  async function deriveKey() {
    // 2.1  Lấy key tải về từ server
    const r1 = await fetch('/key-exchange');
    const { server_pubkey_ecdhe, signature, server_pubkey_ecdsa } = await r1.json();

    // 2.2  Verify chữ ký ECDSA
    const spki = await crypto.subtle.importKey(
      'spki', hex(server_pubkey_ecdsa).buffer,
      { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']
    );
    const ok = await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' }, spki,
      hex(signature).buffer, hex(server_pubkey_ecdhe).buffer
    );
    if (!ok) throw new Error('Bad server signature');

    // 2.3  Tính shared secret ECDH
    const srvPub = await crypto.subtle.importKey(
      'raw', hex(server_pubkey_ecdhe).buffer,
      { name: 'ECDH', namedCurve: 'P-256' }, false, []
    );
    const cli = await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']
    );
    const shared = await crypto.subtle.deriveBits(
      { name: 'ECDH', public: srvPub }, cli.privateKey, 256
    );

    // 2.4  Gửi client pubkey cho server
    const rawPub = await crypto.subtle.exportKey('raw', cli.publicKey);
    const hexPub = [...new Uint8Array(rawPub)].map(b => b.toString(16).padStart(2, '0')).join('');
    await fetch('/submit-client-key', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ client_pubkey_ecdhe: hexPub })
    });

    // 2.5  HKDF → master AES‑CTR key (32 byte)
    const salt = new TextEncoder().encode('stream-salt');
    const info = new TextEncoder().encode('aes-ctr-stream');
    const ikm = await crypto.subtle.importKey('raw', shared, 'HKDF', false, ['deriveBits']);
    const keyBits = await crypto.subtle.deriveBits(
      { name: 'HKDF', hash: 'SHA-256', salt, info },
      ikm,
      256
    );

    return { keyBits }; // chỉ cần raw‑bits để derive sub‑keys
  }

  // ────────────────────────────────────────────────────────────────────────────
  // 3. Phát nhạc với AES‑CTR + nonce ngẫu nhiên mỗi chunk
  // ────────────────────────────────────────────────────────────────────────────
  async function play(file, btn) {
    btn.disabled = true;
    btn.textContent = 'Đang tải…';

    try {
      const { keyBits } = await deriveKey();
      const res = await fetch(`/stream/${file}`);
      if (!res.ok) throw new Error('HTTP ' + res.status);

      const rd = res.body.getReader();
      const outChunks = [];

      const CHUNK_SIZE = 64 * 1024;
      let buffer = new Uint8Array(0);

      while (true) {
        const { value, done } = await rd.read();
        if (value) {
          const tmp = new Uint8Array(buffer.length + value.byteLength);
          tmp.set(buffer);
          tmp.set(value, buffer.length);
          buffer = tmp;
        }

        // ═══ Giải mã các khung đầy đủ (nonce + idx + cipher) ═══
        while (buffer.byteLength >= 16 + CHUNK_SIZE) {
          const frame = buffer.subarray(0, 16 + CHUNK_SIZE);
          buffer = buffer.subarray(16 + CHUNK_SIZE);

          const nonce = frame.subarray(0, 8);
          const idxBytes = frame.subarray(8, 16);
          const cipher = frame.subarray(16);
          const idx = new DataView(idxBytes.buffer, idxBytes.byteOffset).getBigUint64(0, false);

          const subKey = await deriveSubKeyWithNonce(keyBits, Number(idx), nonce);

          const iv = new Uint8Array(16);
          iv.set(nonce);

          const plain = await crypto.subtle.decrypt(
            { name: 'AES-CTR', counter: iv, length: 64 },  // counter length 64 bits
            subKey,
            cipher
          );
          outChunks.push(new Uint8Array(plain));
        }

        // ═══ Khung cuối cùng (< CHUNK_SIZE) ═══
        if (done) {
          if (buffer.byteLength >= 16) {
            const nonce   = buffer.subarray(0, 8);
            const idxBytes= buffer.subarray(8, 16);
            const cipher  = buffer.subarray(16);
            const idx     = new DataView(idxBytes.buffer).getBigUint64(0, false);

            const subKey = await deriveSubKeyWithNonce(keyBits, Number(idx), nonce);
            const iv = new Uint8Array(16); iv.set(nonce);

            const plain = await crypto.subtle.decrypt(
              { name: 'AES-CTR', counter: iv, length: 64 },
              subKey, cipher
            );
            outChunks.push(new Uint8Array(plain));
          }
          break;
        }
      }

      const blob = new Blob(outChunks, { type: 'audio/mpeg' });
      await new Audio(URL.createObjectURL(blob)).play();
    } catch (err) {
      alert(err.message);
      console.error(err);
    } finally {
      btn.disabled = false;
      btn.textContent = 'Play';
    }
  }

  // ────────────────────────────────────────────────────────────────────────────
  // 4. Gắn handler Play cho các nút
  // ────────────────────────────────────────────────────────────────────────────
  document.querySelectorAll('.play-btn').forEach(btn => {
    btn.addEventListener('click', () => play(btn.dataset.file, btn));
  });
})();

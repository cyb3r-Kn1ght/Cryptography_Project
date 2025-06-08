/* global nacl */
(async () => {
  const hex = h => Uint8Array.from(h.match(/../g), b => parseInt(b, 16));

  async function deriveKey() {
    const r1 = await fetch('/key-exchange');
    const { server_pubkey_ecdhe, signature, server_pubkey_ecdsa } = await r1.json();

    // Verify server’s ECDHE pubkey signature
    const spki = await crypto.subtle.importKey(
      'spki', hex(server_pubkey_ecdsa).buffer,
      { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']
    );
    const ok = await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' }, spki,
      hex(signature).buffer, hex(server_pubkey_ecdhe).buffer
    );
    if (!ok) throw Error('Bad server sig');

    // ECDH derive shared secret
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

    // Submit our client ECDHE pubkey
    const rawPub = await crypto.subtle.exportKey('raw', cli.publicKey);
    const hexPub = [...new Uint8Array(rawPub)]
      .map(b => b.toString(16).padStart(2, '0')).join('');
    await fetch('/submit-client-key', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ client_pubkey_ecdhe: hexPub })
    });

    // HKDF → AES-CTR key
    const salt = new TextEncoder().encode('stream-salt');
    const info = new TextEncoder().encode('aes-ctr-stream');
    const ikm = await crypto.subtle.importKey('raw', shared, 'HKDF', false, ['deriveBits']);
    const keyBits = await crypto.subtle.deriveBits(
      { name: 'HKDF', hash: 'SHA-256', salt, info }, ikm, 256
    );
    return crypto.subtle.importKey(
      'raw', keyBits, { name: 'AES-CTR', length: 256 }, false, ['decrypt']
    );
  }

  async function play(file, btn) {
    btn.disabled = true;
    btn.textContent = 'Đang tải...';

    try {
      const aesKey = await deriveKey();
      const res = await fetch(`/stream/${file}`);
      if (!res.ok) throw Error('HTTP ' + res.status);

      const rd = res.body.getReader();
      const out = [];

      // --- NEW: chunk-assembly logic ---
      const CHUNK_SIZE = 64 * 1024;
      let buffer = new Uint8Array(0);

      while (true) {
        const { value, done } = await rd.read();

        // 1) Gom mọi chunk mới vào buffer
        if (value) {
          const tmp = new Uint8Array(buffer.length + value.byteLength);
          tmp.set(buffer, 0);
          tmp.set(value, buffer.length);
          buffer = tmp;
        }

        // 2) Khi có ≥1 frame (8-byte header + cipher), bóc ra decrypt
        while (buffer.byteLength >= 8 + CHUNK_SIZE) {
          const frame = buffer.subarray(0, 8 + CHUNK_SIZE);
          buffer = buffer.subarray(8 + CHUNK_SIZE);

          const dv     = new DataView(frame.buffer, frame.byteOffset, frame.byteLength);
          const idx    = dv.getBigUint64(0, false);
          const cipher = frame.subarray(8);

          const iv = new Uint8Array(16);
          new DataView(iv.buffer).setBigUint64(8, idx, false);

          const plainBuf = await crypto.subtle.decrypt(
            { name: 'AES-CTR', counter: iv, length: 128 },
            aesKey,
            cipher
          );
          out.push(new Uint8Array(plainBuf));
        }

        // 3) Nếu đã hết stream, xử lý chunk cuối (<CHUNK_SIZE) rồi break
        if (done) {
          if (buffer.byteLength >= 8) {
            const dv     = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
            const idx    = dv.getBigUint64(0, false);
            const cipher = buffer.subarray(8);

            const iv = new Uint8Array(16);
            new DataView(iv.buffer).setBigUint64(8, idx, false);

            const plainBuf = await crypto.subtle.decrypt(
              { name: 'AES-CTR', counter: iv, length: 128 },
              aesKey,
              cipher
            );
            out.push(new Uint8Array(plainBuf));
          }
          break;
        }
      }
      // --- END NEW LOGIC ---

      const blob = new Blob(out, { type: 'audio/mpeg' });
      console.log("✅ Blob size:", blob.size);
      console.log("✅ Blob type:", blob.type);
      new Audio(URL.createObjectURL(blob))
        .play()
        .catch(err => console.error('Playback error:', err));

    } catch (e) {
      alert(e.message);
      console.error(e);
    } finally {
      btn.disabled = false;
      btn.textContent = 'Play';
    }
  }

  document.querySelectorAll('.play-btn')
    .forEach(b => b.onclick = () => play(b.dataset.file, b));
})();

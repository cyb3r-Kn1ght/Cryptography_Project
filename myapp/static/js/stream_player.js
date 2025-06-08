/* global nacl */
(async () => {
  const hex = h => Uint8Array.from(h.match(/../g), b => parseInt(b, 16));

  async function deriveKey() {
    const r1 = await fetch('/key-exchange');
    const { server_pubkey_ecdhe, signature, server_pubkey_ecdsa } = await r1.json();

    const spki = await crypto.subtle.importKey(
      'spki', hex(server_pubkey_ecdsa).buffer,
      { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']
    );
    const ok = await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' }, spki,
      hex(signature).buffer, hex(server_pubkey_ecdhe).buffer
    );
    if (!ok) throw Error('Bad server sig');

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

    const rawPub = await crypto.subtle.exportKey('raw', cli.publicKey);
    const hexPub = [...new Uint8Array(rawPub)]
      .map(b => b.toString(16).padStart(2, '0')).join('');
    await fetch('/submit-client-key', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ client_pubkey_ecdhe: hexPub })
    });

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

      while (true) {
        const { value, done } = await rd.read();
        if (done) break;
        if (!value || value.byteLength < 8) {
          console.warn("⚠️ Chunk quá ngắn hoặc rỗng:", value?.byteLength);
          continue;
        }

        try {
          const idx = new DataView(value.buffer).getBigUint64(0, false);
          const cipher = new Uint8Array(value.buffer.slice(8));

          const iv = new Uint8Array(16);
          new DataView(iv.buffer).setBigUint64(8, idx);  // chuẩn IV

          const plainBuf = await crypto.subtle.decrypt(
            { name: 'AES-CTR', counter: iv, length: 128 }, aesKey, cipher
          );

          console.log("🔓 Plain chunk", idx, new Uint8Array(plainBuf).slice(0, 10));
          out.push(new Uint8Array(plainBuf));
        } catch (err) {
          console.error("❌ Lỗi giải mã chunk:", err);
          break;
        }
      }

      const blob = new Blob(out, { type: 'audio/mpeg' });

      new Audio(URL.createObjectURL(blob)).play();
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

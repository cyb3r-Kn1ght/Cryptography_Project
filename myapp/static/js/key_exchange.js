// static/js/key_exchange.js

// Chuyển hex string → ArrayBuffer
function hexToArrayBuffer(hex) {
    const len = hex.length / 2;
    const buf = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        buf[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return buf.buffer;
}

// Chuyển ArrayBuffer → hex string
function arrayBufferToHex(buffer) {
    const bytes = new Uint8Array(buffer);
    return Array.from(bytes)
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

async function main() {
    // 1. Lấy pubkey server + signature
    const res1 = await fetch("/key-exchange");
    if (!res1.ok) throw new Error("Key exchange lỗi: " + res1.status);
    const { server_pubkey_ecdhe, signature, server_pubkey_ecdsa } = await res1.json();

    const ecdheBuf = hexToArrayBuffer(server_pubkey_ecdhe);
    const sigBuf   = hexToArrayBuffer(signature);
    const ecdsaBuf = hexToArrayBuffer(server_pubkey_ecdsa);

    // 2. Verify chữ ký server
    const serverECDSAPubKey = await crypto.subtle.importKey(
        "spki", ecdsaBuf,
        { name: "ECDSA", namedCurve: "P-256" },
        true, ["verify"]
    );
    const ok = await crypto.subtle.verify(
        { name: "ECDSA", hash: "SHA-256" },
        serverECDSAPubKey, sigBuf, ecdheBuf
    );
    if (!ok) {
        alert("❌ Chữ ký của server không hợp lệ");
        return;
    }
    console.log("✅ Server signature verified");

    // 3. Derive shared secret
    const serverECDHPubKey = await crypto.subtle.importKey(
        "raw", ecdheBuf,
        { name: "ECDH", namedCurve: "P-256" },
        true, []
    );
    const clientKeys = await crypto.subtle.generateKey(
        { name: "ECDH", namedCurve: "P-256" },
        true, ["deriveBits"]
    );
    const sharedSecret = await crypto.subtle.deriveBits(
        { name: "ECDH", public: serverECDHPubKey },
        clientKeys.privateKey, 256
    );
    console.log("🔐 Shared secret (client):", arrayBufferToHex(sharedSecret));

    // 4. Export public key của client, convert → hex, rồi POST
    const rawPub = await crypto.subtle.exportKey("raw", clientKeys.publicKey);
    const hexPub = arrayBufferToHex(rawPub);
    console.log("Client ECDHE pubkey (hex):", hexPub);

    const res2 = await fetch("/submit-client-key", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ client_pubkey_ecdhe: hexPub })
    });
    if (!res2.ok) {
        const err = await res2.text();
        throw new Error("submit-client-key lỗi: " + res2.status + " – " + err);
    }
    console.log("✅ Đã submit client key thành công");
}

// Chạy khi DOM load xong
document.addEventListener('DOMContentLoaded', () => {
    main().catch(console.error);
});

from flask import Flask, render_template, Response, request, jsonify, redirect, url_for, session, send_file
import os
from io import BytesIO
from sqlalchemy import create_engine, text
from dotenv import load_dotenv
from auth_utils import hash_password, verify_password
from crypto_utils import (
    generate_ecdhe_keypair,
    serialize_public_key,
    sign_ecdhe_pubkey,
    compute_shared_secret,
    get_ecdsa_public_key_bytes,
    derive_aesctr_key  # NEW
)
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from Crypto.Cipher import AES  # NEW: for AES‑CTR streaming
import hvac

# ---------------------------------------------------------------------------
# 0. Init
# ---------------------------------------------------------------------------
load_dotenv()

app = Flask(__name__)
app.secret_key = os.urandom(24)

# ---------------------------------------------------------------------------
# 1. DB & Vault
# ---------------------------------------------------------------------------
DB_URL = os.getenv("DB_URL")
if not DB_URL:
    raise RuntimeError("DB_URL not set in .env")
engine = create_engine(DB_URL)
print("[BOOT] DB_URL ->", engine.url, flush=True)

vault_addr  = os.getenv("VAULT_ADDR")
vault_token = os.getenv("VAULT_TOKEN")
if not vault_addr or not vault_token:
    raise RuntimeError("VAULT_ADDR / VAULT_TOKEN missing")
vault = hvac.Client(url=vault_addr, token=vault_token)

# ---------------------------------------------------------------------------
# 2. Auth routes
# ---------------------------------------------------------------------------
@app.route('/')
def root():
    return redirect(url_for('login_page'))

@app.route('/login_page', methods=['GET', 'POST'])
def login_page():
    if request.method == 'GET':
        return render_template('login.html')
    username = request.form.get('username')
    password = request.form.get('password')
    with engine.connect() as c:
        row = c.execute(text('SELECT password_hash, role FROM users WHERE username=:u'), {'u': username}).fetchone()
    if row and verify_password(row[0], password):
        session.update(username=username, role=row[1])
        return redirect(url_for('index'))
    return 'Invalid credentials', 401

@app.route('/register_page', methods=['GET', 'POST'])
def register_page():
    if request.method == 'GET':
        return render_template('register.html')
    data = {k: request.form.get(k) for k in ('username', 'email', 'password')}
    if not all(data.values()):
        return 'Missing fields', 400
    role = request.form.get('role', 'user')
    pwd_hash = hash_password(data['password'])
    try:
        with engine.begin() as c:
            c.execute(text('INSERT INTO users (username,email,password_hash,role) VALUES (:u,:e,:p,:r)'),
                      {'u': data['username'], 'e': data['email'], 'p': pwd_hash, 'r': role})
    except Exception as exc:
        return f'Error: {exc}', 400
    return redirect(url_for('login_page'))

# ---------------------------------------------------------------------------
# 3. Music list & upload (artist)
# ---------------------------------------------------------------------------
@app.route('/music_list')
def index():
    if 'username' not in session:
        return redirect(url_for('login_page'))
    with engine.connect() as c:
        files = [r[0] for r in c.execute(text('SELECT filename FROM songs ORDER BY id'))]
    return render_template('index.html', music_files=files, role=session.get('role'))

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if session.get('role') != 'artist':
        return 'Unauthorized', 403
    if request.method == 'GET':
        return render_template('upload.html')
    f = request.files.get('file')
    if not f:
        return 'No file', 400
    f.save(os.path.join(app.root_path, 'static', 'music', f.filename))
    return 'Upload OK'

# ---------------------------------------------------------------------------
# 4. AES‑GCM (preview) route – vẫn giữ để test
# ---------------------------------------------------------------------------
@app.route('/music/<filename>')
def play_music(filename):
    with engine.connect() as c:
        row = c.execute(text('SELECT encrypted_data, nonce, tag, aes_key_id FROM songs WHERE filename=:fn'), {'fn': filename}).fetchone()
    if not row:
        return 'Not Found', 404
    enc_blob, nonce_mv, tag_mv, kid = row
    enc   = bytes(enc_blob)
    nonce = bytes(nonce_mv)
    tag   = bytes(tag_mv)
    key_hex = vault.secrets.kv.v2.read_secret_version(path=f'music/{kid}', mount_point='secret')['data']['data']['key']
    aesgcm = AESGCM(bytes.fromhex(key_hex))
    try:
        pt = aesgcm.decrypt(nonce, enc + tag, None)
    except Exception as exc:
        return f'Decrypt error: {exc}', 500

    return send_file(BytesIO(pt), mimetype='audio/mpeg', as_attachment=False)

# ---------------------------------------------------------------------------
# 5. Helper: decrypt full plaintext from DB
# ---------------------------------------------------------------------------

def get_plaintext_from_db(filename: str) -> bytes:
    with engine.connect() as c:
        row = c.execute(text('SELECT encrypted_data, nonce, tag, aes_key_id FROM songs WHERE filename=:fn'), {'fn': filename}).fetchone()
    if not row:
        raise FileNotFoundError(filename)
    enc_blob, nonce_mv, tag_mv, kid = row
    enc   = bytes(enc_blob)
    nonce = bytes(nonce_mv)
    tag   = bytes(tag_mv)
    key_hex = vault.secrets.kv.v2.read_secret_version(path=f'music/{kid}', mount_point='secret')['data']['data']['key']
    aesgcm = AESGCM(bytes.fromhex(key_hex))
    return aesgcm.decrypt(nonce, enc + tag, None)

# ---------------------------------------------------------------------------
# 6. AES‑CTR streaming endpoint (chunked)
# ---------------------------------------------------------------------------
@app.route('/stream/<filename>')
def stream_music(filename):
    if 'shared_secret' not in session:
        return 'Key‑exchange required', 401

    try:
        pt = get_plaintext_from_db(filename)
    except FileNotFoundError:
        return 'Not Found', 404

    key = derive_aesctr_key(bytes.fromhex(session['shared_secret']))  # 32‑byte

    def gen():
        CHUNK = 64 * 1024
        for idx, off in enumerate(range(0, len(pt), CHUNK)):
            plain_chunk = pt[off:off+CHUNK]
            iv = b'\x00' * 8 + idx.to_bytes(8, 'big')
            nonce = iv[:8]
            initval = int.from_bytes(iv[8:], byteorder='big')
            cipher = AES.new(key, AES.MODE_CTR, nonce=nonce, initial_value=initval)
            yield idx.to_bytes(8, 'big') + cipher.encrypt(plain_chunk)

# ---------------------------------------------------------------------------
# 7. ECDH key‑exchange endpoints
# ---------------------------------------------------------------------------
@app.route('/key-exchange')
def key_exchange():
    if 'username' not in session:
        return jsonify(error='Unauthorized'), 401
    priv, pub = generate_ecdhe_keypair()
    session['server_priv_scalar'] = priv.private_numbers().private_value
    return jsonify(
        server_pubkey_ecdhe=serialize_public_key(pub).hex(),
        signature=sign_ecdhe_pubkey(serialize_public_key(pub)).hex(),
        server_pubkey_ecdsa=get_ecdsa_public_key_bytes().hex()
    )

@app.route('/submit-client-key', methods=['POST'])
def submit_client_key():
    data = request.json or {}
    if 'server_priv_scalar' not in session:
        return jsonify(status='error', message='Session expired'), 400
    client_pub = bytes.fromhex(data.get('client_pubkey_ecdhe', ''))
    server_priv = ec.derive_private_key(session['server_priv_scalar'], ec.SECP256R1())
    shared = compute_shared_secret(server_priv, client_pub)
    session['shared_secret'] = shared.hex()
    print('🔑 Shared secret', shared.hex(), flush=True)
    return jsonify(status='ok')

# ---------------------------------------------------------------------------
if __name__ == '__main__':
    app.run(debug=True)

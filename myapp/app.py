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
    derive_chacha20_key
)
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from Crypto.Cipher import ChaCha20
import hvac

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Database connection
db_url = os.getenv("DB_URL")
if not db_url:
    raise RuntimeError("DB_URL not set in environment")
engine = create_engine(db_url)

# Vault client initialization
vault_addr = os.getenv("VAULT_ADDR")
vault_token = os.getenv("VAULT_TOKEN")
if not vault_addr or not vault_token:
    raise RuntimeError("VAULT_ADDR or VAULT_TOKEN not set in environment")
vault_client = hvac.Client(url=vault_addr, token=vault_token)

# Default route: redirect to login
@app.route('/')
def root():
    return redirect(url_for('login_page'))

# Login page (GET + POST)
@app.route('/login_page', methods=['GET', 'POST'])
def login_page():
    if request.method == 'GET':
        return render_template('login.html')
    username = request.form.get('username')
    password = request.form.get('password')
    try:
        with engine.connect() as conn:
            row = conn.execute(
                text('SELECT password_hash, role FROM users WHERE username = :u'),
                {'u': username}
            ).fetchone()
        if row and verify_password(row[0], password):
            session['username'] = username
            session['role'] = row[1]
            return redirect(url_for('index'))
        return 'Invalid credentials', 401
    except Exception as e:
        return f'Error: {e}', 500

# Register page
@app.route('/register_page', methods=['GET', 'POST'])
def register_page():
    if request.method == 'GET':
        return render_template('register.html')
    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('password')
    role = request.form.get('role', 'user')
    pwd_hash = hash_password(password)
    try:
        with engine.begin() as conn:
            conn.execute(
                text('INSERT INTO users (username, email, password_hash, role) VALUES (:u,:e,:p,:r)'),
                {'u': username, 'e': email, 'p': pwd_hash, 'r': role}
            )
        return redirect(url_for('login_page'))
    except Exception as e:
        return f'Error: {e}', 400

# API: register
@app.route('/register', methods=['POST'])
def register_api():
    data = request.json or {}
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    role = data.get('role', 'user')
    if not username or not email or not password:
        return jsonify({'status':'error','message':'Missing fields'}), 400
    pwd_hash = hash_password(password)
    try:
        with engine.begin() as conn:
            conn.execute(
                text('INSERT INTO users (username, email, password_hash, role) VALUES (:u,:e,:p,:r)'),
                {'u': username, 'e': email, 'p': pwd_hash, 'r': role}
            )
        return jsonify({'status':'success'})
    except Exception as e:
        return jsonify({'status':'error','message':str(e)}), 400

# API: login
@app.route('/login', methods=['POST'])
def login_api():
    data = request.json or {}
    username = data.get('username')
    password = data.get('password')
    try:
        with engine.connect() as conn:
            row = conn.execute(
                text('SELECT password_hash, role FROM users WHERE username = :u'),
                {'u': username}
            ).fetchone()
        if row and verify_password(row[0], password):
            return jsonify({'status':'success','role':row[1]})
        return jsonify({'status':'error','message':'Invalid credentials'}), 401
    except Exception as e:
        return jsonify({'status':'error','message':str(e)}), 500

# Music dashboard
@app.route('/music_list')
def index():
    if 'username' not in session:
        return redirect(url_for('login_page'))
    with engine.connect() as conn:
        rows = conn.execute(text('SELECT filename FROM songs ORDER BY id')).fetchall()
    music_files = [r[0] for r in rows]
    return render_template('index.html', music_files=music_files, role=session.get('role'))

# Upload (artist only)
@app.route('/upload', methods=['GET','POST'])
def upload():
    if session.get('role') != 'artist':
        return 'Unauthorized', 403
    if request.method == 'GET':
        return render_template('upload.html')
    f = request.files.get('file')
    if not f:
        return 'No file', 400
    f.save(os.path.join(app.root_path, 'static', 'music', f.filename))
    return 'Upload successful'

# Play music with AES-GCM decrypt and Range support
@app.route('/music/<filename>')
def play_music(filename):
    with engine.connect() as conn:
        row = conn.execute(
            text('SELECT encrypted_data, nonce, tag, aes_key_id FROM songs WHERE filename = :fn'),
            {'fn': filename}
        ).fetchone()
    if not row:
        return 'Not Found', 404
    enc_blob, nonce_mv, tag_mv, key_id = row
    enc   = bytes(enc_blob)
    nonce = bytes(nonce_mv)
    tag   = bytes(tag_mv)

    # get key from Vault
    try:
        data = vault_client.secrets.kv.v2.read_secret_version(
            path=f'music/{key_id}', mount_point='secret'
        )['data']['data']
        aes_key = bytes.fromhex(data['key'])
    except Exception as e:
        return f'KMS error: {e}', 500

    aesgcm     = AESGCM(aes_key)
    ciphertext = enc + tag
    try:
        pt = aesgcm.decrypt(nonce, ciphertext, None)
    except Exception as e:
        app.logger.error(f'Fail decrypt: {e}')
        return f'Decrypt error: {e}', 500

    # Range support
    size = len(pt)
    r = request.headers.get('Range')
    if r:
        import re
        m = re.match(r'bytes=(\d+)-(\d*)', r)
        if m:
            s = int(m.group(1))
            e = int(m.group(2)) if m.group(2) else size - 1
            if e >= size:
                e = size - 1
            chunk = pt[s:e+1]
            rv = Response(chunk, 206, mimetype='audio/mpeg')
            rv.headers['Content-Range'] = f'bytes {s}-{e}/{size}'
            rv.headers['Accept-Ranges'] = 'bytes'
            rv.headers['Content-Length'] = str(e - s + 1)
            return rv

    # full send
    bio = BytesIO(pt)
    bio.seek(0)
    return send_file(bio, mimetype='audio/mpeg', as_attachment=False, conditional=True)

# Helper: decrypt AES-GCM and return plaintext
def get_plaintext_from_db(filename):
    with engine.connect() as conn:
        row = conn.execute(
            text('SELECT encrypted_data, nonce, tag, aes_key_id FROM songs WHERE filename = :fn'),
            {'fn': filename}
        ).fetchone()
    if not row:
        raise FileNotFoundError(f"{filename} not found")
    enc_blob, nonce_mv, tag_mv, key_id = row
    enc   = bytes(enc_blob)
    nonce = bytes(nonce_mv)
    tag   = bytes(tag_mv)

    data = vault_client.secrets.kv.v2.read_secret_version(
        path=f'music/{key_id}', mount_point='secret'
    )['data']['data']
    aes_key = bytes.fromhex(data['key'])

    aesgcm     = AESGCM(aes_key)
    ciphertext = enc + tag
    return aesgcm.decrypt(nonce, ciphertext, None)

# ChaCha20 streaming endpoint
@app.route('/stream/<filename>')
def stream_music(filename):
    ss_hex = session.get('shared_secret')
    if not ss_hex:
        return 'Key-exchange required', 401

    try:
        pt = get_plaintext_from_db(filename)
    except FileNotFoundError:
        return 'Not Found', 404

    key = derive_chacha20_key(bytes.fromhex(ss_hex))

    def generate():
        idx = 0
        chunk_size = 64 * 1024
        for offset in range(0, len(pt), chunk_size):
            chunk = pt[offset:offset + chunk_size]
            nonce  = b'\x00'*4 + idx.to_bytes(8, 'big')
            cipher = ChaCha20.new(key=key, nonce=nonce)
            yield idx.to_bytes(8, 'big') + cipher.encrypt(chunk)
            idx += 1

    return Response(generate(), mimetype='application/octet-stream')

# ECDHE/ECDSA key exchange endpoints
@app.route('/key-exchange', methods=['GET'])
def key_exchange():
    if 'username' not in session:
        return jsonify({'error':'Unauthorized'}), 401
    priv, pub = generate_ecdhe_keypair()
    pubb      = serialize_public_key(pub)
    sig       = sign_ecdhe_pubkey(pubb)
    ecdsa_pub = get_ecdsa_public_key_bytes()
    session['server_priv_scalar'] = priv.private_numbers().private_value
    return jsonify({
        'server_pubkey_ecdhe': pubb.hex(),
        'signature': sig.hex(),
        'server_pubkey_ecdsa': ecdsa_pub.hex()
    })

@app.route('/submit-client-key', methods=['POST'])
def submit_client_key():
    data = request.json or {}
    priv_scalar = session.get('server_priv_scalar')
    if not priv_scalar:
        return jsonify({'status':'error','message':'Session expired'}), 400
    client_pub = bytes.fromhex(data.get('client_pubkey_ecdhe', ''))
    server_priv = ec.derive_private_key(priv_scalar, ec.SECP256R1())
    shared      = compute_shared_secret(server_priv, client_pub)
    session['shared_secret'] = shared.hex()
    print(f"🔑 Server shared secret: {shared.hex()}", flush=True)
    return jsonify({'status':'ok'})

if __name__ == '__main__':
    app.run(debug=True)

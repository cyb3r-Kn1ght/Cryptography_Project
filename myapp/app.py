from flask import Flask, render_template, Response, request, jsonify, redirect, url_for, session, send_file, current_app, abort
import os
import re
from io import BytesIO
from pydub import AudioSegment
from pydub.generators import Sine
from sqlalchemy import create_engine, text
from dotenv import load_dotenv
from auth_utils import hash_password, verify_password
from crypto_utils import (
    generate_ecdhe_keypair,
    serialize_public_key,
    sign_ecdhe_pubkey,
    compute_shared_secret,
    get_ecdsa_public_key_bytes,
    derive_aesctr_key,  # NEW
    derive_subkey
)
from werkzeug.utils import secure_filename
from mutagen.mp3 import MP3, HeaderNotFoundError                     # NEW
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from Crypto.Cipher import AES  # NEW: for AES‑CTR streaming
import hvac
import hashlib
import numpy as np


# ---------------------------------------------------------------------------
# 0. Init
# ---------------------------------------------------------------------------
load_dotenv()

app = Flask(__name__)
app.secret_key = os.urandom(24)
ALLOWED_EXTENSIONS = {'mp3'}
FRAME = 512          # samples / block
FS    = 44100
K1    = int(15000 / FS * FRAME)   # ≈ 15 kHz bin
K2    = int(17000 / FS * FRAME)   # ≈ 17 kHz bin
DELTA = 10 ** (-34/20)           # -18 dB
FILENAME_RE = re.compile(r'^[A-Za-z0-9_-]+$')

# Cac ham tang cuong bao mat
def allowed_file(filename):
    return (
        '.' in filename and
        filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
    )
def _payload_bits(user_id: str):
    digest = hashlib.sha256(user_id.encode()).digest()  # 256 bit
    for b in digest:
        for i in range(8):
            yield (b >> i) & 1

def embed_watermark(mp3_bytes: bytes, user_id: str) -> bytes:
    """
    Nhúng watermark gắn với user_id bằng cách chỉnh biên độ 2 hệ số FFT (15 & 17 kHz).
    Trả lại bytes MP3 mới (192 kbps).
    """
    audio = AudioSegment.from_file(BytesIO(mp3_bytes), format="mp3")
    samples = np.array(audio.get_array_of_samples(), dtype=np.float32)

    total_blocks = len(samples) // FRAME
    for blk, bit in zip(range(total_blocks), _payload_bits(user_id)):
        start, end = blk * FRAME, (blk + 1) * FRAME
        block = np.fft.rfft(samples[start:end])
        if len(block) <= max(K1, K2):          # bảo vệ array nhỏ
            break
        # áp đặt quan hệ biên độ để mang bit
        if bit == 1 and np.abs(block[K1]) <= np.abs(block[K2]):
            block[K1] = block[K2] * (1 + DELTA)
        elif bit == 0 and np.abs(block[K2]) <= np.abs(block[K1]):
            block[K2] = block[K1] * (1 + DELTA)
        samples[start:end] = np.fft.irfft(block, n=FRAME)

    int16 = np.clip(samples, -32768, 32767).astype(np.int16)
    wm_audio = AudioSegment(
        int16.tobytes(),
        frame_rate=audio.frame_rate,
        sample_width=2,
        channels=audio.channels,
    )
    out = BytesIO()
    wm_audio.export(out, format="mp3", bitrate="192k")
    return out.getvalue()# ---------------------------------------------------------------------------
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

@app.route("/upload", methods=["GET", "POST"])
def upload():
    # 0) Chỉ nghệ sĩ
    if session.get("role") != "artist":
        abort(403)

    if request.method == "GET":
        return render_template("upload.html")

    # 1) Nhận file
    file = request.files.get("file")
    if not file or file.filename == "":
        abort(400, "Chưa chọn file")
    if not allowed_file(file.filename):
        abort(400, "Chỉ cho phép .mp3")

    # 2) Xử lý tên
    filename = secure_filename(file.filename)
    key_id   = filename.rsplit(".", 1)[0]
    if not FILENAME_RE.match(key_id):
        abort(400, "Tên file không hợp lệ")

    # 3) Đọc nội dung
    data = file.read()
    if not data:
        abort(400, "File rỗng")

    # 4) Lấy metadata MP3
    try:
        audio  = MP3(BytesIO(data))
        title  = str(audio.tags.get("TIT2", filename))
        length = int(audio.info.length)
    except HeaderNotFoundError:
        abort(400, "MP3 lỗi")
    artist = session["username"]

    # 5) Mã hoá AES-GCM
    aes_key = AESGCM.generate_key(bit_length=128)
    nonce   = os.urandom(12)
    vault.secrets.kv.v2.create_or_update_secret(
        path=f"music/{key_id}", mount_point="secret",
        secret={"key": aes_key.hex(), "nonce": nonce.hex()}
    )
    aesgcm = AESGCM(aes_key)
    enc    = aesgcm.encrypt(nonce, data, None)
    ciphertext, tag = enc[:-16], enc[-16:]

    # 6) Ghi DB + khởi tạo song_stats
    with engine.begin() as con:
         con.execute(text("INSERT INTO songs (filename,title,artist,length,aes_key_id,nonce,tag,encrypted_data) VALUES (:f,:t,:a,:l,:kid,:n,:tag,:edata)"),
                     {"f": filename, "t": title, "a": artist, "l": length, "kid": key_id, "n": nonce, "tag": tag, "edata": ciphertext})
         song_id = con.execute(text("SELECT id FROM songs WHERE filename=:f"), {"f": filename}).scalar()
         con.execute(text("INSERT INTO song_stats (song_id) VALUES (:sid) ON CONFLICT DO NOTHING"),
                     {"sid": song_id})

    return f"✅ Đã upload & lưu: {filename}", 201


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
@app.route("/stream/<filename>")
def stream_music(filename):
    if "shared_secret" not in session:
        return "Key-exchange required", 401

    try:
        pt = get_plaintext_from_db(filename)
    except FileNotFoundError:
        return "Not Found", 404

    # watermark forensic
    try:
        pt = embed_watermark(pt, session["username"])
    except Exception:
        current_app.logger.exception("Watermark failed")

    master_key = derive_aesctr_key(bytes.fromhex(session["shared_secret"]))

    def gen():
        CHUNK = 64 * 1024
        for idx, off in enumerate(range(0, len(pt), CHUNK)):
            chunk = pt[off:off + CHUNK]
            nonce = os.urandom(8)
            subkey = derive_subkey(master_key, idx, nonce)
            cipher = AES.new(subkey, AES.MODE_CTR, nonce=nonce, initial_value=0)
            yield nonce + idx.to_bytes(8, "big") + cipher.encrypt(chunk)

        # tăng play_count + revenue
        with engine.begin() as con:
            con.execute(text("""
                UPDATE song_stats
                   SET play_count = play_count + 1,
                       revenue    = revenue + 0.005
                 WHERE song_id = (SELECT id FROM songs WHERE filename = :fn)
            """), {"fn": filename})

    return Response(gen(), mimetype="application/octet-stream")
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
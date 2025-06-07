#!/usr/bin/env python3
"""
Script này sẽ:
1. Đọc tất cả file .mp3 trong thư mục `static/music`
2. Sinh key AES-GCM mới cho mỗi file và lưu vào Vault (KV v2 tại `secret/music/<filename>`)
3. Mã hóa nội dung mp3
4. Trích metadata (title, artist, length) bằng mutagen
5. Chèn vào bảng `songs` của PostgreSQL với các trường: filename, title, artist, length, aes_key_id, nonce, tag, encrypted_data

Yêu cầu cài đặt:
  pip install python-dotenv sqlalchemy hvac cryptography mutagen

Phải export trước:
  export DB_URL="postgresql://user:pass@host:5432/cryto_db"
  export VAULT_ADDR="http://<KMS_IP>:8200"
  export VAULT_TOKEN="<root-or-token>"
"""
import os
from dotenv import load_dotenv
from sqlalchemy import create_engine, text
import hvac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from mutagen.mp3 import MP3

load_dotenv()

# Cấu hình kết nối
DB_URL = os.getenv("DB_URL")
VAULT_ADDR = os.getenv("VAULT_ADDR")
VAULT_TOKEN = os.getenv("VAULT_TOKEN")

if not all([DB_URL, VAULT_ADDR, VAULT_TOKEN]):
    raise RuntimeError("Vui lòng set DB_URL, VAULT_ADDR, VAULT_TOKEN trong env")

# Khởi tạo client Vault và DB
vault_client = hvac.Client(url=VAULT_ADDR, token=VAULT_TOKEN)
engine = create_engine(DB_URL)

# Đường dẫn chứa file mp3
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MUSIC_DIR = os.path.join(BASE_DIR, 'static', 'music')

for fname in os.listdir(MUSIC_DIR):
    if not fname.lower().endswith('.mp3'):
        continue
    path = os.path.join(MUSIC_DIR, fname)
    key_id = os.path.splitext(fname)[0]  # dùng tên file (không có đuôi) làm key_id

    # 1) Sinh hoặc ghi key mới vào Vault
    aes_key = AESGCM.generate_key(bit_length=128)
    nonce = os.urandom(12)
    vault_client.secrets.kv.v2.create_or_update_secret(
        path=f"music/{key_id}",
        secret={
            'key': aes_key.hex(),
            'nonce': nonce.hex()
        },
        mount_point='secret'
    )

    # 2) Đọc file và mã hóa
    with open(path, 'rb') as f:
        raw = f.read()
    aesgcm = AESGCM(aes_key)
    encrypted = aesgcm.encrypt(nonce, raw, None)
    ciphertext = encrypted[:-16]
    tag = encrypted[-16:]

    # 3) Lấy metadata
    audio = MP3(path)
    title = audio.tags.get('TIT2', fname)
    artist = audio.tags.get('TPE1', '')
    length = int(audio.info.length)

    # 4) Chèn vào DB
    with engine.begin() as conn:
        conn.execute(text("""
            INSERT INTO songs
            (filename, title, artist, length, aes_key_id, nonce, tag, encrypted_data)
            VALUES
            (:filename, :title, :artist, :length, :aes_key_id, :nonce, :tag, :encrypted_data)
        """), {
            'filename': fname,
            'title': str(title),
            'artist': str(artist),
            'length': length,
            'aes_key_id': key_id,
            'nonce': nonce,
            'tag': tag,
            'encrypted_data': ciphertext
        })
    print(f"Đã lưu nhạc: {fname} -> song_id={key_id}")

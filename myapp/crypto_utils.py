from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF   # <- đúng bảnfrom Crypto.Hash import SHA256
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ECDSA_PRIV_FILE = os.path.join(BASE_DIR, "ecdsa_private_key.pem")
ECDSA_PUB_FILE  = os.path.join(BASE_DIR, "ecdsa_public_key.der")

# Tải hoặc tạo private key ECDSA
if os.path.exists(ECDSA_PRIV_FILE):
    with open(ECDSA_PRIV_FILE, "rb") as f:
        ecdsa_private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )
else:
    ecdsa_private_key = ec.generate_private_key(ec.SECP256R1(), backend=default_backend())
    with open(ECDSA_PRIV_FILE, "wb") as f:
        f.write(ecdsa_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open(ECDSA_PUB_FILE, "wb") as f:
        f.write(ecdsa_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

ecdsa_public_key = ecdsa_private_key.public_key()

def generate_ecdhe_keypair():
    private_key = ec.generate_private_key(ec.SECP256R1(), backend=default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_public_key(pubkey):
    return pubkey.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )

def sign_ecdhe_pubkey(ecdhe_pub_bytes):
    # 1. Sinh DER-signature
    der_sig = ecdsa_private_key.sign(
        ecdhe_pub_bytes,
        ec.ECDSA(hashes.SHA256())
    )
    # 2. Giải mã DER để lấy (r, s)
    r, s = decode_dss_signature(der_sig)
    # 3. Chuyển mỗi số thành 32-byte big-endian và ghép lại
    coord_len = (ec.SECP256R1().key_size + 7) // 8  # =32
    r_bytes = r.to_bytes(coord_len, byteorder='big')
    s_bytes = s.to_bytes(coord_len, byteorder='big')
    return r_bytes + s_bytes

def compute_shared_secret(server_priv_key, client_pub_bytes):
    client_pub_key = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), client_pub_bytes
    )
    shared_secret = server_priv_key.exchange(ec.ECDH(), client_pub_key)
    return shared_secret

def get_ecdsa_public_key_bytes():
    return ecdsa_public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def derive_chacha20_key(shared_secret: bytes, salt: bytes = b'stream-salt') -> bytes:
    """
    HKDF-SHA256 → 32-byte key cho ChaCha20.
    Salt có thể fixe hoặc negotiate trước.
    """
    return HKDF(
        master=shared_secret,
        key_len=32,
        salt=salt,
        hashmod=SHA256,
        context=b'chacha20-stream'
    )
def derive_aesctr_key(shared_secret: bytes) -> bytes:
    """HKDF-SHA256 → 32-byte key cho AES-CTR."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),   # tham số hợp lệ
        length=32,
        salt=b"stream-salt",
        info=b"aes-ctr-stream",
    )
    return hkdf.derive(shared_secret)
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.backends import default_backend

# Tạo key ECDSA (long-term)
ecdsa_private_key = ec.generate_private_key(ec.SECP256R1(), backend=default_backend())
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
    signature = ecdsa_private_key.sign(
        ecdhe_pub_bytes,
        ec.ECDSA(hashes.SHA256())
    )
    return signature

def compute_shared_secret(server_priv_key, client_pub_bytes):
    client_pub_key = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), client_pub_bytes
    )
    shared_secret = server_priv_key.exchange(ec.ECDH(), client_pub_key)
    return shared_secret

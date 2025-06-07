# scripts/gen_client_pub.py
from crypto_utils import generate_ecdhe_keypair, serialize_public_key

priv, pub = generate_ecdhe_keypair()
client_pub_hex = serialize_public_key(pub).hex()
print(client_pub_hex)

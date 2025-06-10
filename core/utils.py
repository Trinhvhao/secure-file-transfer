import os

from cryptography.hazmat.primitives import hashes, serialization, hmac, constant_time  # Updated import
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

DATA_DIR = r"C:\Users\Admin\PycharmProjects\secure_file_transferr\data"
os.makedirs(DATA_DIR, exist_ok=True)
print(f"DATA_DIR in utils.py: {DATA_DIR}")


def generate_rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key


def save_keys(private_key, public_key, private_key_path, public_key_path):
    private_key_full_path = os.path.join(DATA_DIR, private_key_path)
    public_key_full_path = os.path.join(DATA_DIR, public_key_path)
    print(f"Attempting to save private key to: {private_key_full_path}")
    print(f"Attempting to save public key to: {public_key_full_path}")
    try:
        with open(private_key_full_path, 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        with open(public_key_full_path, 'wb') as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        print(f"Successfully saved private key: {os.path.exists(private_key_full_path)}")
        print(f"Successfully saved public key: {os.path.exists(public_key_full_path)}")
    except Exception as e:
        print(f"Error saving keys: {e}")
        raise


def load_public_key(public_key_path):
    public_key_full_path = os.path.join(DATA_DIR, public_key_path)
    print(f"Attempting to load public key from: {public_key_full_path}")
    if not os.path.exists(public_key_full_path):
        print(f"File not found: {public_key_full_path}")
        raise FileNotFoundError(f"Public key file not found: {public_key_full_path}")
    with open(public_key_full_path, 'rb') as f:
        return serialization.load_pem_public_key(f.read())


def sign_data(data, private_key):
    return private_key.sign(data, asym_padding.PKCS1v15(), hashes.SHA512())


def verify_signature(data, signature, public_key):
    try:
        public_key.verify(signature, data, asym_padding.PKCS1v15(), hashes.SHA512())
        return True
    except Exception as e:
        print(f"Signature verification error: {e}")
        return False


def encrypt_session_key(session_key, public_key):
    return public_key.encrypt(session_key, asym_padding.PKCS1v15())


def decrypt_session_key(encrypted_session_key, private_key):
    return private_key.decrypt(encrypted_session_key, asym_padding.PKCS1v15())


def aes_encrypt(data, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padding_length = 16 - (len(data) % 16)
    data += bytes([padding_length] * padding_length)
    ciphertext = encryptor.update(data) + encryptor.finalize()
    return iv, ciphertext


def aes_decrypt(iv, ciphertext, key):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    padding_length = padded_data[-1]
    return padded_data[:-padding_length]


def calculate_hash(data):
    digest = hashes.Hash(hashes.SHA512())
    digest.update(data)
    return digest.finalize()


def generate_hmac(data, key):
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    return h.finalize()


def verify_hmac(data, hmac_value, key):
    calculated_hmac = generate_hmac(data, key)
    return constant_time.bytes_eq(calculated_hmac, hmac_value)  # Fixed line

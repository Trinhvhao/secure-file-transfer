import base64
import json
import logging
import os
import socket
from datetime import datetime, timedelta

from core.utils import generate_rsa_keys, save_keys, load_public_key, encrypt_session_key, aes_encrypt, sign_data, \
    calculate_hash

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

DATA_DIR = r"C:\Users\Admin\PycharmProjects\secure_file_transferr\data"


def send_local(file_path: str, receiver_email: str, receiver_ip: str):
    try:
        try:
            socket.inet_aton(receiver_ip)
        except socket.error:
            logger.error("IP không hợp lệ!")
            return "NACK: Invalid IP"

        if not os.path.exists(file_path):
            logger.error(f"File {file_path} không tồn tại!")
            return "NACK: File not found"

        private_key, public_key = generate_rsa_keys()
        save_keys(private_key, public_key, f"private_{os.getpid()}.pem", f"public_{os.getpid()}.pem")

        session_key = os.urandom(32)
        receiver_public_key = load_public_key(f"public_{receiver_email}.pem")
        encrypted_session_key = encrypt_session_key(session_key, receiver_public_key)

        with open(file_path, 'rb') as f:
            data = f.read()
        iv, ciphertext = aes_encrypt(data, session_key)

        expiration = (datetime.utcnow() + timedelta(hours=24)).isoformat() + 'Z'
        hash_data = iv + ciphertext + expiration.encode()
        file_hash = calculate_hash(hash_data)

        metadata = f"{os.path.basename(file_path)}|{datetime.utcnow().isoformat()}".encode()
        signature = sign_data(metadata, private_key)

        packet = {
            'iv': base64.b64encode(iv).decode('utf-8'),
            'cipher': base64.b64encode(ciphertext).decode('utf-8'),
            'hash': base64.b64encode(file_hash).decode('utf-8'),
            'sig': base64.b64encode(signature).decode('utf-8'),
            'exp': expiration,
            'encrypted_session_key': base64.b64encode(encrypted_session_key).decode('utf-8'),
            'metadata': metadata.decode('utf-8')
        }

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((receiver_ip, 12345))
                s.sendall(json.dumps(packet).encode())
                response = s.recv(1024).decode()
                logger.info(f"Phản hồi: {response}")
                return response
        except Exception as e:
            logger.error(f"Lỗi kết nối: {e}")
            return f"NACK: Connection error {str(e)}"

    except Exception as e:
        logger.error(f"Lỗi gửi file: {e}")
        return f"NACK: Error {str(e)}"

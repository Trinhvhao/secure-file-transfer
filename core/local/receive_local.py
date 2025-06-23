import base64
import json
import logging
import os
import socket
from datetime import datetime

from cryptography.hazmat.primitives import serialization, constant_time

from core.utils import load_public_key, verify_signature, aes_decrypt, calculate_hash, decrypt_session_key

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

DATA_DIR = r"C:\Users\Admin\PycharmProjects\secure_file_transferr\data"
os.makedirs(DATA_DIR, exist_ok=True)


def receive_local(receiver_email: str):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('0.0.0.0', 12345))
        s.listen()
        logger.info("Receiver đang lắng nghe trên cổng 12345...")

        while True:
            try:
                conn, addr = s.accept()
                with conn:
                    logger.info(f"Kết nối từ {addr}")
                    data = conn.recv(4096).decode()
                    if not data:
                        continue
                    packet = json.loads(data)

                    iv = base64.b64decode(packet['iv'])
                    ciphertext = base64.b64decode(packet['cipher'])
                    received_hash = base64.b64decode(packet['hash'])
                    signature = base64.b64decode(packet['sig'])
                    exp = packet['exp']
                    encrypted_session_key = base64.b64decode(packet['encrypted_session_key'])
                    metadata = packet.get('metadata', f"email.txt|{exp}").encode()

                    current_time = datetime.utcnow().isoformat() + 'Z'
                    if current_time > exp:
                        logger.error("File đã hết hạn!")
                        conn.sendall(b"NACK: Timeout")
                        continue

                    hash_data = iv + ciphertext + exp.encode()
                    calculated_hash = calculate_hash(hash_data)
                    if not constant_time.bytes_eq(calculated_hash, received_hash):
                        logger.error("Hash không khớp!")
                        conn.sendall(b"NACK: Invalid hash")
                        continue

                    sender_public_key = load_public_key("public_sender@example.com.pem")
                    if not verify_signature(metadata, signature, sender_public_key):
                        logger.error("Chữ ký không hợp lệ!")
                        conn.sendall(b"NACK: Invalid signature")
                        continue

                    private_key = serialization.load_pem_private_key(
                        open(os.path.join(DATA_DIR, f"private_{receiver_email}.pem"), 'rb').read(),
                        password=None
                    )
                    session_key = decrypt_session_key(encrypted_session_key, private_key)

                    try:
                        plaintext = aes_decrypt(iv, ciphertext, session_key)
                    except Exception as e:
                        logger.error(f"Giải mã AES thất bại: {e}")
                        conn.sendall(b"NACK: Decryption failed")
                        continue

                    filename = packet['metadata'].split('|')[0]
                    output_path = os.path.join(DATA_DIR, f"received_{receiver_email.replace('@', '_')}_{filename}")
                    try:
                        with open(output_path, 'wb') as f:
                            f.write(plaintext)
                        logger.info(f"File giải mã lưu tại: {output_path}")
                        conn.sendall(b"ACK")
                    except Exception as e:
                        logger.error(f"Lỗi lưu file: {e}")
                        conn.sendall(b"NACK: Save failed")

            except Exception as e:
                logger.error(f"Lỗi nhận file: {e}")
                if 'conn' in locals():
                    conn.sendall(f"NACK: Error {str(e)}".encode())


if __name__ == "__main__":
    receiver_email = os.getenv('RECEIVER_EMAIL', input("Nhập email của receiver: "))
    receive_local(receiver_email)

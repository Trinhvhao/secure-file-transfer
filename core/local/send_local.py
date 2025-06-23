import base64
import json
import os
import socket
from datetime import datetime, timedelta
from datetime import timezone

from core.utils import *

HOST = '127.0.0.1'
PORT = 65432
DATA_DIR = r"C:\Users\Admin\PycharmProjects\secure_file_transferr\data"
print(f"DATA_DIR in sender_local.py: {DATA_DIR}")


def sender_local(file_path, receiver_username):
    """
    Gửi file đã mã hóa đến receiver thông qua local network theo đề bài.

    Args:
        file_path (str): Đường dẫn đến file cần gửi (ví dụ: email.txt).
        receiver_username (str): Tên người nhận.

    Returns:
        str: Response từ receiver (ACK hoặc NACK).

    Raises:
        Exception: Nếu có lỗi trong quá trình gửi.
    """
    print(f"Sending encrypted file: {file_path} to receiver: {receiver_username}")
    # Tạo và lưu cặp khóa RSA 2048-bit
    private_key, public_key = generate_rsa_keys()
    save_keys(private_key, public_key, 'sender_private.pem', 'sender_public.pem')

    # Đọc file từ đường dẫn
    full_file_path = os.path.join(DATA_DIR, os.path.basename(file_path))
    print(f"Checking file at: {full_file_path}")
    if not os.path.exists(full_file_path):
        print(f"Error: File not found at {full_file_path}. Directory contents: {os.listdir(DATA_DIR)}")
        raise FileNotFoundError(f"Input file not found: {full_file_path}")
    with open(full_file_path, 'rb') as f:
        file_data = f.read()
    print(f"File read successfully, size: {len(file_data)} bytes")

    # Tạo khóa session và khóa HMAC ngẫu nhiên (32 byte cho AES-256)
    session_key = os.urandom(32)
    hmac_key = os.urandom(32)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(10)  # Timeout 10 giây
        print(f"Connecting to {HOST}:{PORT}")
        try:
            s.connect((HOST, PORT))
        except socket.timeout:
            print("Connection timed out")
            raise Exception("Connection to receiver timed out")
        print("Sending Hello!")
        s.sendall(b"Hello!")
        response = s.recv(1024).decode()
        print(f"Received response: {response}")
        if response != "Ready!":
            raise Exception("Handshake failed")

        # Gửi khóa công khai của sender
        sender_public_path = os.path.join(DATA_DIR, 'sender_public.pem')
        if not os.path.exists(sender_public_path):
            print(f"Error: sender_public.pem not found at {sender_public_path}")
            raise FileNotFoundError(f"Public key file not found: {sender_public_path}")
        with open(sender_public_path, 'rb') as f:
            s.sendall(f.read())
        print("Sent sender's public key")

        # Nhận khóa công khai của receiver
        public_key_data = s.recv(4096)
        with open(os.path.join(DATA_DIR, 'receiver_public.pem'), 'wb') as f:
            f.write(public_key_data)
        print("Received receiver's public key")

        # Thiết lập thời hạn 24 giờ
        expiration = (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat().replace('+00:00', 'Z')
        file_name = os.path.basename(file_path)

        # Tạo metadata và ký số bằng RSA/SHA-512
        metadata = f"{file_name}|{receiver_username}|{expiration}".encode()
        print(f"Signing metadata: {metadata.decode()}")
        signature = sign_data(metadata, private_key)
        print(f"Generated signature: {base64.b64encode(signature).decode()}")

        # Mã hóa khóa session và khóa HMAC bằng RSA của receiver
        encrypted_session_key = encrypt_session_key(session_key, load_public_key('receiver_public.pem'))
        encrypted_hmac_key = encrypt_session_key(hmac_key, load_public_key('receiver_public.pem'))

        # Mã hóa file bằng AES-CBC
        iv, ciphertext = aes_encrypt(file_data, session_key)
        print(f"File encrypted with AES-CBC, size: {len(ciphertext)} bytes")

        # Tính hash SHA-512 cho tính toàn vẹn
        hash_input = iv + ciphertext + expiration.encode()
        hash_value = calculate_hash(hash_input)
        print(f"Calculated SHA-512 hash: {base64.b64encode(hash_value).decode()}")

        # Tính HMAC (sử dụng SHA-256 từ utils.py)
        mac = generate_hmac(hash_input, hmac_key)
        print(f"Generated HMAC: {base64.b64encode(mac).decode()}")

        # Tạo gói tin JSON
        packet = {
            "iv": base64.b64encode(iv).decode(),
            "cipher": base64.b64encode(ciphertext).decode(),
            "hash": base64.b64encode(hash_value).decode(),
            "sig": base64.b64encode(signature).decode(),
            "mac": base64.b64encode(mac).decode(),
            "hmac_key": base64.b64encode(encrypted_hmac_key).decode(),
            "exp": expiration,
            "encrypted_session_key": base64.b64encode(encrypted_session_key).decode(),
            "file_name": file_name,
            "receiver_username": receiver_username
        }
        packet_data = json.dumps(packet).encode()
        packet_length = len(packet_data)
        print(f"Sending encrypted packet of {packet_length} bytes to {receiver_username}")

        # Gửi gói tin
        s.sendall(packet_length.to_bytes(8, 'big'))
        s.sendall(packet_data)

        # Nhận phản hồi
        response = s.recv(1024).decode()
        print(f"Received: {response}")
        if "NACK" in response:
            raise Exception(response)
        return response


if __name__ == "__main__":
    try:
        sender_local(r"C:\Users\Admin\PycharmProjects\secure_file_transfer\data\viettelAI_data3.txt", "user2")
    except Exception as e:
        print(f"Error: {e}")
import base64
import json
import socket
from datetime import datetime, timedelta
from datetime import timezone

from core.utils import *

HOST = '127.0.0.1'
PORT = 65432
DATA_DIR = r"C:\Users\Admin\PycharmProjects\secure_file_transfer\data"
print(f"DATA_DIR in sender_local.py: {DATA_DIR}")


def sender_local(file_path, receiver_username):
    """
    Gửi file đến receiver thông qua local network

    Args:
        file_path (str): Đường dẫn đến file cần gửi
        receiver_username (str): Tên người nhận

    Returns:
        str: Response từ receiver
    """
    print(f"Sending file: {file_path} to receiver: {receiver_username}")
    private_key, public_key = generate_rsa_keys()
    save_keys(private_key, public_key, 'sender_private.pem', 'sender_public.pem')

    full_file_path = os.path.join(DATA_DIR, os.path.basename(file_path))
    print(f"Reading file from: {full_file_path}")
    if not os.path.exists(full_file_path):
        print(f"Error: File not found at {full_file_path}")
        raise FileNotFoundError(f"Input file not found: {full_file_path}")
    with open(full_file_path, 'rb') as f:
        file_data = f.read()
    print("File read successfully")

    session_key = os.urandom(32)
    hmac_key = os.urandom(32)  # Tạo khóa HMAC bí mật

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(10)  # Thêm timeout 10 giây
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

        sender_public_path = os.path.join(DATA_DIR, 'sender_public.pem')
        if not os.path.exists(sender_public_path):
            print(f"Error: sender_public.pem not found at {sender_public_path}")
            raise FileNotFoundError(f"Public key file not found: {sender_public_path}")
        with open(sender_public_path, 'rb') as f:
            s.sendall(f.read())
        print("Sent public key")

        public_key_data = s.recv(4096)
        with open(os.path.join(DATA_DIR, 'receiver_public.pem'), 'wb') as f:
            f.write(public_key_data)
        print("Received receiver's public key")

        expiration = (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat().replace('+00:00', 'Z')
        file_name = os.path.basename(file_path)
        # Thêm receiver_username vào metadata
        metadata = f"{file_name}|{receiver_username}|{expiration}".encode()
        print(f"Sending metadata: {metadata.decode()}")
        signature = sign_data(metadata, private_key)
        print(f"Generated signature: {base64.b64encode(signature).decode()}")
        encrypted_session_key = encrypt_session_key(session_key, load_public_key('receiver_public.pem'))
        encrypted_hmac_key = encrypt_session_key(hmac_key, load_public_key('receiver_public.pem'))  # Mã hóa khóa HMAC

        iv, ciphertext = aes_encrypt(file_data, session_key)
        hash_input = iv + ciphertext + expiration.encode()
        hash_value = calculate_hash(hash_input)
        mac = generate_hmac(iv + ciphertext + expiration.encode(), hmac_key)  # Tạo HMAC

        packet = {
            "iv": base64.b64encode(iv).decode(),
            "cipher": base64.b64encode(ciphertext).decode(),
            "hash": base64.b64encode(hash_value).decode(),
            "sig": base64.b64encode(signature).decode(),
            "mac": base64.b64encode(mac).decode(),  # Thêm HMAC vào gói tin
            "hmac_key": base64.b64encode(encrypted_hmac_key).decode(),  # Gửi khóa HMAC đã mã hóa
            "exp": expiration,
            "encrypted_session_key": base64.b64encode(encrypted_session_key).decode(),
            "file_name": file_name,
            "receiver_username": receiver_username  # Thêm receiver_username vào packet
        }
        packet_data = json.dumps(packet).encode()
        packet_length = len(packet_data)
        print(f"Sending packet of {packet_length} bytes to {receiver_username}")

        s.sendall(packet_length.to_bytes(8, 'big'))
        s.sendall(packet_data)

        response = s.recv(1024).decode()
        print(f"Received: {response}")
        if "NACK" in response:
            raise Exception(response)
        return response
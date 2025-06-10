import base64
import json
import os
import socket
from datetime import datetime, timedelta
from datetime import timezone

from core.utils import *

BASE_DIR = r"C:\Users\Admin\PycharmProjects\secure_file_transferr"
DATA_DIR = os.path.join(BASE_DIR, "data")
print(f"DATA_DIR in sender_local.py: {DATA_DIR}")

# Sử dụng 0.0.0.0 để thử kết nối với bất kỳ máy nào lắng nghe cổng
HOST = '0.0.0.0'  # Không thực sự broadcast, cần receiver chạy
PORT = 65432

def sender_local(file_path, receiver_username):
    print(f"Sending encrypted file: {file_path} to receiver: {receiver_username}")
    private_key, public_key = generate_rsa_keys()
    save_keys(private_key, public_key, 'sender_private.pem', 'sender_public.pem')

    full_file_path = os.path.join(DATA_DIR, os.path.basename(file_path))
    print(f"Checking file at: {full_file_path}")
    if not os.path.exists(full_file_path):
        print(f"Error: File not found at {full_file_path}. Directory contents: {os.listdir(DATA_DIR)}")
        raise FileNotFoundError(f"Input file not found: {full_file_path}")
    with open(full_file_path, 'rb') as f:
        file_data = f.read()
    print(f"File read successfully, size: {len(file_data)} bytes")

    session_key = os.urandom(32)
    hmac_key = os.urandom(32)

    # Thử kết nối với bất kỳ máy nào lắng nghe cổng 65432
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(10)
        print(f"Attempting to connect to any receiver on {HOST}:{PORT}")
        try:
            # Thay 0.0.0.0 bằng IP router hoặc thử các IP trong mạng (cần logic nâng cao hơn)
            s.connect((HOST, PORT))  # Cần receiver chạy và lắng nghe
        except socket.timeout:
            print("Connection timed out. Ensure a receiver is running on the network.")
            raise Exception("No receiver found on network")
        except ConnectionRefusedError:
            print("Connection refused. Ensure a receiver is running on port 65432.")
            raise Exception("No receiver listening")
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
        print("Sent sender's public key")

        public_key_data = s.recv(4096)
        with open(os.path.join(DATA_DIR, 'receiver_public.pem'), 'wb') as f:
            f.write(public_key_data)
        print("Received receiver's public key")

        expiration = (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat().replace('+00:00', 'Z')
        file_name = os.path.basename(file_path)

        metadata = f"{file_name}|{receiver_username}|{expiration}".encode()
        print(f"Signing metadata: {metadata.decode()}")
        signature = sign_data(metadata, private_key)
        print(f"Generated signature: {base64.b64encode(signature).decode()}")

        encrypted_session_key = encrypt_session_key(session_key, load_public_key('receiver_public.pem'))
        encrypted_hmac_key = encrypt_session_key(hmac_key, load_public_key('receiver_public.pem'))

        iv, ciphertext = aes_encrypt(file_data, session_key)
        print(f"File encrypted with AES-CBC, size: {len(ciphertext)} bytes")

        hash_input = iv + ciphertext + expiration.encode()
        hash_value = calculate_hash(hash_input)
        print(f"Calculated SHA-512 hash: {base64.b64encode(hash_value).decode()}")

        mac = generate_hmac(hash_input, hmac_key)
        print(f"Generated HMAC: {base64.b64encode(mac).decode()}")

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

        s.sendall(packet_length.to_bytes(8, 'big'))
        s.sendall(packet_data)

        response = s.recv(1024).decode()
        print(f"Received: {response}")
        if "NACK" in response:
            raise Exception(response)
        return response


if __name__ == "__main__":
    try:
        sender_local(os.path.join(DATA_DIR, "viettelAI_data3.txt"), "user2")
    except Exception as e:
        print(f"Error: {e}")
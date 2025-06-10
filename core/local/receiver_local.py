import base64
import json
import os
import socket
from datetime import datetime, timezone

from core.utils import *

BASE_DIR = r"C:\Users\Admin\PycharmProjects\secure_file_transferr"
DATA_DIR = os.path.join(BASE_DIR, "data")
print(f"DATA_DIR in receiver_local.py: {DATA_DIR}")

HOST = '0.0.0.0'  # Lắng nghe tất cả kết nối từ mạng
PORT = 65432

def receiver_local():
    print("Starting receiver on {}:{}".format(HOST, PORT))
    private_key, public_key = generate_rsa_keys()
    save_keys(private_key, public_key, 'receiver_private.pem', 'receiver_public.pem')

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.settimeout(60)
        s.bind((HOST, PORT))
        s.listen(5)
        print("Listening for connections from any machine on the network...")
        while True:
            try:
                conn, addr = s.accept()
                print(f"Connected by {addr}")
                data = conn.recv(1024).decode()
                print(f"Received handshake: {data}")
                if data != "Hello!":
                    print("Invalid handshake received")
                    conn.sendall(b"NACK: Invalid handshake")
                    conn.close()
                    continue
                conn.sendall(b"Ready!")
                print("Sent Ready response")

                receiver_public_path = os.path.join(DATA_DIR, 'receiver_public.pem')
                if not os.path.exists(receiver_public_path):
                    print(f"Error: receiver_public.pem not found at {receiver_public_path}")
                    conn.sendall(b"NACK: Public key not found")
                    conn.close()
                    continue
                with open(receiver_public_path, 'rb') as f:
                    conn.sendall(f.read())
                print("Sent receiver's public key")

                public_key_data = conn.recv(4096)
                with open(os.path.join(DATA_DIR, 'sender_public.pem'), 'wb') as f:
                    f.write(public_key_data)
                print("Received sender's public key")

                length_data = conn.recv(8)
                if not length_data:
                    conn.sendall(b"NACK: Invalid packet length")
                    conn.close()
                    continue
                packet_length = int.from_bytes(length_data, 'big')
                print(f"Expecting packet of {packet_length} bytes")

                received_data = b""
                while len(received_data) < packet_length:
                    chunk = conn.recv(min(4096, packet_length - len(received_data)))
                    if not chunk:
                        conn.sendall(b"NACK: Connection closed")
                        conn.close()
                        break
                    received_data += chunk
                print("Received encrypted packet")

                try:
                    packet = json.loads(received_data.decode())
                except json.JSONDecodeError as e:
                    print(f"JSON decode error: {e}")
                    conn.sendall(b"NACK: Invalid JSON")
                    conn.close()
                    continue

                iv = base64.b64decode(packet['iv'])
                ciphertext = base64.b64decode(packet['cipher'])
                hash_value = base64.b64decode(packet['hash'])
                signature = base64.b64decode(packet['sig'])
                mac = base64.b64decode(packet['mac'])
                encrypted_session_key = base64.b64decode(packet['encrypted_session_key'])
                encrypted_hmac_key = base64.b64decode(packet['hmac_key'])
                expiration = packet['exp']
                file_name = packet.get('file_name', 'email.txt')
                receiver_username = packet.get('receiver_username', 'unknown')

                current_time = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
                if current_time > expiration:
                    print(f"Timeout: Current time {current_time} > Expiration {expiration}")
                    conn.sendall(b"NACK: Timeout")
                    conn.close()
                    continue

                metadata = f"{file_name}|{receiver_username}|{expiration}".encode()
                print(f"Verifying metadata: {metadata.decode()}")
                if not verify_signature(metadata, signature, load_public_key('sender_public.pem')):
                    print("Signature verification failed")
                    conn.sendall(b"NACK: Invalid signature")
                    conn.close()
                    continue
                print("Signature verified successfully")

                hash_input = iv + ciphertext + expiration.encode()
                if calculate_hash(hash_input) != hash_value:
                    print("Integrity check failed")
                    conn.sendall(b"NACK: Integrity check failed")
                    conn.close()
                    continue
                print("Hash verified successfully")

                session_key = decrypt_session_key(encrypted_session_key, private_key)
                print("Session key decrypted successfully")

                hmac_key = decrypt_session_key(encrypted_hmac_key, private_key)
                if not verify_hmac(hash_input, mac, hmac_key):
                    print("HMAC verification failed")
                    conn.sendall(b"NACK: Invalid HMAC")
                    conn.close()
                    continue
                print("HMAC verified successfully")

                decrypted_data = aes_decrypt(iv, ciphertext, session_key)
                print(f"File decrypted with AES-CBC, size: {len(decrypted_data)} bytes")

                received_file_path = os.path.join(DATA_DIR, f"received_{receiver_username}_{file_name}")
                print(f"Saving decrypted file to: {received_file_path}")
                with open(received_file_path, 'wb') as f:
                    f.write(decrypted_data)
                print(f"Decrypted file saved for user: {receiver_username}")

                conn.sendall(b"ACK")
                print("Sent ACK")
                conn.close()
            except socket.timeout:
                print("Accept timed out, retrying...")
                continue
            except Exception as e:
                print(f"Error: {e}")
                try:
                    conn.sendall(b"NACK: Server error")
                    conn.close()
                except:
                    pass
                continue


if __name__ == "__main__":
    try:
        receiver_local()
    except Exception as e:
        print(f"Error: {e}")
        input("Press Enter to exit...")
import base64
import json
import socket
from datetime import datetime
from datetime import timezone

from core.utils import *

HOST = '127.0.0.1'
PORT = 65432
DATA_DIR = r"C:\Users\Admin\PycharmProjects\secure_file_transfer\data"
print(f"DATA_DIR in receiver_local.py: {DATA_DIR}")


def receiver_local():
    print("Starting receiver on {}:{}".format(HOST, PORT))
    private_key, public_key = generate_rsa_keys()
    save_keys(private_key, public_key, 'receiver_private.pem', 'receiver_public.pem')

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.settimeout(60)  # Tăng timeout lên 60 giây
        s.bind((HOST, PORT))
        s.listen(5)  # Cho phép 5 kết nối chờ
        print("Listening for connections...")
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
                print("Received packet")

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
                encrypted_hmac_key = base64.b64decode(packet['hmac_key'])
                expiration = packet['exp']
                encrypted_session_key = base64.b64decode(packet['encrypted_session_key'])
                file_name = packet.get('file_name', 'email.txt')
                receiver_username = packet.get('receiver_username', 'unknown')  # Lấy receiver_username từ packet

                current_time = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
                if current_time > expiration:
                    conn.sendall(b"NACK: Timeout")
                    conn.close()
                    continue

                # Cập nhật metadata để handle format mới (backward compatible)
                metadata_parts = [file_name]
                if receiver_username != 'unknown':
                    metadata_parts.append(receiver_username)
                metadata_parts.append(expiration)
                metadata = "|".join(metadata_parts).encode()

                print(f"Verifying metadata: {metadata.decode()}")
                print(f"Received signature: {base64.b64encode(signature).decode()}")
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

                session_key = decrypt_session_key(encrypted_session_key, private_key)
                hmac_key = decrypt_session_key(encrypted_hmac_key, private_key)
                if not verify_hmac(iv + ciphertext + expiration.encode(), mac, hmac_key):
                    print("MAC verification failed")
                    conn.sendall(b"NACK: Invalid MAC")
                    conn.close()
                    continue
                print("MAC verified successfully")

                decrypted_data = aes_decrypt(iv, ciphertext, session_key)

                # Thêm receiver_username vào tên file để phân biệt
                if receiver_username != 'unknown':
                    received_file_path = os.path.join(DATA_DIR, f'received_{receiver_username}_{file_name}')
                else:
                    received_file_path = os.path.join(DATA_DIR, f'received_{file_name}')

                print(f"Saving received file to: {received_file_path}")
                with open(received_file_path, 'wb') as f:
                    f.write(decrypted_data)
                print(f"File received and saved for user: {receiver_username}")

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
from classical_crypto import ClassicalCrypto
from post_quantum_crypto import PostQuantumCrypto
from hybrid_crypto import HybridCrypto

import csv
import socket
import threading
import struct
import time

MODE = "PQC"  # CLASSICAL / PQC / HYBRID

HOST = "127.0.0.1"
PORT = 5000

secure_channel_established = False
my_role = None

# Key holders
my_ecdh_public = None
my_kyber_public = None
my_public_key = None

session_start_time = 0
total_messages = 0
total_bytes_sent = 0
total_bytes_received = 0

# Crypto selection
if MODE == "CLASSICAL":
    crypto = ClassicalCrypto()
elif MODE == "PQC":
    crypto = PostQuantumCrypto()
elif MODE == "HYBRID":
    crypto = HybridCrypto()


def send_packet(sock, msg_type, payload):
    global total_bytes_sent
    header = msg_type + struct.pack("!I", len(payload))
    packet = header + payload
    total_bytes_sent += len(packet)
    sock.sendall(packet)

def receive_exact(sock, length):
    global total_bytes_sent
    global total_bytes_received
    data = b''
    while len(data) < length:
        more = sock.recv(length - len(data))
        if not more:
            raise ConnectionError("Connection closed")
        total_bytes_received += len(more)
        data += more
    return data

def receive_messages(sock):
    global secure_channel_established
    global my_role, my_ecdh_public, my_kyber_public, my_public_key
    global session_start_time # now this function is allowed to update time

    while True:
        header = receive_exact(sock, 8)
        msg_type = header[:4]
        length = struct.unpack("!I", header[4:])[0]
        payload = receive_exact(sock, length)
        # ROLE ASSIGNMENT
        if msg_type == b'ROLE':
            my_role = payload.decode()
            print("[*] Assigned role:", my_role)
            
            # -------- CLASSICAL --------
            if MODE == "CLASSICAL":
                my_public_key = crypto.get_public_bytes()
                send_packet(sock, b'KEY_', my_public_key)

            # -------- PQC --------
            elif MODE == "PQC":
                if my_role == "INIT":
                    my_public_key = crypto.generate_keypair()
                    send_packet(sock, b'KYPK', my_public_key)
                    

            # -------- HYBRID --------
            elif MODE == "HYBRID":
                my_ecdh_public = crypto.generate_ecdh_public()
                send_packet(sock, b'ECDH', my_ecdh_public)

                if my_role == "INIT":
                    my_kyber_public = crypto.generate_kyber_public()
                    send_packet(sock, b'KYPK', my_kyber_public)

        # ============================
        # CLASSICAL MODE
        # ============================
        elif MODE == "CLASSICAL" and msg_type == b'KEY_':

            if payload == my_public_key:
                continue

            crypto.derive_shared_key(payload)
            secure_channel_established = True
            session_start_time = time.perf_counter()
            print("\n[*] Secure channel established (CLASSICAL)")

        # ============================
        # PQC MODE
        # ============================
        elif MODE == "PQC":

            if msg_type == b'KYPK' and my_role == "RESP":
                ciphertext = crypto.encapsulate(payload)
                send_packet(sock, b'KYCT', ciphertext)

                secure_channel_established = True
                session_start_time = time.perf_counter()
                print("SHARED KEY (first 16 bytes):", crypto.shared_key[:16])
                print("\n[*] Secure channel established (PQC)")
                

            elif msg_type == b'KYCT' and my_role == "INIT":
                crypto.decapsulate(payload)

                secure_channel_established = True
                session_start_time = time.perf_counter()
                print("SHARED KEY (first 16 bytes):", crypto.shared_key[:16])
                print("\n[*] Secure channel established (PQC)")
                

        # ============================
        # HYBRID MODE
        # ============================
        elif MODE == "HYBRID":

            if msg_type == b'ECDH':

                if payload == my_ecdh_public:
                    continue

                crypto.derive_ecdh_secret(payload)

                if crypto.derive_final_key():
                    secure_channel_established = True
                    session_start_time = time.perf_counter()
                    print("\n[*] Secure channel established (HYBRID)")
                    

            elif msg_type == b'KYPK' and my_role == "RESP":

                ciphertext = crypto.encapsulate_kyber(payload)
                send_packet(sock, b'KYCT', ciphertext)

                if crypto.derive_final_key():
                    secure_channel_established = True
                    session_start_time = time.perf_counter()
                    print("\n[*] Secure channel established (HYBRID)")
                    

            elif msg_type == b'KYCT' and my_role == "INIT":

                crypto.decapsulate_kyber(payload)

                if crypto.derive_final_key():
                    secure_channel_established = True
                    session_start_time = time.perf_counter()
                    print("\n[*] Secure channel established (HYBRID)")
                    

        # ============================
        # MESSAGE PHASE
        # ============================
        if msg_type == b'MSG_':

            if not secure_channel_established:
                continue

            try:
                decrypted = crypto.decrypt(payload)

                # Clear current line
                #print("\r" + " " * 100, end="")

                # Move cursor to beginning
                print("\rPeer:", decrypted)

                # Reprint prompt
                print("You: ", end="", flush=True)

            except Exception as e:
                print("\n[Decrypt Error]:", e)

def export_metrics(message_length):
    metrics = crypto.get_metrics()
   
    key_exchange = metrics.get("key_exchange_time")

    if key_exchange is None:
        key_exchange = metrics.get("ecdh_time")

    if key_exchange is None:
        key_exchange = (
            (metrics.get("encapsulation_time") or 0) +
            (metrics.get("decapsulation_time") or 0)
        )
    session_duration = time.perf_counter() - session_start_time
    row = [
    MODE,
    message_length,
    metrics.get("keygen_time"),
    key_exchange,
    metrics.get("key_derivation_time", 0),
    metrics.get("encrypt_time"),
    metrics.get("decrypt_time"),
    metrics.get("ciphertext_size"),
    total_messages,
    total_bytes_sent,
    session_duration,
    total_bytes_sent / session_duration
    ]
    with open("chat_metrics.csv", "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(row)
def print_session_summary():
    session_duration = time.perf_counter() - session_start_time
    bandwidth_sent = total_bytes_sent / session_duration
    bandwidth_received = total_bytes_received / session_duration
    print("\n...session summary...")

    print("Mode:", MODE)
    print("Messages sent:", total_messages)
    print("Total bytes sent:", total_bytes_sent)
    print("Session duration:", round(session_duration, 3), "seconds")
    print("Bandwidth (sent):", round(bandwidth_sent,2), "bytes/sec")
    print("Bandwidth (received):", round(bandwidth_received,2), "bytes/sec")

    print(".........")

def main():
    global total_messages
    global total_bytes_sent
    global secure_channel_established

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))
    print("[*] Connected to server")

    thread = threading.Thread(target=receive_messages, args=(sock,))
    thread.daemon = True
    thread.start()  

    while True:
        try:
            if secure_channel_established:
                print("You: ", end="", flush=True)
                message = input()
                if(message.lower() == "exit"):
                    print("\n[*] Ending chat session...")
                    print_session_summary()
                    sock.close()
                    break
                message_length = len(message)
                encrypted = crypto.encrypt(message)
                ciphertext_length = len(encrypted)
                total_messages += 1
                total_bytes_sent += ciphertext_length
                send_packet(sock, b'MSG_', encrypted)
                export_metrics(message_length)
            else:
                time.sleep(0.5)
        except ConnectionError:
            print("\n[*] Peer Disconnected")
            break



if __name__ == "__main__":
    main()
    
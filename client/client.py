from classical_crypto import ClassicalCrypto
from post_quantum_crypto import PostQuantumCrypto
from hybrid_crypto import HybridCrypto

import socket
import threading
import struct
import time

MODE = "HYBRID"  # CLASSICAL / PQC / HYBRID

HOST = "127.0.0.1"
PORT = 5000

secure_channel_established = False
my_role = None

# Key holders
my_ecdh_public = None
my_kyber_public = None
my_public_key = None

# Crypto selection
if MODE == "CLASSICAL":
    crypto = ClassicalCrypto()
elif MODE == "PQC":
    crypto = PostQuantumCrypto()
elif MODE == "HYBRID":
    crypto = HybridCrypto()


def send_packet(sock, msg_type, payload):
    header = msg_type + struct.pack("!I", len(payload))
    sock.sendall(header + payload)


def receive_exact(sock, length):
    data = b''
    while len(data) < length:
        more = sock.recv(length - len(data))
        if not more:
            raise ConnectionError("Connection closed")
        data += more
    return data


def receive_messages(sock):
    global secure_channel_established
    global my_role, my_ecdh_public, my_kyber_public, my_public_key

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
            print("\n[*] Secure channel established (CLASSICAL)")

        # ============================
        # PQC MODE
        # ============================
        elif MODE == "PQC":

            if msg_type == b'KYPK' and my_role == "RESP":
                ciphertext = crypto.encapsulate(payload)
                send_packet(sock, b'KYCT', ciphertext)

                secure_channel_established = True
                print("SHARED KEY (first 16 bytes):", crypto.shared_key[:16])
                print("\n[*] Secure channel established (PQC)")
                

            elif msg_type == b'KYCT' and my_role == "INIT":
                crypto.decapsulate(payload)

                secure_channel_established = True
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
                    print("\n[*] Secure channel established (HYBRID)")
                    

            elif msg_type == b'KYPK' and my_role == "RESP":

                ciphertext = crypto.encapsulate_kyber(payload)
                send_packet(sock, b'KYCT', ciphertext)

                if crypto.derive_final_key():
                    secure_channel_established = True
                    print("\n[*] Secure channel established (HYBRID)")
                    

            elif msg_type == b'KYCT' and my_role == "INIT":

                crypto.decapsulate_kyber(payload)

                if crypto.derive_final_key():
                    secure_channel_established = True
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
def main():
    global secure_channel_established

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))
    print("[*] Connected to server")

    thread = threading.Thread(target=receive_messages, args=(sock,))
    thread.daemon = True
    thread.start()

    while True:
        if secure_channel_established:
            print("You: ", end="", flush=True)
            message = input()
            encrypted = crypto.encrypt(message)
            send_packet(sock, b'MSG_', encrypted)
        else:
            time.sleep(0.5)


if __name__ == "__main__":
    main()
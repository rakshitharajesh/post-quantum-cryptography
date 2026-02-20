# client/client.py

import socket
import threading
import struct
import time
from classical_crypto import ClassicalCrypto

HOST = "127.0.0.1"
PORT = 5000

crypto = ClassicalCrypto()
secure_channel_established = False
my_public_key = crypto.get_public_bytes()


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

    while True:
        header = receive_exact(sock, 8)
        msg_type = header[:4]
        length = struct.unpack("!I", header[4:])[0]
        payload = receive_exact(sock, length)

        if msg_type == b'KEY_':

            if payload == my_public_key:
                continue

            crypto.derive_shared_key(payload)
            secure_channel_established = True
            print("\n[*] Secure channel established (Classical ECDH + AES-GCM)")
            print("You: ", end="", flush=True)

        elif msg_type == b'MSG_':

            if not secure_channel_established:
                continue

            decrypted = crypto.decrypt(payload)

            # Clean print formatting
            print("\r" + " " * 80, end="")   # Clear current line
            print("\rPeer:", decrypted)
            print("You: ", end="", flush=True)


def main():
    global secure_channel_established

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))
    print("[*] Connected to server")

    send_packet(sock, b'KEY_', my_public_key)

    thread = threading.Thread(target=receive_messages, args=(sock,))
    thread.daemon = True
    thread.start()

    while True:
        if secure_channel_established:
            message = input("You: ")
            encrypted = crypto.encrypt(message)
            send_packet(sock, b'MSG_', encrypted)
        else:
            time.sleep(0.5)


if __name__ == "__main__":
    main()

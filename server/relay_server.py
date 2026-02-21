# server/relay_server.py

import struct
import socket
import threading
client_roles = {}
HOST = "127.0.0.1"
PORT = 5000

clients = []
public_keys = {}

def handle_client(conn, addr):
    print(f"[+] New connection from {addr}")
    clients.append(conn)
    if len(clients) == 1:
        client_roles[conn] = b'INIT'
        conn.sendall(b'ROLE' + struct.pack("!I", 4) + b'INIT')
    elif len(clients) == 2:
        client_roles[conn] = b'RESP'
        conn.sendall(b'ROLE' + struct.pack("!I", 4) + b'RESP')
    try:
        while True:
            data = conn.recv(4096)
            if not data:
                break

            # Store KEY_ messages
            if data[:4] in [b'KEY_', b'KYPK']:
                public_keys[conn] = data

                # If two clients connected, exchange keys
                if len(public_keys) == 2:
                    for c in clients:
                        for other_conn, key in public_keys.items():
                            if c != other_conn:
                                c.sendall(key)

            else:
                # Forward normal messages
                for client in clients:
                    if client != conn:
                        client.sendall(data)

    except:
        pass
    finally:
        print(f"[-] Connection closed {addr}")
        clients.remove(conn)
        if conn in public_keys:
            del public_keys[conn]
        conn.close()

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen()
    print(f"[SERVER] Listening on {HOST}:{PORT}")

    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()

if __name__ == "__main__":
    start_server()

import socket
import threading
import struct

HOST = "127.0.0.1"
PORT = 5000

clients = []
lock = threading.Lock()


def send_packet(sock, msg_type, payload):
    header = msg_type + struct.pack("!I", len(payload))
    sock.sendall(header + payload)


def handle_client(conn, addr):
    global clients
    print(f"[+] New connection from {addr}")

    with lock:
        clients.append(conn)

        # Assign roles ONLY when two clients are connected
        if len(clients) == 2:
            print("[SERVER] Two clients connected. Assigning roles.")
            send_packet(clients[0], b'ROLE', b'INIT')
            send_packet(clients[1], b'ROLE', b'RESP')

    try:
        while True:
            # Read header (8 bytes)
            header = conn.recv(8)
            if not header:
                break

            msg_type = header[:4]
            length = struct.unpack("!I", header[4:])[0]

            # Read exact payload
            payload = b''
            while len(payload) < length:
                chunk = conn.recv(length - len(payload))
                if not chunk:
                    break
                payload += chunk

            packet = header + payload

            # Forward packet to other client(s)
            with lock:
                for client in clients:
                    if client != conn:
                        client.sendall(packet)

    except Exception as e:
        print("Server error:", e)

    finally:
        with lock:
            if conn in clients:
                clients.remove(conn)

        print(f"[-] Connection closed {addr}")
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
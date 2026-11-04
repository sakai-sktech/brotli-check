"""Relay TCP 127.0.0.1:<free port> to a unix socket, for the C14 step of run.sh.

Usage: python3 -I relay.py UNIX-SOCKET-PATH
Prints the port on its first line, then relays every connection until it is killed. With
DOCKER_HOST=tcp://127.0.0.1:<port>, docker reaches the same engine through tcp://, which the tool
must not take for this host (docs/design.md 10.20).
"""
import socket
import sys
import threading


def pipe(src: socket.socket, dst: socket.socket) -> None:
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def main() -> int:
    path = sys.argv[1]
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(16)
    print(server.getsockname()[1], flush=True)
    while True:
        client, _ = server.accept()
        upstream = socket.socket(socket.AF_UNIX)
        try:
            upstream.connect(path)
        except OSError:
            client.close()
            continue
        threading.Thread(target=pipe, args=(client, upstream), daemon=True).start()
        threading.Thread(target=pipe, args=(upstream, client), daemon=True).start()


if __name__ == "__main__":
    sys.exit(main())

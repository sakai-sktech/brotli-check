"""Relay TCP 127.0.0.1:<free port> to a unix socket, for the C14 step of run.sh.

Usage: python3 -I relay.py UNIX-SOCKET-PATH
Prints the port on its first line, then relays every connection until it is killed. With
DOCKER_HOST=tcp://127.0.0.1:<port>, docker reaches the same engine through tcp://, which the tool
must not take for this host (docs/design.md 10.20).

The engine's socket gives control of the engine (and, with most engines, of the host), and a
loopback port can be reached by every user of the machine. So a connection is relayed only when
its other end is a socket of the user running the relay, by the owner that /proc/net/tcp gives for
it; anything else, or a lookup that fails, is closed unanswered.
"""
import os
import socket
import sys
import threading


def peer_uid(client: socket.socket):
    """The owner of the other end of a loopback connection, from /proc/net/tcp, or None."""
    _, here = client.getsockname()
    _, there = client.getpeername()
    # The peer's own row: its local address is the peer, its remote address is this end.
    want = ("0100007F:%04X" % there, "0100007F:%04X" % here)
    try:
        with open("/proc/net/tcp", encoding="ascii") as rows:
            next(rows)
            for row in rows:
                fields = row.split()
                if (fields[1], fields[2]) == want:
                    return int(fields[7])
    except (OSError, ValueError, IndexError, StopIteration):
        return None
    return None


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
    me = os.getuid()
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(16)
    print(server.getsockname()[1], flush=True)
    while True:
        client, _ = server.accept()
        if peer_uid(client) != me:
            client.close()
            continue
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

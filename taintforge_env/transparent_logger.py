from __future__ import annotations
import subprocess
import asyncio
import socket
import struct
from pathlib import Path

from .event_logger import append_jsonl_event


SO_ORIGINAL_DST = 80
IP_RECVORIGDSTADDR = 20

PREVIEW_BYTES = 64
TCP_RESPONSE = b"OK\n"


def lookup_udp_original_destination_conntrack(
    peer_host: str | None,
    peer_port: int | None,
) -> tuple[str | None, int | None]:
    if not peer_host or peer_port is None:
        return None, None

    try:
        result = subprocess.run(
            ["conntrack", "-L", "-p", "udp"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=1,
            check=False,
        )
    except Exception:
        return None, None

    for line in result.stdout.splitlines():
        original = parse_conntrack_original_tuple(line)

        if original is None:
            continue

        src_ip, dst_ip, src_port, dst_port = original

        if src_ip == peer_host and src_port == peer_port:
            return dst_ip, dst_port

    return None, None


def parse_conntrack_original_tuple(
    line: str,
) -> tuple[str, str, int, int] | None:
    fields: dict[str, str] = {}

    for token in line.split():
        if "=" not in token:
            continue

        key, value = token.split("=", 1)

        # conntrack line has two tuples:
        # original: src=... dst=... sport=... dport=...
        # reply:    src=... dst=... sport=... dport=...
        #
        # We only want the first/original occurrence.
        if key in {"src", "dst", "sport", "dport"} and key not in fields:
            fields[key] = value

        if {"src", "dst", "sport", "dport"} <= fields.keys():
            break

    try:
        return (
            fields["src"],
            fields["dst"],
            int(fields["sport"]),
            int(fields["dport"]),
        )
    except (KeyError, ValueError):
        return None

def parse_sockaddr_in(raw: bytes) -> tuple[str | int | None, int | None]:
    if len(raw) < 8:
        return None, None

    port = struct.unpack("!H", raw[2:4])[0]
    ip = socket.inet_ntoa(raw[4:8])

    return ip, port


def safe_name(value: str | int | None) -> str:
    if value is None:
        return "unknown"

    return str(value).replace(".", "_").replace(":", "_").replace("/", "_")


def guess_udp_role(port: int | None) -> str:
    if port == 53:
        return "dns"

    if port == 123:
        return "ntp"

    return "udp"

def is_redirected_udp_destination(
    original_ip: str | None,
    original_port: int | None,
    bind_ip: str,
    bind_port: int,
) -> bool:
    if original_ip is None or original_port is None:
        return True

    if original_port != bind_port:
        return False

    return original_ip in {
        bind_ip,
        "127.0.0.1",
        "0.0.0.0",
    }


class TransparentTCPLogger:
    def __init__(
        self,
        bind_ip: str,
        bind_port: int,
        log_dir: str | Path,
    ):
        self.bind_ip = bind_ip
        self.bind_port = bind_port
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.events_log_path = self.log_dir / "network_events.jsonl"
        self.connection_counter = 0

    async def start(self) -> asyncio.AbstractServer:
        server = await asyncio.start_server(
            self.handle_client,
            host=self.bind_ip,
            port=self.bind_port,
        )

        print(
            f"[+] Transparent TCP catch-all logger listening on "
            f"{self.bind_ip}:{self.bind_port}"
        )

        return server

    async def handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        self.connection_counter += 1
        conn_id = self.connection_counter

        peer = writer.get_extra_info("peername")
        peer_host, peer_port = self.parse_peer(peer)

        sock = writer.get_extra_info("socket")
        original_ip, original_port = self.get_original_tcp_destination(sock)

        payload_file = (
            f"catchall_tcp_"
            f"{safe_name(original_ip)}_"
            f"{safe_name(original_port)}_"
            f"conn_{conn_id}.bin"
        )

        payload_path = self.log_dir / payload_file

        append_jsonl_event(
            self.events_log_path,
            {
                "event": "tcp_connection_open",
                "listener_type": "catch_all_transparent",
                "connection_id": conn_id,
                "peer_host": peer_host,
                "peer_port": peer_port,
                "bind_ip": self.bind_ip,
                "bind_port": self.bind_port,
                "original_remote_ip": original_ip,
                "original_remote_port": original_port,
                "payload_file": payload_file,
            },
        )

        try:
            with payload_path.open("ab") as f:
                while True:
                    data = await reader.read(4096)

                    if not data:
                        append_jsonl_event(
                            self.events_log_path,
                            {
                                "event": "tcp_connection_close",
                                "listener_type": "catch_all_transparent",
                                "connection_id": conn_id,
                                "peer_host": peer_host,
                                "peer_port": peer_port,
                                "bind_ip": self.bind_ip,
                                "bind_port": self.bind_port,
                                "original_remote_ip": original_ip,
                                "original_remote_port": original_port,
                                "payload_file": payload_file,
                            },
                        )

                        break

                    f.write(data)
                    f.flush()

                    append_jsonl_event(
                        self.events_log_path,
                        {
                            "event": "tcp_data",
                            "listener_type": "catch_all_transparent",
                            "connection_id": conn_id,
                            "peer_host": peer_host,
                            "peer_port": peer_port,
                            "bind_ip": self.bind_ip,
                            "bind_port": self.bind_port,
                            "original_remote_ip": original_ip,
                            "original_remote_port": original_port,
                            "payload_file": payload_file,
                            "bytes_received": len(data),
                            "payload_hex_preview": data[:PREVIEW_BYTES].hex(),
                        },
                    )

                    writer.write(TCP_RESPONSE)
                    await writer.drain()

                    append_jsonl_event(
                        self.events_log_path,
                        {
                            "event": "tcp_response",
                            "listener_type": "catch_all_transparent",
                            "connection_id": conn_id,
                            "peer_host": peer_host,
                            "peer_port": peer_port,
                            "bind_ip": self.bind_ip,
                            "bind_port": self.bind_port,
                            "original_remote_ip": original_ip,
                            "original_remote_port": original_port,
                            "payload_file": payload_file,
                            "bytes_sent": len(TCP_RESPONSE),
                            "response_hex_preview": TCP_RESPONSE.hex(),
                        },
                    )

        except ConnectionResetError:
            append_jsonl_event(
                self.events_log_path,
                {
                    "event": "tcp_connection_reset",
                    "listener_type": "catch_all_transparent",
                    "connection_id": conn_id,
                    "peer_host": peer_host,
                    "peer_port": peer_port,
                    "bind_ip": self.bind_ip,
                    "bind_port": self.bind_port,
                    "original_remote_ip": original_ip,
                    "original_remote_port": original_port,
                    "payload_file": payload_file,
                },
            )

        finally:
            writer.close()
            await writer.wait_closed()

    @staticmethod
    def get_original_tcp_destination(sock) -> tuple[str | None, int | None]:
        if sock is None:
            return None, None

        try:
            raw = sock.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
            ip, port = parse_sockaddr_in(raw)
            return str(ip), port
        except OSError:
            return None, None

    @staticmethod
    def parse_peer(peer) -> tuple[str | None, int | None]:
        if not peer:
            return None, None

        if isinstance(peer, tuple) and len(peer) >= 2:
            return str(peer[0]), int(peer[1])

        return str(peer), None


class TransparentUDPLogger:
    def __init__(
        self,
        bind_ip: str,
        bind_port: int,
        log_dir: str | Path,
    ):
        self.bind_ip = bind_ip
        self.bind_port = bind_port
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.events_log_path = self.log_dir / "network_events.jsonl"
        self.datagram_counter = 0
        self.sock: socket.socket | None = None

    def start(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)

        sock.setsockopt(socket.SOL_IP, IP_RECVORIGDSTADDR, 1)
        sock.bind((self.bind_ip, self.bind_port))

        self.sock = sock

        loop = asyncio.get_running_loop()
        loop.add_reader(sock.fileno(), self.handle_readable)

        print(
            f"[+] Transparent UDP logger listening on "
            f"{self.bind_ip}:{self.bind_port}"
        )

    def handle_readable(self) -> None:
        if self.sock is None:
            return

        while True:
            try:
                data, ancdata, _flags, peer = self.sock.recvmsg(
                    65535,
                    1024,
                )
            except BlockingIOError:
                break

            self.datagram_counter += 1
            datagram_id = self.datagram_counter

            peer_host, peer_port = self.parse_peer(peer)

            original_ip, original_port = self.extract_udp_original_destination(ancdata)

            original_destination_source = "recvmsg"

            if is_redirected_udp_destination(
                original_ip=original_ip,
                original_port=original_port,
                bind_ip=self.bind_ip,
                bind_port=self.bind_port,
            ):
                ct_ip, ct_port = lookup_udp_original_destination_conntrack(peer_host=peer_host,peer_port=peer_port)

                if ct_ip is not None and ct_port is not None:
                    original_ip = ct_ip
                    original_port = ct_port
                    original_destination_source = "conntrack"
                else:
                    original_destination_source = "recvmsg_redirected"

            udp_role = guess_udp_role(original_port)

            payload_file = (
                f"{udp_role}_udp_"
                f"{safe_name(original_ip)}_"
                f"{safe_name(original_port)}_"
                f"dgram_{datagram_id}.bin"
            )

            payload_path = self.log_dir / payload_file
            payload_path.write_bytes(data)

            append_jsonl_event(
                self.events_log_path,
                {
                    "event": "udp_datagram",
                    "listener_type": "udp_transparent",
                    "datagram_id": datagram_id,
                    "udp_role": udp_role,
                    "peer_host": peer_host,
                    "peer_port": peer_port,
                    "bind_ip": self.bind_ip,
                    "bind_port": self.bind_port,
                    "original_remote_ip": original_ip,
                    "original_remote_port": original_port,
                    "original_destination_source": original_destination_source,
                    "payload_file": payload_file,
                    "bytes_received": len(data),
                    "payload_hex_preview": data[:PREVIEW_BYTES].hex(),
                },
            )

    @staticmethod
    def extract_udp_original_destination(
        ancdata,
    ) -> tuple[str | None, int | None]:
        for level, cmsg_type, cmsg_data in ancdata:
            if level == socket.SOL_IP and cmsg_type == IP_RECVORIGDSTADDR:
                ip, port = parse_sockaddr_in(cmsg_data)
                return str(ip), port

        return None, None

    @staticmethod
    def parse_peer(peer) -> tuple[str | None, int | None]:
        if not peer:
            return None, None

        if isinstance(peer, tuple) and len(peer) >= 2:
            return str(peer[0]), int(peer[1])

        return str(peer), None


async def run_transparent_logger(
    log_dir: str | Path,
    tcp_bind_ip: str = "127.0.0.1",
    tcp_bind_port: int = 40000,
    udp_bind_ip: str = "127.0.0.1",
    udp_bind_port: int = 40001,
) -> None:
    tcp_logger = TransparentTCPLogger(
        bind_ip=tcp_bind_ip,
        bind_port=tcp_bind_port,
        log_dir=log_dir,
    )

    udp_logger = TransparentUDPLogger(
        bind_ip=udp_bind_ip,
        bind_port=udp_bind_port,
        log_dir=log_dir,
    )

    tcp_server = await tcp_logger.start()
    udp_logger.start()

    print("[+] Transparent logger is running. Press Ctrl+C to stop.")

    await tcp_server.serve_forever()

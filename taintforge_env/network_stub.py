from __future__ import annotations
import asyncio
from pathlib import Path
from .network_policy import NetworkPolicy, NetworkServicePolicy

class TCPFakeService:
    def __init__(self, service: NetworkServicePolicy, log_dir: str | Path):
        self.service = service
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.connection_counter = 0
    async def start(self) -> asyncio.AbstractServer:
        server = await asyncio.start_server(self.handle_client, host=self.service.bind_ip, port = self.service.bind_port)

        print(f"Fake TCP {self.service.role} listening on {self.service.bind_ip}:{self.service.bind_port}")
        
        print(f"original target: {self.service.domain} or {self.service.remote_ip}:{self.service.remote_port}")

        return server

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.connection_counter += 1
        conn_id = self.connection_counter

        peer = writer.get_extra_info("peername")
        print(f"conn = {conn_id} from {peer}")

        log_path = (self.log_dir / f"tcp_{self.service.bind_port}_conn_{conn_id}.bin")

        try:
            with log_path.open("ab") as log_file:
                while True:
                    data = await reader.read(4096)

                    if not data:
                        print(f"connection {conn_id} closed")
                        break

                    print(f"connection {conn_id} sent {len(data)} bytes hex = {data.hex()}")

                    log_file.write(data)
                    log_file.flush()

                    response = self.build_response(data)

                    if response:
                        writer.write(response)
                        await writer.drain()

                        print(f"connection {conn_id} sent {len(response)} bytes hex = {response.hex()}")

        except ConnectionResetError:
            print(f"connection {conn_id} reset by peer")
        except Exception as e:
            print(f"connection {conn_id} error: {e}")
        finally:
            writer.close()
            await writer.wait_closed()

    def build_response(self, data: bytes) -> bytes:
        if self.service.protocol_hint == "mirai-like":
            return b"\x00\x00\x00\x00"

        if self.service.protocol_hint == "text":
            return b"OK\n"

        return b"OK\n"

async def run_network_emulator(policy: NetworkPolicy, log_dir: str | Path) -> None:
    tcp_services = [
            service for service in policy.services
            if service.service_type == "tcp"
    ]

    if not tcp_services:
        print(f"No TCP services in network policy")
        return 

    servers: list[asyncio.AbstractServer] = []

    for service in tcp_services:
        fake_service = TCPFakeService(service = service, log_dir = log_dir)
        server = await fake_service.start()
        servers.append(server)

    print("Network emulator in running. Precc Ctrl+C to stop.")

    try:
        await asyncio.gather(*(server.serve_forever() for server in servers))
    except asyncio.CancelledError:
        pass

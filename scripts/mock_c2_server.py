import argparse
import asyncio
from pathlib import Path


async def handle_client(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    response: bytes,
) -> None:
    request = await reader.read(1024 * 1024)
    peer = writer.get_extra_info("peername")
    print(
        f"[mock-c2] peer={peer} request_size={len(request)} "
        f"request_hex={request[:64].hex()}",
        flush=True,
    )
    writer.write(response)
    await writer.drain()
    writer.close()
    await writer.wait_closed()


async def run_server(bind_ip: str, port: int, response: bytes) -> None:
    server = await asyncio.start_server(
        lambda r, w: handle_client(r, w, response),
        bind_ip,
        port,
    )
    print(
        f"[mock-c2] listening on {bind_ip}:{port} "
        f"response_size={len(response)}",
        flush=True,
    )
    async with server:
        await server.serve_forever()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bind-ip", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=49001)
    parser.add_argument("--response-hex", default="776f726c64")
    parser.add_argument("--response-file")
    args = parser.parse_args()

    if args.response_file:
        response = Path(args.response_file).read_bytes()
    else:
        try:
            response = bytes.fromhex(args.response_hex)
        except ValueError as exc:
            parser.error(f"invalid --response-hex: {exc}")

    asyncio.run(run_server(args.bind_ip, args.port, response))


if __name__ == "__main__":
    main()

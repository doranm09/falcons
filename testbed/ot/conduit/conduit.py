#!/usr/bin/env python3
import asyncio
import json
import os

CONDUIT_MAP = json.loads(os.getenv("CONDUIT_MAP", "[]"))
LOG_PATH = os.getenv("LOG_PATH", "/data/conduit.log")
FIXED_TIME = os.getenv("FIXED_TIME", "2026-01-25T00:00:00Z")


def log(msg: str) -> None:
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    with open(LOG_PATH, "a", encoding="utf-8") as handle:
        handle.write(f"{FIXED_TIME} {msg}\n")


async def handle_client(reader, writer, target_host, target_port):
    try:
        target_reader, target_writer = await asyncio.open_connection(target_host, target_port)
    except Exception as exc:
        log(f"connect_fail {target_host}:{target_port} {exc}")
        writer.close()
        return

    async def pipe(src, dst, label):
        try:
            while True:
                data = await src.read(4096)
                if not data:
                    break
                dst.write(data)
                await dst.drain()
        except Exception as exc:
            log(f"pipe_error {label} {exc}")
        finally:
            try:
                dst.close()
            except Exception:
                pass

    await asyncio.gather(
        pipe(reader, target_writer, "to_target"),
        pipe(target_reader, writer, "to_client"),
    )


async def main():
    servers = []
    for mapping in CONDUIT_MAP:
        listen_port = int(mapping["listen_port"])
        target_host = mapping["target_host"]
        target_port = int(mapping["target_port"])
        server = await asyncio.start_server(
            lambda r, w: handle_client(r, w, target_host, target_port),
            host="0.0.0.0",
            port=listen_port,
        )
        servers.append(server)
        log(f"listen {listen_port} -> {target_host}:{target_port}")
    await asyncio.gather(*(s.serve_forever() for s in servers))


if __name__ == "__main__":
    asyncio.run(main())

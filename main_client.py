import asyncio
import atexit
import random
import socket
import struct
import json
import os
import subprocess
import sys
import hashlib
import re
import ssl
import uuid as uuid_module
from urllib.parse import urlparse, parse_qs, unquote

import aiohttp

CLIENT_ID_WIDTH = 3

# Linux kernel value for SO_MARK; present as socket.SO_MARK on Python 3.12+ / Linux.
_SO_MARK: int = getattr(socket, "SO_MARK", 36)

# Forward declaration — overwritten after config is loaded below.
fwmark: int = 0


def bytes_xor(data: bytes, key: bytes) -> bytes:
    return bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))


def create_v4_udp_dgram_socket(blocking: bool, bind_addr: tuple[str, int] | None = None) -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setblocking(blocking)
    if bind_addr is not None:
        s.bind(bind_addr)
    return s


def _apply_fwmark(sock: socket.socket) -> None:
    """Set SO_MARK on *sock* so the packet bypasses WireGuard routing rules.

    Linux only — SO_MARK does not exist on Windows or macOS.
    Requires CAP_NET_ADMIN (or root).  A failure is logged but not fatal.
    """
    if not fwmark or sys.platform != "linux":
        return
    try:
        sock.setsockopt(socket.SOL_SOCKET, _SO_MARK, fwmark)
    except OSError as e:
        print(
            f"[fwmark] WARNING: Could not set SO_MARK={fwmark} on socket: {e}. "
            "Run as root or grant CAP_NET_ADMIN for WireGuard bypass to work."
        )


# ---------------------------------------------------------------------------
# DNS resolution that bypasses WireGuard routing via SO_MARK
# ---------------------------------------------------------------------------

# Default DNS server used when resolving hostnames through a marked socket.
_BYPASS_DNS_SERVER = "1.1.1.1"
_BYPASS_DNS_PORT = 53


def _build_dns_query(hostname: str) -> tuple[bytes, int]:
    """Build a minimal DNS A-record UDP query for *hostname*.

    Returns ``(packet_bytes, query_id)`` where *query_id* can be matched
    against the response.
    """
    qid = random.randint(1, 65535)
    # Header: ID, FLAGS=standard query (RD=1), QDCOUNT=1, rest 0
    header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    question = b""
    for label in hostname.rstrip(".").split("."):
        enc = label.encode("ascii")
        question += bytes([len(enc)]) + enc
    question += b"\x00"             # root label
    question += struct.pack(">HH", 1, 1)  # QTYPE=A, QCLASS=IN
    return header + question, qid


def _parse_dns_a_response(data: bytes, expected_id: int) -> str | None:
    """Parse a DNS UDP response and return the first A-record IP string.

    Returns *None* if the response is invalid, does not match *expected_id*,
    or contains no A records.
    """
    if len(data) < 12:
        return None
    resp_id, flags, qdcount, ancount = struct.unpack(">HHHH", data[:8])
    if resp_id != expected_id or not (flags & 0x8000):  # QR bit must be set
        return None
    if ancount == 0:
        return None

    def _skip_name(pos: int) -> int:
        """Advance *pos* past a DNS name (handles pointer compression)."""
        while pos < len(data):
            length = data[pos]
            if length & 0xC0 == 0xC0:   # compressed pointer — 2 bytes total
                return pos + 2
            elif length == 0:           # root label
                return pos + 1
            else:
                pos += 1 + length
        return pos

    # Skip the question section
    pos = 12
    for _ in range(qdcount):
        pos = _skip_name(pos)
        pos += 4  # QTYPE + QCLASS

    # Parse answer records looking for the first A record
    for _ in range(ancount):
        if pos >= len(data):
            break
        pos = _skip_name(pos)
        if pos + 10 > len(data):
            break
        rtype, rclass, _ttl, rdlen = struct.unpack(">HHIH", data[pos: pos + 10])
        pos += 10
        if rtype == 1 and rclass == 1 and rdlen == 4:   # A record, IN class
            return ".".join(str(data[pos + i]) for i in range(4))
        pos += rdlen

    return None


async def _resolve_host_bypass_wg(
    hostname: str, loop: asyncio.AbstractEventLoop
) -> str:
    """Resolve *hostname* to an IPv4 address, bypassing WireGuard routing.

    On Linux with *fwmark* configured a raw DNS A-query is sent over a UDP
    socket that has ``SO_MARK`` stamped on it, so the Linux policy-routing
    rules used by WireGuard do *not* apply.  This is necessary because the
    normal OS resolver (``getaddrinfo``) ignores ``SO_MARK``, meaning DNS
    queries would otherwise be swallowed by the WireGuard interface and fail
    whenever the VLESS tunnel is not yet established.

    Falls back to ``loop.getaddrinfo()`` when *fwmark* is not set, or on
    non-Linux platforms.
    """
    # If hostname is already a literal IP address, return it as-is.
    try:
        socket.inet_aton(hostname)
        return hostname
    except OSError:
        pass

    if not fwmark or sys.platform != "linux":
        # No bypass needed (or not supported): use the normal OS resolver.
        results = await loop.getaddrinfo(hostname, None, family=socket.AF_INET)
        return results[0][4][0]

    query, qid = _build_dns_query(hostname)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    _apply_fwmark(sock)
    try:
        await loop.sock_sendto(sock, query, (_BYPASS_DNS_SERVER, _BYPASS_DNS_PORT))
        data = await asyncio.wait_for(loop.sock_recv(sock, 512), timeout=5.0)
        ip = _parse_dns_a_response(data, qid)
        if ip:
            return ip
        raise OSError(f"No A record in DNS response for {hostname!r}")
    except Exception as exc:
        # Best-effort fallback to the OS resolver.
        print(
            f"[vless] Marked-socket DNS lookup failed for {hostname!r}: {exc}; "
            "falling back to OS resolver"
        )
        results = await loop.getaddrinfo(hostname, None, family=socket.AF_INET)
        return results[0][4][0]
    finally:
        sock.close()


def _make_aiohttp_connector() -> aiohttp.TCPConnector:
    """Return a TCPConnector that stamps every TCP socket with SO_MARK when fwmark is set.

    socket_options are only applied on Linux; on other platforms a plain
    TCPConnector is returned so Windows users are not affected.
    """
    if fwmark and sys.platform == "linux":
        try:
            return aiohttp.TCPConnector(
                socket_options=[(socket.SOL_SOCKET, _SO_MARK, fwmark)]
            )
        except TypeError:
            print(
                "[fwmark] WARNING: Installed aiohttp does not support socket_options; "
                "upgrade aiohttp for WireGuard bypass on TCP connections."
            )
    return aiohttp.TCPConnector()


# ---------------------------------------------------------------------------
# Windows WireGuard routing bypass
# ---------------------------------------------------------------------------

_windows_bypass_ips: list[str] = []
_HOST_ROUTE_MASK = "255.255.255.255"

# Mapping from my_public_ip shorthand → (key, fetch URL) used both for bypass
# route resolution and for the actual IP-fetch call in main().
_IP_SVC_URLS: dict[str, str] = {
    "ezping":     "https://ezping.ir/geoip",
    "ipnumberia": "https://ipnumberia.com/",
    "ipmyp":      "https://ipmyp.ir/",
}


def _get_default_gateway_windows() -> str | None:
    """Return the IPv4 default gateway on Windows by parsing ``route print 0.0.0.0``."""
    try:
        result = subprocess.run(
            ["route", "print", "0.0.0.0"],
            text=True, timeout=5, capture_output=True,
        )
        out = result.stdout
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                try:
                    socket.inet_aton(parts[2])
                    return parts[2]
                except OSError:
                    continue
    except Exception as e:
        print(f"[windows_bypass] Could not determine default gateway: {e}")
    return None


def _apply_windows_bypass(ips: list[str]) -> None:
    """Add temporary host routes so QS-Tunnel's traffic bypasses the WireGuard interface.

    Uses ``route add <IP> mask <HOST_ROUTE_MASK> <GATEWAY>``.  Requires Administrator.
    A non-fatal warning is printed if any route cannot be added.
    """
    gateway = _get_default_gateway_windows()
    if not gateway:
        print(
            "[windows_bypass] WARNING: Could not detect default gateway — "
            "QS-Tunnel traffic may be captured by WireGuard routing.\n"
            f"  Fix: run  route add <SERVER_IP> mask {_HOST_ROUTE_MASK} <DEFAULT_GATEWAY>"
            "  as Administrator."
        )
        return
    for ip in ips:
        try:
            subprocess.run(
                ["route", "add", ip, "mask", _HOST_ROUTE_MASK, gateway],
                check=True, capture_output=True, text=True, timeout=5,
            )
            _windows_bypass_ips.append(ip)
            print(f"[windows_bypass] Route added: {ip} via {gateway}")
        except subprocess.CalledProcessError as e:
            stderr = (e.stderr or "").strip()
            print(
                f"[windows_bypass] WARNING: Failed to add route for {ip}: "
                f"{stderr or e}\n"
                "  Ensure QS-Tunnel is running as Administrator for WireGuard bypass."
            )


def _remove_windows_bypass() -> None:
    """Remove host routes previously added by :func:`_apply_windows_bypass`."""
    for ip in _windows_bypass_ips:
        try:
            subprocess.run(
                ["route", "delete", ip, "mask", _HOST_ROUTE_MASK],
                capture_output=True, text=True, timeout=5,
            )
            print(f"[windows_bypass] Route removed: {ip}")
        except Exception:
            pass


def _setup_windows_bypass_routes() -> None:
    """Resolve all server hostnames to IPs and install Windows host routes for each.

    Called once at startup on Windows before any outbound connections are made.
    This is the Windows equivalent of the Linux ``fwmark`` / ``ip rule`` bypass.
    """
    bypass: set[str] = set()

    # Registration server
    try:
        bypass.add(socket.gethostbyname(server_reg_addr[0]))
    except OSError as e:
        print(f"[windows_bypass] Could not resolve registration server host: {e}")

    # NAT keep-alive / spoofed-source IP (always a literal IP)
    bypass.add(fake_send_ip)

    # VLESS server
    if use_builtin_vless:
        try:
            bypass.add(socket.gethostbyname(vless_info["host"]))
        except OSError as e:
            print(f"[windows_bypass] Could not resolve VLESS host: {e}")

    # Public IP detection services — use _IP_SVC_URLS as single source of truth
    svc_url = _IP_SVC_URLS.get(config.get("my_public_ip", ""))
    if svc_url:
        svc_host = urlparse(svc_url).hostname or ""
        try:
            bypass.add(socket.gethostbyname(svc_host))
        except OSError as e:
            print(f"[windows_bypass] Could not resolve IP-service host {svc_host!r}: {e}")

    if bypass:
        _apply_windows_bypass(list(bypass))
        atexit.register(_remove_windows_bypass)


def parse_vless_url(url: str) -> dict:
    """Parse a vless:// URL into its components."""
    parsed = urlparse(url)
    if parsed.scheme != "vless":
        raise ValueError(f"Expected vless:// URL, got scheme: {parsed.scheme!r}")
    raw_uuid = parsed.username
    if not raw_uuid:
        raise ValueError("VLESS URL missing UUID")
    try:
        uuid_bytes = uuid_module.UUID(raw_uuid).bytes
    except ValueError as e:
        raise ValueError(f"Invalid UUID in VLESS URL: {e}") from e
    host = parsed.hostname
    port = parsed.port
    if not host or not port:
        raise ValueError("VLESS URL missing host or port")
    params = parse_qs(parsed.query)
    transport = params.get("type", ["tcp"])[0].lower()
    security = params.get("security", ["none"])[0].lower()
    if transport != "ws":
        raise ValueError(
            f"Unsupported built-in VLESS transport type={transport!r}; only 'ws' is supported "
            "without Xray core."
        )
    if security not in ("none", "tls"):
        raise ValueError(
            f"Unsupported built-in VLESS security={security!r}; only 'none' and 'tls' are supported "
            "without Xray core."
        )
    path = unquote(params.get("path", ["/"])[0])
    sni = params.get("sni", [host])[0]
    ws_host_header = params.get("host", [host])[0]
    return {
        "uuid_bytes": uuid_bytes,
        "host": host,
        "port": port,
        "transport": transport,
        "security": security,
        "path": path,
        "sni": sni,
        "ws_host_header": ws_host_header,
    }


def build_vless_udp_request_header(uuid_bytes: bytes, dest_host: str, dest_port: int) -> bytes:
    """
    Build a VLESS request header for UDP.
      [1B version=0][16B UUID][1B addon_len=0][1B cmd=0x02 UDP]
      [2B dest_port BE][1B addr_type=1 IPv4][4B dest_IPv4]
    """
    header = bytearray()
    header.append(0x00)                             # version
    header.extend(uuid_bytes)                       # UUID (16 bytes)
    header.append(0x00)                             # addon length (none)
    header.append(0x02)                             # command: UDP
    header.extend(dest_port.to_bytes(2, "big"))     # destination port
    header.append(0x01)                             # address type: IPv4
    header.extend(socket.inet_aton(dest_host))      # destination IPv4
    return bytes(header)


try:
    with open(os.path.join(os.path.dirname(sys.argv[0]), "config_client.json"), encoding="utf-8-sig") as f:
        config = json.loads(f.read())
except FileNotFoundError:
    print("[error] config_client.json not found. Make sure it exists in the same directory as main_client.py.")
    sys.exit(1)
except json.JSONDecodeError as e:
    print(f"[error] Failed to parse config_client.json: {e}")
    print("[error] Ensure the file is valid JSON and saved with UTF-8 encoding (with or without BOM).")
    sys.exit(1)

info_encryption_pass = hashlib.sha256(config["info_encryption_pass"].encode()).digest()

fwmark = int(config.get("fwmark", 0))
if fwmark:
    print(f"[init] fwmark={fwmark}: QS-Tunnel sockets will be marked to bypass WireGuard routing")

fixed_client_id = config.get("client_id", "").strip()
if fixed_client_id:
    client_id_bytes = bytes.fromhex(fixed_client_id)
    print(f"[init] client_id: {client_id_bytes.hex()} (fixed)")
else:
    client_id_bytes = os.urandom(CLIENT_ID_WIDTH)
    print(f"[init] client_id: {client_id_bytes.hex()} (random)")

# --- Determine upload mode: built-in VLESS or external dokodemo-door ---
vless_cfg_str = config.get("vless_config", "").strip()
bridge_addr_str = config.get("bridge_address", "").strip()
xray_bridge_str = config.get("xray_bridge_inbound", "").strip()

use_builtin_vless = bool(vless_cfg_str)

if use_builtin_vless:
    if not bridge_addr_str:
        raise ValueError("'bridge_address' must be set when 'vless_config' is configured")
    vless_info = parse_vless_url(vless_cfg_str)
    try:
        _bh, _bp = bridge_addr_str.rsplit(":", 1)
        bridge_host = _bh
        bridge_port_num = int(_bp)
    except Exception as e:
        raise ValueError(f"Invalid 'bridge_address' format: {bridge_addr_str!r}") from e
    print("[init] Upload mode: built-in VLESS WebSocket client")
    print(f"[init] VLESS server: {vless_info['host']}:{vless_info['port']}, "
          f"transport={vless_info['transport']}, security={vless_info['security']}, "
          f"path={vless_info['path']!r}")
    print(f"[init] QS-Tunnel bridge target: {bridge_host}:{bridge_port_num}")
    xray_bridge_addr = None
    xray_bridge_socket = None
else:
    print("[init] Upload mode: external Xray dokodemo-door (xray_bridge_inbound)")
    if not xray_bridge_str:
        if bridge_addr_str:
            raise ValueError(
                "'bridge_address' is set but 'vless_config' is empty; either set 'vless_config' "
                "for built-in mode or set 'xray_bridge_inbound' for external Xray mode"
            )
        raise ValueError("Neither built-in VLESS ('vless_config') nor 'xray_bridge_inbound' is configured")
    xray_bridge_addr = (xray_bridge_str.rsplit(":", 1)[0], int(xray_bridge_str.rsplit(":", 1)[1]))
    xray_bridge_socket = create_v4_udp_dgram_socket(False, None)
    _apply_fwmark(xray_bridge_socket)
    print(f"[init] Xray bridge inbound: {xray_bridge_addr}")
    vless_info = None
    bridge_host = bridge_port_num = None

server_reg_addr = (config["server_registration_address"].rsplit(":", 1)[0],
                   int(config["server_registration_address"].rsplit(":", 1)[1]))
print(f"[init] Registration server: {server_reg_addr}")

h_inbound_bind_addr = (config["h_in_address"].rsplit(":", 1)[0],
                       int(config["h_in_address"].rsplit(":", 1)[1]))
print(f"[init] VPN app listen address: {h_inbound_bind_addr}")

h_inbound_socket = create_v4_udp_dgram_socket(False, h_inbound_bind_addr)

fake_send_ip = config["fake_send_ip"]
fake_send_port = int(config["fake_send_port"])
print(f"[init] Spoof source (fake_send_ip:port): {fake_send_ip}:{fake_send_port}")

wan_main_socket = create_v4_udp_dgram_socket(False, ("0.0.0.0", int(config.get("wan_port", 0))))
_apply_fwmark(wan_main_socket)
wan_main_socket_port = int(wan_main_socket.getsockname()[1])
print(f"[init] WAN receive socket bound to port: {wan_main_socket_port}")

last_h_addr = None

# Queue for outbound VLESS packets (used only when use_builtin_vless is True)
vless_send_queue: asyncio.Queue[bytes] = asyncio.Queue()


# ---------------------------------------------------------------------------
# Built-in VLESS WebSocket UDP client
# ---------------------------------------------------------------------------

async def _vless_send_loop(ws, is_tls: bool):
    """Read packets from vless_send_queue and send them over the WebSocket."""
    header_sent = False
    print("[vless] Send loop started")
    while True:
        data = await vless_send_queue.get()
        if not header_sent:
            req_header = build_vless_udp_request_header(
                vless_info["uuid_bytes"], bridge_host, bridge_port_num
            )
            frame = req_header + len(data).to_bytes(2, "big") + data
            header_sent = True
            print(f"[vless] Sent VLESS request header + first UDP packet ({len(data)} bytes)")
        else:
            frame = len(data).to_bytes(2, "big") + data
        await ws.send_bytes(frame)


async def _vless_drain_loop(ws):
    """
    Read and discard data arriving on the WebSocket.
    The download path uses IP spoofing (wan_recv), so WebSocket responses
    from the VLESS server are not meaningful for us — but we must drain them
    to avoid back-pressure that would stall the connection.
    """
    header_received = False
    print("[vless] Drain loop started")
    async for msg in ws:
        if msg.type == aiohttp.WSMsgType.BINARY:
            if not header_received:
                header_received = True
                data = msg.data
                addon_len = data[1] if len(data) >= 2 else 0
                print(f"[vless] Server response header received (addon_len={addon_len})")
            # Discard — download comes via IP-spoofed UDP in wan_recv()
        elif msg.type in (aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.ERROR):
            print(f"[vless] WebSocket closed/error in drain loop: type={msg.type}")
            break
    print("[vless] Drain loop exiting")


async def vless_manager():
    """
    Maintains a persistent VLESS WebSocket UDP connection.
    Reconnects automatically on failure.
    """
    security = vless_info["security"]
    scheme = "wss" if security in ("tls", "reality") else "ws"
    host = vless_info["host"]
    port = vless_info["port"]
    path = vless_info["path"]
    headers = {"Host": vless_info["ws_host_header"]}
    ssl_context = None
    if scheme == "wss":
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE

    print(f"[vless] Manager started — will connect to {scheme}://{host}:{port}{path}")

    loop = asyncio.get_running_loop()
    while True:
        try:
            # Resolve the hostname through a WireGuard-bypassing DNS query so
            # that getaddrinfo (which ignores SO_MARK) does not send DNS traffic
            # through the WireGuard tunnel.  We then connect to the resolved IP
            # and supply the original hostname via the Host header so that
            # SNI / virtual-hosting continues to work.
            try:
                resolved_ip = await _resolve_host_bypass_wg(host, loop)
            except Exception as e:
                print(f"[vless] DNS resolution failed for {host!r}: {e}")
                print("[vless] Reconnecting in 3 seconds...")
                await asyncio.sleep(3)
                continue

            ws_url = f"{scheme}://{resolved_ip}:{port}{path}"
            if resolved_ip != host:
                print(f"[vless] Resolved {host} → {resolved_ip}")
            print(f"[vless] Connecting to {ws_url} ...")
            connector = _make_aiohttp_connector()
            async with aiohttp.ClientSession(headers=headers, connector=connector) as session:
                async with session.ws_connect(
                    ws_url,
                    ssl=ssl_context,
                    heartbeat=30,
                    receive_timeout=None,
                ) as ws:
                    print(f"[vless] WebSocket connected to {ws_url}")
                    send_task = asyncio.create_task(_vless_send_loop(ws, scheme == "wss"))
                    drain_task = asyncio.create_task(_vless_drain_loop(ws))

                    done, pending = await asyncio.wait(
                        [send_task, drain_task],
                        return_when=asyncio.FIRST_COMPLETED,
                    )
                    for t in pending:
                        t.cancel()
                        try:
                            await t
                        except (asyncio.CancelledError, Exception):
                            pass
                    for t in done:
                        exc = t.exception()
                        if exc:
                            print(f"[vless] Task ended with error: {exc}")

        except Exception as e:
            print(f"[vless] Connection error: {e}")

        print("[vless] Reconnecting in 3 seconds...")
        await asyncio.sleep(3)


# ---------------------------------------------------------------------------
# Core tunnel tasks
# ---------------------------------------------------------------------------

async def h_recv():
    """Receive UDP from the local VPN app and forward upstream (via VLESS or dokodemo-door)."""
    loop = asyncio.get_running_loop()
    global h_inbound_socket
    global last_h_addr
    print(f"[h_recv] Listening for VPN app traffic on {h_inbound_bind_addr}")
    while True:
        use_socket = h_inbound_socket
        try:
            raw_data, addr_h = await loop.sock_recvfrom(use_socket, 65535)
        except Exception as e:
            print(f"[h_recv] Receive error: {e}")
            use_socket.close()
            while True:
                if h_inbound_socket != use_socket:
                    break
                try:
                    h_inbound_socket = create_v4_udp_dgram_socket(False, h_inbound_bind_addr)
                    print("[h_recv] Socket recreated")
                    break
                except Exception as e:
                    print(f"[h_recv] Socket recreate error: {e}")
                    await asyncio.sleep(1)
            continue

        if not raw_data:
            continue

        if last_h_addr != addr_h:
            last_h_addr = addr_h
            print(f"[h_recv] VPN app address updated: {addr_h}")

        packet = client_id_bytes + raw_data

        if use_builtin_vless:
            try:
                vless_send_queue.put_nowait(packet)
            except asyncio.QueueFull:
                print("[h_recv] VLESS send queue full, dropping packet")
        else:
            try:
                await loop.sock_sendto(xray_bridge_socket, packet, xray_bridge_addr)
            except Exception as e:
                print(f"[h_recv] xray_bridge_socket send error: {e}")


async def wan_recv():
    """Receive IP-spoofed UDP replies from the server and forward to the VPN app."""
    loop = asyncio.get_running_loop()
    global h_inbound_socket
    print(f"[wan_recv] Listening for spoofed replies on port {wan_main_socket_port}")
    while True:
        try:
            data, addr_w = await loop.sock_recvfrom(wan_main_socket, 65535)
        except Exception as e:
            print(f"[wan_recv] Receive error: {e}")
            raise

        if not data:
            continue

        if last_h_addr is None:
            print("[wan_recv] Received packet but no VPN app address yet, discarding")
            continue

        use_socket = h_inbound_socket
        try:
            await loop.sock_sendto(use_socket, data, last_h_addr)
        except Exception as e:
            print(f"[wan_recv] Forward to VPN app error: {e}")
            use_socket.close()
            while True:
                if h_inbound_socket != use_socket:
                    break
                try:
                    h_inbound_socket = create_v4_udp_dgram_socket(False, h_inbound_bind_addr)
                    print("[wan_recv] Socket recreated")
                    break
                except Exception as e:
                    print(f"[wan_recv] Socket recreate error: {e}")
                    await asyncio.sleep(1)


async def reg_send(my_public_ip: str):
    """Send registration packets to the QS-Tunnel server every 20 seconds."""
    loop = asyncio.get_running_loop()
    reg_socket = create_v4_udp_dgram_socket(False, None)
    _apply_fwmark(reg_socket)
    info_plain = (
        socket.inet_pton(socket.AF_INET, my_public_ip) +
        wan_main_socket_port.to_bytes(2, byteorder="big") +
        socket.inet_pton(socket.AF_INET, fake_send_ip) +
        fake_send_port.to_bytes(2, byteorder="big")
    )
    info_encrypted = bytes_xor(info_plain, info_encryption_pass)
    reg_packet = client_id_bytes + info_encrypted
    print(f"[reg_send] Will register as public IP {my_public_ip}, "
          f"WAN port {wan_main_socket_port}, "
          f"fake_send {fake_send_ip}:{fake_send_port}")
    while True:
        try:
            await loop.sock_sendto(reg_socket, reg_packet, server_reg_addr)
            print(f"[reg_send] Registration packet sent to {server_reg_addr}")
        except Exception as e:
            print(f"[reg_send] Send error: {e}")
        await asyncio.sleep(20)


async def nat_keep_alive():
    """Send periodic keep-alive packets to keep the NAT mapping open."""
    loop = asyncio.get_running_loop()
    print(f"[nat_keep_alive] Sending keep-alives to {fake_send_ip}:{fake_send_port} every 2s")
    while True:
        try:
            await asyncio.sleep(2)
            data = os.urandom(random.randint(257, 499))
            await loop.sock_sendto(wan_main_socket, data, (fake_send_ip, fake_send_port))
        except Exception as e:
            print(f"[nat_keep_alive] Send error: {e}")
            raise


async def fetch_ip(url: str):
    print(f"[fetch_ip] Fetching public IP from {url}")
    connector = _make_aiohttp_connector()
    async with aiohttp.ClientSession(connector=connector) as session:
        async with session.get(url) as response:
            response.raise_for_status()
            text = await response.text()
            ip_regex = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
            match = ip_regex.search(text)
            if match:
                print(f"[fetch_ip] Detected public IP: {match.group(0)}")
                return match.group(0)
            raise ValueError(f"No IP address found in response from {url}")


async def main():
    loop = asyncio.get_running_loop()

    # On Windows, WireGuard has no fwmark/SO_MARK equivalent.  Instead, install
    # explicit host routes for every server IP so QS-Tunnel's traffic bypasses the
    # WireGuard default route.  Must be done before any outbound connections.
    if sys.platform == "win32":
        _setup_windows_bypass_routes()

    my_public_ip = config["my_public_ip"]
    svc_url = _IP_SVC_URLS.get(my_public_ip)
    if svc_url:
        my_public_ip = await fetch_ip(svc_url)
    else:
        print(f"[main] Using configured public IP: {my_public_ip}")

    print(f"[main] Public IP: {my_public_ip}")

    print("[main] Sending initial NAT punch packets...")
    for i in range(3):
        data = os.urandom(random.randint(257, 499))
        await loop.sock_sendto(wan_main_socket, data, (fake_send_ip, fake_send_port))
        print(f"[main] NAT punch packet {i + 1}/3 sent to {fake_send_ip}:{fake_send_port}")
        await asyncio.sleep(0.001)

    tasks = [
        asyncio.create_task(h_recv()),
        asyncio.create_task(wan_recv()),
        asyncio.create_task(reg_send(my_public_ip)),
        asyncio.create_task(nat_keep_alive()),
    ]

    if use_builtin_vless:
        tasks.append(asyncio.create_task(vless_manager()))
        print("[main] Built-in VLESS manager task added")

    print("[main] All tasks started — tunnel is running")
    await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    print("[main] A task completed unexpectedly, shutting down")


asyncio.run(main())

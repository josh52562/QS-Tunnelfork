"""
QS-Tunnel Manual Registration Injector
روی سرور خارجی اجرا کن تا کلاینت رو دستی register کنه
"""

import socket
import hashlib
import struct
import sys

# ─────────────────────────────────────────────
#  مقادیر رو از config_client.json پر کن
# ─────────────────────────────────────────────

CLIENT_ID_HEX      = "3c8bcf"           # config_client.json : "client_id"
CLIENT_PUBLIC_IP   = "YOUR_CLIENT_IP"   # config_client.json : "my_public_ip"
WAN_OPEN_PORT      = 55000              # config_client.json : "wan_port"
FAKE_SEND_IP       = "1.1.1.1"          # config_client.json : "fake_send_ip"
FAKE_SEND_PORT     = 443                # config_client.json : "fake_send_port"
SHARED_PASSWORD    = ""                 # config_client.json : "info_encryption_pass"

# آدرس سرور خارجی — چون روی localhost اجرا می‌کنیم
SERVER_REG_IP      = "127.0.0.1"
SERVER_REG_PORT    = 5300

# ─────────────────────────────────────────────

def bytes_xor(data: bytes, key: bytes) -> bytes:
    return bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))

def build_registration_packet() -> bytes:
    client_id_bytes   = bytes.fromhex(CLIENT_ID_HEX)
    key               = hashlib.sha256(SHARED_PASSWORD.encode()).digest()
    client_ip_bytes   = socket.inet_pton(socket.AF_INET, CLIENT_PUBLIC_IP)
    wan_port_bytes    = WAN_OPEN_PORT.to_bytes(2, byteorder="big")
    fake_ip_bytes     = socket.inet_pton(socket.AF_INET, FAKE_SEND_IP)
    fake_port_bytes   = FAKE_SEND_PORT.to_bytes(2, byteorder="big")

    info_plain        = client_ip_bytes + wan_port_bytes + fake_ip_bytes + fake_port_bytes
    info_encrypted    = bytes_xor(info_plain, key)

    return client_id_bytes + info_encrypted

def main():
    packet = build_registration_packet()

    print(f"[+] client_id      : {CLIENT_ID_HEX}")
    print(f"[+] client_ip      : {CLIENT_PUBLIC_IP}")
    print(f"[+] wan_open_port  : {WAN_OPEN_PORT}")
    print(f"[+] fake_send      : {FAKE_SEND_IP}:{FAKE_SEND_PORT}")
    print(f"[+] packet size    : {len(packet)} bytes")
    print(f"[+] sending to     : {SERVER_REG_IP}:{SERVER_REG_PORT}")
    print()

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.sendto(packet, (SERVER_REG_IP, SERVER_REG_PORT))
        print("[+] Registration packet sent successfully!")
        print("[+] در لاگ main_server.py باید ببینی:")
        print(f"    [registration_recv] New client registered: {CLIENT_ID_HEX} ...")
    except Exception as e:
        print(f"[-] Error: {e}")
        sys.exit(1)
    finally:
        s.close()

if __name__ == "__main__":
    main()

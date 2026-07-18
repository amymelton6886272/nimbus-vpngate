#!/usr/bin/env python3
from __future__ import annotations
import base64
import os
import secrets
import select
import socket
import threading
import urllib.parse
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any
from pathlib import Path

def parse_positive_int(value: str | None, default: int) -> int:
    try:
        return max(1, int(value or default))
    except (TypeError, ValueError):
        return default

# 并发连接上限（默认从 256 降到 64，避免线程爆炸）
MAX_PROXY_CONNECTIONS = parse_positive_int(os.environ.get("LOCAL_PROXY_MAX_CONNECTIONS"), 64)
# 工作线程池大小：略大于并发上限，避免任务排队过久
PROXY_WORKER_THREADS = parse_positive_int(os.environ.get("LOCAL_PROXY_WORKER_THREADS"), min(96, MAX_PROXY_CONNECTIONS + 16))
# 握手/建连超时
PROXY_HANDSHAKE_TIMEOUT = parse_positive_int(os.environ.get("LOCAL_PROXY_HANDSHAKE_TIMEOUT"), 15)
PROXY_CONNECT_TIMEOUT = parse_positive_int(os.environ.get("LOCAL_PROXY_CONNECT_TIMEOUT"), 12)
# 转发空闲超时（秒）：两端都无数据则断开
PROXY_IDLE_TIMEOUT = parse_positive_int(os.environ.get("LOCAL_PROXY_IDLE_TIMEOUT"), 60)
# 单连接最大存活时间（秒）
PROXY_MAX_LIFETIME = parse_positive_int(os.environ.get("LOCAL_PROXY_MAX_LIFETIME"), 600)


# 客户端来源限制（Docker 网关转发后源 IP 可能是网关；仍可挡明显公网直扫）
PROXY_ALLOW_CIDRS = [x.strip() for x in os.environ.get("PROXY_ALLOW_CIDRS", "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8").split(",") if x.strip()]

def _ip_in_cidrs(ip: str, cidrs: list[str]) -> bool:
    try:
        import ipaddress
        addr = ipaddress.ip_address(ip)
        for c in cidrs:
            try:
                if addr in ipaddress.ip_network(c, strict=False):
                    return True
            except Exception:
                continue
        return False
    except Exception:
        return True  # 解析失败时不误杀

def client_allowed(address: tuple[str, int] | None) -> bool:
    if not address:
        return True
    ip = str(address[0] or "")
    if not ip:
        return True
    # 未配置则放行；配置后仅允许 CIDR
    if not PROXY_ALLOW_CIDRS:
        return True
    return _ip_in_cidrs(ip, PROXY_ALLOW_CIDRS)

proxy_connection_sem = threading.BoundedSemaphore(MAX_PROXY_CONNECTIONS)

# 备援上游代理（由 vpngate_manager 在「本区无 OpenVPN 可用」时写入）
FALLBACK_UPSTREAM_FILE = Path(os.environ.get("VPNGATE_DATA_DIR", "/app/vpngate_data")) / "fallback_upstream.json"
_fallback_cache: dict[str, Any] = {"mtime": -1.0, "data": None}

def load_fallback_upstream() -> dict[str, Any] | None:
    """读取 manager 下发的备援上游；enabled=false 或文件不存在则直连/走 tun。"""
    try:
        if not FALLBACK_UPSTREAM_FILE.exists():
            return None
        mtime = FALLBACK_UPSTREAM_FILE.stat().st_mtime
        if _fallback_cache.get("mtime") == mtime:
            return _fallback_cache.get("data")
        import json as _json
        raw = _json.loads(FALLBACK_UPSTREAM_FILE.read_text(encoding="utf-8"))
        data = raw if isinstance(raw, dict) and raw.get("enabled") else None
        _fallback_cache["mtime"] = mtime
        _fallback_cache["data"] = data
        return data
    except Exception:
        return None


def connect_via_http_proxy(proxy_host: str, proxy_port: int, target_host: str, target_port: int, timeout: float, user: str = "", password: str = "") -> socket.socket:
    sock = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
    set_socket_timeouts(sock, timeout)
    auth = ""
    if user or password:
        token = base64.b64encode(f"{user}:{password}".encode()).decode()
        auth = f"Proxy-Authorization: Basic {token}\r\n"
    req = (
        f"CONNECT {target_host}:{target_port} HTTP/1.1\r\n"
        f"Host: {target_host}:{target_port}\r\n"
        f"{auth}"
        f"Proxy-Connection: Keep-Alive\r\n\r\n"
    )
    sock.sendall(req.encode("iso-8859-1"))
    buf = b""
    while b"\r\n\r\n" not in buf and len(buf) < 8192:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
    head = buf.split(b"\r\n\r\n", 1)[0].decode("iso-8859-1", errors="replace")
    if " 200 " not in head.split("\r\n", 1)[0]:
        close_quietly(sock)
        raise ConnectionError(f"HTTP proxy CONNECT failed: {head.split(chr(10),1)[0][:120]}")
    return sock


def connect_via_socks5(proxy_host: str, proxy_port: int, target_host: str, target_port: int, timeout: float, user: str = "", password: str = "") -> socket.socket:
    sock = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
    set_socket_timeouts(sock, timeout)
    if user or password:
        sock.sendall(b"\x05\x02\x00\x02")  # no-auth + user/pass
    else:
        sock.sendall(b"\x05\x01\x00")
    resp = recv_exact(sock, 2)
    if resp[0] != 5:
        close_quietly(sock)
        raise ConnectionError("SOCKS5 version error")
    method = resp[1]
    if method == 2:
        u = user.encode()[:255]
        p = password.encode()[:255]
        sock.sendall(b"\x01" + bytes([len(u)]) + u + bytes([len(p)]) + p)
        auth_resp = recv_exact(sock, 2)
        if auth_resp[1] != 0:
            close_quietly(sock)
            raise ConnectionError("SOCKS5 auth failed")
    elif method != 0:
        close_quietly(sock)
        raise ConnectionError(f"SOCKS5 method rejected: {method}")
    # CONNECT domain
    host_b = target_host.encode("idna")
    req = b"\x05\x01\x00\x03" + bytes([len(host_b)]) + host_b + target_port.to_bytes(2, "big")
    sock.sendall(req)
    hdr = recv_exact(sock, 4)
    if hdr[1] != 0:
        close_quietly(sock)
        raise ConnectionError(f"SOCKS5 connect failed code={hdr[1]}")
    atyp = hdr[3]
    if atyp == 1:
        recv_exact(sock, 4 + 2)
    elif atyp == 3:
        ln = recv_exact(sock, 1)[0]
        recv_exact(sock, ln + 2)
    elif atyp == 4:
        recv_exact(sock, 16 + 2)
    return sock

_proxy_pool: ThreadPoolExecutor | None = None
_proxy_pool_lock = threading.Lock()

# 错误日志限流：同一类错误 10 秒内最多打 1 次
_log_last: dict[str, float] = {}
_log_lock = threading.Lock()

def _rate_limited_log(key: str, message: str, interval: float = 30.0) -> None:
    now = time.time()
    with _log_lock:
        last = _log_last.get(key, 0.0)
        if now - last < interval:
            return
        _log_last[key] = now
    print(message, flush=True)

def get_proxy_pool() -> ThreadPoolExecutor:
    global _proxy_pool
    with _proxy_pool_lock:
        if _proxy_pool is None:
            _proxy_pool = ThreadPoolExecutor(
                max_workers=PROXY_WORKER_THREADS,
                thread_name_prefix="proxy",
            )
            print(
                f"[代理] 线程池已启动: workers={PROXY_WORKER_THREADS}, max_conn={MAX_PROXY_CONNECTIONS}, "
                f"idle={PROXY_IDLE_TIMEOUT}s, lifetime={PROXY_MAX_LIFETIME}s",
                flush=True,
            )
        return _proxy_pool

def parse_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0

def set_socket_timeouts(sock: socket.socket, timeout: float) -> None:
    try:
        sock.settimeout(timeout)
    except OSError:
        pass
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    except OSError:
        pass
    # TCP keepalive 细调（Linux）
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 30)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
    except (OSError, AttributeError):
        pass

def close_quietly(sock: socket.socket | None) -> None:
    if sock is None:
        return
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    try:
        sock.close()
    except OSError:
        pass

def recv_exact(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("Unexpected disconnect.")
        data += chunk
    return data

def parse_host_port(authority: str, default_port: int) -> tuple[str, int]:
    authority = authority.strip()
    if authority.startswith("["):
        host_part, sep, rest = authority.partition("]")
        host = host_part.lstrip("[")
        port = default_port
        if sep and rest.startswith(":"):
            port_text = rest[1:]
            port = parse_int(port_text) or default_port
        return host, port
    if authority.count(":") == 1:
        host, _, port_text = authority.rpartition(":")
        return host, parse_int(port_text) or default_port
    return authority, default_port

def get_proxy_credentials() -> tuple[str | None, str | None]:
    user = os.environ.get("LOCAL_PROXY_USER") or os.environ.get("LOCAL_PROXY_USERNAME")
    password = os.environ.get("LOCAL_PROXY_PASS") or os.environ.get("LOCAL_PROXY_PASSWORD")
    if user is None and password is None:
        return None, None
    return user or "", password or ""

def proxy_auth_enabled() -> bool:
    user, password = get_proxy_credentials()
    return user is not None and password is not None

def parse_http_basic_auth(lines: list[str]) -> tuple[str | None, str | None]:
    for line in lines:
        name, sep, value = line.partition(":")
        if not sep or name.strip().lower() != "proxy-authorization":
            continue
        scheme, _, token = value.strip().partition(" ")
        if scheme.lower() != "basic" or not token:
            return None, None
        try:
            decoded = base64.b64decode(token, validate=True).decode("utf-8", errors="replace")
        except Exception:
            return None, None
        username, sep, password = decoded.partition(":")
        if not sep:
            return None, None
        return username, password
    return None, None

def check_credentials(username: str | None, password: str | None) -> bool:
    expected_user, expected_pass = get_proxy_credentials()
    if expected_user is None or expected_pass is None:
        return True
    return secrets.compare_digest(username or "", expected_user) and secrets.compare_digest(password or "", expected_pass)

def dns_query_over_tun0(host: str, qtype: int, dns_server: str, timeout: float) -> str | None:
    import random
    sock = None
    try:
        tx_id = random.getrandbits(16).to_bytes(2, "big")
        flags = b"\x01\x00"
        questions = b"\x00\x01"
        rrs = b"\x00\x00\x00\x00\x00\x00"

        qname = b""
        for part in host.split("."):
            if not part:
                continue
            part_bytes = part.encode("idna")
            if len(part_bytes) > 63:
                return None
            qname += len(part_bytes).to_bytes(1, "big") + part_bytes
        qname += b"\x00"

        qtype_qclass = qtype.to_bytes(2, "big") + b"\x00\x01"
        packet = tx_id + flags + questions + rrs + qname + qtype_qclass

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b"tun0")
        except OSError as e:
            if "operation not permitted" in str(e).lower() or e.errno == 1:
                _rate_limited_log(
                    "dns_perm",
                    "[DNS 绑定失败] [错误代码 3006] DNS 解析绑定 tun0 权限不足，请确保程序以 root 权限运行！",
                )
            elif "no such device" in str(e).lower() or e.errno == 19:
                _rate_limited_log(
                    "dns_nodev",
                    "[DNS 绑定失败] [错误代码 3004] DNS 解析绑定 tun0 失败，网卡设备不存在，请检查 VPN 连接！",
                )
            return None
        sock.sendto(packet, (dns_server, 53))
        resp, _ = sock.recvfrom(4096)
    except Exception:
        return None
    finally:
        close_quietly(sock)

    try:
        if len(resp) < 12 or resp[:2] != tx_id:
            return None
        rcode = resp[3] & 0x0F
        if rcode != 0:
            return None

        offset = 12
        while offset < len(resp):
            length = resp[offset]
            if length == 0:
                offset += 1
                break
            if (length & 0xC0) == 0xC0:
                offset += 2
                break
            offset += 1 + length

        offset += 4
        answers_count = int.from_bytes(resp[6:8], "big")
        for _ in range(answers_count):
            if offset >= len(resp):
                break
            while offset < len(resp):
                length = resp[offset]
                if length == 0:
                    offset += 1
                    break
                if (length & 0xC0) == 0xC0:
                    offset += 2
                    break
                offset += 1 + length
            if offset + 10 > len(resp):
                break
            atype = int.from_bytes(resp[offset : offset + 2], "big")
            aclass = int.from_bytes(resp[offset + 2 : offset + 4], "big")
            rdlength = int.from_bytes(resp[offset + 8 : offset + 10], "big")
            offset += 10
            if offset + rdlength > len(resp):
                break
            record = resp[offset : offset + rdlength]
            if atype == qtype and aclass == 1:
                if qtype == 1 and rdlength == 4:
                    return socket.inet_ntoa(record)
                if qtype == 28 and rdlength == 16:
                    return socket.inet_ntop(socket.AF_INET6, record)
            offset += rdlength
    except Exception:
        return None
    return None

def resolve_dns_over_tun0(host: str, dns_server: str = "8.8.8.8", timeout: float = 3.0) -> str | None:
    try:
        socket.inet_aton(host)
        return host
    except OSError:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, host)
        return host
    except OSError:
        pass
    return dns_query_over_tun0(host, 1, dns_server, timeout) or dns_query_over_tun0(host, 28, dns_server, timeout)

def create_connection(address: tuple[str, int], timeout: float | None = None) -> socket.socket:
    if timeout is None:
        timeout = float(PROXY_CONNECT_TIMEOUT)
    host, port = address

    # 备援上游：仅当 manager 明确启用（通常意味着本区无 OpenVPN）
    fb = load_fallback_upstream()
    if fb:
        ptype = str(fb.get("type") or fb.get("protocol") or "http").lower()
        ph = str(fb.get("host") or "")
        pp = int(fb.get("port") or 0)
        user = str(fb.get("username") or "")
        password = str(fb.get("password") or "")
        if ph and pp:
            try:
                if ptype.startswith("socks"):
                    return connect_via_socks5(ph, pp, host, port, timeout, user, password)
                return connect_via_http_proxy(ph, pp, host, port, timeout, user, password)
            except Exception as e:
                _rate_limited_log(f"fallback:{ph}:{pp}", f"[备援上游失败] {ptype}://{ph}:{pp} -> {host}:{port}: {e}", 20.0)
                raise

    # 默认：有 tun0 则绑定，否则普通直连（备援模式不会走到这里）
    bind_tun = Path("/sys/class/net/tun0").exists()
    err: Exception | None = None
    for res in socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM):
        af, socktype, proto, canonname, sa = res
        sock = None
        try:
            sock = socket.socket(af, socktype, proto)
            set_socket_timeouts(sock, timeout)
            if bind_tun:
                try:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b"tun0")
                except OSError as e:
                    if e.errno in (1,):
                        raise OSError(
                            "[错误代码 3006] [ERR_PROXY_BIND_TUN_PERM_DENIED] 绑定虚拟网卡 tun0 失败，权限不足！"
                        ) from e
            sock.connect(sa)
            return sock
        except OSError as e:
            err = e
            close_quietly(sock)
    if err is not None:
        raise err
    raise OSError("getaddrinfo returns empty list")

def relay(left: socket.socket, right: socket.socket) -> None:
    """双向转发，带空闲超时与最大存活时间，防止僵尸连接占线程。"""
    sockets = [left, right]
    started = time.time()
    # 转发阶段用非阻塞 + select 超时控制
    for s in sockets:
        try:
            s.settimeout(None)
            s.setblocking(True)
        except OSError:
            pass

    while True:
        if time.time() - started > PROXY_MAX_LIFETIME:
            return
        readable, _, errored = select.select(sockets, [], sockets, PROXY_IDLE_TIMEOUT)
        if errored or not readable:
            # 空闲超时或错误
            return
        for source in readable:
            target = right if source is left else left
            try:
                data = source.recv(65536)
            except OSError:
                return
            if not data:
                return
            try:
                target.sendall(data)
            except OSError:
                return

def socks5_client(client: socket.socket, first_byte: bytes) -> None:
    upstream = None
    try:
        methods_count = recv_exact(client, 1)[0]
        methods = recv_exact(client, methods_count)
        if proxy_auth_enabled():
            if 2 not in methods:
                client.sendall(b"\x05\xff")
                return
            client.sendall(b"\x05\x02")
            auth_version = recv_exact(client, 1)[0]
            if auth_version != 1:
                client.sendall(b"\x01\x01")
                return
            username = recv_exact(client, recv_exact(client, 1)[0]).decode("utf-8", errors="replace")
            password = recv_exact(client, recv_exact(client, 1)[0]).decode("utf-8", errors="replace")
            if not check_credentials(username, password):
                client.sendall(b"\x01\x01")
                return
            client.sendall(b"\x01\x00")
        else:
            client.sendall(b"\x05\x00")
        version, command, _, address_type = recv_exact(client, 4)
        if version != 5 or command != 1:
            client.sendall(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
            return
        if address_type == 1:
            host = socket.inet_ntoa(recv_exact(client, 4))
        elif address_type == 3:
            host = recv_exact(client, recv_exact(client, 1)[0]).decode("idna")
        elif address_type == 4:
            host = socket.inet_ntop(socket.AF_INET6, recv_exact(client, 16))
        else:
            client.sendall(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
            return
        port = int.from_bytes(recv_exact(client, 2), "big")
        try:
            upstream = create_connection((host, port), timeout=float(PROXY_CONNECT_TIMEOUT))
        except Exception as e:
            _rate_limited_log(f"socks5:{host}", f"[SOCKS5 代理失败] 目标 {host}:{port} 连接失败: {e}", 60.0)
            try:
                client.sendall(b"\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00")
            except OSError:
                pass
            raise
        client.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        relay(client, upstream)
    finally:
        close_quietly(client)
        close_quietly(upstream)

def read_http_header(client: socket.socket, first_byte: bytes) -> bytes:
    data = first_byte
    while b"\r\n\r\n" not in data and len(data) < 65536:
        chunk = client.recv(4096)
        if not chunk:
            break
        data += chunk
    return data

def http_client(client: socket.socket, first_byte: bytes) -> None:
    upstream = None
    try:
        header = read_http_header(client, first_byte)
        if b"\r\n\r\n" not in header:
            client.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
            return
        head, rest = header.split(b"\r\n\r\n", 1)
        lines = head.decode("iso-8859-1", errors="replace").split("\r\n")
        try:
            method, target, version = lines[0].split(" ", 2)
        except ValueError:
            client.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
            return
        if not version.startswith("HTTP/"):
            client.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
            return
        if proxy_auth_enabled():
            username, password = parse_http_basic_auth(lines[1:])
            if not check_credentials(username, password):
                client.sendall(
                    b"HTTP/1.1 407 Proxy Authentication Required\r\n"
                    b'Proxy-Authenticate: Basic realm="NimbusVPN Proxy"\r\n'
                    b"Content-Length: 0\r\n\r\n"
                )
                return

        fb = load_fallback_upstream()

        if method.upper() == "CONNECT":
            host, port = parse_host_port(target, 443)
            if isinstance(host, str) and host.count(":") == 1 and not host.startswith("["):
                h2, p2 = parse_host_port(host, port)
                host, port = h2, (p2 or port)
            # CONNECT 需要上游支持隧道；HTTP 备援走 create_connection->CONNECT
            upstream = create_connection((host, int(port)), timeout=float(PROXY_CONNECT_TIMEOUT))
            client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            if rest:
                upstream.sendall(rest)
            relay(client, upstream)
            return

        try:
            parsed = urllib.parse.urlsplit(target)
        except ValueError:
            client.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
            return

        hostname = parsed.hostname
        port = parsed.port
        scheme = (parsed.scheme or "http").lower()
        if not hostname:
            for line in lines[1:]:
                if line.lower().startswith("host:"):
                    host_val = line.split(":", 1)[1].strip()
                    hostname, parsed_port = parse_host_port(host_val, 0)
                    port = parsed_port or None
                    break
        if not hostname:
            client.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
            return
        port = int(port or (443 if scheme == "https" else 80))
        path = urllib.parse.urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
        if not path.startswith("/"):
            path = "/" + path

        # 备援 HTTP 上游：直接 absolute-form 转发（不走 create_connection/CONNECT）
        if fb and not str(fb.get("type") or fb.get("protocol") or "http").lower().startswith("socks"):
            ph = str(fb.get("host") or "")
            pp = int(fb.get("port") or 0)
            user = str(fb.get("username") or "")
            password = str(fb.get("password") or "")
            if not ph or not pp:
                raise ConnectionError("fallback proxy incomplete")
            if target.lower().startswith("http://") or target.lower().startswith("https://"):
                abs_url = target
            else:
                abs_url = f"http://{hostname}{path}" if port == 80 else f"http://{hostname}:{port}{path}"
            out_headers = []
            for line in lines[1:]:
                low = line.lower()
                if low.startswith(("proxy-connection:", "connection:", "proxy-authorization:", "host:")):
                    continue
                out_headers.append(line)
            out_headers.insert(0, f"Host: {hostname}" if port in (80, 443) else f"Host: {hostname}:{port}")
            if user or password:
                token = base64.b64encode(f"{user}:{password}".encode()).decode()
                out_headers.append(f"Proxy-Authorization: Basic {token}")
            out_headers.append("Connection: close")
            raw = f"{method} {abs_url} {version}\r\n" + "\r\n".join(out_headers) + "\r\n\r\n"
            try:
                upstream = socket.create_connection((ph, pp), timeout=float(PROXY_CONNECT_TIMEOUT))
            except Exception as e:
                raise ConnectionError(f"connect parent {ph}:{pp} failed: {e}") from e
            set_socket_timeouts(upstream, float(PROXY_CONNECT_TIMEOUT))
            upstream.sendall(raw.encode("iso-8859-1") + rest)
            relay(client, upstream)
            return

        headers = []
        has_host = False
        for line in lines[1:]:
            low = line.lower()
            if low.startswith(("proxy-connection:", "connection:", "proxy-authorization:")):
                continue
            if low.startswith("host:"):
                has_host = True
            headers.append(line)
        if not has_host:
            headers.insert(0, f"Host: {hostname}" if port in (80, 443) else f"Host: {hostname}:{port}")
        request = f"{method} {path} {version}\r\n" + "\r\n".join(headers) + "\r\nConnection: close\r\n\r\n"
        upstream = create_connection((hostname, port), timeout=float(PROXY_CONNECT_TIMEOUT))
        upstream.sendall(request.encode("iso-8859-1") + rest)
        relay(client, upstream)
    except Exception as e:
        _rate_limited_log("http_proxy_fail", f"[HTTP 代理失败] 代理请求目标连接失败: {e}", 5.0)
        try:
            client.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
        except OSError:
            pass
    finally:
        close_quietly(client)
        close_quietly(upstream)



def proxy_client(client: socket.socket, address: tuple[str, int]) -> None:
    try:
        if not client_allowed(address):
            _rate_limited_log(f"deny:{address[0]}", f"[代理拒绝] 非允许网段 {address[0]}", 30.0)
            close_quietly(client)
            return

        set_socket_timeouts(client, float(PROXY_HANDSHAKE_TIMEOUT))
        first = recv_exact(client, 1)
        if first == b"\x05":
            socks5_client(client, first)
        else:
            http_client(client, first)
    except Exception as e:
        err_msg = str(e)
        if "[错误代码" in err_msg:
            _rate_limited_log(
                "client_sys",
                f"[代理客户端连接失败] 客户端 {address} 遭遇系统性阻碍: {err_msg}",
            )
        close_quietly(client)

def start_proxy_server(host: str, port: int) -> None:
    is_ipv6 = ":" in host or host == ""
    af = socket.AF_INET6 if is_ipv6 else socket.AF_INET
    server = None
    try:
        server = socket.socket(af, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if is_ipv6:
            try:
                server.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            except OSError:
                pass
        server.bind((host, port))
        server.listen(128)
        print(f"HTTP/SOCKS5 proxy listening on {host}:{port}", flush=True)
    except Exception as e:
        close_quietly(server)
        if is_ipv6 and host in ("::", ""):
            print(f"[警告] 绑定 IPv6 {host}:{port} 失败 ({e})，正在尝试回退至 IPv4 0.0.0.0 ...", flush=True)
            try:
                server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server.bind(("0.0.0.0", port))
                server.listen(128)
                print(f"HTTP/SOCKS5 proxy listening on 0.0.0.0:{port} (仅 IPv4)", flush=True)
            except Exception as ex:
                import vpn_utils
                diag = vpn_utils.diagnose_local_obstructions(port, host="0.0.0.0")
                diag_msg = diag[1] if diag else str(ex)
                print(f"[ERROR] Failed to start HTTP/SOCKS5 proxy on 0.0.0.0:{port}: {diag_msg}", flush=True)
                return
        elif is_ipv6 and host == "::1":
            print(f"[警告] 绑定 IPv6 {host}:{port} 失败 ({e})，正在尝试回退至 IPv4 127.0.0.1 ...", flush=True)
            try:
                server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server.bind(("127.0.0.1", port))
                server.listen(128)
                print(f"HTTP/SOCKS5 proxy listening on 127.0.0.1:{port} (仅 IPv4)", flush=True)
            except Exception as ex:
                import vpn_utils
                diag = vpn_utils.diagnose_local_obstructions(port, host="127.0.0.1")
                diag_msg = diag[1] if diag else str(ex)
                print(f"[ERROR] Failed to start HTTP/SOCKS5 proxy on 127.0.0.1:{port}: {diag_msg}", flush=True)
                return
        else:
            import vpn_utils
            diag = vpn_utils.diagnose_local_obstructions(port, host=host)
            diag_msg = diag[1] if diag else str(e)
            print(f"[ERROR] Failed to start HTTP/SOCKS5 proxy on {host}:{port}: {diag_msg}", flush=True)
            return

    pool = get_proxy_pool()
    reject_log_ts = 0.0

    while True:
        try:
            client, address = server.accept()
            if not proxy_connection_sem.acquire(blocking=False):
                now = time.time()
                if now - reject_log_ts > 10:
                    print(
                        f"[代理限流] 当前连接数已达到上限 {MAX_PROXY_CONNECTIONS}，拒绝客户端 {address}",
                        flush=True,
                    )
                    reject_log_ts = now
                close_quietly(client)
                continue

            def run_client(c: socket.socket = client, addr: tuple[str, int] = address) -> None:
                try:
                    proxy_client(c, addr)
                finally:
                    proxy_connection_sem.release()

            try:
                pool.submit(run_client)
            except Exception as e:
                # 线程池满/关闭时立即释放信号量
                proxy_connection_sem.release()
                close_quietly(client)
                _rate_limited_log("pool_submit", f"[ERROR] Proxy submit failed: {e}")
        except Exception as e:
            print(f"[ERROR] Proxy accept failed: {e}", flush=True)
            time.sleep(0.5)

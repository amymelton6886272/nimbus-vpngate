#!/usr/bin/env python3
from __future__ import annotations

import base64
import csv
import json
import os
import queue
import re
import secrets
import select
import shlex
import signal
import socket
import subprocess
import threading
import time
import urllib.parse
import urllib.request
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
import concurrent.futures
import sys
import uuid

# Prefer IPv4 resolution to avoid slow AAAA DNS timeouts (e.g. in WSL),
# but fall back to system default (IPv6) if IPv4 resolution fails.
# This ensures pure-IPv6 VPS (with NAT64/clatd) can still function.
_orig_getaddrinfo = socket.getaddrinfo
def _ipv4_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    if family == 0:
        if isinstance(host, str) and ":" in host:
            return _orig_getaddrinfo(host, port, socket.AF_INET6, type, proto, flags)
        # Try IPv4 first for speed; fall back to system default (allows IPv6/NAT64)
        try:
            results = _orig_getaddrinfo(host, port, socket.AF_INET, type, proto, flags)
            if results:
                return results
        except socket.gaierror:
            pass
        return _orig_getaddrinfo(host, port, 0, type, proto, flags)
    return _orig_getaddrinfo(host, port, family, type, proto, flags)
socket.getaddrinfo = _ipv4_getaddrinfo

class DualStackHTTPServer(ThreadingHTTPServer):
    def __init__(self, server_address, RequestHandlerClass, bind_and_activate=True):
        host, port = server_address
        if ":" in host or host == "":
            self.address_family = socket.AF_INET6
        else:
            self.address_family = socket.AF_INET
        
        try:
            super().__init__(server_address, RequestHandlerClass, bind_and_activate)
        except OSError as e:
            if self.address_family == socket.AF_INET6:
                fallback_host = "0.0.0.0" if host in ("::", "") else "127.0.0.1"
                print(f"[警告] 绑定 Web 管理后台 IPv6 {host}:{port} 失败 ({e})，正在尝试回退至 IPv4 {fallback_host} ...", flush=True)
                # 关闭第一次失败时可能已创建的 socket
                try:
                    self.socket.close()
                except Exception:
                    pass
                self.address_family = socket.AF_INET
                super().__init__((fallback_host, port), RequestHandlerClass, bind_and_activate)
            else:
                raise e

    def server_bind(self):
        if self.address_family == socket.AF_INET6:
            try:
                self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            except OSError:
                pass
        super().server_bind()

import vpn_utils
import proxy_server

def env_int(name: str, default: int, min_value: int | None = None, max_value: int | None = None) -> int:
    raw = os.environ.get(name)
    try:
        value = int(raw) if raw not in (None, "") else default
    except (TypeError, ValueError):
        print(f"[配置警告] 环境变量 {name}={raw!r} 不是有效整数，使用默认值 {default}", flush=True)
        value = default
    if min_value is not None and value < min_value:
        print(f"[配置警告] 环境变量 {name}={value} 小于允许值 {min_value}，使用默认值 {default}", flush=True)
        return default
    if max_value is not None and value > max_value:
        print(f"[配置警告] 环境变量 {name}={value} 大于允许值 {max_value}，使用默认值 {default}", flush=True)
        return default
    return value

def env_str(name: str, default: str) -> str:
    raw = os.environ.get(name)
    if raw in (None, ""):
        return default
    return raw.strip()

def env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw in (None, ""):
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")

def bounded_int(value: Any, default: int, min_value: int | None = None, max_value: int | None = None) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    if min_value is not None and parsed < min_value:
        return default
    if max_value is not None and parsed > max_value:
        return default
    return parsed

API_URL = "https://www.vpngate.net/api/iphone/"
FETCH_INTERVAL_SECONDS = env_int("FETCH_INTERVAL_SECONDS", 1260, 1)
CHECK_INTERVAL_SECONDS = env_int("CHECK_INTERVAL_SECONDS", 1260, 1)
TARGET_VALID_NODES = env_int("TARGET_VALID_NODES", 3, 1)
MAX_SCAN_ROWS = env_int("MAX_SCAN_ROWS", 300, 1)
OPENVPN_TEST_TIMEOUT_SECONDS = env_int("OPENVPN_TEST_TIMEOUT_SECONDS", 12, 1)
OPENVPN_CMD = os.environ.get("OPENVPN_CMD", "openvpn")
OPENVPN_AUTH_USER = os.environ.get("OPENVPN_AUTH_USER", "vpn")
OPENVPN_AUTH_PASS = os.environ.get("OPENVPN_AUTH_PASS", "vpn")
LOCAL_PROXY_HOST = os.environ.get("LOCAL_PROXY_HOST", "127.0.0.1")
LOCAL_PROXY_PORT = env_int("LOCAL_PROXY_PORT", 7928, 1, 65535)
UI_HOST = os.environ.get("UI_HOST", "::")
UI_PORT = env_int("UI_PORT", 8787, 1, 65535)
INVALID_BACKOFF_SECONDS = env_int("INVALID_BACKOFF_SECONDS", 30 * 60, 1)
LOG_RETENTION_DAYS = env_int("LOG_RETENTION_DAYS", 3, 1)
CONFIG_RETENTION_DAYS = env_int("CONFIG_RETENTION_DAYS", 7, 1)
MIN_NODE_SPEED = env_int("MIN_NODE_SPEED", 0, 0)
MAX_NODE_LATENCY_MS = env_int("MAX_NODE_LATENCY_MS", 0, 0)
MAX_NODE_SESSIONS = env_int("MAX_NODE_SESSIONS", 0, 0)
ENV_ROUTING_MODE = env_str("ROUTING_MODE", "")
ENV_FORCE_COUNTRY = env_str("FORCE_COUNTRY", "")
ENV_ROUTING_IP_TYPE = env_str("ROUTING_IP_TYPE", "")
ENV_CONNECTION_ENABLED = env_bool("CONNECTION_ENABLED", True)
ENV_HUB_API_TOKEN = env_str("HUB_API_TOKEN", "")
ENV_EXCLUDE_COUNTRIES = {
    item.strip().upper()
    for item in env_str("EXCLUDE_COUNTRIES", "").split(",")
    if item.strip()
}

IS_SCANNER = env_bool("IS_SCANNER", False)
SHARED_DATA_DIR = os.environ.get("SHARED_DATA_DIR", "/app/shared_data")

VALID_ROUTING_MODES = {"auto", "fixed_ip", "fixed_region", "favorites"}
VALID_ROUTING_IP_TYPES = {"all", "residential", "hosting"}

def node_country_code(node: dict[str, Any]) -> str:
    country_short = str(node.get("country_short") or "").strip().upper()
    if country_short:
        return country_short
    node_id = str(node.get("id") or "").strip().upper()
    if "_" in node_id:
        return node_id.split("_", 1)[0]
    return ""

def apply_routing_filters(nodes: list[dict[str, Any]], ui_cfg: dict[str, Any]) -> list[dict[str, Any]]:
    routing_mode = ui_cfg.get("routing_mode", "auto")
    target_country = str(ui_cfg.get("force_country", "") or "").strip().upper()
    filtered = list(nodes)

    if ENV_EXCLUDE_COUNTRIES:
        filtered = [n for n in filtered if node_country_code(n) not in ENV_EXCLUDE_COUNTRIES]

    if MIN_NODE_SPEED > 0:
        filtered = [n for n in filtered if parse_int(n.get("speed")) >= MIN_NODE_SPEED]
    if MAX_NODE_LATENCY_MS > 0:
        filtered = [
            n for n in filtered
            if (parse_int(n.get("latency_ms")) or parse_int(n.get("ping")) or 999999) <= MAX_NODE_LATENCY_MS
        ]
    if MAX_NODE_SESSIONS > 0:
        filtered = [n for n in filtered if parse_int(n.get("sessions")) <= MAX_NODE_SESSIONS]

    if routing_mode == "fixed_region" and target_country:
        filtered = [
            n for n in filtered
            if node_country_code(n) == target_country
            or n.get("country") == target_country
            or vpn_utils.COUNTRY_TRANSLATIONS.get(n.get("country", ""), n.get("country", "")) == target_country
        ]
    elif routing_mode == "favorites":
        fav_ids = set(ui_cfg.get("favorite_node_ids", []))
        fav_candidates = [n for n in filtered if n.get("id") in fav_ids]
        if fav_candidates:
            filtered = fav_candidates
        elif not ui_cfg.get("fav_fail_fallback", True):
            filtered = []

    routing_ip_type = ui_cfg.get("routing_ip_type", "all")
    if routing_ip_type == "residential":
        filtered = [n for n in filtered if n.get("ip_type") in ("residential", "mobile")]
    elif routing_ip_type == "hosting":
        filtered = [n for n in filtered if n.get("ip_type") == "hosting"]

    return filtered

def compute_quality_score(node: dict[str, Any]) -> int:
    """综合质量分：越高越好。用于连接排序。"""
    base = parse_int(node.get("score"))  # VPNGate 原始分
    success = parse_int(node.get("success_count"))
    fails = parse_int(node.get("fail_count"))
    latency = parse_int(node.get("latency_ms")) or parse_int(node.get("ping")) or 0
    ip_type = str(node.get("ip_type") or "").strip().lower()

    # 成功率加成
    quality = base
    quality += success * 40
    quality -= fails * 80

    # 延迟：越低越好
    if latency > 0:
        if latency <= 80:
            quality += 60
        elif latency <= 150:
            quality += 30
        elif latency <= 300:
            quality += 10
        elif latency >= 800:
            quality -= 40

    # IP 类型
    if ip_type in ("residential", "mobile"):
        quality += 50
    elif ip_type == "hosting":
        quality += 10

    # 探测级别：仅握手成功降权
    st = str(node.get("probe_status") or "")
    if st == "soft_available":
        quality -= 120
    if node.get("probe_egress_ok") is False and node.get("probe_handshake_ok"):
        quality -= 80

    # 最近成功过
    last_ok = float(node.get("last_success_at") or 0)
    if last_ok and time.time() - last_ok < 3600:
        quality += 25

    # 黑名单/冷却中的节点大幅降权
    if float(node.get("blacklist_until") or 0) > time.time():
        quality -= 500

    node["quality_score"] = quality
    return quality



def is_us_node(node: dict[str, Any]) -> bool:
    code = str(node.get("country_short") or "").upper()
    nid = str(node.get("id") or "")
    return code == "US" or nid.startswith("US_")


def us_node_extra_score(node: dict[str, Any]) -> float:
    """US 节点额外加权：最近成功、低延迟、非黑名单。"""
    score = 0.0
    if node.get("probe_status") == "available":
        score += 50
    lat = float(node.get("latency_ms") or node.get("ping") or 9999)
    if lat < 200:
        score += 30
    elif lat < 400:
        score += 15
    sc = int(node.get("success_count") or 0)
    fc = int(node.get("fail_count") or 0)
    score += sc * 5 - fc * 8
    if is_node_in_cooldown(str(node.get("id") or "")):
        score -= 100
    return score


def node_preference_key(node: dict[str, Any]) -> tuple[int, int, int, int]:
    ip_type = str(node.get("ip_type") or "").strip().lower()
    type_rank = 0 if ip_type in ("residential", "mobile") else 1 if ip_type == "hosting" else 2
    latency = parse_int(node.get("latency_ms")) or parse_int(node.get("ping")) or 999999
    q = compute_quality_score(node)
    vpngate_score = parse_int(node.get("score"))
    # 先类型，再质量分，再延迟，再原始分
    return (type_rank, -q, latency, -vpngate_score)

def best_available_node(nodes: list[dict[str, Any]], ui_cfg: dict[str, Any], include_active: bool = False) -> dict[str, Any] | None:
    candidates = [
        n for n in nodes
        if n.get("probe_status") == "available"
        and (include_active or not n.get("active"))
    ]
    candidates = apply_routing_filters(candidates, ui_cfg)
    candidates.sort(key=node_preference_key)
    return candidates[0] if candidates else None

def process_memory_rss_bytes() -> int:
    try:
        if sys.platform.startswith("linux"):
            statm = Path("/proc/self/statm").read_text(encoding="utf-8").split()
            if len(statm) >= 2:
                return int(statm[1]) * os.sysconf("SC_PAGE_SIZE")
    except Exception:
        pass
    return 0

ROOT_DIR = Path(sys.executable).resolve().parent if globals().get("__compiled__") else Path(__file__).resolve().parent
DATA_DIR = Path(os.environ["VPNGATE_DATA_DIR"]).resolve() if os.environ.get("VPNGATE_DATA_DIR") else ROOT_DIR / "vpngate_data"
CONFIG_DIR = DATA_DIR / "configs"
NODES_FILE = DATA_DIR / "nodes.json"
STATE_FILE = DATA_DIR / "state.json"
AUTH_FILE = DATA_DIR / "vpngate_auth.txt"
UPSTREAM_PROXY_AUTH_FILE = DATA_DIR / "upstream_proxy_auth.txt"
BLACKLIST_FILE = DATA_DIR / "blacklist.json"

# Shared scan (centralized scanning across Docker containers)
SHARED_NODES_FILE = Path(SHARED_DATA_DIR) / "shared_nodes.json"
SHARED_META_FILE = Path(SHARED_DATA_DIR) / "shared_meta.json"
SHARED_PROXIES_FILE = Path(SHARED_DATA_DIR) / "shared_proxies.json"
SHARED_PROXIES_META_FILE = Path(SHARED_DATA_DIR) / "shared_proxies_meta.json"
FALLBACK_UPSTREAM_FILE = DATA_DIR / "fallback_upstream.json"
FREEPROXYDB_ENABLED = env_bool("FREEPROXYDB_ENABLED", True)
FREEPROXYDB_API = os.environ.get("FREEPROXYDB_API", "https://freeproxydb.com/api/proxy").rstrip("/")
FREEPROXYDB_PROTOCOLS = os.environ.get("FREEPROXYDB_PROTOCOLS", "socks5,http")
FREEPROXYDB_PER_REGION = env_int("FREEPROXYDB_PER_REGION", 8, 1)
FREEPROXYDB_TEST_LIMIT = env_int("FREEPROXYDB_TEST_LIMIT", 12, 1)


lock = threading.RLock()
maintenance_lock = threading.Lock()
active_sessions: dict[str, float] = {}
active_openvpn_process: subprocess.Popen[str] | None = None
active_openvpn_node_id = ""
is_connecting = True
is_scanning = False
scan_progress = {"total": 0, "tested": 0, "current": "", "started_at": 0.0}
node_fail_cooldown: dict[str, float] = {}
region_fail_pause_until = 0.0
CONNECT_FAIL_COOLDOWN_SECONDS = env_int("CONNECT_FAIL_COOLDOWN_SECONDS", 900, 1)
REGION_FAIL_PAUSE_SECONDS = env_int("REGION_FAIL_PAUSE_SECONDS", 1800, 1)
REGION_FAIL_THRESHOLD = env_int("REGION_FAIL_THRESHOLD", 3, 1)
region_fail_streak = 0
last_active_ping_time = 0.0
last_active_latency = 0

last_collector_heartbeat = 0.0
last_checker_heartbeat = 0.0
last_pinger_heartbeat = 0.0
server_start_time = time.time()

def ensure_dirs() -> None:
    DATA_DIR.mkdir(exist_ok=True, parents=True)
    CONFIG_DIR.mkdir(exist_ok=True, parents=True)
    if not AUTH_FILE.exists():
        AUTH_FILE.write_text(f"{OPENVPN_AUTH_USER}\n{OPENVPN_AUTH_PASS}\n", encoding="utf-8")
        try:
            AUTH_FILE.chmod(0o600)
        except OSError:
            pass

def upstream_proxy_auth_file() -> str | None:
    username, password = vpn_utils.get_upstream_proxy_auth()
    if username is None:
        return None
    try:
        DATA_DIR.mkdir(exist_ok=True, parents=True)
        UPSTREAM_PROXY_AUTH_FILE.write_text(f"{username}\n{password or ''}\n", encoding="utf-8")
        try:
            UPSTREAM_PROXY_AUTH_FILE.chmod(0o600)
        except OSError:
            pass
        return str(UPSTREAM_PROXY_AUTH_FILE)
    except Exception as exc:
        print(f"[上游代理认证] 写入认证文件失败: {exc}", flush=True)
        return None

def write_json(path: Path, data: Any) -> None:
    with lock:
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(path)

def read_json(path: Path, default: Any) -> Any:
    with lock:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return default

import hashlib
import random

def generate_random_password() -> str:
    import string
    chars = string.ascii_letters + string.digits
    while True:
        pwd = "".join(random.choices(chars, k=12))
        # Ensure it contains at least one lowercase, one uppercase, and one digit
        has_lower = any(c.islower() for c in pwd)
        has_upper = any(c.isupper() for c in pwd)
        has_digit = any(c.isdigit() for c in pwd)
        if has_lower and has_upper and has_digit:
            return pwd

def generate_random_username() -> str:
    import string
    chars = string.ascii_letters + string.digits
    while True:
        uname = "".join(random.choices(chars, k=12))
        # Ensure it starts with a letter and contains at least one lowercase, one uppercase, and one digit
        if uname[0].isalpha():
            has_lower = any(c.islower() for c in uname)
            has_upper = any(c.isupper() for c in uname)
            has_digit = any(c.isdigit() for c in uname)
            if has_lower and has_upper and has_digit:
                return uname

def load_ui_config() -> dict[str, Any]:
    with lock:
        auth_file = DATA_DIR / "ui_auth.json"
        config = {
            "username": "",
            "secret_path": "EJsW2EeBo9lY",
            "password": "",
            "host": UI_HOST,
            "port": UI_PORT,
            "proxy_port": LOCAL_PROXY_PORT,
            "routing_mode": "auto",
            "force_country": "",
            "routing_ip_type": "all",
            "connection_enabled": True,
            "fixed_node_id": "",
            "favorite_node_ids": [],
            "fav_fail_fallback": True
        }
        updated = False
        if auth_file.exists():
            try:
                data = json.loads(auth_file.read_text(encoding="utf-8"))
                for key, val in data.items():
                    config[key] = val
                for key in ["host", "port", "proxy_port", "routing_mode", "force_country", "routing_ip_type", "connection_enabled", "fixed_node_id", "favorite_node_ids", "fav_fail_fallback"]:
                    if key not in data:
                        updated = True
            except Exception:
                pass

        if ENV_ROUTING_MODE in VALID_ROUTING_MODES:
            config["routing_mode"] = ENV_ROUTING_MODE
        if ENV_FORCE_COUNTRY:
            config["force_country"] = ENV_FORCE_COUNTRY.upper()
        if ENV_ROUTING_IP_TYPE in VALID_ROUTING_IP_TYPES:
            config["routing_ip_type"] = ENV_ROUTING_IP_TYPE
        if "CONNECTION_ENABLED" in os.environ:
            config["connection_enabled"] = ENV_CONNECTION_ENABLED

        config["host"] = env_str("UI_HOST", str(config.get("host", UI_HOST)))
        config["port"] = env_int("UI_PORT", bounded_int(config.get("port"), UI_PORT, 1, 65535), 1, 65535)
        config["proxy_port"] = env_int(
            "LOCAL_PROXY_PORT",
            bounded_int(config.get("proxy_port"), LOCAL_PROXY_PORT, 1024, 65535),
            1024,
            65535,
        )
        
        if not config.get("username"):
            config["username"] = generate_random_username()
            updated = True
            
        if not config.get("password"):
            config["password"] = generate_random_password()
            updated = True

        normalized_port = bounded_int(config.get("port"), UI_PORT, 1, 65535)
        if normalized_port != config.get("port"):
            config["port"] = normalized_port
            updated = True

        normalized_proxy_port = bounded_int(config.get("proxy_port"), LOCAL_PROXY_PORT, 1024, 65535)
        if normalized_proxy_port == normalized_port:
            fallback_proxy_port = LOCAL_PROXY_PORT if LOCAL_PROXY_PORT != normalized_port else 7928
            if fallback_proxy_port == normalized_port:
                fallback_proxy_port = 7929
            normalized_proxy_port = fallback_proxy_port
        if normalized_proxy_port != config.get("proxy_port"):
            config["proxy_port"] = normalized_proxy_port
            updated = True
            
        if not auth_file.exists() or updated:
            try:
                DATA_DIR.mkdir(exist_ok=True, parents=True)
                auth_file.write_text(json.dumps(config, ensure_ascii=False, indent=2), encoding="utf-8")
            except Exception:
                pass
                
        return config

# 初始化时优先从 ui_auth.json 加载保存的代理出站端口和网页端口配置以覆盖环境变量
try:
    _init_cfg = load_ui_config()
    if "proxy_port" in _init_cfg:
        LOCAL_PROXY_PORT = bounded_int(_init_cfg["proxy_port"], LOCAL_PROXY_PORT, 1024, 65535)
    if "port" in _init_cfg:
        UI_PORT = bounded_int(_init_cfg["port"], UI_PORT, 1, 65535)
    if "host" in _init_cfg:
        UI_HOST = _init_cfg["host"]
except Exception:
    pass

def get_session_token(password: str, username: str = "admin") -> str:
    salt = "nimbusvpn_secure_salt_2026"
    return hashlib.sha256((username + ":" + password + salt).encode("utf-8")).hexdigest()

_last_cleanup_time = 0.0

def cleanup_old_logs(logs_dir: Path) -> None:
    global _last_cleanup_time
    now = time.time()
    with lock:
        if now - _last_cleanup_time < 3600:
            return
        _last_cleanup_time = now
    try:
        retention_sec = LOG_RETENTION_DAYS * 24 * 60 * 60
        for path in logs_dir.glob("*.json"):
            match = re.match(r"^(\d{4}-\d{2}-\d{2})\.json$", path.name)
            if match:
                date_str = match.group(1)
                try:
                    file_time = time.mktime(time.strptime(date_str, "%Y-%m-%d"))
                    today_str = time.strftime("%Y-%m-%d", time.localtime())
                    today_time = time.mktime(time.strptime(today_str, "%Y-%m-%d"))
                    if today_time - file_time >= retention_sec:
                        with lock:
                            path.unlink()
                        print(f"[清理] 已删除3天前的旧日志文件: {path.name}", flush=True)
                except Exception:
                    if now - path.stat().st_mtime > retention_sec:
                        with lock:
                            path.unlink()
    except Exception as e:
        print(f"[清理错误] 清理旧日志失败: {e}", flush=True)

def cleanup_old_configs() -> None:
    try:
        cutoff = time.time() - CONFIG_RETENTION_DAYS * 24 * 60 * 60
        active_files = set()
        with lock:
            for node in read_nodes():
                config_file = node.get("config_file")
                if config_file:
                    active_files.add(Path(config_file).name)
        for path in CONFIG_DIR.glob("*.ovpn"):
            if path.name in active_files:
                continue
            try:
                if path.stat().st_mtime < cutoff:
                    path.unlink()
            except OSError:
                pass
    except Exception as e:
        print(f"[Cleanup Error] Failed to clean old configs: {e}", flush=True)

_print_last: dict[str, float] = {}

def rate_limited_print(key: str, message: str, interval: float = 60.0) -> None:
    now = time.time()
    last = float(_print_last.get(key) or 0)
    if now - last < interval:
        return
    _print_last[key] = now
    print(message, flush=True)

def log_to_json(level: str, module: str, message: str) -> None:
    try:
        logs_dir = DATA_DIR / "logs"
        logs_dir.mkdir(exist_ok=True, parents=True)
        date_str = time.strftime("%Y-%m-%d", time.localtime())
        log_file = logs_dir / f"{date_str}.json"
        entry = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
            "level": level,
            "module": module,
            "message": message
        }
        with lock:
            with open(log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        cleanup_old_logs(logs_dir)
    except Exception as e:
        print(f"[Log Error] Failed to write JSON log: {e}", flush=True)

def set_state(**updates: Any) -> None:
    global is_connecting, is_scanning, active_openvpn_node_id
    if "is_connecting" in updates:
        is_connecting = bool(updates["is_connecting"])
    if "is_scanning" in updates:
        is_scanning = bool(updates["is_scanning"])
    if "active_openvpn_node_id" in updates:
        active_openvpn_node_id = str(updates.get("active_openvpn_node_id") or "")
    state = get_state()
    state.update(updates)
    write_json(STATE_FILE, state)

def read_nodes() -> list[dict[str, Any]]:
    raw = read_json(NODES_FILE, [])
    if not isinstance(raw, list):
        return []
    return [item for item in raw if isinstance(item, dict)]

def get_state() -> dict[str, Any]:
    global active_openvpn_node_id, is_connecting
    state = read_json(STATE_FILE, {})
    state.pop("password", None)
    state["active_openvpn_node_id"] = active_openvpn_node_id
    state["is_connecting"] = is_connecting
    state["is_scanning"] = is_scanning
    state["scan_progress"] = dict(scan_progress)
    state.setdefault("fallback_mode", False)
    state.setdefault("fallback_proxy", "")
    # FreeProxyDB 共享摘要（worker/scanner 均可读）
    try:
        _pm = read_json(SHARED_PROXIES_META_FILE, {})
        if isinstance(_pm, dict):
            state["fallback_available_count"] = int(_pm.get("available_count") or 0)
            state["fallback_by_region"] = _pm.get("by_region") or {}
            state["fallback_scanned_at"] = _pm.get("scanned_at") or 0
    except Exception:
        pass
    state["region_fail_pause_until"] = region_fail_pause_until
    state["region_fail_streak"] = region_fail_streak
    state.setdefault("api_url", API_URL)
    state.setdefault("target_valid_nodes", TARGET_VALID_NODES)
    state.setdefault("fetch_interval_seconds", FETCH_INTERVAL_SECONDS)
    state.setdefault("check_interval_seconds", CHECK_INTERVAL_SECONDS)
    _proxy_display = f"[{LOCAL_PROXY_HOST}]" if ":" in LOCAL_PROXY_HOST else LOCAL_PROXY_HOST
    state["local_proxy"] = f"http://{_proxy_display}:{LOCAL_PROXY_PORT}"
    state.setdefault("last_fetch_status", "not_started")
    state.setdefault("last_check_message", "")
    state.setdefault("blacklisted_nodes", 0)
    
    # Pre-populate settings inputs in UI
    ui_cfg = load_ui_config()
    state["username"] = ui_cfg.get("username", "admin")
    state["port"] = ui_cfg.get("port", 8787)
    state["secret_path"] = ui_cfg.get("secret_path", "EJsW2EeBo9lY")
    state["password_set"] = bool(ui_cfg.get("password"))
    state["proxy_port"] = ui_cfg.get("proxy_port", 7928)
    state["routing_mode"] = ui_cfg.get("routing_mode", "auto")
    state["force_country"] = ui_cfg.get("force_country", "")
    state["routing_ip_type"] = ui_cfg.get("routing_ip_type", "all")
    state["connection_enabled"] = ui_cfg.get("connection_enabled", True)
    state["fixed_node_id"] = ui_cfg.get("fixed_node_id", "")
    state["favorite_node_ids"] = ui_cfg.get("favorite_node_ids", [])
    state["fav_fail_fallback"] = ui_cfg.get("fav_fail_fallback", True)
    
    return state

def safe_name(value: str) -> str:
    value = re.sub(r"[^A-Za-z0-9_.-]+", "_", value.strip())
    return value.strip("._") or "node"


def mark_node_connect_failure(node_id: str, reason: str = "") -> None:
    """节点连接失败冷却，避免空转重试。"""
    global node_fail_cooldown, region_fail_streak, region_fail_pause_until
    nid = str(node_id or "").strip()
    if not nid:
        return
    until = time.time() + CONNECT_FAIL_COOLDOWN_SECONDS
    node_fail_cooldown[nid] = until
    region_fail_streak += 1
    if region_fail_streak >= REGION_FAIL_THRESHOLD:
        region_fail_pause_until = time.time() + REGION_FAIL_PAUSE_SECONDS
        print(
            f"[冷却] 连续失败 {region_fail_streak} 次，本区暂停自动连接 {REGION_FAIL_PAUSE_SECONDS}s",
            flush=True,
        )
    print(f"[冷却] 节点 {nid} 冷却至 {int(until)} ({reason})", flush=True)


def mark_node_connect_success(node_id: str = "") -> None:
    global region_fail_streak, region_fail_pause_until, node_fail_cooldown
    region_fail_streak = 0
    region_fail_pause_until = 0.0
    nid = str(node_id or "").strip()
    if nid and nid in node_fail_cooldown:
        node_fail_cooldown.pop(nid, None)


def is_node_in_cooldown(node_id: str) -> bool:
    nid = str(node_id or "").strip()
    if not nid:
        return False
    until = float(node_fail_cooldown.get(nid) or 0)
    if until <= time.time():
        node_fail_cooldown.pop(nid, None)
        return False
    return True


def region_auto_connect_paused() -> bool:
    global region_fail_pause_until
    if region_fail_pause_until <= time.time():
        region_fail_pause_until = 0.0
        return False
    return True


def empty_region_message(available_count: int, filtered_count: int) -> str:
    ui_cfg = load_ui_config()
    country = str(ui_cfg.get("force_country") or ENV_FORCE_COUNTRY or "").upper()
    if available_count > 0:
        return ""
    if filtered_count == 0:
        if country:
            return f"待命：共享池暂无 {country} 可用节点，等待扫描器补充（不频繁重试）"
        return "待命：共享池暂无本区可用节点，等待扫描器补充（不频繁重试）"
    return f"待命：本区 {filtered_count} 个候选暂不可用（冷却/测速失败），等待下一轮共享更新"



def slim_shared_node(node: dict[str, Any]) -> dict[str, Any]:
    """共享 JSON 只保留元数据，不携带 config_text（配置走 shared/configs）。"""
    n = dict(node)
    n.pop("config_text", None)
    n["active"] = False
    cfg_name = Path(n.get("config_file") or f"{safe_name(n.get('id','node'))}.ovpn").name
    n["config_file"] = cfg_name  # 共享侧仅保留文件名
    return n


def node_fail_count(node: dict[str, Any]) -> int:
    try:
        return int(node.get("fail_count") or 0)
    except Exception:
        return 0


def is_scan_blacklisted(node: dict[str, Any], now_ts: float | None = None) -> bool:
    """长期失败节点在黑名单窗口内跳过复测。"""
    now = time.time() if now_ts is None else now_ts
    until = float(node.get("blacklist_until") or 0)
    if until > now:
        return True
    # 兼容：fail_count 高且最近失败
    fails = node_fail_count(node)
    last_fail = float(node.get("last_fail_at") or 0)
    if fails >= 3 and last_fail and now - last_fail < 3600:
        return True
    return False


def apply_probe_result_counters(node: dict[str, Any], status: str) -> None:
    if status == "available":
        node["fail_count"] = 0
        node["blacklist_until"] = 0
        node["success_count"] = int(node.get("success_count") or 0) + 1
        node["last_success_at"] = time.time()
    elif status == "unavailable":
        fails = node_fail_count(node) + 1
        node["fail_count"] = fails
        node["last_fail_at"] = time.time()
        # 指数黑名单：15m / 30m / 60m / 120m
        minutes = min(120, 15 * (2 ** max(0, fails - 1)))
        node["blacklist_until"] = time.time() + minutes * 60
    try:
        compute_quality_score(node)
    except Exception:
        pass



def probe_egress_via_tun(dev_name: str, timeout: float = 8.0) -> tuple[bool, str, int]:
    """在测试用 tun 上做轻量出口探测，避免仅握手成功就标 available。"""
    dev = str(dev_name or "").strip()
    if not dev:
        return False, "empty tun device", 0
    # 给接口一点时间起来
    time.sleep(0.4)
    urls = [
        "http://api.ipify.org",
        "http://ifconfig.me/ip",
        "http://icanhazip.com",
    ]
    started = time.time()
    last_err = "egress probe failed"
    for url in urls:
        remain = timeout - (time.time() - started)
        if remain <= 1:
            break
        try:
            # curl --interface 走指定网卡；不走系统默认路由，更接近真实出口能力
            cmd = [
                "curl", "-sS", "-m", str(max(2, int(remain))),
                "--interface", dev,
                url,
            ]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=max(3, int(remain) + 1))
            body = (res.stdout or "").strip()
            if res.returncode == 0 and body and len(body) < 80:
                # 粗判 IP
                if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", body) or ":" in body:
                    latency = int((time.time() - started) * 1000)
                    return True, body, latency
            last_err = (res.stderr or body or f"curl rc={res.returncode}")[:180]
        except Exception as exc:
            last_err = str(exc)[:180]
    return False, last_err, 0


def classify_probe_result(handshake_ok: bool, egress_ok: bool, handshake_msg: str = "", egress_msg: str = "") -> tuple[str, str]:
    """
    available: 握手+出口都过
    soft_available: 仅握手成功（可连但出口未验证/不稳）
    unavailable: 握手失败或出口明确失败
    """
    if handshake_ok and egress_ok:
        return "available", f"handshake+egress ok ({egress_msg})"
    if handshake_ok and not egress_ok:
        # 默认更严格：握手成功但出口失败 => unavailable（提高准确性）
        # 若想放宽可改为 soft_available
        strict = str(os.environ.get("PROBE_STRICT_EGRESS", "true")).strip().lower() in ("1", "true", "yes", "on")
        if strict:
            return "unavailable", f"handshake ok but egress failed: {egress_msg or handshake_msg}"
        return "soft_available", f"handshake ok, egress unverified: {egress_msg or handshake_msg}"
    return "unavailable", handshake_msg or "handshake failed"



def report_shared_node_failure(node_id: str, reason: str = "") -> None:
    """worker 连接/出口失败时回写共享池，降低后续误选概率。"""
    nid = str(node_id or "").strip()
    if not nid or IS_SCANNER:
        return
    try:
        Path(SHARED_DATA_DIR).mkdir(exist_ok=True, parents=True)
        shared = read_json(SHARED_NODES_FILE, [])
        if not isinstance(shared, list):
            return
        changed = False
        for n in shared:
            if str(n.get("id") or "") != nid:
                continue
            n["probe_status"] = "unavailable"
            n["probe_message"] = f"worker feedback: {reason or 'connect/proxy failed'}"[:240]
            n["probed_at"] = time.time()
            n["fail_count"] = int(n.get("fail_count") or 0) + 1
            n["last_fail_at"] = time.time()
            minutes = min(120, 15 * (2 ** max(0, int(n["fail_count"]) - 1)))
            n["blacklist_until"] = time.time() + minutes * 60
            try:
                compute_quality_score(n)
            except Exception:
                pass
            changed = True
            break
        if changed:
            tmp = Path(str(SHARED_NODES_FILE) + ".fb.tmp")
            write_json(tmp, shared)
            tmp.replace(SHARED_NODES_FILE)
            # 轻量 bump generation，让其他 worker 尽快感知
            gen = int(time.time())
            meta = read_json(SHARED_META_FILE, {})
            if not isinstance(meta, dict):
                meta = {}
            meta["generation"] = gen
            meta["feedback_at"] = time.time()
            meta["feedback_node"] = nid
            write_json(SHARED_META_FILE, meta)
            try:
                (Path(SHARED_DATA_DIR) / "shared.generation").write_text(str(gen), encoding="utf-8")
            except Exception:
                pass
            rate_limited_print(f"fb:{nid}", f"[反馈] 已将节点 {nid} 标记为 unavailable（{reason[:120]}）", 20.0)
    except Exception as exc:
        rate_limited_print("fb:err", f"[反馈] 写共享失败: {exc}", 30.0)



def region_bucket_for_country(code: str) -> str:
    c = (code or "").upper()[:2]
    if c in ("JP", "US", "KR", "RU", "VN"):
        return c
    return "OTHER"



def publish_scan_progress(force: bool = False) -> None:
    """把当前扫描进度写到共享 meta，供 Hub 实时显示正在检测的节点。"""
    global scan_progress, is_scanning
    try:
        progress = dict(scan_progress) if isinstance(scan_progress, dict) else {}
        # 节流：默认最多 ~0.8s 写一次；force 立即写
        now = time.time()
        last = float(progress.get("_published_at") or 0)
        if (not force) and (now - last < 0.8):
            return
        progress["_published_at"] = now
        scan_progress = dict(progress)
        # 不丢其它 meta 字段
        meta = {}
        try:
            meta = read_json(SHARED_META_FILE, {})
            if not isinstance(meta, dict):
                meta = {}
        except Exception:
            meta = {}
        meta["scanning"] = bool(is_scanning)
        meta["check_interval_seconds"] = CHECK_INTERVAL_SECONDS
        if not is_scanning:
            # 空闲时用 scanned_at + interval 估下次
            try:
                last = float(meta.get("scanned_at") or 0)
                meta["next_scan_at"] = (last + CHECK_INTERVAL_SECONDS) if last else (time.time() + CHECK_INTERVAL_SECONDS)
            except Exception:
                meta["next_scan_at"] = time.time() + CHECK_INTERVAL_SECONDS
        meta["scan_progress"] = {
            "total": int(progress.get("total") or 0),
            "tested": int(progress.get("tested") or 0),
            "current": str(progress.get("current") or ""),
            "current_list": list(progress.get("current_list") or []),
            "batch": int(progress.get("batch") or 0),
            "batches": int(progress.get("batches") or 0),
            "queue_left": int(progress.get("queue_left") or 0),
            "started_at": float(progress.get("started_at") or 0),
            "updated_at": now,
            "message": str(progress.get("message") or ""),
        }
        # 扫描中也刷新 scanned_at 的 companion 字段，避免 UI 以为卡死
        meta["scanner_role"] = "scanner" if IS_SCANNER else meta.get("scanner_role") or "worker"
        write_json(SHARED_META_FILE, meta)
    except Exception as e:
        rate_limited_print("publish_scan_progress", f"[扫描进度] 写入共享失败: {e}", 30.0)


def clear_fallback_upstream(reason: str = "") -> None:
    try:
        FALLBACK_UPSTREAM_FILE.write_text(
            json.dumps({"enabled": False, "reason": reason, "updated_at": time.time()}, ensure_ascii=False),
            encoding="utf-8",
        )
    except Exception:
        pass


def write_fallback_upstream(proxy: dict[str, Any], reason: str = "") -> None:
    payload = {
        "enabled": True,
        "reason": reason or "openvpn empty region",
        "updated_at": time.time(),
        "id": proxy.get("id"),
        "type": proxy.get("protocol") or proxy.get("type") or "http",
        "host": proxy.get("ip") or proxy.get("host"),
        "port": int(proxy.get("port") or 0),
        "username": proxy.get("username") or "",
        "password": proxy.get("password") or "",
        "country": proxy.get("country") or "",
        "source": "freeproxydb",
        "connect_string": proxy.get("connect_string") or "",
    }
    FALLBACK_UPSTREAM_FILE.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    set_state(
        fallback_mode=True,
        fallback_proxy_id=payload.get("id"),
        fallback_proxy=f"{payload.get('type')}://{payload.get('host')}:{payload.get('port')}",
        last_check_message=f"OpenVPN 无可用节点，已启用备援代理 {payload.get('host')}:{payload.get('port')}",
    )


def test_http_socks_proxy(protocol: str, host: str, port: int, username: str = "", password: str = "", timeout: int = 8) -> tuple[bool, str, int]:
    """测 HTTP/SOCKS 代理是否能拿到出口 IP。"""
    proto = (protocol or "http").lower()
    auth = ""
    if username or password:
        auth = f"{urllib.parse.quote(username)}:{urllib.parse.quote(password)}@"
    if proto.startswith("socks"):
        proxy_url = f"socks5h://{auth}{host}:{port}"
    else:
        proxy_url = f"http://{auth}{host}:{port}"
    urls = ["http://api.ipify.org", "http://ifconfig.me/ip", "http://icanhazip.com"]
    started = time.time()
    last_err = "proxy test failed"
    for url in urls:
        remain = timeout - (time.time() - started)
        if remain <= 1:
            break
        try:
            cmd = ["curl", "-sS", "-m", str(max(2, int(remain))), "-x", proxy_url, url]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=max(3, int(remain) + 1))
            body = (res.stdout or "").strip()
            if res.returncode == 0 and body and len(body) < 80:
                if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", body) or ":" in body:
                    return True, body, int((time.time() - started) * 1000)
            last_err = (res.stderr or body or f"rc={res.returncode}")[:160]
        except Exception as exc:
            last_err = str(exc)[:160]
    return False, last_err, 0


def fetch_freeproxydb_region(region: str, page_size: int = 30) -> list[dict[str, Any]]:
    """从 FreeProxyDB 拉某国家/OTHER 的 HTTP+SOCKS5 列表（未测活）。"""
    if not FREEPROXYDB_ENABLED:
        return []
    region = (region or "OTHER").upper()
    params = {
        "protocol": FREEPROXYDB_PROTOCOLS,
        "page_size": str(max(5, min(50, page_size))),
        "page": "1",
    }
    if region != "OTHER":
        params["country"] = region
    url = FREEPROXYDB_API + "/search?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers={"User-Agent": "nimbus-vpngate-fallback/1.0", "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
    except Exception as exc:
        rate_limited_print(f"fpdb:fetch:{region}", f"[FreeProxyDB] 拉取 {region} 失败: {exc}", 60.0)
        return []
    rows = []
    if isinstance(data, dict):
        payload = data.get("data")
        if isinstance(payload, dict) and isinstance(payload.get("data"), list):
            rows = payload["data"]
        elif isinstance(payload, list):
            rows = payload
    out: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        ip = str(row.get("ip") or "").strip()
        port = parse_int(row.get("port"))
        protocol = str(row.get("protocol") or "http").lower()
        if not ip or not port:
            continue
        if protocol not in ("http", "https", "socks4", "socks5"):
            continue
        country = str(row.get("country") or region).upper()[:2]
        bucket = region_bucket_for_country(country)
        if region != "OTHER" and bucket != region:
            continue
        if region == "OTHER" and bucket != "OTHER":
            # OTHER 请求时若 API 未按国家过滤，丢弃重点国家
            continue
        pid = f"FPDB_{bucket}_{protocol}_{ip}_{port}"
        out.append({
            "id": pid,
            "source": "freeproxydb",
            "protocol": "socks5" if protocol.startswith("socks") else "http",
            "ip": ip,
            "host": ip,
            "port": port,
            "country": country,
            "region": bucket,
            "city": row.get("city") or "",
            "anonymity": row.get("anonymity") or "",
            "speed": row.get("speed") or 0,
            "username": row.get("username") or "",
            "password": row.get("password") or "",
            "connect_string": row.get("connect_string") or f"{protocol}://{ip}:{port}",
            "probe_status": "not_checked",
            "probe_message": "",
            "latency_ms": 0,
            "fetched_at": time.time(),
        })
    return out


def scan_freeproxydb_fallback() -> dict[str, Any]:
    """scanner：按 JP/US/KR/RU/VN/OTHER 拉 HTTP/SOCKS 并测活，写入 shared_proxies。"""
    if not IS_SCANNER or not FREEPROXYDB_ENABLED:
        return {"enabled": False}
    regions = ["JP", "US", "KR", "RU", "VN", "OTHER"]
    available_all: list[dict[str, Any]] = []
    stats: dict[str, dict[str, int]] = {}
    for region in regions:
        candidates = fetch_freeproxydb_region(region, page_size=max(20, FREEPROXYDB_TEST_LIMIT * 2))
        # 简单排序：speed 高优先
        candidates.sort(key=lambda n: (-float(n.get("speed") or 0), parse_int(n.get("port"))))
        tested = 0
        ok_list: list[dict[str, Any]] = []
        for c in candidates:
            if tested >= FREEPROXYDB_TEST_LIMIT:
                break
            if len(ok_list) >= FREEPROXYDB_PER_REGION:
                break
            tested += 1
            ok, msg, latency = test_http_socks_proxy(
                str(c.get("protocol") or "http"),
                str(c.get("ip") or ""),
                int(c.get("port") or 0),
                str(c.get("username") or ""),
                str(c.get("password") or ""),
                timeout=env_int("FREEPROXYDB_TEST_TIMEOUT", 8, 1),
            )
            c["probed_at"] = time.time()
            c["latency_ms"] = latency
            if ok:
                c["probe_status"] = "available"
                c["probe_message"] = f"egress ok ({msg})"
                c["egress_ip"] = msg
                ok_list.append(c)
            else:
                c["probe_status"] = "unavailable"
                c["probe_message"] = msg
        available_all.extend(ok_list)
        stats[region] = {"candidates": len(candidates), "tested": tested, "available": len(ok_list)}
        print(f"[FreeProxyDB] {region}: candidates={len(candidates)} tested={tested} available={len(ok_list)}", flush=True)

    # merge with previous available (short retain)
    prev = read_json(SHARED_PROXIES_FILE, [])
    if not isinstance(prev, list):
        prev = []
    now = time.time()
    retain_s = env_int("FREEPROXYDB_RETAIN_SECONDS", 1800, 1)
    merged = {str(p.get("id")): p for p in available_all if p.get("id")}
    for p in prev:
        if not isinstance(p, dict) or not p.get("id"):
            continue
        if p.get("probe_status") != "available":
            continue
        pid = str(p.get("id"))
        if pid in merged:
            continue
        probed = float(p.get("probed_at") or 0)
        if probed and now - probed <= retain_s:
            merged[pid] = p
    final = list(merged.values())
    final.sort(key=lambda n: (n.get("region") or "ZZ", parse_int(n.get("latency_ms")) or 99999))
    Path(SHARED_DATA_DIR).mkdir(exist_ok=True, parents=True)
    write_json(SHARED_PROXIES_FILE, final)
    by_region: dict[str, int] = {}
    for p in final:
        r = str(p.get("region") or "OTHER")
        by_region[r] = by_region.get(r, 0) + 1
    meta = {
        "scanned_at": time.time(),
        "generation": int(time.time()),
        "available_count": len(final),
        "by_region": by_region,
        "stats": stats,
        "source": "freeproxydb",
        "priority": "fallback_only",
    }
    write_json(SHARED_PROXIES_META_FILE, meta)
    print(f"[FreeProxyDB] 共享备援已写入 available={len(final)} by_region={by_region}", flush=True)
    return meta


def load_region_fallback_proxies(region: str) -> list[dict[str, Any]]:
    region = (region or "OTHER").upper()
    raw = read_json(SHARED_PROXIES_FILE, [])
    if not isinstance(raw, list):
        return []
    items = [
        p for p in raw
        if isinstance(p, dict)
        and p.get("probe_status") == "available"
        and str(p.get("region") or "").upper() == region
    ]
    items.sort(key=lambda n: (parse_int(n.get("latency_ms")) or 99999, -float(n.get("speed") or 0)))
    return items


def maybe_enable_proxy_fallback(filtered_nodes: list[dict[str, Any]] | None = None, force: bool = False) -> bool:
    """OpenVPN 空区或出口失败时启用 FreeProxyDB 备援（低优先级）。"""
    if IS_SCANNER or not FREEPROXYDB_ENABLED:
        clear_fallback_upstream("scanner_or_disabled")
        return False
    ui_cfg = load_ui_config()
    if not ui_cfg.get("connection_enabled", True):
        clear_fallback_upstream("connection_disabled")
        set_state(fallback_mode=False, fallback_proxy="", fallback_proxy_id="")
        return False
    nodes = filtered_nodes if filtered_nodes is not None else apply_routing_filters(read_nodes(), ui_cfg)
    ovpn_available = [
        n for n in nodes
        if n.get("probe_status") == "available"
        and (n.get("config_text") or Path(str(n.get("config_file") or "")).exists())
        and not is_node_in_cooldown(str(n.get("id") or ""))
    ]
    if active_openvpn_running() and not force:
        clear_fallback_upstream("openvpn_running")
        set_state(fallback_mode=False, fallback_proxy="", fallback_proxy_id="")
        return False

    st_now = get_state()
    proxy_bad = (st_now.get("proxy_ok") is False) or bool(st_now.get("proxy_error"))
    try:
        paused = bool(region_auto_connect_paused())
    except Exception:
        paused = False
    try:
        streak = int(region_fail_streak or 0)
    except Exception:
        streak = 0

    allow = bool(force) or (not ovpn_available) or ((not active_openvpn_running()) and (proxy_bad or paused or streak >= 1))
    if not allow:
        clear_fallback_upstream("openvpn_candidates_exist")
        set_state(fallback_mode=False, fallback_proxy="", fallback_proxy_id="")
        return False

    region = str(ui_cfg.get("force_country") or ENV_FORCE_COUNTRY or "OTHER").upper()
    if region not in ("JP", "US", "KR", "RU", "VN"):
        if str(ENV_EXCLUDE_COUNTRY or ""):
            region = "OTHER"

    def _stop_ovpn_for_fallback() -> None:
        try:
            if active_openvpn_running() or Path("/sys/class/net/tun0").exists():
                stop_active_openvpn()
        except Exception as _e:
            print(f"[备援] 断开 OpenVPN 时忽略: {_e}", flush=True)

    def _sort_fb(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
        def key(n: dict[str, Any]):
            proto = str(n.get("protocol") or "http").lower()
            # socks5 优先；延迟低优先；速度高优先
            return (
                0 if proto.startswith("socks") else 1,
                float(n.get("latency_ms") or 99999),
                -float(n.get("speed") or 0),
            )
        return sorted(items, key=key)

    def _activate(pxy: dict[str, Any], msg: str, latency: int, why: str) -> bool:
        _stop_ovpn_for_fallback()
        write_fallback_upstream(pxy, reason=f"{why}:{region}")
        try:
            if hasattr(proxy_server, "_fallback_cache"):
                proxy_server._fallback_cache["mtime"] = -1.0
                proxy_server._fallback_cache["data"] = None
        except Exception:
            pass
        time.sleep(0.25)
        # 对 HTTP 备援用本地 HTTP 代理探测；SOCKS 用 socks5h
        res = check_proxy_health()
        ip = (res.get("ip") if res.get("ok") else None) or msg or "-"
        # 直连测活已给出出口 IP 则视为成功（备援无 tun0 时 health 可能误报）
        ok = bool(msg) or bool(res.get("ok"))
        if not ok:
            return False
        set_state(
            proxy_ok=True,
            proxy_ip=ip,
            proxy_latency_ms=(res.get("latency_ms") if res.get("ok") else None) or latency or 0,
            proxy_error="",
            fallback_mode=True,
            empty_region=False,
            last_check_message=f"备援代理已启用 {pxy.get('protocol')}://{pxy.get('ip')}:{pxy.get('port')} 出口 {ip}",
        )
        print(f"[备援] 已启用 {region} {pxy.get('protocol')}://{pxy.get('ip')}:{pxy.get('port')} via {why} egress={ip}", flush=True)
        return True

    def _try_list(items: list[dict[str, Any]], why: str) -> bool:
        failed_hosts: set[str] = set()
        for pxy in _sort_fb(items)[:8]:
            host = str(pxy.get("ip") or pxy.get("host") or "")
            if host in failed_hosts:
                continue
            ok, msg, latency = test_http_socks_proxy(
                str(pxy.get("protocol") or "http"),
                host,
                int(pxy.get("port") or 0),
                str(pxy.get("username") or ""),
                str(pxy.get("password") or ""),
                timeout=env_int("FREEPROXYDB_TEST_TIMEOUT", 8, 1),
            )
            if not ok:
                failed_hosts.add(host)
                continue
            if _activate(pxy, msg, latency, why):
                return True
            failed_hosts.add(host)
        return False

    shared = load_region_fallback_proxies(region if region in ("JP", "US", "KR", "RU", "VN") else "OTHER")
    if _try_list(shared, "shared"):
        return True

    # 现场重拉：US 多拉一些
    try:
        page = 20 if region == "US" else 15
        fresh = fetch_freeproxydb_region(region if region in ("JP", "US", "KR", "RU", "VN") else "OTHER", page_size=page)
        if _try_list(fresh, "live"):
            # best-effort write-back of successful one already in write_fallback; also append fresh ok ones
            try:
                live_ok = []
                for c in _sort_fb(fresh)[:20]:
                    ok, msg, latency = test_http_socks_proxy(
                        str(c.get("protocol") or "http"),
                        str(c.get("ip") or ""),
                        int(c.get("port") or 0),
                        timeout=6,
                    )
                    if not ok:
                        continue
                    c["probe_status"] = "available"
                    c["probe_message"] = f"egress ok ({msg})"
                    c["egress_ip"] = msg
                    c["latency_ms"] = latency
                    c["probed_at"] = time.time()
                    live_ok.append(c)
                    if len(live_ok) >= 6:
                        break
                if live_ok:
                    prev = read_json(SHARED_PROXIES_FILE, [])
                    if not isinstance(prev, list):
                        prev = []
                    by_id = {str(x.get("id")): x for x in prev if isinstance(x, dict) and x.get("id")}
                    for item in live_ok:
                        by_id[str(item.get("id"))] = item
                    write_json(SHARED_PROXIES_FILE, list(by_id.values()))
            except Exception:
                pass
            return True
    except Exception as exc:
        rate_limited_print(f"fpdb:live:{region}", f"[FreeProxyDB] 现场拉取失败: {exc}", 60.0)

    clear_fallback_upstream("fallback_health_failed")
    set_state(
        fallback_mode=False,
        proxy_ok=False,
        last_check_message=f"备援代理测活失败（{region}）",
    )
    return False



def region_available_targets() -> dict[str, int]:
    return {
        "JP": env_int("SCAN_TARGET_JP", 40, 1),
        "US": env_int("SCAN_TARGET_US", 25, 1),
        "KR": env_int("SCAN_TARGET_KR", 20, 1),
        "RU": env_int("SCAN_TARGET_RU", 10, 1),
        "VN": env_int("SCAN_TARGET_VN", 10, 1),
        "OTHER": env_int("SCAN_TARGET_OTHER", 15, 1),
    }


def count_available_by_country(nodes: list[dict[str, Any]]) -> dict[str, int]:
    out: dict[str, int] = {}
    for n in nodes:
        if n.get("probe_status") != "available":
            continue
        code = node_country_code(n) or "OTHER"
        if code not in ("JP", "US", "KR", "RU", "VN"):
            code = "OTHER"
        out[code] = out.get(code, 0) + 1
    return out


def clear_active_connection_state(message: str) -> None:
    global active_openvpn_process, active_openvpn_node_id
    stop_process(active_openvpn_process)
    active_openvpn_process = None
    active_openvpn_node_id = ""
    with lock:
        nodes = read_nodes()
        for item in nodes:
            item["active"] = False
        write_json(NODES_FILE, nodes)
    set_state(
        active_openvpn_node_id="",
        is_connecting=False,
        active_node_latency="无活动连接",
        last_check_message=message,
    )

def parse_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0

def proxy_basic_auth_header(username: str, password: str) -> str:
    token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    return f"Proxy-Authorization: Basic {token}\r\n"

def recv_exact_from_socket(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise RuntimeError("Unexpected EOF while reading proxy response")
        data += chunk
    return data

def read_http_response_head(sock: socket.socket, limit: int = 65536) -> bytes:
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
        if len(data) > limit:
            raise RuntimeError("Proxy response header too large")
    if b"\r\n\r\n" not in data:
        raise RuntimeError("Incomplete HTTP proxy response header")
    return data

def socks5_address_bytes(host: str) -> tuple[int, bytes]:
    try:
        return 1, socket.inet_aton(host)
    except OSError:
        pass
    try:
        return 4, socket.inet_pton(socket.AF_INET6, host)
    except OSError:
        pass
    host_bytes = host.encode("idna")
    if len(host_bytes) > 255:
        raise RuntimeError("SOCKS5 target host name is too long")
    return 3, bytes([len(host_bytes)]) + host_bytes

def read_socks5_connect_reply(sock: socket.socket) -> None:
    header = recv_exact_from_socket(sock, 4)
    if header[0] != 5:
        raise RuntimeError("Invalid SOCKS5 reply version")
    atyp = header[3]
    if atyp == 1:
        recv_exact_from_socket(sock, 4)
    elif atyp == 3:
        domain_len = recv_exact_from_socket(sock, 1)[0]
        recv_exact_from_socket(sock, domain_len)
    elif atyp == 4:
        recv_exact_from_socket(sock, 16)
    else:
        raise RuntimeError(f"Invalid SOCKS5 reply address type: {atyp}")
    recv_exact_from_socket(sock, 2)
    if header[1] != 0:
        raise RuntimeError(f"SOCKS5 connection request rejected, code={header[1]}")

def format_host_port(host: str, port: int) -> str:
    return f"[{host}]:{port}" if ":" in host and not host.startswith("[") else f"{host}:{port}"

def fetch_api_text_via_proxy(url: str, ptype: str, phost: str, pport: int, use_ssl_verify: bool = True) -> str:
    import socket
    import ssl
    import urllib.parse

    parsed = urllib.parse.urlsplit(url)
    domain = parsed.hostname or "www.vpngate.net"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    is_https = parsed.scheme == "https"
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    is_ipv6 = ":" in phost
    af = socket.AF_INET6 if is_ipv6 else socket.AF_INET
    s = None
    try:
        s = socket.socket(af, socket.SOCK_STREAM)
        s.settimeout(12)
        s.connect((phost, pport))
        proxy_user, proxy_pass = vpn_utils.get_upstream_proxy_auth()
        if ptype == "socks":
            # SOCKS5 Handshake
            if proxy_user is not None:
                s.sendall(b"\x05\x02\x00\x02")
            else:
                s.sendall(b"\x05\x01\x00")
            resp = recv_exact_from_socket(s, 2)
            if len(resp) < 2 or resp[0] != 5:
                raise RuntimeError("SOCKS5 authentication failed or unsupported")
            if resp[1] == 2:
                if proxy_user is None:
                    raise RuntimeError("SOCKS5 proxy requires username/password authentication")
                user_bytes = proxy_user.encode("utf-8")
                pass_bytes = (proxy_pass or "").encode("utf-8")
                if len(user_bytes) > 255 or len(pass_bytes) > 255:
                    raise RuntimeError("SOCKS5 proxy credentials are too long")
                s.sendall(b"\x01" + bytes([len(user_bytes)]) + user_bytes + bytes([len(pass_bytes)]) + pass_bytes)
                auth_resp = recv_exact_from_socket(s, 2)
                if len(auth_resp) < 2 or auth_resp[1] != 0:
                    raise RuntimeError("SOCKS5 username/password authentication failed")
            elif resp[1] != 0:
                raise RuntimeError("SOCKS5 authentication method unsupported")
            # SOCKS5 Connect
            atyp, addr_bytes = socks5_address_bytes(domain)
            req = b"\x05\x01\x00" + bytes([atyp]) + addr_bytes + port.to_bytes(2, 'big')
            s.sendall(req)
            read_socks5_connect_reply(s)
            # If HTTPS, wrap socket with SSL
            if is_https:
                ctx = ssl.create_default_context() if use_ssl_verify else ssl._create_unverified_context()
                s = ctx.wrap_socket(s, server_hostname=domain)
        else: # http proxy
            if is_https:
                # HTTP CONNECT tunnel
                authority = format_host_port(domain, port)
                auth_header = proxy_basic_auth_header(proxy_user, proxy_pass or "") if proxy_user is not None else ""
                req_str = f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: Mozilla/5.0 vpngate-openvpn-manager/2.0\r\n{auth_header}Proxy-Connection: Keep-Alive\r\n\r\n"
                s.sendall(req_str.encode('ascii'))
                resp = read_http_response_head(s)
                status_line = resp.split(b"\r\n", 1)[0].decode("utf-8", errors="replace")
                status_parts = status_line.split()
                status_code = int(status_parts[1]) if len(status_parts) >= 2 and status_parts[1].isdigit() else 0
                if status_code != 200:
                    raise RuntimeError(f"HTTP CONNECT tunnel failed: {status_line}")
                # Wrap socket with SSL
                ctx = ssl.create_default_context() if use_ssl_verify else ssl._create_unverified_context()
                s = ctx.wrap_socket(s, server_hostname=domain)
            else:
                # Direct HTTP request through proxy: request URI must be absolute
                pass

        # Send HTTP GET request
        if ptype == "http" and not is_https:
            request_uri = url
        else:
            request_uri = path
            
        req_headers = (
            f"GET {request_uri} HTTP/1.1\r\n"
            f"Host: {domain}\r\n"
            f"User-Agent: Mozilla/5.0 vpngate-openvpn-manager/2.0\r\n"
            f"Accept: text/plain,*/*\r\n"
            f"{proxy_basic_auth_header(proxy_user, proxy_pass or '') if ptype == 'http' and not is_https and proxy_user is not None else ''}"
            f"Connection: close\r\n\r\n"
        )
        s.sendall(req_headers.encode('utf-8'))

        # Read response
        response_data = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            response_data += chunk
            if len(response_data) > 10 * 1024 * 1024: # max 10MB safety guard
                break
    finally:
        if s is not None:
            try:
                s.close()
            except Exception:
                pass

    # Parse HTTP response
    header_end = response_data.find(b"\r\n\r\n")
    if header_end == -1:
        raise RuntimeError("Invalid HTTP response format")
    
    headers_part = response_data[:header_end].decode('utf-8', errors='replace')
    body_part = response_data[header_end+4:]

    # Check for HTTP status code
    lines = headers_part.splitlines()
    if not lines:
        raise RuntimeError("Empty response headers")
    status_line = lines[0]
    status_parts = status_line.split()
    if len(status_parts) >= 2:
        try:
            status_code = int(status_parts[1])
            if status_code != 200:
                raise RuntimeError(f"HTTP Server returned status {status_code}: {status_line}")
        except ValueError:
            pass

    # Handle chunked transfer encoding
    is_chunked = False
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            if k.strip().lower() == "transfer-encoding" and "chunked" in v.lower():
                is_chunked = True
                break

    if is_chunked:
        decoded = b""
        idx = 0
        while idx < len(body_part):
            c_end = body_part.find(b"\r\n", idx)
            if c_end == -1:
                break
            chunk_size_str = body_part[idx:c_end].split(b";")[0].strip()
            try:
                chunk_size = int(chunk_size_str, 16)
            except ValueError:
                break
            if chunk_size == 0:
                break
            idx = c_end + 2
            decoded += body_part[idx : idx + chunk_size]
            idx += chunk_size + 2
        body_part = decoded

    return body_part.decode('utf-8', errors='replace')

def fetch_api_text(url: str | None = None, use_ssl_verify: bool = True) -> str:
    if url is None:
        url = API_URL
    
    ptype, phost, pport = vpn_utils.get_upstream_proxy()
    if ptype and phost and pport:
        try:
            print(f"[fetch_api_text] 监测到上游代理 ({ptype}://{phost}:{pport})，尝试通过代理获取 API...", flush=True)
            return fetch_api_text_via_proxy(url, ptype, phost, pport, use_ssl_verify)
        except Exception as e:
            print(f"[fetch_api_text] 通过代理获取 API 失败: {e}，尝试使用直连/默认系统代理...", flush=True)
            log_to_json("WARNING", "Main", f"使用代理 {ptype}://{phost}:{pport} 获取 API 失败: {e}")

    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Mozilla/5.0 vpngate-openvpn-manager/2.0",
            "Accept": "text/plain,*/*",
        },
    )
    if url.startswith("https://") and not use_ssl_verify:
        import ssl
        ctx = ssl._create_unverified_context()
        with urllib.request.urlopen(request, timeout=12, context=ctx) as response:
            return response.read().decode("utf-8", errors="replace")
    else:
        with urllib.request.urlopen(request, timeout=12) as response:
            return response.read().decode("utf-8", errors="replace")

def parse_vpngate_rows(text: str) -> list[dict[str, str]]:
    lines = [line for line in text.splitlines() if line and not line.startswith("*")]
    if lines and lines[0].startswith("#"):
        lines[0] = lines[0][1:]
    return list(csv.DictReader(lines))

def decode_config(encoded: str) -> str:
    return base64.b64decode(encoded.encode("ascii"), validate=False).decode("utf-8", errors="replace")

def load_blacklist() -> dict[str, dict[str, Any]]:
    now = time.time()
    raw = read_json(BLACKLIST_FILE, {})
    if not isinstance(raw, dict):
        return {}
    cleaned: dict[str, dict[str, Any]] = {}
    changed = False
    for key, entry in raw.items():
        if not isinstance(entry, dict):
            changed = True
            continue
        until = float(entry.get("until", 0) or 0)
        if until and until > now:
            cleaned[str(key)] = entry
        else:
            changed = True
    if changed:
        write_json(BLACKLIST_FILE, cleaned)
    return cleaned

def mark_blacklisted(node: dict[str, Any], message: str) -> None:
    node_id = str(node.get("id") or "").strip()
    if not node_id:
        return
    blacklist = load_blacklist()
    now = time.time()
    blacklist[node_id] = {
        "id": node_id,
        "ip": node.get("ip") or node.get("remote_host") or "",
        "country": node.get("country", ""),
        "reason": message,
        "marked_at": now,
        "until": now + INVALID_BACKOFF_SECONDS,
    }
    write_json(BLACKLIST_FILE, blacklist)

def row_to_node(row: dict[str, str], config_text: str) -> dict[str, Any]:
    ip = row.get("IP", "")
    country_short = row.get("CountryShort", "")
    remote_host, remote_port, proto = vpn_utils.parse_remote(config_text, ip)
    node_id = safe_name("_".join([country_short or "XX", ip or remote_host, str(remote_port), proto]))
    config_path = CONFIG_DIR / f"{node_id}.ovpn"
    
    country_long = row.get("CountryLong", "")
    country_zh = vpn_utils.COUNTRY_TRANSLATIONS.get(country_long, vpn_utils.COUNTRY_TRANSLATIONS.get(country_long.strip(), country_long))
    return {
        "id": node_id,
        "country": country_zh,
        "country_short": country_short,
        "host_name": row.get("HostName", ""),
        "ip": ip,
        "score": parse_int(row.get("Score")),
        "ping": parse_int(row.get("Ping")),
        "speed": parse_int(row.get("Speed")),
        "sessions": parse_int(row.get("NumVpnSessions")),
        "owner": "",
        "asn": "",
        "as_name": "",
        "location": "",
        "ip_type": "",
        "quality": "",
        "latency_ms": 0,
        "config_file": str(config_path),
        "config_text": config_text,
        "proto": proto,
        "remote_host": remote_host,
        "remote_port": remote_port,
        "fetched_at": time.time(),
        "probe_status": "not_checked",
        "probe_message": "",
        "probed_at": 0,
    }

def fetch_candidates() -> list[dict[str, Any]]:
    """拉取 VPNGate 节点，并按国家补齐（JP 优先更多）。"""
    blacklist = load_blacklist()
    candidates: list[dict[str, Any]] = []
    seen_ips = set()

    has_cache = len(cached_nodes()) > 0
    max_attempts = 1 if has_cache else 2
    attempts_targets = [(API_URL, True), (API_URL, False)]
    if API_URL.startswith("https://"):
        attempts_targets.append((API_URL.replace("https://", "http://"), True))

    # 国家补齐目标：优先保证各区域有足够候选
    country_targets = {
        "JP": env_int("SCAN_TARGET_JP", 40, 1),
        "US": env_int("SCAN_TARGET_US", 15, 1),
        "KR": env_int("SCAN_TARGET_KR", 20, 1),
        "RU": env_int("SCAN_TARGET_RU", 10, 1),
        "VN": env_int("SCAN_TARGET_VN", 10, 1),
    }
    other_target = env_int("SCAN_TARGET_OTHER", 15, 1)
    hard_cap = max(MAX_SCAN_ROWS, sum(country_targets.values()) + other_target)

    log_to_json("INFO", "Main", "开始拉取官方 API 节点列表...")
    last_err = None
    all_nodes: list[dict[str, Any]] = []

    for url, verify_ssl in attempts_targets:
        for i in range(max_attempts):
            if i > 0:
                time.sleep(1.5)
            try:
                msg = f"尝试拉取 {url} (SSL验证: {verify_ssl}, 第 {i+1} 次尝试)..."
                print(f"[fetch_candidates] {msg}", flush=True)
                log_to_json("INFO", "Main", msg)
                api_text = fetch_api_text(url, verify_ssl)
                rows = parse_vpngate_rows(api_text)
                # 先解析尽量多的行（不只前 40），再按国家补齐
                parse_limit = max(hard_cap * 3, MAX_SCAN_ROWS, 300)
                for row in rows[:parse_limit]:
                    ip = row.get("IP", "")
                    if not ip or ip in seen_ips:
                        continue
                    encoded = row.get("OpenVPN_ConfigData_Base64", "")
                    if not encoded:
                        continue
                    try:
                        config_text = decode_config(encoded)
                        node = row_to_node(row, config_text)
                    except Exception as row_exc:
                        print(f"[fetch_candidates] 跳过损坏的节点配置记录: {row_exc}", flush=True)
                        continue
                    entry = blacklist.get(node["id"])
                    if entry and float(entry.get("until", 0) or 0) > time.time():
                        continue
                    all_nodes.append(node)
                    seen_ips.add(ip)
                if all_nodes:
                    break
            except Exception as e:
                last_err = e
                print(f"[fetch_candidates] 拉取失败 (URL: {url}, 验证: {verify_ssl}): {e}", flush=True)
                log_to_json("WARNING", "Main", f"拉取失败 (URL: {url}, 验证: {verify_ssl}): {e}")
        if all_nodes:
            break

    if not all_nodes:
        err_code, diag_msg = vpn_utils.diagnose_api_failure(API_URL)
        full_err_msg = f"获取官方 API 节点最终失败: {last_err} | 诊断结果: {diag_msg}"
        print(f"[错误代码 {err_code}] {full_err_msg}", flush=True)
        set_state(last_fetch_status="error", last_fetch_error_code=err_code, last_fetch_message=diag_msg)
        if last_err:
            raise RuntimeError(diag_msg) from last_err
        raise RuntimeError(diag_msg)

    # 按国家补齐挑选
    by_country: dict[str, list[dict[str, Any]]] = {}
    for n in all_nodes:
        code = node_country_code(n) or "XX"
        by_country.setdefault(code, []).append(n)

    # 各国内部优先：score 高、ping 低
    for code, items in by_country.items():
        items.sort(key=lambda n: (-parse_int(n.get("score")), parse_int(n.get("ping")) or 999999))

    selected: list[dict[str, Any]] = []
    selected_ids: set[str] = set()

    def take(code: str, limit: int) -> int:
        got = 0
        for n in by_country.get(code, []):
            nid = n.get("id")
            if not nid or nid in selected_ids:
                continue
            selected.append(n)
            selected_ids.add(nid)
            got += 1
            if got >= limit:
                break
        return got

    # 先保证重点国家
    for code, target in country_targets.items():
        got = take(code, target)
        print(f"[fetch_candidates] 国家补齐 {code}: {got}/{target}", flush=True)

    # 再补 OTHER
    other_codes = [c for c in by_country.keys() if c not in country_targets]
    other_got = 0
    for code in other_codes:
        if other_got >= other_target:
            break
        need = other_target - other_got
        other_got += take(code, need)
    print(f"[fetch_candidates] OTHER 补齐: {other_got}/{other_target}", flush=True)

    # 若总数仍不足，按全局分数补齐
    if len(selected) < min(hard_cap, len(all_nodes)):
        for n in sorted(all_nodes, key=lambda x: (-parse_int(x.get("score")), parse_int(x.get("ping")) or 999999)):
            nid = n.get("id")
            if not nid or nid in selected_ids:
                continue
            selected.append(n)
            selected_ids.add(nid)
            if len(selected) >= hard_cap:
                break

    candidates = selected
    set_state(
        last_fetch_at=time.time(),
        last_fetch_status="ok",
        last_fetch_message=f"Fetched {len(candidates)} candidates with country fill (parsed={len(all_nodes)}).",
        blacklisted_nodes=len(blacklist),
    )
    log_to_json("INFO", "Main", f"成功获取官方 API 节点，解析 {len(all_nodes)}，最终候选 {len(candidates)}")
    print(f"[fetch_candidates] 解析 {len(all_nodes)} 个，最终候选 {len(candidates)} 个", flush=True)
    return candidates

def cached_nodes() -> list[dict[str, Any]]:
    return read_nodes()

_openvpn_version = None

def split_openvpn_command() -> list[str]:
    try:
        return shlex.split(OPENVPN_CMD, posix=(os.name != "nt")) or ["openvpn"]
    except ValueError as exc:
        raise RuntimeError(f"OPENVPN_CMD 配置无法解析: {exc}") from exc

def get_openvpn_version() -> float:
    global _openvpn_version
    if _openvpn_version is not None:
        return _openvpn_version
    try:
        cmd = split_openvpn_command()
        res = subprocess.run(cmd + ["--version"], capture_output=True, text=True, timeout=2)
        match = re.search(r"OpenVPN\s+(\d+\.\d+)", res.stdout or res.stderr)
        if match:
            _openvpn_version = float(match.group(1))
            return _openvpn_version
    except Exception:
        pass
    _openvpn_version = 2.4
    return _openvpn_version

def openvpn_command(config_file: str, route_nopull: bool, dev: str = "tun0") -> list[str]:
    command = split_openvpn_command()
    command.extend(
        [
            "--config",
            config_file,
            "--dev",
            dev,
            "--dev-type",
            "tun",
            "--pull-filter",
            "ignore",
            "route-ipv6",
            "--pull-filter",
            "ignore",
            "ifconfig-ipv6",
            "--route-delay",
            "2",
            "--connect-retry-max",
            "1",
            "--connect-timeout",
            "15",
            "--auth-user-pass",
            str(AUTH_FILE),
            "--auth-nocache",
        ]
    )
    
    version = get_openvpn_version()
    if version >= 2.5:
        command.extend(["--data-ciphers", "AES-128-CBC:AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305"])
    else:
        command.extend(["--ncp-ciphers", "AES-128-CBC:AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305"])

    command.extend(["--verb", "3"])
    
    # 检查配置是否使用 TLS（有 ca 或 tls-client 指令）
    try:
        cfg_content = Path(config_file).read_text(encoding="utf-8", errors="replace")
        _uses_tls = "tls-client" in cfg_content.lower() or "ca " in cfg_content.lower() or "ca	" in cfg_content.lower()
    except Exception:
        _uses_tls = True
    if os.path.exists("/etc/ssl/certs") and _uses_tls:
        command.extend(["--capath", "/etc/ssl/certs"])
    
    try:
        content = Path(config_file).read_text(encoding="utf-8", errors="replace")
        if vpn_utils.is_config_tcp(content):
            ptype, host, port = vpn_utils.get_upstream_proxy()
            auth_file = upstream_proxy_auth_file()
            if ptype == "socks" and host and port:
                command.extend(["--socks-proxy", host, str(port)])
                if auth_file:
                    command.append(auth_file)
            elif ptype == "http" and host and port:
                command.extend(["--http-proxy", host, str(port)])
                if auth_file:
                    command.append(auth_file)
    except Exception:
        pass
        
    # OpenVPN 2.6: --auth-user-pass 需要 --pull；route-nopull 只忽略默认路由推送，不能去掉 pull
    if route_nopull:
        command.extend(["--pull", "--route-nopull"])
    return command

def stop_process(process: subprocess.Popen[str] | None) -> None:
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=8)
    except subprocess.TimeoutExpired:
        process.kill()

def kill_existing_openvpn_processes() -> None:
    if not sys.platform.startswith("linux"):
        return
    try:
        own_markers = [
            str(DATA_DIR),
            str(CONFIG_DIR),
            str(AUTH_FILE),
            str(UPSTREAM_PROXY_AUTH_FILE),
        ]
        killed_pids: list[int] = []
        proc_root = Path("/proc")
        if not proc_root.exists():
            return
        for proc_dir in proc_root.iterdir():
            if not proc_dir.name.isdigit():
                continue
            pid = int(proc_dir.name)
            if pid == os.getpid():
                continue
            try:
                raw = (proc_dir / "cmdline").read_bytes()
            except OSError:
                continue
            if not raw:
                continue
            args = [part.decode("utf-8", errors="replace") for part in raw.split(b"\0") if part]
            if not args:
                continue
            cmdline = " ".join(args)
            executable = Path(args[0]).name.lower()
            if "openvpn" not in executable and "openvpn" not in cmdline.lower():
                continue
            if any(marker and marker in cmdline for marker in own_markers):
                try:
                    os.kill(pid, signal.SIGTERM)
                    killed_pids.append(pid)
                except ProcessLookupError:
                    pass
                except PermissionError:
                    print(f"[Cleanup] No permission to terminate OpenVPN PID {pid}", flush=True)
        if killed_pids:
            time.sleep(0.5)
            for pid in killed_pids:
                try:
                    raw = (proc_root / str(pid) / "cmdline").read_bytes()
                    cmdline = " ".join(part.decode("utf-8", errors="replace") for part in raw.split(b"\0") if part)
                    if any(marker and marker in cmdline for marker in own_markers):
                        os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                except (OSError, PermissionError):
                    pass
            print(f"[Cleanup] Terminated NimbusVPN OpenVPN processes: {killed_pids}", flush=True)
    except Exception as e:
        print(f"[Cleanup Error] Failed to kill existing OpenVPN processes: {e}", flush=True)

def update_handshake_status(line_lower: str) -> None:
    status_map = {
        "resolving": ("解析域名", "正在解析服务器域名与 IP 地址..."),
        "udp link local": ("物理连接", "已创建本地套接字，开始尝试发送数据包..."),
        "tcp link local": ("物理连接", "已创建本地套接字，开始尝试发送数据包..."),
        "tls: initial packet": ("证书握手", "已成功发送首包，正在与远程服务器建立 TLS 安全通道..."),
        "verify ok": ("证书校验", "服务器证书校验成功，正在进行身份验证..."),
        "peer connection initiated": ("协商加密", "控制通道已建立，已初始化与服务器的加密对等连接..."),
        "push_request": ("请求配置", "正在向服务器发送 PUSH_REQUEST 请求配置参数与 IP 分配..."),
        "push_reply": ("应用配置", "已接收服务器 PUSH_REPLY，获取到 IP 分配，正在准备配置网卡..."),
        "tun/tap device": ("创建网卡", "正在创建虚拟通道并打开 TUN 虚拟网卡设备..."),
        "do_ifconfig": ("网卡配置", "正在为虚拟网卡配置 IP 地址及相关网络属性..."),
    }
    for key, (short_status, detailed_desc) in status_map.items():
        if key in line_lower:
            set_state(active_node_latency=short_status, last_check_message=detailed_desc)
            break

def run_openvpn_until_ready(config_file: str, keep_alive: bool, route_nopull: bool, timeout: int | None = None, dev: str = "tun0") -> tuple[bool, str, subprocess.Popen[str] | None]:
    limit = timeout if timeout is not None else OPENVPN_TEST_TIMEOUT_SECONDS
    try:
        process = subprocess.Popen(
            openvpn_command(config_file, route_nopull, dev),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            cwd=str(ROOT_DIR),
        )
    except FileNotFoundError:
        return False, "[错误代码 2001] [ERR_OVPN_CMD_NOT_FOUND] 未找到 openvpn 命令。原因: 系统未安装 openvpn，或 PATH 环境变量不正确。", None
    except OSError as exc:
        return False, f"[错误代码 2002] [ERR_OVPN_START_FAILED] openvpn 启动失败: {exc}。原因: 系统权限不足或配置冲突。", None

    lines: queue.Queue[str | None] = queue.Queue()
    startup_done = [False]
    openvpn_logs: list[str] = []

    def reader() -> None:
        assert process.stdout is not None
        for line in process.stdout:
            line_str = line.rstrip()
            if not startup_done[0]:
                openvpn_logs.append(line_str)
                lines.put(line_str)
            else:
                if keep_alive:
                    print(f"[OpenVPN] {line_str}", flush=True)
                    level = "INFO"
                    line_lower = line_str.lower()
                    if "error" in line_lower or "failed" in line_lower or "cannot" in line_lower or "fatal" in line_lower or "permission denied" in line_lower:
                        level = "ERROR"
                    elif "warning" in line_lower or "warn" in line_lower or "deprecated" in line_lower:
                        level = "WARNING"
                    log_to_json(level, "VPN", f"[OpenVPN] {line_str}")
        if not startup_done[0]:
            lines.put(None)

    threading.Thread(target=reader, daemon=True).start()
    started = time.time()
    tail: list[str] = []
    ok = False
    message = "OpenVPN did not complete initialization."
    while time.time() - started < limit:
        try:
            line = lines.get(timeout=0.5)
        except queue.Empty:
            if process.poll() is not None:
                break
            continue
        if line is None:
            break
        if line:
            tail.append(line)
            tail = tail[-50:]
            if keep_alive:
                print(f"[OpenVPN] {line}", flush=True)
        lower = line.lower()
        if keep_alive:
            update_handshake_status(lower)
        if "initialization sequence completed" in lower:
            ok = True
            message = f"OpenVPN connected in {int((time.time() - started) * 1000)} ms."
            break
        if "auth_failed" in lower or "authentication failed" in lower:
            message = "AUTH_FAILED"
            break
        if "cannot ioctl" in lower or "fatal error" in lower:
            message = line[-220:]
            break
    else:
        message = f"OpenVPN timeout after {limit}s."

    # Bulk write accumulated startup logs
    for line_str in openvpn_logs:
        level = "INFO"
        line_lower = line_str.lower()
        if "error" in line_lower or "failed" in line_lower or "cannot" in line_lower or "fatal" in line_lower or "permission denied" in line_lower:
            level = "ERROR"
        elif "warning" in line_lower or "warn" in line_lower or "deprecated" in line_lower:
            level = "WARNING"
        log_to_json(level, "VPN", f"[OpenVPN] {line_str}")

    if not ok:
        err_code, diag_msg = vpn_utils.diagnose_openvpn_failure(tail)
        message = f"[错误代码 {err_code}] {diag_msg} (原始日志尾部: {tail[-1][-100:] if tail else '无'})"
    startup_done[0] = True
    if not keep_alive or not ok:
        stop_process(process)
        process = None
    return ok, message, process


def setup_policy_routing(interface: str = "tun0") -> None:
    try:
        subprocess.run(["ip", "rule", "del", "table", "100"], capture_output=True, timeout=2)
    except Exception:
        pass
    try:
        subprocess.run(["ip", "route", "flush", "table", "100"], capture_output=True, timeout=2)
    except Exception:
        pass
    
    success = False
    for attempt in range(1, 4):
        try:
            subprocess.run(["ip", "route", "add", "default", "dev", interface, "table", "100"], check=True, timeout=2)
            subprocess.run(["ip", "rule", "add", "oif", interface, "table", "100"], check=True, timeout=2)
            # 配置反向路径过滤 rp_filter 为 loose 模式 (2)，防止回包被内核静默丢弃
            for proc_path in ["all", "default", interface]:
                try:
                    subprocess.run(["sysctl", "-w", f"net.ipv4.conf.{proc_path}.rp_filter=2"], capture_output=True, timeout=2)
                except Exception:
                    pass
            print(f"[policy_routing] Enabled policy routing for interface {interface} (attempt {attempt} success)", flush=True)
            success = True
            break
        except Exception as e:
            print(f"[policy_routing] Attempt {attempt} failed to enable policy routing: {e}", flush=True)
            time.sleep(1)
            
    if not success:
        print("[路由配置失败] [错误代码 3003] [ERR_ROUTE_TABLE_ADD_FAILED] 策略路由配置失败。原因: 无法向路由表 100 添加默认路由，这可能会导致通过 VPN 接口的出站路由无法正常解析。请检查系统是否支持策略路由、iproute2 工具是否完整，以及是否具有 root 权限。", flush=True)
        log_to_json("ERROR", "Routing", "[错误代码 3003] [ERR_ROUTE_TABLE_ADD_FAILED] 策略路由配置失败。原因: 无法向路由表 100 添加默认路由")

def cleanup_policy_routing() -> None:
    try:
        subprocess.run(["ip", "rule", "del", "table", "100"], capture_output=True, timeout=2)
        subprocess.run(["ip", "route", "flush", "table", "100"], capture_output=True, timeout=2)
        print("[policy_routing] Cleared policy routing table 100", flush=True)
    except Exception:
        pass

def stop_active_openvpn() -> None:
    global active_openvpn_process, active_openvpn_node_id
    with lock:
        cleanup_policy_routing()
        config_to_delete = None
        if active_openvpn_node_id:
            nodes = read_nodes()
            node = next((item for item in nodes if item.get("id") == active_openvpn_node_id), None)
            if node:
                config_to_delete = node.get("config_file")
                
        stop_process(active_openvpn_process)
        active_openvpn_process = None
        active_openvpn_node_id = ""
        kill_existing_openvpn_processes()
        
        if config_to_delete:
            try:
                path = Path(config_to_delete)
                if path.exists():
                    path.unlink()
            except Exception:
                pass

def active_openvpn_running() -> bool:
    return active_openvpn_process is not None and active_openvpn_process.poll() is None

def sort_all_nodes(nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    available_nodes = sorted(
        [n for n in nodes if n.get("probe_status") == "available" or n.get("active")],
        key=lambda n: (
            0 if n.get("ip_type") in ("residential", "mobile") else 1,
            parse_int(n.get("latency_ms")) or 999999,
            -parse_int(n.get("score"))
        )
    )
    untested_nodes = sorted(
        [n for n in nodes if n.get("probe_status") == "not_checked" and not n.get("active")],
        key=lambda n: (-parse_int(n.get("score")), parse_int(n.get("ping")))
    )
    unavailable_nodes = sorted(
        [n for n in nodes if n.get("probe_status") == "unavailable" and not n.get("active")],
        key=lambda n: (-parse_int(n.get("score")), -float(n.get("probed_at", 0)))
    )
    return available_nodes + untested_nodes + unavailable_nodes

active_test_indexes = set()
test_indexes_lock = threading.Lock()

def get_free_test_index() -> int:
    with test_indexes_lock:
        for idx in range(2, 100):
            if idx not in active_test_indexes:
                active_test_indexes.add(idx)
                return idx
        raise RuntimeError("没有可用的 OpenVPN 测试网卡编号，请稍后重试")

def release_test_index(idx: int) -> None:
    with test_indexes_lock:
        active_test_indexes.discard(idx)

def test_config_path(node_id: str) -> Path:
    safe_id = safe_name(node_id)
    return CONFIG_DIR / f".test_{safe_id}_{uuid.uuid4().hex}.ovpn"

def test_node_by_id(node_id: str) -> dict[str, Any]:
    with lock:
        nodes = read_nodes()
        node = next((item for item in nodes if item.get("id") == node_id), None)
        if not node:
            raise ValueError(f"Node not found: {node_id}")
        config_text = node.get("config_text") or ""
        h = str(node.get("remote_host") or node.get("ip"))
        p = parse_int(node.get("remote_port"))
        fallback_ping = parse_int(node.get("ping"))

    temp_path = test_config_path(node_id)
    try:
        CONFIG_DIR.mkdir(exist_ok=True, parents=True)
        temp_path.write_text(config_text, encoding="utf-8")
    except Exception as e:
        raise RuntimeError(f"Failed to write temp config file: {e}")

    latency = vpn_utils.ping_latency_ms(h, p, fallback_ping)

    idx = None
    process = None
    handshake_ok = False
    handshake_msg = ""
    egress_ok = False
    egress_msg = ""
    try:
        idx = get_free_test_index()
        dev_name = f"tun{idx}"
        test_timeout = env_int("OPENVPN_TEST_TIMEOUT_SECONDS", 12, 1)
        handshake_ok, handshake_msg, process = run_openvpn_until_ready(
            str(temp_path), keep_alive=True, route_nopull=True, timeout=test_timeout, dev=dev_name
        )
        if handshake_ok and process is not None:
            egress_ok, egress_msg, egress_latency = probe_egress_via_tun(
                dev_name, timeout=float(env_int("PROBE_EGRESS_TIMEOUT_SECONDS", 8, 1))
            )
            if egress_latency > 0:
                latency = egress_latency
        ok = handshake_ok and egress_ok
        message = handshake_msg if not handshake_ok else (
            f"handshake+egress ok ({egress_msg})" if egress_ok else f"handshake ok but egress failed: {egress_msg}"
        )
    finally:
        try:
            if process is not None:
                stop_process(process)
        except Exception:
            pass
        if idx is not None:
            release_test_index(idx)
        try:
            if temp_path.exists():
                temp_path.unlink()
        except Exception:
            pass

    temp_node = {
        "id": node_id,
        "ip": h,
        "remote_host": h,
        "remote_port": p,
        "owner": "",
        "asn": "",
        "as_name": "",
        "location": "",
        "ip_type": "",
        "quality": "",
    }
    if ok:
        vpn_utils.enrich_ip_info([temp_node])

    with lock:
        nodes = read_nodes()
        node = next((item for item in nodes if item.get("id") == node_id), None)
        if node:
            node["latency_ms"] = latency
            node["probe_status"] = "available" if ok else "unavailable"
            node["probe_message"] = message
            node["probed_at"] = time.time()
            if ok:
                node["owner"] = temp_node["owner"]
                node["asn"] = temp_node["asn"]
                node["as_name"] = temp_node["as_name"]
                node["location"] = temp_node["location"]
                node["ip_type"] = temp_node["ip_type"]
                node["quality"] = temp_node["quality"]
            
            sorted_nodes = sort_all_nodes(nodes)
            write_json(NODES_FILE, sorted_nodes)
            res = next((item for item in sorted_nodes if item.get("id") == node_id), node)
            return res
        else:
            return {}

def test_multiple_nodes(node_ids: list[str]) -> list[dict[str, Any]]:
    global scan_progress, is_scanning
    with lock:
        nodes = read_nodes()
        to_test = [n for n in nodes if n.get("id") in node_ids]
        
    def test_worker(args: tuple[int, dict[str, Any]]) -> dict[str, Any]:
        idx, n_info = args
        node_id = n_info["id"]
        config_text = n_info.get("config_text") or ""
        h = str(n_info.get("remote_host") or n_info.get("ip"))
        p = parse_int(n_info.get("remote_port"))
        fallback_ping = parse_int(n_info.get("ping"))
        
        # 开始检测：立刻上报当前节点（不要等测完）
        try:
            global scan_progress
            cl = list(scan_progress.get("current_list") or [])
            if node_id not in cl:
                cl.append(str(node_id))
            scan_progress["current_list"] = cl[-4:]
            scan_progress["current"] = " | ".join(scan_progress["current_list"])
            scan_progress["message"] = f"正在检测 {scan_progress.get('tested',0)}/{scan_progress.get('total',0)} · {scan_progress['current']}"
            set_state(
                scan_progress=dict(scan_progress),
                last_check_message=scan_progress["message"],
            )
            publish_scan_progress(force=True)
        except Exception:
            pass
        temp_path = test_config_path(node_id)
        try:
            CONFIG_DIR.mkdir(exist_ok=True, parents=True)
            temp_path.write_text(config_text, encoding="utf-8")
        except Exception as e:
            return {
                "id": node_id,
                "latency_ms": 0,
                "probe_status": "unavailable",
                "probe_message": f"Failed to write configuration: {e}",
                "probed_at": time.time(),
                "owner": "",
                "asn": "",
                "as_name": "",
                "location": "",
                "ip_type": "",
                "quality": "",
            }
            
        latency = vpn_utils.ping_latency_ms(h, p, fallback_ping)
        tun_idx = None
        process = None
        handshake_ok = False
        handshake_msg = ""
        egress_ok = False
        egress_msg = ""
        egress_latency = 0
        try:
            tun_idx = get_free_test_index()
            dev_name = f"tun{tun_idx}"
            # keep_alive=True 以便握手后立刻做出口探测，再主动关闭
            test_timeout = env_int("OPENVPN_TEST_TIMEOUT_SECONDS", 12, 1)
            handshake_ok, handshake_msg, process = run_openvpn_until_ready(
                str(temp_path), keep_alive=True, route_nopull=True, timeout=test_timeout, dev=dev_name
            )
            if handshake_ok and process is not None:
                egress_ok, egress_msg, egress_latency = probe_egress_via_tun(
                    dev_name, timeout=float(env_int("PROBE_EGRESS_TIMEOUT_SECONDS", 8, 1))
                )
                if egress_latency > 0:
                    latency = egress_latency
            status, message = classify_probe_result(handshake_ok, egress_ok, handshake_msg, egress_msg)
        finally:
            try:
                if process is not None:
                    stop_process(process)
            except Exception:
                pass
            if tun_idx is not None:
                release_test_index(tun_idx)
            try:
                if temp_path.exists():
                    temp_path.unlink()
            except Exception:
                pass

        temp_node = {
            "id": node_id,
            "ip": n_info.get("ip") or h,
            "remote_host": h,
            "remote_port": p,
            "latency_ms": latency,
            "probe_status": status if 'status' in locals() else ("available" if handshake_ok else "unavailable"),
            "probe_message": message if 'message' in locals() else handshake_msg,
            "probe_handshake_ok": bool(handshake_ok),
            "probe_egress_ok": bool(egress_ok),
            "probed_at": time.time(),
            "owner": "",
            "asn": "",
            "as_name": "",
            "location": "",
            "ip_type": "",
            "quality": "",
        }
        return temp_node

    updated_nodes_map = {}
    max_workers = min(2, max(1, len(to_test)))
    global scan_progress, is_scanning
    scan_progress = {
        "total": len(to_test),
        "tested": 0,
        "current": "",
        "current_list": [],
        "queue_left": len(to_test),
        "started_at": time.time(),
        "message": f"准备检测 {len(to_test)} 个节点",
    }
    set_state(scan_progress=dict(scan_progress), is_scanning=True,
              last_check_message=f"正在检测 0/{len(to_test)} …")
    publish_scan_progress(force=True)
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(test_worker, (idx, n)): n["id"] for idx, n in enumerate(to_test)}
        for future in concurrent.futures.as_completed(futures):
            nid = futures[future]
            try:
                res = future.result()
                updated_nodes_map[nid] = res
            except Exception as e:
                updated_nodes_map[nid] = {
                    "id": nid,
                    "probe_status": "unavailable",
                    "probe_message": f"Test exception: {e}",
                    "latency_ms": 0
                }
            scan_progress["tested"] = int(scan_progress.get("tested") or 0) + 1
            # 从 in-flight 列表移除已完成
            try:
                cl = [x for x in list(scan_progress.get("current_list") or []) if str(x) != str(nid)]
                scan_progress["current_list"] = cl
            except Exception:
                pass
            scan_progress["queue_left"] = max(0, int(scan_progress.get("total") or 0) - int(scan_progress.get("tested") or 0))
            if scan_progress.get("current_list"):
                scan_progress["current"] = " | ".join(str(x) for x in scan_progress["current_list"])
            else:
                scan_progress["current"] = str(nid)  # 刚完成的节点，短暂显示
            scan_progress["message"] = (
                f"扫描进度 {scan_progress['tested']}/{scan_progress['total']}"
                + (f" · 检测中 {scan_progress['current']}" if scan_progress.get("current_list") else f" · 刚完成 {nid}")
            )
            set_state(
                scan_progress=dict(scan_progress),
                last_check_message=scan_progress["message"],
            )
            publish_scan_progress(force=True)
                
    # 批量查询并丰富可用节点的地理及 ISP 信息，防止并发时被定位 API 接口限流
    # 回写 fail/success 计数与黑名单
    with lock:
        nodes = read_nodes()
        by_id = {str(n.get("id")): n for n in nodes if n.get("id")}
        for nid, res in updated_nodes_map.items():
            n = by_id.get(str(nid))
            if not n:
                continue
            status = res.get("probe_status") or "unavailable"
            n["probe_status"] = status
            n["probe_message"] = res.get("probe_message") or n.get("probe_message") or ""
            n["latency_ms"] = res.get("latency_ms") or 0
            n["probed_at"] = res.get("probed_at") or time.time()
            for k in ("owner", "asn", "as_name", "location", "ip_type", "quality"):
                if res.get(k):
                    n[k] = res.get(k)
            apply_probe_result_counters(n, status)
        write_json(NODES_FILE, nodes)

    successful_nodes = [res for res in updated_nodes_map.values() if res.get("probe_status") == "available"]
    if successful_nodes:
        try:
            vpn_utils.enrich_ip_info(successful_nodes)
        except Exception as ee:
            print(f"[test_multiple_nodes] 批量富化 IP 失败: {ee}", flush=True)

    with lock:
        current_nodes = read_nodes()
        for n in current_nodes:
            nid = n.get("id")
            if nid in updated_nodes_map:
                n.update(updated_nodes_map[nid])
        sorted_nodes = sort_all_nodes(current_nodes)
        write_json(NODES_FILE, sorted_nodes)
        
    return list(updated_nodes_map.values())

def auto_switch_node(attempt: int = 0) -> None:
    if attempt >= 3:
        print("[自动切换] 连续切换失败已达 3 次，停止切换以防止主线程死锁，将在后台重新加载节点...", flush=True)
        return
        
    ui_cfg = load_ui_config()
    connection_enabled = ui_cfg.get("connection_enabled", True)
    if not connection_enabled:
        print("[自动切换] 连接已禁用，不进行自动切换。", flush=True)
        return

    routing_mode = ui_cfg.get("routing_mode", "auto")
    if routing_mode == "fixed_ip":
        print("[自动切换] 当前处于固定 IP 模式，不进行自动连接或切换。", flush=True)
        return

    if region_auto_connect_paused():
        remain = int(max(0, region_fail_pause_until - time.time()))
        msg = f"本区自动连接暂停中（剩余 {remain}s），跳过切换"
        print(f"[自动切换] {msg}", flush=True)
        set_state(last_check_message=msg)
        return

    # Find the next best available node（跳过冷却节点）
    with lock:
        nodes = read_nodes()
        candidates = [
            n for n in nodes
            if n.get("probe_status") == "available" and not is_node_in_cooldown(str(n.get("id") or ""))
        ]
        candidates = apply_routing_filters(candidates, ui_cfg)
        candidates.sort(key=node_preference_key)
        next_node = candidates[0] if candidates else None
        
    if next_node:
        msg = f"当前连接已失效或代理连通性检测失败，正在自动切换至最佳备用节点: {next_node['id']}"
        print(f"[自动切换] {msg}", flush=True)
        log_to_json("INFO", "VPN", msg)
        try:
            connect_node(next_node["id"])
        except Exception as e:
            err_msg = f"切换到备用节点 {next_node['id']} 失败: {e}，将尝试下一个..."
            print(f"[自动切换] {err_msg}", flush=True)
            log_to_json("WARNING", "VPN", err_msg)
            mark_node_connect_failure(next_node["id"], str(e))
            report_shared_node_failure(next_node["id"], str(e))
            auto_switch_node(attempt + 1)
    else:
        msg = empty_region_message(0, 0) or "没有可用的备选节点，将自动断开并清理当前连接状态，同时在后台异步获取新节点..."
        target_country = str(ui_cfg.get("force_country", "") or "").strip().upper()
        if routing_mode == "fixed_region" and target_country:
            msg = f"没有可用的【{target_country}】备选节点，优先尝试备援代理..."
        print(f"[自动切换] {msg}", flush=True)
        log_to_json("WARNING", "VPN", msg)
        stop_active_openvpn()
        with lock:
            nodes = read_nodes()
            for item in nodes:
                item["active"] = False
            write_json(NODES_FILE, nodes)
        set_state(active_openvpn_node_id="", last_check_message=msg)
        # 无 OpenVPN 候选：立即切备援（主路径）
        try:
            if not IS_SCANNER and FREEPROXYDB_ENABLED:
                if maybe_enable_proxy_fallback(force=True):
                    print("[自动切换] 无 OpenVPN，已自动启用备援", flush=True)
                    return
        except Exception as _fb:
            rate_limited_print("autoswitch:fallback", f"[备援] 自动启用失败: {_fb}", 30.0)

        def bg_fetch_and_switch():
            try:
                maintain_valid_nodes(force=False)
                auto_switch_node()
                try:
                    if not IS_SCANNER and not active_openvpn_running():
                        maybe_enable_proxy_fallback(force=True)
                except Exception as _fb:
                    rate_limited_print("checker:fallback", f"[备援] checker 启用失败: {_fb}", 60.0)
            except Exception as e:
                print(f"[自动切换后台补齐] 获取并测试节点失败: {e}", flush=True)

        threading.Thread(target=bg_fetch_and_switch, daemon=True).start()

def connect_node(node_id: str) -> str:
    global active_openvpn_process, active_openvpn_node_id, is_connecting
    node_id = str(node_id or "").strip()
    if not node_id:
        raise ValueError("Node id is required")
    stopped_existing = False
    with lock:
        if is_connecting:
            print("[连接] 正在建立其他连接中，跳过此请求", flush=True)
            raise RuntimeError("当前已有连接或节点检测任务正在运行，请稍后再试")
        is_connecting = True
        set_state(is_connecting=True, active_node_latency="正在连接", last_check_message=f"正在初始化连接配置: {node_id}")
        
    try:
        log_to_json("INFO", "VPN", f"开始连接节点: {node_id}")

        nodes = read_nodes()
        node = next((item for item in nodes if item.get("id") == node_id), None)
        if not node:
            raise ValueError(f"Node not found: {node_id}")
        
        ui_cfg = load_ui_config()
        ui_cfg["connection_enabled"] = True
        if ui_cfg.get("routing_mode") == "fixed_ip":
            ui_cfg["fixed_node_id"] = node_id
        auth_file = DATA_DIR / "ui_auth.json"
        with lock:
            DATA_DIR.mkdir(exist_ok=True, parents=True)
            auth_file.write_text(json.dumps(ui_cfg, ensure_ascii=False, indent=2), encoding="utf-8")
        
        set_state(active_node_latency="清理连接", last_check_message="正在关闭与清理旧的 VPN 连接及网卡...")
        stop_active_openvpn()
        stopped_existing = True

        set_state(active_node_latency="写入配置", last_check_message="正在写入 OpenVPN 节点配置文件...")
        config_path = Path(node["config_file"])
        try:
            CONFIG_DIR.mkdir(exist_ok=True, parents=True)
            config_path.write_text(node.get("config_text") or "", encoding="utf-8")
        except Exception as e:
            raise RuntimeError(f"Failed to write configuration: {e}")

        set_state(active_node_latency="启动核心", last_check_message="正在启动 OpenVPN Core 核心服务并建立连接...")
        ok, message, process = run_openvpn_until_ready(str(node["config_file"]), keep_alive=True, route_nopull=True)
        if not ok or process is None:
            try:
                if config_path.exists():
                    config_path.unlink()
            except Exception:
                pass
            node["probe_status"] = "unavailable"
            node["probe_message"] = message
            for item in nodes:
                item["active"] = False
            write_json(NODES_FILE, nodes)
            log_to_json("ERROR", "VPN", f"连接节点 {node_id} 失败: {message}")
            rate_limited_print(f"connfail:{node_id}", f"[连接核心失败] 无法与 VPN 节点 {node_id} 建立隧道连接！详情: {message}", 30.0)

            # OpenVPN 未连接时才启用 FreeProxyDB 备援（低优先级）
            try:
                if not active_openvpn_running():
                    maybe_enable_proxy_fallback(force=True)
            except Exception as _fb_exc:
                rate_limited_print("fb:enable", f"[备援] 启用失败: {_fb_exc}", 30.0)

            set_state(active_openvpn_node_id="", is_connecting=False, active_node_latency="无活动连接", last_check_message=f"连接失败: {message}")
            with lock:
                active_openvpn_node_id = ""
            raise RuntimeError(message)
            
        with lock:
            active_openvpn_process = process
            active_openvpn_node_id = node_id
        
        set_state(active_node_latency="配置路由", last_check_message="正在配置策略路由规则与流量转发...")
        setup_policy_routing("tun0")
        
        global last_active_ping_time, last_active_latency
        last_active_ping_time = time.time()
        last_active_latency = 0
        
        set_state(active_node_latency="测试延迟", last_check_message="正在直连测试代理出口延迟与可用性...")
        try:
            ip = node.get("ip") or node.get("remote_host")
            port = parse_int(node.get("remote_port"))
            fallback = parse_int(node.get("ping"))
            latency = vpn_utils.ping_latency_ms(ip, port, fallback)
            if latency > 0:
                last_active_latency = latency
        except Exception:
            pass
            
        for item in nodes:
            item["active"] = item.get("id") == node_id
            if item["active"]:
                _ph = f"[{LOCAL_PROXY_HOST}]" if ":" in LOCAL_PROXY_HOST else LOCAL_PROXY_HOST
                item["probe_message"] = f"Active node. HTTP proxy: http://{_ph}:{LOCAL_PROXY_PORT}"
        write_json(NODES_FILE, nodes)
        
        set_state(last_check_message="正在测试本地代理出站联通性与出口 IP...")
        res = check_proxy_health()
        if res["ok"]:
            set_state(
                proxy_ok=True,
                proxy_ip=res["ip"],
                proxy_latency_ms=res["latency_ms"],
                proxy_error=""
            )
        else:
            set_state(
                proxy_ok=False,
                proxy_ip="-",
                proxy_latency_ms=0,
                proxy_error=res.get("error", "未知错误")
            )
            
        latency_str = f"{last_active_latency} ms" if last_active_latency > 0 else "检测超时"
        set_state(active_openvpn_node_id=node_id, is_connecting=False, last_check_message=f"Connected {node_id}", active_node_latency=latency_str)
        log_to_json("INFO", "VPN", f"节点 {node_id} 连接成功，出口网卡 tun0 已启用")
        return f"Connected {node_id}"
    except Exception as exc:
        if stopped_existing or (active_openvpn_node_id == node_id and not active_openvpn_running()):
            clear_active_connection_state(f"连接失败: {exc}")
        else:
            set_state(is_connecting=False, last_check_message=f"连接失败: {exc}")
        raise
    finally:
        with lock:
            is_connecting = False

def connect_best_node() -> dict[str, Any]:
    """优先 OpenVPN 最佳节点；无可用 VPN 时自动启用 FreeProxyDB 备援。"""
    ui_cfg = load_ui_config()
    nodes = read_nodes()
    node = best_available_node(nodes, ui_cfg, include_active=True)
    if node:
        node_id = str(node.get("id") or "").strip()
        if not node_id:
            raise ValueError("Best node has empty id")
        # 连 VPN 前清掉备援，避免双路径
        try:
            if (get_state() or {}).get("fallback_mode"):
                clear_fallback_upstream("prefer_openvpn")
        except Exception:
            pass
        message = connect_node(node_id)
        return {
            "message": message,
            "mode": "openvpn",
            "node": {
                "id": node_id,
                "ip_type": node.get("ip_type", ""),
                "latency_ms": node.get("latency_ms") or node.get("ping") or 0,
                "score": node.get("score", 0),
            },
        }

    available_count = len([n for n in nodes if n.get("probe_status") == "available"])
    if is_connecting or maintenance_lock.locked():
        # 检测中：仍可尝试备援，避免 UI 空等
        pass
    # 无 OpenVPN 可用 → 自动备援
    if not IS_SCANNER and FREEPROXYDB_ENABLED:
        try:
            ok = maybe_enable_proxy_fallback(force=True)
            st = get_state() or {}
            if ok or (st.get("fallback_mode") and st.get("proxy_ok")):
                return {
                    "message": st.get("last_check_message") or "无 OpenVPN 可用，已自动启用备援代理",
                    "mode": "fallback",
                    "node": {
                        "id": st.get("fallback_proxy") or "fallback",
                        "ip_type": "fallback",
                        "latency_ms": st.get("proxy_latency_ms") or 0,
                        "score": 0,
                    },
                    "fallback_mode": True,
                    "proxy_ip": st.get("proxy_ip") or "-",
                }
        except Exception as exc:
            raise ValueError(f"无 OpenVPN 可用，且备援启用失败: {exc}") from exc
    if is_connecting or maintenance_lock.locked():
        raise ValueError("节点检测仍在进行中，暂时没有可连接的可用节点，请稍后再试")
    raise ValueError(f"当前没有匹配路由策略的可用节点（可用 OpenVPN: {available_count}），备援也不可用")

def maintain_valid_nodes(force: bool = False) -> str:
    global is_scanning, is_connecting, scan_progress, active_openvpn_node_id
    global active_openvpn_process, active_openvpn_node_id, is_connecting, is_scanning
    ensure_dirs()
    if not maintenance_lock.acquire(blocking=False):
        msg = "节点维护任务正在运行，请稍后再试"
        set_state(last_check_message=msg)
        return msg
    # 扫描/维护默认不占用 is_connecting；仅在真正 connect 时由 connect_node 设置
    is_connecting = False
    try:
        if force and IS_SCANNER:
            # 仅扫描器 force 才断开重扫；从节点 force 只表示强制同步共享
            with lock:
                stop_active_openvpn()
        elif not active_openvpn_running():
            ui_cfg = load_ui_config()
            routing_mode = ui_cfg.get("routing_mode", "auto")
            connection_enabled = ui_cfg.get("connection_enabled", True)
            if connection_enabled:
                if routing_mode == "fixed_ip":
                    target_id = active_openvpn_node_id or ui_cfg.get("fixed_node_id", "")
                    if target_id:
                        nodes = read_nodes()
                        if any(n.get("id") == target_id for n in nodes):
                            print(f"[维护线程] 检测到固定 IP 模式下 OpenVPN 未运行，正在重新拉起同一节点: {target_id}", flush=True)
                            is_connecting = False
                            try:
                                connect_node(target_id)
                            except Exception as e:
                                print(f"[维护线程] 重新拉起固定节点 {target_id} 失败: {e}", flush=True)
                            is_connecting = True
                else:
                    has_active_id = False
                    with lock:
                        if active_openvpn_node_id:
                            has_active_id = True
                            stop_active_openvpn()
                    if has_active_id:
                        print("[维护线程] 检测到当前 OpenVPN 进程已意外退出，准备自动切换节点", flush=True)
                        is_connecting = False
                        auto_switch_node()
                        is_connecting = True

        if IS_SCANNER:
            # ---- Scanner: 执行完整的拉取+测试，写入共享目录 ----
            try:
                set_state(is_connecting=True, last_check_message="正在拉取最新的免费 VPN 节点列表...")
                candidates = fetch_candidates()
            except Exception as exc:
                vpn_utils.check_and_fix_dns()
                diag_msg = str(exc)
                if not any(token in diag_msg for token in ["[ERR_", "错误代码"]):
                    err_code, raw_diag = vpn_utils.diagnose_api_failure(API_URL)
                    diag_msg = f"[错误代码 {err_code}] 获取节点失败: {exc} | 诊断结果: {raw_diag}"
                set_state(last_fetch_at=time.time(), last_fetch_status="error", last_fetch_message=diag_msg)
                candidates = []

            if not candidates:
                return "没有拉取到新节点"

            with lock:
                active_node = None
                if active_openvpn_node_id:
                    current_nodes = read_nodes()
                    active_node = next((n for n in current_nodes if n.get("id") == active_openvpn_node_id), None)

                merged: list[dict[str, Any]] = []
                seen_ids: set[str] = set()

                if active_node:
                    merged.append(active_node)
                    seen_ids.add(active_node["id"])

                for cand in candidates:
                    if cand["id"] not in seen_ids:
                        merged.append(cand)
                        seen_ids.add(cand["id"])

                if len(merged) > 1000:
                    merged = merged[:1000]

                for n in merged:
                    config_path = Path(n["config_file"])
                    if not config_path.exists():
                        try:
                            config_path.write_text(n["config_text"], encoding="utf-8")
                        except Exception:
                            pass

                write_json(NODES_FILE, merged)

            # 增量测试：优先复测 available，再 not_checked，跳过黑名单；保底达标后少测
            with lock:
                current_nodes = read_nodes()
            now_ts = time.time()
            targets = region_available_targets()
            have = count_available_by_country(current_nodes)
            priority = {"JP": 0, "US": 1, "KR": 2, "RU": 3, "VN": 4, "OTHER": 5}

            def country_bucket(n: dict[str, Any]) -> str:
                code = node_country_code(n) or "OTHER"
                return code if code in targets else "OTHER"

            retest_available: list[dict[str, Any]] = []
            unchecked: list[dict[str, Any]] = []
            others: list[dict[str, Any]] = []
            for n in current_nodes:
                if n.get("active"):
                    continue
                if is_scan_blacklisted(n, now_ts):
                    continue
                st = n.get("probe_status") or "not_checked"
                if st == "available":
                    # 可用节点也周期性复测，但优先老旧的
                    retest_available.append(n)
                elif st in (None, "", "not_checked"):
                    unchecked.append(n)
                else:
                    # unavailable：只挑 fail_count 低且不在黑名单的
                    if node_fail_count(n) < 3:
                        others.append(n)

            def sort_key(n: dict[str, Any]):
                bucket = country_bucket(n)
                need = max(0, targets.get(bucket, 0) - have.get(bucket, 0))
                probed_at = float(n.get("probed_at") or 0)
                return (
                    0 if need > 0 else 1,  # 未达标国家优先
                    priority.get(bucket, 9),
                    probed_at,  # 越旧越优先复测
                    -parse_int(n.get("score")),
                    parse_int(n.get("ping")) or 999999,
                )

            retest_available.sort(key=sort_key)
            unchecked.sort(key=sort_key)
            others.sort(key=sort_key)

            # 配额：先补未达标国家的 unchecked，再少量复测 available，再挑少量历史失败
            max_test = env_int("MAX_TEST_NODES_PER_ROUND", 24, 1)
            # 未测积压时：本轮几乎全给 not_checked，少做复测
            unchecked_backlog = len(unchecked)
            if unchecked_backlog >= max_test:
                retest_quota = max(2, max_test // 6)
                unchecked_quota = max_test - retest_quota
            else:
                retest_quota = max(4, max_test // 3)
                unchecked_quota = max_test - retest_quota
            selected: list[dict[str, Any]] = []
            selected.extend(unchecked[:unchecked_quota])
            selected.extend(retest_available[:retest_quota])
            if len(selected) < max_test:
                selected.extend(others[: max_test - len(selected)])

            # 仅当未测积压清空且重点国家达标，才轻量复测
            all_met = all(have.get(k, 0) >= min(targets.get(k, 0), 5) for k in ("JP", "KR"))
            if unchecked_backlog == 0 and all_met and have.get("US", 0) >= min(1, targets.get("US", 1)):
                selected = (retest_available[:max(6, max_test // 2)] + unchecked[:4])[:max_test]
                print(f"[扫描器] 未测已清空且重点达标 have={have}，本轮轻量复测 {len(selected)} 个", flush=True)
            else:
                print(
                    f"[扫描器] 未测积压 {unchecked_backlog}，本轮配额 unchecked={unchecked_quota} retest={retest_quota}",
                    flush=True,
                )

            # 去重保持顺序
            seen = set()
            to_test = []
            for n in selected:
                nid = str(n.get("id") or "")
                if not nid or nid in seen:
                    continue
                seen.add(nid)
                to_test.append(n)
            to_test_ids = [n["id"] for n in to_test]

            msg = (
                f"[扫描器] 增量检测 {len(to_test_ids)} 个 "
                f"(未测优先+复测+跳过黑名单) have={dict(list(have.items())[:6])}"
            )
            print(f"[周期检测] {msg}", flush=True)
            log_to_json("INFO", "Main", msg)

            is_scanning = True
            is_connecting = False
            set_state(is_scanning=True, is_connecting=False, last_check_message=f"正在并发检测节点可用性 ({len(to_test_ids)} 个)...")
            try:
                # 单轮可多批：尽快消化 not_checked，避免 UI 长期「待检测」
                max_batches = env_int("SCAN_BATCHES_PER_ROUND", 3, 1)
                batch_no = 0
                while to_test_ids and batch_no < max_batches:
                    batch_no += 1
                    print(f"[扫描器] 第 {batch_no}/{max_batches} 批检测 {len(to_test_ids)} 个", flush=True)
                    scan_progress.update({
                        "batch": batch_no,
                        "batches": max_batches,
                        "queue_left": len(to_test_ids),
                        "message": f"扫描批次 {batch_no}/{max_batches}（{len(to_test_ids)} 个）",
                    })
                    set_state(scan_progress=dict(scan_progress), last_check_message=f"扫描批次 {batch_no}/{max_batches}（{len(to_test_ids)} 个）...")
                    publish_scan_progress(force=True)
                    test_multiple_nodes(to_test_ids)
                    # 重新挑选下一批未测
                    with lock:
                        current_nodes = read_nodes()
                    now_ts = time.time()
                    have = count_available_by_country(current_nodes)
                    unchecked = [
                        n for n in current_nodes
                        if not n.get("active")
                        and not is_scan_blacklisted(n, now_ts)
                        and (n.get("probe_status") in (None, "", "not_checked"))
                    ]
                    def _bucket(n: dict[str, Any]) -> str:
                        code = node_country_code(n) or "OTHER"
                        return code if code in targets else "OTHER"
                    unchecked.sort(key=lambda n: (
                        0 if max(0, targets.get(_bucket(n), 0) - have.get(_bucket(n), 0)) > 0 else 1,
                        {"JP": 0, "US": 1, "KR": 2, "RU": 3, "VN": 4, "OTHER": 5}.get(_bucket(n), 9),
                        parse_int(n.get("ping")) or 999999,
                    ))
                    if not unchecked:
                        print("[扫描器] 未测节点已清空，结束本轮多批检测", flush=True)
                        break
                    to_test_ids = [n["id"] for n in unchecked[:max_test]]
            finally:
                is_scanning = False
                is_connecting = False
                try:
                    scan_progress.update({
                        "current": "done",
                        "current_list": [],
                        "message": "节点检测完成，正在写入共享结果...",
                    })
                except Exception:
                    pass
                set_state(is_scanning=False, is_connecting=False, scan_progress=dict(scan_progress), last_check_message="节点检测完成，正在写入共享结果...")
                publish_scan_progress(force=True)

            # 写入共享目录（合并上轮 available，避免扫描中把 UI 刷成 0）
            try:
                Path(SHARED_DATA_DIR).mkdir(exist_ok=True, parents=True)
                tested_nodes = read_nodes()
                prev_shared = read_json(SHARED_NODES_FILE, [])
                if not isinstance(prev_shared, list):
                    prev_shared = []
                prev_map = {str(n.get("id")): n for n in prev_shared if isinstance(n, dict) and n.get("id")}

                merged_map: dict[str, dict[str, Any]] = {}
                for n in tested_nodes:
                    sn = dict(n)
                    sn["active"] = False
                    nid = str(sn.get("id") or "")
                    if not nid:
                        continue
                    status = sn.get("probe_status") or "not_checked"
                    if status in (None, "", "not_checked"):
                        prev = prev_map.get(nid)
                        if prev and prev.get("probe_status") in ("available", "unavailable"):
                            sn["probe_status"] = prev.get("probe_status")
                            sn["probe_message"] = prev.get("probe_message") or sn.get("probe_message") or ""
                            sn["latency_ms"] = prev.get("latency_ms") or sn.get("latency_ms") or 0
                            sn["ip_type"] = sn.get("ip_type") or prev.get("ip_type") or ""
                            # config_text 不再依赖共享 JSON（可能已瘦身）
                    merged_map[nid] = sn

                now_ts = time.time()
                for nid, prev in prev_map.items():
                    if nid in merged_map:
                        continue
                    if prev.get("probe_status") != "available":
                        continue
                    probed_at = float(prev.get("probed_at") or prev.get("fetched_at") or 0)
                    if probed_at and now_ts - probed_at > env_int("SHARED_AVAILABLE_RETAIN_SECONDS", 2700, 1):
                        continue  # 默认 45 分钟，避免过期 available 虚高
                    keep = dict(prev)
                    keep["active"] = False
                    keep["probe_message"] = (keep.get("probe_message") or "") + " (retained)"
                    merged_map[nid] = keep

                # 先把配置落到 shared/configs，再写瘦身 JSON（无 config_text）
                shared_cfg_dir = Path(SHARED_DATA_DIR) / "configs"
                shared_cfg_dir.mkdir(exist_ok=True, parents=True)
                fat_nodes = list(merged_map.values())
                for n in fat_nodes:
                    cfg_text = n.get("config_text") or ""
                    if not cfg_text:
                        # 尝试从本地 config_file 绝对路径读
                        local_cfg = Path(str(n.get("config_file") or ""))
                        if local_cfg.exists() and local_cfg.is_file():
                            try:
                                cfg_text = local_cfg.read_text(encoding="utf-8", errors="replace")
                            except Exception:
                                cfg_text = ""
                    if not cfg_text:
                        continue
                    cfg_name = Path(n.get("config_file") or f"{safe_name(n.get('id','node'))}.ovpn").name
                    try:
                        (shared_cfg_dir / cfg_name).write_text(cfg_text, encoding="utf-8")
                        n["config_file"] = cfg_name
                    except Exception:
                        pass

                shared_nodes = [slim_shared_node(n) for n in fat_nodes]
                shared_nodes.sort(key=lambda n: (
                    0 if n.get("probe_status") == "available" else 1 if n.get("probe_status") == "unavailable" else 2,
                    node_country_code(n) or "ZZ",
                    -parse_int(n.get("score")),
                ))
                # 原子写：tmp + replace
                tmp_shared = Path(str(SHARED_NODES_FILE) + ".tmp")
                write_json(tmp_shared, shared_nodes)
                tmp_shared.replace(SHARED_NODES_FILE)

                country_total: dict[str, int] = {}
                country_available: dict[str, int] = {}
                for n in shared_nodes:
                    code = node_country_code(n) or "XX"
                    country_total[code] = country_total.get(code, 0) + 1
                    if n.get("probe_status") == "available":
                        country_available[code] = country_available.get(code, 0) + 1

                generation = int(time.time())
                scanning = bool(is_scanning)
                write_json(SHARED_META_FILE, {
                    "scanned_at": time.time(),
                    "generation": generation,
                    "node_count": len(shared_nodes),
                    "available_count": len([n for n in shared_nodes if n.get("probe_status") == "available"]),
                    "scanner_role": "nimbus-scanner",
                    "scanner_container": active_openvpn_node_id or "unknown",
                    "scanning": scanning,
                    "check_interval_seconds": CHECK_INTERVAL_SECONDS,
                    "next_scan_at": time.time() + CHECK_INTERVAL_SECONDS,
                    "scan_progress": dict(scan_progress),
                "check_interval_seconds": CHECK_INTERVAL_SECONDS,
                "next_scan_at": (float((read_json(SHARED_META_FILE, {}) or {}).get("next_scan_at") or 0) or (time.time() + CHECK_INTERVAL_SECONDS)),
                    "country_total": country_total,
                    "country_available": country_available,
                })
                try:
                    (Path(SHARED_DATA_DIR) / "shared.generation").write_text(str(generation), encoding="utf-8")
                except Exception:
                    pass
                print(
                    f"[共享扫描] 已写入 {len(shared_nodes)} 个节点 generation={generation} "
                    f"available={dict(list(country_available.items())[:8])} scanning={scanning}",
                    flush=True,
                )
            except Exception as e:
                print(f"[共享扫描] 写入共享节点失败: {e}", flush=True)

            with lock:
                merged = read_nodes()
                available_nodes = [n["id"] for n in merged if n.get("probe_status") == "available"]
                unavailable_nodes = [n["id"] for n in merged if n.get("probe_status") == "unavailable"]
                active_node = next((n["id"] for n in merged if n.get("active")), "无")

                status_report = (
                    f"周期节点检测完成。实时同步状态: 获取到候选节点共 {len(merged)} 个。 "
                    f"其中【可用节点】{len(available_nodes)} 个: {available_nodes[:15]}...; "
                    f"【不可用节点】{len(unavailable_nodes)} 个; "
                    f"当前【正在正常运行的活动连接节点】为: {active_node}。"
                )
                print(f"[周期检测] {status_report}", flush=True)
                log_to_json("INFO", "Main", status_report)

                # 扫描完成后：仅当允许连接时才自动连（独立 scanner 默认 CONNECTION_ENABLED=false）
                if not active_openvpn_running():
                    try:
                        ui_cfg = load_ui_config()
                        if ui_cfg.get("connection_enabled", True) and ui_cfg.get("routing_mode", "auto") != "fixed_ip":
                            candidates = [
                                n for n in merged
                                if n.get("probe_status") == "available"
                                and (n.get("config_text") or Path(str(n.get("config_file") or "")).exists())
                            ]
                            candidates = apply_routing_filters(candidates, ui_cfg)
                            candidates.sort(key=node_preference_key)
                            if candidates:
                                best_id = str(candidates[0].get("id") or "")
                                if best_id:
                                    print(f"[扫描器] 扫描完成，自动连接本区最佳节点: {best_id}", flush=True)
                                    connect_node(best_id)
                        else:
                            print("[扫描器] 扫描完成（纯扫描模式，不自动连接 VPN）", flush=True)
                    except Exception as auto_exc:
                        print(f"[扫描器] 扫描后自动连接失败: {auto_exc}", flush=True)

                if active_node != "无" and not active_openvpn_running():
                    warn_msg = f"[诊断警告] 活动节点 {active_node} 被标记为活动状态，但 OpenVPN 进程实际并未正常运行！"
                    print(warn_msg, flush=True)
                    log_to_json("WARNING", "Main", warn_msg)

                if not active_openvpn_running():
                    ui_cfg = load_ui_config()
                    connection_enabled = ui_cfg.get("connection_enabled", True)
                    if connection_enabled:
                        routing_mode = ui_cfg.get("routing_mode", "auto")
                        if routing_mode != "fixed_ip":
                            next_node = best_available_node(merged, ui_cfg, include_active=True)
                            if next_node:
                                next_node_id = str(next_node.get("id") or "").strip()
                                if next_node_id:
                                    try:
                                        connect_node(next_node_id)
                                    except Exception as exc:
                                        warn_msg = f"[自动连接失败] 候选节点 {next_node_id} 连接失败: {exc}"
                                        print(warn_msg, flush=True)
                                        log_to_json("WARNING", "Main", warn_msg)
                                        auto_switch_node()

            valid_nodes_count = len([n for n in merged if n.get("probe_status") == "available"])
            cleanup_old_configs()
            message = f"Fetched {len(candidates)} nodes. Tested {len(to_test_ids)} non-active nodes."
            set_state(
                last_check_at=time.time(),
                last_check_message=message,
                active_openvpn_node_id=active_openvpn_node_id,
                valid_nodes=valid_nodes_count,
            )
            return message

        else:
            # ---- 非 Scanner: 从共享目录读取节点，按地区过滤，不拉取 VPNGate，不测试 ----
            print(f"[从节点] 非扫描模式，从共享目录读取节点... force={force}", flush=True)
            shared_nodes = read_json(SHARED_NODES_FILE, [])
            if not isinstance(shared_nodes, list):
                shared_nodes = []

            if not shared_nodes:
                msg = "共享目录无可用节点数据，等待扫描器首次完成..."
                print(f"[从节点] {msg}", flush=True)
                set_state(last_check_message=msg)
                # 尝试从本地缓存读取
                cached = read_nodes()
                if cached:
                    shared_nodes = cached
                else:
                    return msg

            # 补全 config_text / config_file：共享节点 -> 共享 configs -> 本地缓存
            local_nodes = read_nodes()
            local_map = {n.get("id"): n for n in local_nodes if n.get("id")}
            shared_cfg_dir = Path(SHARED_DATA_DIR) / "configs"
            CONFIG_DIR.mkdir(exist_ok=True, parents=True)

            # 按地区过滤
            ui_cfg = load_ui_config()
            filtered = apply_routing_filters(shared_nodes, ui_cfg)

            for n in filtered:
                nid = str(n.get("id") or "").strip()
                if not nid:
                    continue

                # 保留本地活动节点状态
                local_n = local_map.get(nid)
                if local_n and local_n.get("active") and active_openvpn_node_id == nid:
                    n["active"] = True
                else:
                    n["active"] = False

                # 1) 优先共享 configs 目录（瘦身后主路径）
                cfg_name = Path(n.get("config_file") or f"{safe_name(nid)}.ovpn").name
                shared_cfg_path = shared_cfg_dir / cfg_name
                cfg_text = ""
                if shared_cfg_path.exists():
                    try:
                        cfg_text = shared_cfg_path.read_text(encoding="utf-8", errors="replace")
                    except Exception:
                        cfg_text = ""
                # 2) 兼容旧共享 JSON 里可能残留的 config_text
                if not cfg_text:
                    cfg_text = n.get("config_text") or ""
                # 3) 最后回退本地缓存
                if not cfg_text and local_n:
                    cfg_text = local_n.get("config_text") or ""
                    if not cfg_text:
                        local_cfg = Path(str(local_n.get("config_file") or ""))
                        if local_cfg.exists():
                            try:
                                cfg_text = local_cfg.read_text(encoding="utf-8", errors="replace")
                            except Exception:
                                pass

                n["config_text"] = cfg_text
                n["config_file"] = str(CONFIG_DIR / cfg_name)

                # 把可用配置落到本容器本地，供 OpenVPN 直接读取
                if cfg_text:
                    try:
                        Path(n["config_file"]).write_text(cfg_text, encoding="utf-8")
                    except Exception as e:
                        print(f"[从节点] 写入配置失败 {nid}: {e}", flush=True)
                else:
                    # 没有配置的节点不可连接
                    if n.get("probe_status") == "available":
                        n["probe_status"] = "unavailable"
                        n["probe_message"] = "缺少 OpenVPN 配置文件，无法连接"
                        print(f"[从节点] 节点 {nid} 缺少 config_text，标记为 unavailable", flush=True)

            # 还原当前活跃节点状态
            with lock:
                if active_openvpn_node_id:
                    for n in filtered:
                        n["active"] = (n.get("id") == active_openvpn_node_id)
                write_json(NODES_FILE, filtered)

            available_count = len([n for n in filtered if n.get("probe_status") == "available"])
            msg = f"从共享加载 {len(shared_nodes)} 个节点，过滤后 {len(filtered)} 个，可用 {available_count} 个"
            empty_msg = empty_region_message(available_count, len(filtered))
            if empty_msg:
                msg = f"{msg}；{empty_msg}"
            if force:
                msg = "强制同步完成：" + msg
            print(f"[从节点] {msg}", flush=True)
            log_to_json("INFO", "Main", msg)
            set_state(
                last_check_message=msg,
                last_check_at=time.time(),
                empty_region=bool(empty_msg),
                available_nodes=available_count,
            )

            # 非扫描器已完成读取，释放 is_connecting 锁，允许自动连接
            is_connecting = False

            # 尝试连接最佳节点（如果当前无活跃连接；force 时若已连接则保持）
            if not active_openvpn_running():
                ui_cfg = load_ui_config()
                connection_enabled = ui_cfg.get("connection_enabled", True)
                if connection_enabled and not region_auto_connect_paused():
                    routing_mode = ui_cfg.get("routing_mode", "auto")
                    if routing_mode != "fixed_ip":
                        candidates = [
                            n for n in filtered
                            if n.get("probe_status") == "available"
                            and (n.get("config_text") or Path(str(n.get("config_file") or "")).exists())
                            and not is_node_in_cooldown(str(n.get("id") or ""))
                        ]
                        if not candidates:
                            # 严格模式下 soft_available 默认不存在；若开启非严格可作回退
                            candidates = [
                                n for n in filtered
                                if n.get("probe_status") == "soft_available"
                                and (n.get("config_text") or Path(str(n.get("config_file") or "")).exists())
                                and not is_node_in_cooldown(str(n.get("id") or ""))
                            ]
                        candidates = apply_routing_filters(candidates, ui_cfg)
                        candidates.sort(key=node_preference_key)
                        if not candidates:
                            if empty_msg:
                                set_state(last_check_message=empty_msg, empty_region=True, standby=True)
                            try:
                                maybe_enable_proxy_fallback(filtered, force=True)
                            except Exception:
                                pass
                            # 空区待命：不空转
                            pass
                        tried = 0
                        for next_node in candidates:
                            next_node_id = str(next_node.get("id") or "").strip()
                            if not next_node_id:
                                continue
                            tried += 1
                            try:
                                print(f"[从节点] 尝试自动连接: {next_node_id}", flush=True)
                                connect_node(next_node_id)
                                break
                            except Exception as exc:
                                rate_limited_print(f"autofail:{next_node_id}", f"[从节点] 自动连接 {next_node_id} 失败: {exc}", 30.0)
                                mark_node_connect_failure(next_node_id, str(exc))
                                if tried >= 2:
                                    print("[从节点] 连续失败，进入冷却，等待下一轮", flush=True)
                                    try:
                                        maybe_enable_proxy_fallback(filtered, force=True)
                                    except Exception:
                                        pass
                                    break
                elif region_auto_connect_paused():
                    remain = int(max(0, region_fail_pause_until - time.time()))
                    set_state(last_check_message=f"本区自动连接暂停中（剩余 {remain}s）")

            set_state(
                last_check_at=time.time(),
                last_check_message=msg,
                active_openvpn_node_id=active_openvpn_node_id,
                valid_nodes=available_count,
            )
            return msg

    except Exception as e:
        raise e
    finally:
        is_connecting = False
        maintenance_lock.release()

def _read_shared_generation() -> int:
    try:
        gen_file = Path(SHARED_DATA_DIR) / "shared.generation"
        if gen_file.exists():
            return int((gen_file.read_text(encoding="utf-8") or "0").strip() or "0")
        meta = read_json(SHARED_META_FILE, {})
        return int(meta.get("generation") or meta.get("scanned_at") or 0)
    except Exception:
        return 0


def collector_loop() -> None:
    global last_collector_heartbeat
    backoff = 30
    last_seen_generation = 0
    while True:
        last_collector_heartbeat = time.time()
        success = False
        try:
            if IS_SCANNER:
                print("[扫描器] 开始执行节点拉取与可用性检测周期任务...", flush=True)
                log_to_json("INFO", "Main", "开始执行节点拉取与可用性检测周期任务...")
                res = maintain_valid_nodes(force=False)
            else:
                current_gen = _read_shared_generation()
                need_sync = (
                    current_gen > last_seen_generation
                    or not active_openvpn_running()
                    or last_seen_generation == 0
                )
                if need_sync:
                    print(f"[从节点] 检测到共享更新 generation={current_gen}，立即同步...", flush=True)
                    log_to_json("INFO", "Main", f"共享 generation={current_gen}，开始同步")
                    res = maintain_valid_nodes(force=False)
                    if current_gen > 0:
                        last_seen_generation = current_gen
                else:
                    res = f"共享未变化 generation={current_gen}，跳过同步"
            if "没有拉取到新节点" not in str(res) and "等待扫描器" not in str(res):
                success = True
                backoff = 30
            log_to_json("INFO", "Main", f"周期同步与检测任务完成，结果: {res}")
        except Exception as exc:
            err_msg = f"周期节点同步任务执行异常: {exc}"
            print(f"[错误] {err_msg}", flush=True)
            log_to_json("ERROR", "Main", err_msg)
            set_state(last_check_at=time.time(), last_check_message=f"check error: {exc}")

        if IS_SCANNER:
            if not active_openvpn_running() and not success:
                sleep_time = backoff
                backoff = min(backoff * 2, 600)
            else:
                sleep_time = CHECK_INTERVAL_SECONDS
        else:
            # 从节点：每 20 秒检查 generation；断线时更快
            if not active_openvpn_running():
                sleep_time = min(backoff, 30)
                backoff = min(backoff * 2, 120)
            else:
                sleep_time = 20

        time.sleep(sleep_time)

LOGIN_HTML = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>NimbusVPN - 安全登录</title>
  <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg-dark: #090d16;
      --bg-surface: rgba(15, 23, 42, 0.45);
      --border-color: rgba(255, 255, 255, 0.08);
      --text-primary: #f8fafc;
      --text-secondary: #94a3b8;
      --primary: #6366f1;
      --primary-gradient: linear-gradient(135deg, #6366f1 0%, #4f46e5 100%);
      --primary-hover: linear-gradient(135deg, #4f46e5 0%, #3730a3 100%);
      --success: #10b981;
      --danger: #f43f5e;
    }

    body {
      margin: 0;
      padding: 0;
      font-family: 'Outfit', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background-color: var(--bg-dark);
      background-image: 
        radial-gradient(at 0% 0%, rgba(99, 102, 241, 0.15) 0px, transparent 50%),
        radial-gradient(at 100% 0%, rgba(16, 185, 129, 0.08) 0px, transparent 50%);
      height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      overflow: hidden;
    }

    .login-container {
      width: 100%;
      max-width: 400px;
      padding: 24px;
      box-sizing: border-box;
    }

    .login-card {
      background: var(--bg-surface);
      backdrop-filter: blur(16px);
      -webkit-backdrop-filter: blur(16px);
      border: 1px solid var(--border-color);
      border-radius: 20px;
      padding: 40px 32px;
      box-shadow: 0 20px 40px rgba(0, 0, 0, 0.3);
      text-align: center;
      transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
    }

    .brand-logo {
      width: 64px;
      height: 64px;
      background: rgba(99, 102, 241, 0.1);
      border: 1px solid rgba(99, 102, 241, 0.25);
      border-radius: 16px;
      display: flex;
      align-items: center;
      justify-content: center;
      margin: 0 auto 24px auto;
      color: var(--primary);
      position: relative;
    }

    .brand-logo::after {
      content: '';
      position: absolute;
      width: 100%;
      height: 100%;
      border-radius: 16px;
      border: 1px solid var(--success);
      opacity: 0.5;
      animation: ripple 2s infinite ease-out;
    }

    @keyframes ripple {
      0% { transform: scale(1); opacity: 0.5; }
      100% { transform: scale(1.3); opacity: 0; }
    }

    .login-title {
      font-size: 24px;
      font-weight: 700;
      color: var(--text-primary);
      margin: 0 0 8px 0;
      letter-spacing: 0.5px;
    }

    .login-subtitle {
      font-size: 14px;
      color: var(--text-secondary);
      margin: 0 0 32px 0;
    }

    .form-group {
      margin-bottom: 20px;
      text-align: left;
    }

    .form-label {
      display: block;
      font-size: 13px;
      font-weight: 500;
      color: var(--text-secondary);
      margin-bottom: 8px;
      margin-left: 4px;
    }

    .input-wrapper {
      position: relative;
    }

    .input-field {
      width: 100%;
      height: 48px;
      background: rgba(255, 255, 255, 0.03);
      border: 1px solid var(--border-color);
      border-radius: 10px;
      padding: 0 16px;
      box-sizing: border-box;
      color: var(--text-primary);
      font-family: inherit;
      font-size: 15px;
      outline: none;
      transition: all 0.2s ease;
    }

    .input-field:focus {
      border-color: var(--primary);
      box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.2);
      background: rgba(15, 23, 42, 0.6);
    }

    .error-message {
      color: var(--danger);
      font-size: 13px;
      margin-top: 8px;
      min-height: 18px;
      text-align: left;
      margin-left: 4px;
      display: none;
    }

    .login-btn {
      width: 100%;
      height: 48px;
      background: var(--primary-gradient);
      border: none;
      border-radius: 10px;
      color: white;
      font-family: inherit;
      font-size: 15px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.2s ease;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      box-shadow: 0 4px 12px rgba(99, 102, 241, 0.25);
    }

    .login-btn:hover {
      background: var(--primary-hover);
      transform: translateY(-1px);
      box-shadow: 0 6px 16px rgba(99, 102, 241, 0.35);
    }

    .login-btn:active {
      transform: translateY(1px);
    }

    .login-btn:disabled {
      opacity: 0.6;
      cursor: not-allowed;
      transform: none !important;
    }
  </style>
</head>
<body>
  <div class="login-container">
    <div class="login-card">
      <div class="brand-logo">
        <svg xmlns="http://www.w3.org/2000/svg" width="28" height="28" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
          <path stroke-linecap="round" stroke-linejoin="round" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
        </svg>
      </div>
      <h2 class="login-title">NimbusVPN</h2>
      <p class="login-subtitle">请输入您的管理账号和安全密码以继续</p>
      
      <form id="login_form" onsubmit="handleLogin(event)">
        <div class="form-group">
          <label class="form-label" for="username">管理账号</label>
          <div class="input-wrapper">
            <input type="text" id="username" name="username" class="input-field" placeholder="请输入管理账号" required autocomplete="username">
          </div>
        </div>
        <div class="form-group" style="margin-top: 16px;">
          <label class="form-label" for="password">安全密码</label>
          <div class="input-wrapper">
            <input type="password" id="password" name="password" class="input-field" placeholder="请输入安全密码" required autocomplete="current-password">
          </div>
          <div id="error_text" class="error-message"></div>
        </div>
        
        <button type="submit" id="submit_btn" class="login-btn">
          <span>登录</span>
        </button>
      </form>
    </div>
  </div>

  <script>
    async function handleLogin(e) {
      e.preventDefault();
      const uname = document.getElementById("username").value.trim();
      const pwd = document.getElementById("password").value.trim();
      const errorText = document.getElementById("error_text");
      const submitBtn = document.getElementById("submit_btn");
      
      errorText.style.display = "none";
      submitBtn.disabled = true;
      submitBtn.querySelector("span").textContent = "正在验证...";
      
      try {
        const response = await fetch("./api/login", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username: uname, password: pwd })
        });
        
        const data = await response.json();
        if (response.ok && data.ok) {
          window.location.reload();
        } else {
          errorText.textContent = data.error || "账号或密码不正确，请重新输入";
          errorText.style.display = "block";
          submitBtn.disabled = false;
          submitBtn.querySelector("span").textContent = "登录";
        }
      } catch (err) {
        errorText.textContent = "连接服务器失败，请稍后重试";
        errorText.style.display = "block";
        submitBtn.disabled = false;
        submitBtn.querySelector("span").textContent = "登录";
      }
    }
  </script>
</body>
</html>
"""

INDEX_HTML = r"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>NimbusVPN 节点池管理系统</title>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');
    
    :root {
      --bg-dark: #0b0f19;
      --bg-surface: rgba(22, 30, 49, 0.6);
      --bg-surface-hover: rgba(30, 41, 67, 0.85);
      --border-color: rgba(255, 255, 255, 0.08);
      --border-color-hover: rgba(99, 102, 241, 0.35);
      --text-primary: #f3f4f6;
      --text-secondary: #9ca3af;
      --primary: #6366f1;
      --primary-gradient: linear-gradient(135deg, #6366f1 0%, #4f46e5 100%);
      --primary-hover: linear-gradient(135deg, #4f46e5 0%, #3730a3 100%);
      --success: #10b981;
      --success-gradient: linear-gradient(135deg, #34d399 0%, #059669 100%);
      --danger: #f43f5e;
      --danger-gradient: linear-gradient(135deg, #fb7185 0%, #e11d48 100%);
      --warning: #f59e0b;
      --warning-gradient: linear-gradient(135deg, #fbbf24 0%, #d97706 100%);
      --active-row-bg: rgba(16, 185, 129, 0.06);
      --active-row-border: rgba(16, 185, 129, 0.25);
    }

    body {
      margin: 0;
      font-family: 'Outfit', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background-color: var(--bg-dark);
      background-image: 
        radial-gradient(at 0% 0%, rgba(99, 102, 241, 0.15) 0px, transparent 50%),
        radial-gradient(at 100% 0%, rgba(16, 185, 129, 0.08) 0px, transparent 50%),
        radial-gradient(at 50% 100%, rgba(79, 70, 229, 0.05) 0px, transparent 50%);
      background-attachment: fixed;
      color: var(--text-primary);
      min-height: 100vh;
      -webkit-font-smoothing: antialiased;
    }

    header {
      padding: 16px 32px;
      background: rgba(11, 15, 25, 0.7);
      backdrop-filter: blur(20px);
      -webkit-backdrop-filter: blur(20px);
      border-bottom: 1px solid var(--border-color);
      display: flex;
      justify-content: space-between;
      gap: 16px;
      align-items: center;
      position: sticky;
      top: 0;
      z-index: 100;
    }

    .brand {
      display: flex;
      flex-direction: column;
    }

    h1 {
      font-size: 20px;
      font-weight: 700;
      margin: 0;
      background: linear-gradient(135deg, #a5b4fc 0%, #6366f1 100%);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      letter-spacing: -0.5px;
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .status {
      font-size: 13px;
      color: var(--text-secondary);
      margin-top: 4px;
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .status-dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: var(--success);
      box-shadow: 0 0 10px var(--success);
      display: inline-block;
    }

    .btn-group {
      display: flex;
      gap: 12px;
    }

    button, .btn-telegram {
      height: 38px;
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 0 16px;
      font-weight: 600;
      font-size: 13px;
      cursor: pointer;
      transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 6px;
      background: rgba(255, 255, 255, 0.04);
      color: var(--text-primary);
      white-space: nowrap;
      text-decoration: none;
      box-sizing: border-box;
    }

    button:hover {
      background: rgba(255, 255, 255, 0.08);
      border-color: rgba(255, 255, 255, 0.15);
      transform: translateY(-1px);
    }

    .btn-telegram {
      background: rgba(43, 162, 223, 0.15);
      border: 1px solid rgba(43, 162, 223, 0.3);
      color: #2ba2df;
    }

    .btn-telegram:hover {
      background: rgba(43, 162, 223, 0.25);
      border-color: rgba(43, 162, 223, 0.5);
      color: #2ba2df;
      transform: translateY(-1px);
    }

    .btn-primary {
      background: var(--primary-gradient);
      color: white;
      border: none;
      box-shadow: 0 4px 12px rgba(99, 102, 241, 0.2);
    }

    .btn-primary:hover {
      background: var(--primary-hover);
      box-shadow: 0 6px 16px rgba(99, 102, 241, 0.35);
    }

    .btn-danger {
      background: var(--danger-gradient);
      color: white;
      border: none;
      box-shadow: 0 4px 12px rgba(244, 63, 94, 0.2);
    }

    .btn-danger:hover {
      opacity: 0.95;
      box-shadow: 0 6px 16px rgba(244, 63, 94, 0.35);
    }

    button:disabled {
      opacity: 0.4;
      cursor: not-allowed;
      transform: none !important;
      box-shadow: none !important;
    }

    main {
      padding: 24px 32px;
      max-width: 1400px;
      margin: 0 auto;
    }

    .active-card {
      background: linear-gradient(135deg, rgba(99, 102, 241, 0.12) 0%, rgba(79, 70, 229, 0.04) 100%);
      backdrop-filter: blur(20px);
      -webkit-backdrop-filter: blur(20px);
      border: 1px solid rgba(99, 102, 241, 0.25);
      border-radius: 16px;
      padding: 24px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 24px;
      box-shadow: 0 8px 32px rgba(99, 102, 241, 0.12);
      transition: all 0.3s ease;
      width: 100%;
      box-sizing: border-box;
    }
    
    .active-card-info {
      display: flex;
      align-items: center;
      gap: 20px;
      flex-wrap: wrap;
    }
    
    .active-card-details {
      display: flex;
      flex-direction: column;
      gap: 6px;
    }
    
    .active-card-title {
      font-size: 14px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 1px;
      color: #a5b4fc;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    
    .active-card-value {
      font-size: 24px;
      font-weight: 700;
      color: var(--text-primary);
    }
    
    .active-card-meta {
      display: flex;
      gap: 16px;
      font-size: 13px;
      color: var(--text-secondary);
      flex-wrap: wrap;
    }

    .active-card-meta span strong {
      color: var(--text-primary);
    }

    .stats {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 16px;
      margin-bottom: 24px;
    }

    .stat {
      background: var(--bg-surface);
      backdrop-filter: blur(12px);
      -webkit-backdrop-filter: blur(12px);
      border: 1px solid var(--border-color);
      border-radius: 12px;
      padding: 20px;
      transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
      position: relative;
      overflow: hidden;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }

    .stat:hover {
      background: var(--bg-surface-hover);
      border-color: var(--border-color-hover);
      transform: translateY(-2px);
      box-shadow: 0 8px 24px rgba(99, 102, 241, 0.1);
    }

    .stat-info {
      display: flex;
      flex-direction: column;
    }

    .stat strong {
      font-size: 32px;
      font-weight: 700;
      display: block;
      margin-bottom: 4px;
      background: linear-gradient(135deg, #ffffff 0%, #cbd5e1 100%);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }

    .stat span {
      font-size: 13px;
      color: var(--text-secondary);
      font-weight: 500;
    }

    .stat-icon-wrapper {
      width: 44px;
      height: 44px;
      border-radius: 10px;
      background: rgba(255, 255, 255, 0.04);
      display: flex;
      align-items: center;
      justify-content: center;
      border: 1px solid rgba(255, 255, 255, 0.06);
    }

    .stat-icon {
      width: 22px;
      height: 22px;
      color: var(--primary);
    }

    .stat:nth-child(2) .stat-icon { color: var(--warning); }
    .stat:nth-child(3) .stat-icon { color: var(--success); }

    /* New style additions */
    .header-badge-link {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 4px 10px;
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid var(--border-color);
      border-radius: 6px;
      color: var(--text-secondary);
      text-decoration: none;
      font-size: 12px;
      font-weight: 600;
      transition: all 0.2s ease;
      height: 24px;
      box-sizing: border-box;
    }
    .header-badge-link:hover {
      background: rgba(255, 255, 255, 0.1);
      border-color: var(--border-color-hover);
      color: var(--text-primary);
      transform: translateY(-1px);
    }
    .flex-row-container {
      display: flex;
      gap: 20px;
      flex-wrap: wrap;
      margin-bottom: 24px;
    }
    .flex-row-container > * {
      flex: 1;
      min-width: 320px;
      margin-bottom: 0 !important;
    }
    .vps-recommend-tab {
      position: fixed;
      right: 0;
      top: 50%;
      transform: translateY(-50%);
      width: 38px;
      background: var(--primary-gradient);
      border: 1px solid var(--border-color-hover);
      border-right: none;
      border-radius: 8px 0 0 8px;
      padding: 16px 6px;
      color: white;
      font-weight: 700;
      font-size: 13px;
      line-height: 1.4;
      text-align: center;
      cursor: pointer;
      z-index: 999;
      box-shadow: -4px 0 20px rgba(99, 102, 241, 0.3);
      transition: all 0.3s ease;
      writing-mode: vertical-rl;
      text-orientation: mixed;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 4px;
    }
    .vps-recommend-tab:hover {
      padding-right: 10px;
      box-shadow: -4px 0 25px rgba(99, 102, 241, 0.5);
    }

    .vps-links {
      display: grid;
      grid-template-columns: repeat(2, 1fr);
      gap: 16px;
    }
    
    @media (max-width: 576px) {
      .vps-links {
        grid-template-columns: 1fr;
      }
    }
    
    .vps-item {
      background: rgba(255, 255, 255, 0.02);
      border: 1px solid rgba(255, 255, 255, 0.04);
      border-radius: 12px;
      padding: 20px;
      display: flex;
      flex-direction: column;
      gap: 14px;
      justify-content: space-between;
      transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
      box-shadow: 0 4px 20px rgba(0, 0, 0, 0.15);
    }
    
    .vps-item:hover {
      background: rgba(255, 255, 255, 0.05);
      border-color: rgba(99, 102, 241, 0.3);
      transform: translateY(-2px);
      box-shadow: 0 8px 30px rgba(99, 102, 241, 0.1);
    }
    
    .vps-tag {
      font-size: 11px;
      font-weight: 700;
      padding: 4px 10px;
      border-radius: 6px;
      width: fit-content;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    
    .tag-normal {
      background: rgba(99, 102, 241, 0.15);
      color: #a5b4fc;
      border: 1px solid rgba(99, 102, 241, 0.2);
    }
    
    .tag-premium {
      background: rgba(16, 185, 129, 0.15);
      color: #6ee7b7;
      border: 1px solid rgba(16, 185, 129, 0.2);
    }
    
    .vps-desc {
      font-size: 13px;
      color: var(--text-secondary);
      line-height: 1.6;
      flex: 1;
    }
    
    .vps-btn {
      align-self: stretch;
      text-decoration: none;
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid rgba(255, 255, 255, 0.08);
      color: var(--text-primary);
      font-size: 12px;
      font-weight: 600;
      padding: 8px 16px;
      border-radius: 8px;
      transition: all 0.2s ease;
      text-align: center;
    }
    
    .vps-item:hover .vps-btn {
      background: var(--primary-gradient);
      border-color: transparent;
      color: white;
      box-shadow: 0 4px 10px rgba(99, 102, 241, 0.2);
    }
    
    .vps-footer {
      border-top: 1px dashed rgba(255, 255, 255, 0.08);
      padding-top: 12px;
      font-size: 13px;
      color: var(--text-secondary);
      text-align: center;
    }
    
    .forum-link {
      color: #818cf8;
      font-weight: 700;
      text-decoration: none;
      transition: color 0.2s ease;
    }
    
    .forum-link:hover {
      color: #a5b4fc;
      text-decoration: underline;
    }

    .toolbar {
      background: var(--bg-surface);
      backdrop-filter: blur(12px);
      -webkit-backdrop-filter: blur(12px);
      border: 1px solid var(--border-color);
      border-radius: 12px;
      padding: 16px;
      margin-bottom: 24px;
      display: flex;
      gap: 16px;
      flex-wrap: wrap;
      align-items: center;
    }

    .toolbar select {
      width: 180px;
      height: 42px;
      background: rgba(255, 255, 255, 0.03);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 0 12px;
      color: var(--text-primary);
      font-family: inherit;
      font-size: 14px;
      outline: none;
      transition: all 0.2s ease;
      cursor: pointer;
    }

    .toolbar select:focus {
      border-color: var(--primary);
      box-shadow: 0 0 0 2px rgba(99, 102, 241, 0.2);
      background: #0f172a;
    }

    .toolbar input {
      flex: 1;
      min-width: 250px;
      height: 42px;
      background: rgba(255, 255, 255, 0.03);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 0 16px;
      color: var(--text-primary);
      font-family: inherit;
      font-size: 14px;
      transition: all 0.2s ease;
    }

    .toolbar input:focus {
      outline: none;
      border-color: var(--primary);
      box-shadow: 0 0 0 2px rgba(99, 102, 241, 0.2);
      background: rgba(15, 23, 42, 0.8);
    }

    .table-wrapper {
      background: var(--bg-surface);
      backdrop-filter: blur(12px);
      -webkit-backdrop-filter: blur(12px);
      border: 1px solid var(--border-color);
      border-radius: 16px;
      overflow: hidden;
      box-shadow: 0 8px 32px rgba(0, 0, 0, 0.2);
    }

    .table-container {
      overflow-x: auto;
    }

    table {
      width: 100%;
      border-collapse: collapse;
      text-align: left;
      table-layout: fixed;
    }

    th, td {
      padding: 14px 20px;
      border-bottom: 1px solid var(--border-color);
      font-size: 14px;
    }

    th {
      background: rgba(17, 24, 39, 0.4);
      font-size: 12px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.8px;
      color: var(--text-secondary);
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }

    tr {
      transition: background 0.2s ease;
    }

    tr:hover {
      background: rgba(255, 255, 255, 0.015);
    }

    .active-row {
      background: var(--active-row-bg) !important;
      outline: 2px solid var(--success) !important;
      outline-offset: -2px;
      position: relative;
      z-index: 5;
    }

    .active-row td {
      border-bottom: 1px solid var(--active-row-border);
      border-top: 1px solid var(--active-row-border);
    }

    .badge {
      padding: 4px 10px;
      border-radius: 6px;
      font-size: 12px;
      font-weight: 600;
      display: inline-flex;
      align-items: center;
      gap: 6px;
      border: 1px solid transparent;
    }

    .badge-pulse {
      width: 6px;
      height: 6px;
      border-radius: 50%;
      background: currentColor;
      animation: pulse 1.5s infinite;
      display: inline-block;
    }

    @keyframes pulse {
      0% { transform: scale(0.9); opacity: 1; }
      50% { transform: scale(1.6); opacity: 0.4; }
      100% { transform: scale(0.9); opacity: 1; }
    }

    @keyframes spin {
      from { transform: rotate(0deg); }
      to { transform: rotate(360deg); }
    }

    .available {
      background: rgba(16, 185, 129, 0.1);
      color: #34d399;
      border-color: rgba(16, 185, 129, 0.2);
    }

    .unavailable {
      background: rgba(244, 63, 94, 0.1);
      color: #fb7185;
      border-color: rgba(244, 63, 94, 0.2);
    }

    .not_checked {
      background: rgba(245, 158, 11, 0.1);
      color: #fbbf24;
      border-color: rgba(245, 158, 11, 0.2);
    }

    .current-badge {
      background: rgba(99, 102, 241, 0.15);
      color: #818cf8;
      border-color: rgba(99, 102, 241, 0.3);
    }

    .table-actions {
      display: flex;
      gap: 8px;
    }

    .connect-btn {
      background: transparent;
      color: #818cf8;
      border: 1px solid rgba(99, 102, 241, 0.4);
      border-radius: 6px;
      padding: 0 12px;
      height: 30px;
      font-size: 12px;
      font-weight: 600;
      transition: all 0.2s ease;
      cursor: pointer;
    }

    .connect-btn:hover:not(:disabled) {
      background: var(--primary-gradient);
      color: white;
      border-color: transparent;
      box-shadow: 0 4px 10px rgba(99, 102, 241, 0.3);
    }

    .connect-btn:disabled {
      opacity: 0.3;
      cursor: not-allowed;
    }

    .test-btn {
      background: transparent;
      color: #34d399;
      border: 1px solid rgba(16, 185, 129, 0.4);
      border-radius: 6px;
      padding: 0 12px;
      height: 30px;
      font-size: 12px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.2s ease;
    }

    .test-btn:hover:not(:disabled) {
      background: var(--success-gradient);
      color: white;
      border-color: transparent;
      box-shadow: 0 4px 10px rgba(16, 185, 129, 0.3);
    }

    .test-btn:disabled {
      opacity: 0.4;
      cursor: not-allowed;
    }

    .mono {
      font-family: 'JetBrains Mono', Consolas, monospace;
      font-size: 13px;
      color: #e2e8f0;
    }

    .latency-val {
      font-weight: 600;
      padding: 2px 6px;
      border-radius: 4px;
      font-size: 12px;
    }

    .latency-good {
      background: rgba(16, 185, 129, 0.1);
      color: #34d399;
    }
    
    .latency-medium {
      background: rgba(245, 158, 11, 0.1);
      color: #fbbf24;
    }
    
    .latency-poor {
      background: rgba(244, 63, 94, 0.1);
      color: #fb7185;
    }

    @media (max-width: 768px) {
      header {
        flex-direction: column;
        align-items: flex-start;
        padding: 16px 20px;
      }
      .btn-group {
        width: 100%;
        margin-top: 12px;
      }
      .btn-group button, .btn-group .btn-telegram {
        flex: 1;
      }
      .btn-group .dropdown {
        flex: 1;
        display: flex;
      }
      .btn-group .dropdown button {
        width: 100%;
        flex: 1;
      }
      main {
        padding: 16px 20px;
      }
      .active-card {
        flex-direction: column;
        align-items: flex-start;
        gap: 16px;
      }
      .active-card button {
        width: 100%;
      }
    }
    
    /* Admin dropdown styles */
    .dropdown {
      position: relative;
      display: inline-block;
    }
    .dropdown-content {
      display: none;
      position: absolute;
      right: 0;
      margin-top: 6px;
      min-width: 140px;
      background: rgba(22, 30, 49, 0.95);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      box-shadow: 0 10px 25px rgba(0,0,0,0.5);
      z-index: 1000;
      overflow: hidden;
      backdrop-filter: blur(10px);
      -webkit-backdrop-filter: blur(10px);
    }
    .dropdown-content a {
      display: flex;
      align-items: center;
      gap: 8px;
      padding: 10px 16px;
      color: var(--text-primary);
      text-decoration: none;
      font-size: 13px;
      font-weight: 500;
      transition: background 0.2s;
    }
    .dropdown-content a:hover {
      background: rgba(255,255,255,0.08);
    }
    
    /* Modal styles */
    .modal {
      display: none;
      position: fixed;
      z-index: 10000;
      left: 0;
      top: 0;
      width: 100%;
      height: 100%;
      overflow: auto;
      background-color: rgba(9, 13, 22, 0.7);
      backdrop-filter: blur(8px);
      -webkit-backdrop-filter: blur(8px);
      align-items: center;
      justify-content: center;
    }
    .modal-content {
      background: rgba(22, 30, 49, 0.9);
      border: 1px solid var(--border-color);
      border-radius: 20px;
      width: 90%;
      max-width: 480px;
      padding: 32px;
      box-shadow: 0 20px 50px rgba(0, 0, 0, 0.5);
      position: relative;
      box-sizing: border-box;
      animation: modalFadeIn 0.3s cubic-bezier(0.4, 0, 0.2, 1);
    }
    @keyframes modalFadeIn {
      from { transform: scale(0.95); opacity: 0; }
      to { transform: scale(1); opacity: 1; }
    }
    
    /* Inputs in settings */
    .form-group {
      margin-bottom: 20px;
      text-align: left;
    }
    .form-label {
      display: block;
      font-size: 13px;
      font-weight: 500;
      color: var(--text-secondary);
      margin-bottom: 8px;
      margin-left: 4px;
    }
    .input-field {
      width: 100%;
      height: 40px;
      background: rgba(255, 255, 255, 0.03);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 0 12px;
      box-sizing: border-box;
      color: var(--text-primary);
      font-family: inherit;
      font-size: 14px;
      outline: none;
      transition: all 0.2s ease;
    }
    .input-field:focus {
      border-color: var(--primary);
      box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.2);
      background: rgba(15, 23, 42, 0.6);
    }
    select option {
      background-color: #0f172a;
      color: #f8fafc;
    }
    
    /* Option Card Styles for Proxy/Routing Settings */
    .option-group {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 10px;
      margin-top: 6px;
    }
    
    @media (max-width: 480px) {
      .option-group {
        grid-template-columns: 1fr;
      }
    }
    
    .option-card {
      background: rgba(255, 255, 255, 0.02);
      border: 1px solid var(--border-color);
      border-radius: 10px;
      padding: 12px 14px;
      cursor: pointer;
      transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
      user-select: none;
      position: relative;
      text-align: left;
    }
    
    .option-card:hover {
      background: rgba(255, 255, 255, 0.05);
      border-color: rgba(99, 102, 241, 0.25);
      transform: translateY(-1px);
    }
    
    .option-card.active {
      background: rgba(99, 102, 241, 0.08);
      border-color: var(--primary);
      box-shadow: 0 0 12px rgba(99, 102, 241, 0.15);
    }
    
    .option-card-title {
      font-size: 13px;
      font-weight: 600;
      color: var(--text-primary);
      margin-bottom: 4px;
    }
    
    .option-card-desc {
      font-size: 11px;
      color: var(--text-secondary);
      line-height: 1.3;
    }
  </style>
</head>
<body>
<header>
  <div class="brand">
    <h1>
      <svg xmlns="http://www.w3.org/2000/svg" style="width:24px; height:24px; color:#818cf8;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" /></svg>
      NimbusVPN 节点管理系统
    </h1>
    <div id="status" class="status" style="display: none;"><span class="status-dot"></span>服务加载中...</div>
  </div>
  <div class="btn-group">

    <div class="dropdown">
      <button id="github_btn" class="btn-primary" style="background: rgba(255, 255, 255, 0.08); border: 1px solid var(--border-color); color: var(--text-primary);">
        <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" fill="currentColor" viewBox="0 0 16 16" style="vertical-align: middle; margin-right: 4px;"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.012 8.012 0 0 0 16 8c0-4.42-3.58-8-8-8z"/></svg>
        GITHUB
        <svg xmlns="http://www.w3.org/2000/svg" style="width:12px; height:12px; margin-left: 2px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="3"><path stroke-linecap="round" stroke-linejoin="round" d="M19 9l-7 7-7-7" /></svg>
      </button>
      <div id="github_dropdown" class="dropdown-content">
        <a href="https://github.com/nimbus-vpngate" target="_blank">正式版</a>
        <a href="https://github.com/nimbus-vpngate/tree/bate" target="_blank">测试版</a>
      </div>
    </div>
    <a href="https://t.me/arestemple" target="_blank" class="btn-telegram">
      <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" fill="currentColor" viewBox="0 0 16 16" style="vertical-align: middle; margin-right: 4px;"><path d="M16 8A8 8 0 1 1 0 8a8 8 0 0 1 16 0zM8.287 5.906c-.778.324-2.334.994-4.666 2.01-.378.15-.577.298-.595.442-.03.243.275.339.69.47l.175.055c.408.133.958.288 1.243.294.26.006.549-.1.868-.32 2.179-1.471 3.304-2.214 3.374-2.23.05-.012.12-.026.166.016.047.041.042.12.037.141-.03.129-1.227 1.241-1.846 1.817-.193.18-.33.307-.358.336-.063.065-.129.13-.19.193-.34.347-.597.609-.043.974.265.175.474.319.684.457.228.15.457.301.765.503.074.049.143.098.207.143.297.206.58.404.916.373.195-.018.398-.2.502-.754.25-1.332.74-4.22.842-5.281.01-.088.001-.22-.103-.312-.104-.092-.252-.09-.323-.087a1.52 1.52 0 0 0-.254.04z"/></svg>
      Telegram
    </a>
    <button id="refresh" class="btn-primary" style="background: var(--success-gradient);">
      <svg xmlns="http://www.w3.org/2000/svg" style="width:16px; height:16px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 1121.21 8H18.5" /></svg>
      更新节点
    </button>
    <div class="dropdown">
      <button id="admin_btn" class="btn-primary" style="background: rgba(255, 255, 255, 0.08); border: 1px solid var(--border-color); color: var(--text-primary);">
        <svg xmlns="http://www.w3.org/2000/svg" style="width:16px; height:16px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" /></svg>
        管理员
        <svg xmlns="http://www.w3.org/2000/svg" style="width:12px; height:12px; margin-left: 2px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="3"><path stroke-linecap="round" stroke-linejoin="round" d="M19 9l-7 7-7-7" /></svg>
      </button>
      <div id="admin_dropdown" class="dropdown-content">
        <a href="javascript:void(0)" onclick="openCredentialsModal()">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:14px; height:14px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" /></svg>
          网页安全
        </a>
        <a href="javascript:void(0)" onclick="openNetworkModal()">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:14px; height:14px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" /><path stroke-linecap="round" stroke-linejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" /></svg>
          代理设置
        </a>
        <a href="javascript:void(0)" onclick="openGatewayModal()">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:14px; height:14px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" /></svg>
          网关设置
        </a>
        <a href="javascript:void(0)" onclick="openLogsModal()">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:14px; height:14px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" /></svg>
          日志
        </a>
        <a href="javascript:void(0)" onclick="logoutAdmin()" style="color: var(--danger); border-top: 1px solid rgba(255,255,255,0.05);">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:14px; height:14px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" /></svg>
          退出
        </a>
      </div>
    </div>
  </div>
</header>
<main>
  
    <!-- 当前连接活动节点卡片 -->
    <section class="active-node-section" id="active_node_card" style="margin-bottom: 24px;">
      <!-- Rendered dynamically by render() -->
    </section>



  <section class="toolbar">
    <select id="status_filter">
      <option value="all">全部节点</option>
      <option value="available">可用节点</option>
      <option value="unavailable">失效节点</option>
    </select>
    <select id="country_filter">
      <option value="">所有国家</option>
    </select>
    <select id="ip_type_filter">
      <option value="">所有IP类型</option>
      <option value="residential">住宅IP</option>
      <option value="hosting">机房IP</option>
    </select>
    <button id="btn_favorites" class="toolbar-btn" type="button" onclick="toggleFavoritesView()" style="margin-left: auto; height: 42px; gap: 6px;">
      <svg xmlns="http://www.w3.org/2000/svg" style="width:16px; height:16px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
        <path stroke-linecap="round" stroke-linejoin="round" d="M11.049 2.927c.3-.921 1.603-.921 1.902 0l1.519 4.674a1 1 0 00.95.69h4.907c.961 0 1.371 1.24.588 1.81l-3.97 2.883a1 1 0 00-.364 1.118l1.518 4.674c.3.922-.755 1.688-1.538 1.118l-3.971-2.883a1 1 0 00-1.175 0l-3.97 2.883c-.783.57-1.838-.197-1.538-1.118l1.518-4.674a1 1 0 00-.364-1.118l-3.97-2.883c-.783-.57-.372-1.81.588-1.81h4.906a1 1 0 00.951-.69l1.519-4.674z" />
      </svg>
      收藏菜单
    </button>
  </section>
  <div id="favorites_panel" style="display: none; background: rgba(22, 30, 49, 0.85); backdrop-filter: blur(10px); -webkit-backdrop-filter: blur(10px); border: 1px solid var(--border-color); border-radius: 16px; padding: 20px; margin-bottom: 20px; animation: modalFadeIn 0.25s ease-out;">
    <div style="display: flex; flex-direction: column; gap: 16px;">
      <div style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 16px;">
        <div style="display: flex; flex-direction: column; gap: 4px;">
          <span style="font-size: 15px; font-weight: 600; color: var(--text-primary); display: flex; align-items: center; gap: 6px;">
            ⭐ 收藏专属管理面板
          </span>
          <span style="font-size: 13px; color: var(--text-secondary);">
            在这里管理您的收藏节点过滤，以及设置出站连接漂移策略。
          </span>
        </div>
        <div style="display: flex; gap: 12px; align-items: center;">
          <button id="btn_toggle_fav_routing" type="button" class="toolbar-btn" style="height: 36px; padding: 0 14px; font-size: 13px; border-radius: 6px;" onclick="toggleFavRouting()">
            启用仅用收藏出站
          </button>
        </div>
      </div>
      
      <div style="border-top: 1px solid rgba(255,255,255,0.06); padding-top: 16px;">
        <label style="display: flex; align-items: flex-start; gap: 10px; cursor: pointer; user-select: none;">
          <input type="checkbox" id="fav_fail_fallback_checkbox" style="margin-top: 3px; cursor: pointer;" onchange="handleFavFallbackChange(this.checked)" checked />
          <div style="display: flex; flex-direction: column; gap: 2px;">
            <span style="font-size: 14px; font-weight: 500; color: var(--text-primary);">收藏节点失效后自动切换其他（非收藏）可用节点</span>
            <span style="font-size: 12px; color: var(--text-secondary);">勾选此项，当所有收藏节点不可用时，系统将自动使用其他最快的非收藏可用节点，保障网络连接不中断。</span>
          </div>
        </label>
        <div id="fav_fallback_warning" style="display: none; margin-top: 12px; padding: 10px 14px; background: rgba(244, 63, 94, 0.1); border: 1px solid rgba(244, 63, 94, 0.25); border-radius: 8px; font-size: 12px; color: var(--danger); line-height: 1.4; animation: modalFadeIn 0.2s ease-out;">
          ⚠️ <strong>警告</strong>：您已取消勾选此项。如果当前收藏的节点均不可用，系统将<strong>无法切换</strong>到其他可用节点，可能导致网络<strong>彻底断开连接</strong>！
        </div>
      </div>
    </div>
  </div>

  <div class="table-wrapper">
    <div class="table-container">
      <table>
        <thead>
          <tr>
            <th style="width: 90px;">状态</th>
            <th style="width: 220px;">IP 地址 : 端口</th>
            <th>物理位置</th>
            <th>运营主体 / ISP</th>
            <th style="width: 110px;">IP 类型</th>
            <th style="width: 180px;">操作</th>
          </tr>
        </thead>
        <tbody id="rows"></tbody>
      </table>
    </div>
    
    <!-- 分页控制栏 -->
    <div class="pagination-container" style="padding: 16px; display: none; justify-content: space-between; align-items: center; border-top: 1px solid var(--border-color); flex-wrap: wrap; gap: 12px;">
      <div style="font-size: 13px; color: var(--text-secondary);">
        显示第 <span id="page_start" style="color: var(--text-primary); font-weight:600;">0</span> - <span id="page_end" style="color: var(--text-primary); font-weight:600;">0</span> 条，共 <span id="filtered_count" style="color: var(--text-primary); font-weight:600;">0</span> 条备选节点
      </div>
      <div style="display: flex; gap: 8px; align-items: center;">
        <button id="btn_first_page" class="connect-btn" style="height: 32px; padding: 0 10px;">首页</button>
        <button id="btn_prev_page" class="connect-btn" style="height: 32px; padding: 0 10px;">上一页</button>
        <span style="font-size: 13px; color: var(--text-secondary); margin: 0 8px;">
          页码 <strong id="current_page_val" style="color: var(--primary);">1</strong> / <strong id="total_pages_val">1</strong>
        </span>
        <button id="btn_next_page" class="connect-btn" style="height: 32px; padding: 0 10px;">下一页</button>
        <button id="btn_last_page" class="connect-btn" style="height: 32px; padding: 0 10px;">尾页</button>
      </div>
    </div>
  </div>

  <!-- Credentials Modal (网页安全设置) -->
  <div id="credentials_modal" class="modal">
    <div class="modal-content">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px;">
        <h3 style="margin: 0; font-size: 18px; font-weight: 700; color: var(--text-primary); display: flex; align-items: center; gap: 8px;">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:20px; height:20px; color: var(--primary);" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" /></svg>
          网页安全
        </h3>
        <button type="button" onclick="closeCredentialsModal()" style="background: transparent; border: none; padding: 4px; cursor: pointer; color: var(--text-secondary); width: 28px; height: 28px; display: flex; align-items: center; justify-content: center; border-radius: 50%;" onmouseover="this.style.background='rgba(255,255,255,0.05)'" onmouseout="this.style.background='transparent'">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:18px; height:18px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" /></svg>
        </button>
      </div>
      
      <div id="credentials_error" style="color: var(--danger); font-size: 13px; margin-bottom: 16px; padding: 8px 12px; background: rgba(244,63,94,0.1); border: 1px solid rgba(244,63,94,0.2); border-radius: 6px; display: none;"></div>
      <div id="credentials_success" style="color: var(--success); font-size: 13px; margin-bottom: 16px; padding: 8px 12px; background: rgba(16,185,129,0.1); border: 1px solid rgba(16,185,129,0.2); border-radius: 6px; display: none;"></div>

      <form id="credentials_form" onsubmit="saveCredentials(event)">
        <div class="form-group" style="margin-bottom: 12px;">
          <label class="form-label" for="cred_username">管理账号</label>
          <input type="text" id="cred_username" class="input-field" required placeholder="请输入管理账号">
        </div>
        
        <div class="form-group" style="margin-bottom: 12px;">
          <label class="form-label" for="cred_password">安全密码</label>
          <input type="password" id="cred_password" class="input-field" placeholder="留空则保留当前密码">
        </div>

        <div class="form-group" style="margin-bottom: 12px;">
          <label class="form-label" for="cred_port">网页管理端口</label>
          <input type="number" id="cred_port" class="input-field" required min="1" max="65535" placeholder="8787">
        </div>
        
        <div class="form-group" style="margin-bottom: 20px;">
          <label class="form-label" for="cred_suffix">登录安全后缀 (仅字母和数字)</label>
          <input type="text" id="cred_suffix" class="input-field" required pattern="[A-Za-z0-9]+" placeholder="EJsW2EeBo9lY">
        </div>
        
        <div style="display: flex; gap: 12px; justify-content: flex-end;">
          <button type="button" onclick="closeCredentialsModal()" style="height: 40px; padding: 0 16px; font-weight: 600; border-radius: 8px; border: 1px solid var(--border-color); background: transparent; color: var(--text-secondary); cursor: pointer;">取消</button>
          <button type="submit" id="credentials_submit_btn" class="btn-primary" style="height: 40px; padding: 0 20px; font-weight: 600; border-radius: 8px;">保存修改</button>
        </div>
      </form>
    </div>
  </div>

  <!-- Network Modal (代理及网络设置，包括出站路由) -->
  <div id="network_modal" class="modal">
    <div class="modal-content" style="max-width: 480px;">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px;">
        <h3 style="margin: 0; font-size: 18px; font-weight: 700; color: var(--text-primary); display: flex; align-items: center; gap: 8px;">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:20px; height:20px; color: var(--primary);" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" /><path stroke-linecap="round" stroke-linejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" /></svg>
          代理设置
        </h3>
        <button type="button" onclick="closeNetworkModal()" style="background: transparent; border: none; padding: 4px; cursor: pointer; color: var(--text-secondary); width: 28px; height: 28px; display: flex; align-items: center; justify-content: center; border-radius: 50%;" onmouseover="this.style.background='rgba(255,255,255,0.05)'" onmouseout="this.style.background='transparent'">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:18px; height:18px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" /></svg>
        </button>
      </div>
      
      <div id="network_error" style="color: var(--danger); font-size: 13px; margin-bottom: 16px; padding: 8px 12px; background: rgba(244,63,94,0.1); border: 1px solid rgba(244,63,94,0.2); border-radius: 6px; display: none;"></div>
      <div id="network_success" style="color: var(--success); font-size: 13px; margin-bottom: 16px; padding: 8px 12px; background: rgba(16,185,129,0.1); border: 1px solid rgba(16,185,129,0.2); border-radius: 6px; display: none;"></div>

      <form id="network_form" onsubmit="saveNetwork(event)">
        <div class="form-group" style="margin-bottom: 16px;">
          <label class="form-label" for="net_proxy_port">HTTP/SOCKS5 代理出站端口</label>
          <input type="number" id="net_proxy_port" class="input-field" required min="1024" max="65535" placeholder="7928">
        </div>

        <div style="border-top: 1px dashed rgba(255,255,255,0.08); padding-top: 16px; margin-bottom: 16px;">
          <div class="form-group" style="margin-bottom: 16px;">
            <label class="form-label">IP 出站路由模式</label>
            <input type="hidden" id="net_routing_mode" value="auto">
            <div class="option-group" id="routing_mode_group">
              <div class="option-card active" data-value="auto" onclick="setRoutingMode('auto')">
                <div class="option-card-title">自动配置</div>
                <div class="option-card-desc">智能切换，最稳定</div>
              </div>
              <div class="option-card" data-value="fixed_ip" onclick="setRoutingMode('fixed_ip')">
                <div class="option-card-title">固定 IP</div>
                <div class="option-card-desc">锁定IP，不自动切换</div>
              </div>
              <div class="option-card" data-value="fixed_region" onclick="setRoutingMode('fixed_region')">
                <div class="option-card-title">固定地区</div>
                <div class="option-card-desc">锁定特定国家地区</div>
              </div>
            </div>
          </div>
          
          <div id="net_force_country_group" class="form-group" style="margin-bottom: 16px; display: none;">
            <label class="form-label" for="net_force_country">锁定国家地区</label>
            <select id="net_force_country" class="input-field" style="background: rgba(255, 255, 255, 0.03); border: 1px solid var(--border-color); color: var(--text-primary); outline: none; cursor: pointer; width: 100%; height: 40px; border-radius: 8px; padding: 0 12px;">
              <option value="">正在加载节点国家...</option>
            </select>
          </div>
          
          <div class="form-group" style="margin-bottom: 16px;">
            <label class="form-label">IP 出站类型过滤</label>
            <input type="hidden" id="net_routing_ip_type" value="all">
            <div class="option-group" id="routing_ip_type_group">
              <div class="option-card active" data-value="all" onclick="setRoutingIpType('all')">
                <div class="option-card-title">所有IP</div>
                <div class="option-card-desc">机房 + 住宅</div>
              </div>
              <div class="option-card" data-value="residential" onclick="setRoutingIpType('residential')">
                <div class="option-card-title">住宅IP</div>
                <div class="option-card-desc">静态家宽</div>
              </div>
              <div class="option-card" data-value="hosting" onclick="setRoutingIpType('hosting')">
                <div class="option-card-title">机房IP</div>
                <div class="option-card-desc">普通机房</div>
              </div>
            </div>
          </div>
          
          <div id="net_routing_warning" style="font-size: 12px; color: var(--text-secondary); line-height: 1.4; padding: 8px 12px; background: rgba(255, 255, 255, 0.02); border: 1px solid rgba(255, 255, 255, 0.05); border-radius: 6px; margin-top: 8px;">
            ℹ️ <strong>自动配置</strong>：全自动测试并选择最佳IP。在使用过程中，如果当前连接节点没有失效，将不再更换IP；如果当前节点失效，系统将立刻秒级自动漂移到其他最快的可用节点。
          </div>
        </div>
        
        <div style="display: flex; gap: 12px; justify-content: flex-end;">
          <button type="button" onclick="closeNetworkModal()" style="height: 40px; padding: 0 16px; font-weight: 600; border-radius: 8px; border: 1px solid var(--border-color); background: transparent; color: var(--text-secondary); cursor: pointer;">取消</button>
          <button type="submit" id="network_submit_btn" class="btn-primary" style="height: 40px; padding: 0 20px; font-weight: 600; border-radius: 8px;">保存修改</button>
        </div>
      </form>
    </div>
  </div>


  <!-- VPS 购买推荐 Modal -->
  <div id="vps_recommend_modal" class="modal">
    <div class="modal-content" style="max-width: 640px;">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px;">
        <h3 style="margin: 0; font-size: 18px; font-weight: 700; color: var(--text-primary); display: flex; align-items: center; gap: 8px;">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:20px; height:20px; color: var(--warning);" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9.663 17h4.673M12 3v1m6.364.364l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" /></svg>
          VPS 购买推荐
        </h3>
        <button type="button" onclick="closeVpsModal()" style="background: transparent; border: none; padding: 4px; cursor: pointer; color: var(--text-secondary); width: 28px; height: 28px; display: flex; align-items: center; justify-content: center; border-radius: 50%;" onmouseover="this.style.background='rgba(255,255,255,0.05)'" onmouseout="this.style.background='transparent'">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:18px; height:18px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" /></svg>
        </button>
      </div>
      
      <div class="vps-links">
        <div class="vps-item">
          <span class="vps-tag tag-normal">RNVPS (RackNerd) 推荐</span>
          <span class="vps-desc">超低折扣价格，性价比极高，日常使用实惠方便，海外多机房可选，非常适合普通大众用户。</span>
          <a href="https://my.racknerd.com/aff.php?aff=18708" target="_blank" class="vps-btn">点击进入官网</a>
        </div>
        <div class="vps-item">
          <span class="vps-tag tag-premium">搬瓦工 (Bandwagon) 推荐</span>
          <span class="vps-desc">直连三网顶级专线，经典高带宽 CN2 GIA/9929 优化线路，极致速度且超凡稳定，高端用户首选。</span>
          <a href="https://bandwagonhost.com/aff.php?aff=81790" target="_blank" class="vps-btn">点击进入官网</a>
        </div>
      </div>
      
      <div class="vps-footer" style="margin-top: 20px;">
        官方技术支持及优质资源交流论坛：<a href="https://339936.xyz" target="_blank" class="forum-link">339936.xyz</a>
      </div>

      <div class="vps-footer" style="margin-top: 16px; border-top: 1px solid rgba(255,255,255,0.06); padding-top: 16px; text-align: left; font-size: 13px; color: var(--text-secondary); line-height: 1.6;">
        <div style="font-weight: bold; color: var(--text-primary); margin-bottom: 4px; display: flex; align-items: center; gap: 6px;">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:16px; height:16px; color: var(--primary);" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M12 8c-1.657 0-3 .895-3 2s1.343 2 3 2 3 .895 3 2-1.343 2-3 2m0-8c1.11 0 2.08.402 2.599 1M12 8V7m0 1v8m0 0v1m0-1c-1.11 0-2.08-.402-2.599-1M21 12a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
          🎁 捐赠支持项目开发：
        </div>
        <div style="font-family: monospace; background: rgba(0,0,0,0.2); padding: 8px 12px; border-radius: 6px; margin-top: 6px; word-break: break-all; select-all: true;">
          <span style="color: var(--primary); font-weight: bold;">BNB (BSC):</span> 0xB6d78c42CEB0687A31B8cfEBE4b51b6eB8953C17<br>
          <span style="color: var(--primary); font-weight: bold;">TRX (TRC20):</span> TSdzCW6JvsrqcppodYjhSrku4mYmDJ9pxf
        </div>
      </div>
    </div>
  </div>

  <div class="vps-recommend-tab" onclick="openVpsModal()">VPS购买推荐</div>

  <!-- Gateway Modal (网关自检与代理测试) -->
  <div id="gateway_modal" class="modal">
    <div class="modal-content" style="max-width: 600px; width: 90%;">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
        <h3 style="margin: 0; font-size: 18px; font-weight: 700; color: var(--text-primary); display: flex; align-items: center; gap: 8px;">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:20px; height:20px; color: var(--primary);" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" /></svg>
          网关设置与自检
        </h3>
        <button type="button" onclick="closeGatewayModal()" style="background: transparent; border: none; padding: 4px; cursor: pointer; color: var(--text-secondary); width: 28px; height: 28px; display: flex; align-items: center; justify-content: center; border-radius: 50%;" onmouseover="this.style.background='rgba(255,255,255,0.05)'" onmouseout="this.style.background='transparent'">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:18px; height:18px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" /></svg>
        </button>
      </div>

      <!-- 服务列表 -->
      <div id="gateway_services_list" style="display: flex; flex-direction: column; gap: 12px; margin-bottom: 24px;">
        <div style="text-align: center; color: var(--text-secondary); padding: 20px 0;">
          <svg style="animation: spin 1s linear infinite; width: 20px; height: 20px; display: inline-block; margin-bottom: 8px;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><circle cx="12" cy="12" r="10" stroke="currentColor" stroke-opacity="0.2" fill="none"></circle><path d="M4 12a8 8 0 018-8" stroke="currentColor" fill="none"></path></svg>
          <div>正在加载系统网关状态...</div>
        </div>
      </div>

      <!-- 分割线 -->
      <div style="border-top: 1px dashed rgba(255, 255, 255, 0.08); margin: 20px 0;"></div>

      <!-- 本地代理出口检测 -->
      <div style="background: rgba(255, 255, 255, 0.02); border: 1px solid var(--border-color); border-radius: 12px; padding: 16px;">
        <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 12px;">
          <div class="stat-icon-wrapper" style="background: rgba(99, 102, 241, 0.1); border-color: rgba(99, 102, 241, 0.2); width: 36px; height: 36px; border-radius: 8px; flex-shrink: 0;">
            <svg xmlns="http://www.w3.org/2000/svg" class="stat-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2" style="color: var(--primary); width: 18px; height: 18px;"><path stroke-linecap="round" stroke-linejoin="round" d="M8.111 16.404a5.5 5.5 0 017.778 0M12 20h.01m-7.08-7.071a10.5 10.5 0 0114.14 0M1.414 8.05a16 16 0 0121.172 0" /></svg>
          </div>
          <div>
            <h4 style="margin: 0; font-size: 14px; font-weight: 600; color: var(--text-primary);">本地代理出口检测</h4>
            <p style="margin: 2px 0 0 0; font-size: 12px; color: var(--text-secondary);">检测 HTTP/SOCKS5 代理出站连通性与 IP</p>
          </div>
        </div>
        
        <div style="display: flex; justify-content: space-between; align-items: center; background: rgba(0, 0, 0, 0.2); border-radius: 8px; padding: 12px; margin-bottom: 12px; flex-wrap: wrap; gap: 10px;">
          <div style="font-size: 13px; color: var(--text-secondary);">
            测试状态: <span id="proxy_status_badge" class="badge not_checked" style="margin-left: 4px;">未检测</span>
          </div>
          <div style="font-size: 13px; color: var(--text-secondary); text-align: right;">
            出口 IP: <span id="proxy_ip_val" class="mono" style="font-weight: 600; color: var(--text-primary);">-</span> 
            <span id="proxy_latency_val" style="margin-left: 6px;"></span>
          </div>
        </div>

        <div style="display: flex; gap: 12px; justify-content: flex-end;">
          <button id="btn_test_proxy" class="btn-primary" style="height: 36px; padding: 0 16px; font-size: 13px;">
            <svg xmlns="http://www.w3.org/2000/svg" style="width:14px; height:14px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
            开始检测
          </button>
        </div>
      </div>
      
      <div style="display: flex; justify-content: flex-end; margin-top: 20px;">
        <button type="button" onclick="closeGatewayModal()" style="height: 38px; padding: 0 20px; font-weight: 600; border-radius: 8px; border: 1px solid var(--border-color); background: transparent; color: var(--text-secondary); cursor: pointer;">关闭</button>
      </div>
    </div>
  </div>

  <!-- Logs Modal (日志监控与分类筛选) -->
  <div id="logs_modal" class="modal">
    <div class="modal-content" style="max-width: 800px; width: 95%;">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; flex-wrap: wrap; gap: 12px;">
        <h3 style="margin: 0; font-size: 18px; font-weight: 700; color: var(--text-primary); display: flex; align-items: center; gap: 8px;">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:20px; height:20px; color: var(--primary);" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" /></svg>
          今日运行日志
        </h3>
        
        <div style="display: flex; align-items: center; gap: 10px; margin-left: auto;">
          <label class="form-label" for="log_filter_select" style="margin: 0; font-size: 13px; color: var(--text-secondary);">日志筛选:</label>
          <select id="log_filter_select" class="input-field" style="width: 140px; height: 32px; font-size: 12px; border-radius: 6px; padding: 0 8px; background: rgba(255, 255, 255, 0.03);" onchange="filterAndRenderLogs()">
            <option value="all">全部日志</option>
            <option value="proxy">代理相关 (Proxy)</option>
            <option value="vpn">VPN 连接 (VPN)</option>
            <option value="system">系统运行 (Main/Route)</option>
          </select>
        </div>
        
        <button type="button" onclick="closeLogsModal()" style="background: transparent; border: none; padding: 4px; cursor: pointer; color: var(--text-secondary); width: 28px; height: 28px; display: flex; align-items: center; justify-content: center; border-radius: 50%;" onmouseover="this.style.background='rgba(255,255,255,0.05)'" onmouseout="this.style.background='transparent'">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:18px; height:18px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" /></svg>
        </button>
      </div>

      <!-- Terminal Log Container -->
      <div id="log_terminal_container" style="background: #050811; border: 1px solid rgba(255, 255, 255, 0.05); border-radius: 10px; height: 400px; padding: 16px; overflow-y: auto; font-family: 'JetBrains Mono', Consolas, Courier, monospace; font-size: 12px; line-height: 1.5; text-align: left; white-space: pre-wrap; word-break: break-all; color: #a5b4fc; box-shadow: inset 0 4px 20px rgba(0,0,0,0.8); position: relative; margin-bottom: 20px;">
        <div style="color: var(--text-secondary); text-align: center; margin-top: 150px;">
          暂无今日运行日志记录。
        </div>
      </div>

      <div style="display: flex; justify-content: space-between; align-items: center;">
        <div style="display: flex; gap: 8px;">
          <button type="button" onclick="copyLogContent()" class="btn-primary" style="height: 38px; padding: 0 16px; background: rgba(255,255,255,0.05); color: var(--text-primary); border: 1px solid var(--border-color);">
            <svg xmlns="http://www.w3.org/2000/svg" style="width:14px; height:14px; margin-right: 4px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M8 5H6a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2v-1M8 5a2 2 0 002 2h2a2 2 0 002-2M8 5a2 2 0 012-2h2a2 2 0 012 2m0 0h2a2 2 0 012 2v3m2 4H10m0 0l3-3m-3 3l3 3" /></svg>
            一键复制
          </button>
          <button type="button" onclick="exportLogContent()" class="btn-primary" style="height: 38px; padding: 0 16px; background: rgba(255,255,255,0.05); color: var(--text-primary); border: 1px solid var(--border-color);">
            <svg xmlns="http://www.w3.org/2000/svg" style="width:14px; height:14px; margin-right: 4px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" /></svg>
            导出日志
          </button>
        </div>
        <button type="button" onclick="closeLogsModal()" style="height: 38px; padding: 0 20px; font-weight: 600; border-radius: 8px; border: 1px solid var(--border-color); background: transparent; color: var(--text-secondary); cursor: pointer;">关闭</button>
      </div>
    </div>
  </div>
</main>
<script>
let nodes=[], state={}, testingNodeIds = new Set();
let currentPage = 1;
const pageSize = 99999;
let currentPageNodes = [];

const $=id=>document.getElementById(id);
const esc=s=>String(s||"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"}[c]));
const base=p=>(p||"").split(/[\\/]/).pop();
function time(ts){return ts?new Date(ts*1000).toLocaleString():"从未"}
function speed(v){return v?`${(v*8/1000/1000).toFixed(1)} Mbps`:"-"}

const translateQuality = q => {
  const dict = {"normal": "普通", "proxy": "代理", "datacenter": "数据中心", "mobile": "移动端"};
  return dict[q] || q || "-";
};

const translateIpType = t => {
  const dict = {"residential": "住宅 IP", "hosting": "机房 IP", "mobile": "移动网", "proxy": "代理 IP"};
  return dict[t] || t || "-";
};

const translateCountry = c => {
  const dict = {
    "Japan": "日本",
    "Korea Republic of": "韩国",
    "Korea": "韩国",
    "Republic of Korea": "韩国",
    "Thailand": "泰国",
    "United States": "美国",
    "United Kingdom": "英国",
    "Russian Federation": "俄罗斯",
    "Russian": "俄罗斯",
    "Viet Nam": "越南",
    "Vietnam": "越南",
    "China": "中国",
    "Taiwan": "台湾",
    "Taiwan Province of China": "台湾",
    "Hong Kong": "香港",
    "Singapore": "新加坡",
    "Malaysia": "马来西亚",
    "Indonesia": "印度尼西亚",
    "India": "印度",
    "Philippines": "菲律宾",
    "Australia": "澳大利亚",
    "New Zealand": "新西兰",
    "Canada": "加拿大",
    "Ukraine": "乌克兰",
    "France": "法国",
    "Germany": "德国",
    "Netherlands": "荷兰",
    "Sweden": "瑞典",
    "Norway": "挪威",
    "Spain": "西班牙",
    "Turkey": "土耳其",
    "South Africa": "南非",
    "Brazil": "巴西",
    "Argentina": "阿根廷",
    "Chile": "智利",
    "Mexico": "墨西哥",
    "Egypt": "埃及",
    "Romania": "罗马尼亚",
    "Poland": "波兰",
    "Kazakhstan": "哈萨克斯坦",
    "Georgia": "格鲁吉亚",
    "Mongolia": "蒙古",
    "Saudi Arabia": "沙特阿拉伯",
    "Iran": "伊朗",
    "Iraq": "伊拉克",
    "Colombia": "哥伦比亚",
    "Cambodia": "柬埔寨",
    "Ireland": "爱尔兰",
    "Italy": "意大利",
    "Switzerland": "瑞士",
    "Belgium": "比利时",
    "Austria": "奥地利",
    "Denmark": "丹麦",
    "Finland": "芬兰",
    "Portugal": "葡萄牙",
    "Greece": "希腊",
    "Czech Republic": "捷克",
    "Hungary": "匈牙利",
    "Israel": "以色列",
    "United Arab Emirates": "阿联酋",
    "UAE": "阿联酋",
    "Macao": "澳门",
    "Macau": "澳门",
    "Iceland": "冰岛",
    "Luxembourg": "卢森堡"
  };
  return dict[c] || c || "-";
};

const translateStatus = s => {
  const dict = {"available": "可用", "unavailable": "不可用", "not_checked": "待检测"};
  return dict[s] || s || "待检测";
};

function getLatencyClass(ms) {
  if (!ms) return '';
  if (ms < 50) return 'latency-good';
  if (ms < 150) return 'latency-medium';
  return 'latency-poor';
}

function updateCountryFilter() {
  const select = $("country_filter");
  const selectedValue = select.value;
  const countries = Array.from(new Set(nodes.map(n => n ? translateCountry(n.country) : "").filter(Boolean))).sort();
  
  const currentOptions = Array.from(select.options).map(o => o.value).filter(Boolean);
  if (JSON.stringify(countries) === JSON.stringify(currentOptions)) {
    return;
  }
  
  select.innerHTML = '<option value="">所有国家</option>' + 
    countries.map(c => `<option value="${esc(c)}">${esc(c)}</option>`).join("");
  
  if (countries.includes(selectedValue)) {
    select.value = selectedValue;
  } else {
    select.value = "";
  }
}

function getFilteredNodes() {
  const selectedCountry = $("country_filter").value;
  const selectedIpType = $("ip_type_filter").value;
  const selectedStatus = $("status_filter").value;
  return nodes.filter(n => {
    if (!n) return false;
    if (selectedCountry && translateCountry(n.country) !== selectedCountry) {
      return false;
    }
    if (selectedIpType) {
      if (selectedIpType === "residential" && !["residential", "mobile"].includes(n.ip_type)) {
        return false;
      }
      if (selectedIpType === "hosting" && n.ip_type !== "hosting") {
        return false;
      }
    }
    if (selectedStatus === "available" && n.probe_status !== "available" && !n.active) {
      return false;
    }
    if (selectedStatus === "unavailable" && (n.probe_status !== "unavailable" || n.active)) {
      return false;
    }
    const favoriteIds = Array.isArray(state.favorite_node_ids) ? state.favorite_node_ids : [];
    if (showFavoritesOnly && !favoriteIds.includes(n.id)) {
      return false;
    }
    return true;
  });
}

function stableSortNodes() {
  nodes.sort((a, b) => {
    if (!a || !b) return 0;
    const aScore = a.score || 0;
    const bScore = b.score || 0;
    if (bScore !== aScore) {
      return bScore - aScore;
    }
    const aId = a.id || "";
    const bId = b.id || "";
    return aId.localeCompare(bId);
  });
}

function render(){
  const activeNodeId = state.active_openvpn_node_id;
  const activeNode = nodes.find(n => n && (n.active || n.id === activeNodeId));
  
  // Render separated Active Node Card
  const activeCardContainer = $("active_node_card");
  if (state.is_connecting && !activeNode) {
    activeCardContainer.innerHTML = `
      <div class="active-card" style="background: var(--bg-surface); border-color: var(--warning); box-shadow: 0 0 15px rgba(245, 158, 11, 0.15);">
        <div class="active-card-info">
          <div class="stat-icon-wrapper" style="background: rgba(245, 158, 11, 0.15); border-color: rgba(245, 158, 11, 0.3); width: 48px; height: 48px; border-radius: 12px;">
            <svg xmlns="http://www.w3.org/2000/svg" class="stat-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5" style="color: #f59e0b; width: 24px; height: 24px; animation: spin 2s linear infinite;"><path stroke-linecap="round" stroke-linejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 1121.21 8H18" /></svg>
          </div>
          <div class="active-card-details">
            <div class="active-card-title" style="color: var(--text-primary);">
              <span class="badge" style="background: rgba(245, 158, 11, 0.15); color: #f59e0b; border-color: rgba(245, 158, 11, 0.3);"><span class="badge-pulse" style="background: #f59e0b;"></span>正在连接</span>
              <strong>${esc(state.active_node_latency || '正在连接...')}</strong>
            </div>
            <div class="active-card-meta" style="margin-top: 4px;">
              ${esc(state.last_check_message || '正在与 VPN 节点建立加密隧道，请稍候...')}
            </div>
          </div>
        </div>
      </div>
    `;
  } else if (activeNode) {
    const latencyClass = getLatencyClass(activeNode.latency_ms);
    const latencyText = activeNode.latency_ms ? `<span class="latency-val ${latencyClass}">${activeNode.latency_ms} ms</span>` : "-";
    const displayLocation = activeNode.location || translateCountry(activeNode.country) || "-";
    activeCardContainer.innerHTML = `
      <div class="active-card">
        <div class="active-card-info">
          <div class="stat-icon-wrapper" style="background: rgba(16, 185, 129, 0.15); border-color: rgba(16, 185, 129, 0.3); width: 48px; height: 48px; border-radius: 12px;">
            <svg xmlns="http://www.w3.org/2000/svg" class="stat-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5" style="color: #34d399; width: 24px; height: 24px;"><path stroke-linecap="round" stroke-linejoin="round" d="M13 10V3L4 14h7v7l9-11h-7z" /></svg>
          </div>
          <div class="active-card-details">
            <div class="active-card-title">
              <span class="badge available"><span class="badge-pulse"></span>已连接</span>
              <strong>${esc(translateCountry(activeNode.country))} 节点</strong>
            </div>
            <div class="active-card-value mono" style="font-size: 20px; margin-top: 2px;">
              ${esc(activeNode.ip || activeNode.remote_host)}:${activeNode.remote_port || ""}
            </div>
            <div class="active-card-meta" style="margin-top: 4px;">
              <span>物理位置: <strong>${esc(displayLocation)}</strong></span>
              <span style="margin-left: 12px;">延时: <strong>${latencyText}</strong></span>
              <span style="margin-left: 12px;">运营主体: <strong>${esc(activeNode.owner || activeNode.as_name || "-")}</strong></span>
              <span style="margin-left: 12px;">IP 类型: <strong>${esc(translateIpType(activeNode.ip_type))}</strong></span>
            </div>
          </div>
        </div>
        <button class="btn-danger" style="height: 38px; padding: 0 16px; border-radius: 8px;" onclick="disconnectNode()">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:16px; height:16px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
          断开连接
        </button>
      </div>
    `;
  } else {
    activeCardContainer.innerHTML = `
      <div class="active-card" style="background: var(--bg-surface); border-color: var(--border-color); box-shadow: none;">
        <div class="active-card-info">
          <div class="stat-icon-wrapper" style="background: rgba(244, 63, 94, 0.1); border-color: rgba(244, 63, 94, 0.2); width: 48px; height: 48px; border-radius: 12px;">
            <svg xmlns="http://www.w3.org/2000/svg" class="stat-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5" style="color: var(--danger); width: 24px; height: 24px;"><path stroke-linecap="round" stroke-linejoin="round" d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" /></svg>
          </div>
          <div class="active-card-details">
            <div class="active-card-title" style="color: var(--text-secondary);">
              <span class="badge unavailable" style="padding: 2px 8px;">未连接</span> 当前未连接 VPN 节点
            </div>
            <div class="active-card-meta" style="margin-top: 4px;">
              在下方列表中选择一个可用备用节点并点击 “切换” 按钮开始连接。
            </div>
          </div>
        </div>
      </div>
    `;
  }

  const shown = getFilteredNodes();
  
  if ($("total")) $("total").textContent = nodes.length; 
  if ($("target")) $("target").textContent = state.target_valid_nodes || 3;
  if ($("active")) $("active").textContent = activeNode ? 1 : 0; 
  
  const statusMessage = state.last_check_message || "";
  const activeNodeInfo = activeNode ? `<span class="badge available" style="margin-left:8px; padding:2px 8px;">${esc(translateCountry(activeNode.country))} (${activeNode.id})</span>` : `<span class="badge unavailable" style="margin-left:8px; padding:2px 8px;">无</span>`;
  const localProxy = state.local_proxy || `http://127.0.0.1:${state.proxy_port || 7928}`;
  if ($("status")) { $("status").innerHTML=`<span class="status-dot"></span>HTTP 代理本地接口：${localProxy} | 活动节点：${activeNodeInfo} | 状态：${statusMessage}`; }
  
  // Update proxy test status card based on background checks
  const pBadge = $("proxy_status_badge");
  const pIpVal = $("proxy_ip_val");
  const pLatVal = $("proxy_latency_val");
  const pBtn = $("btn_test_proxy");
  
  if (state.is_connecting) {
    pBadge.className = "badge";
    pBadge.style.background = "rgba(245, 158, 11, 0.15)";
    pBadge.style.color = "#f59e0b";
    pBadge.style.borderColor = "rgba(245, 158, 11, 0.3)";
    pBadge.innerHTML = `<span class="badge-pulse" style="background: #f59e0b;"></span>正在连接`;
    pIpVal.textContent = state.active_node_latency || "正在连接...";
    pLatVal.innerHTML = `<span style="color: var(--text-secondary); font-size: 12px;">${esc(state.last_check_message || "正在与 VPN 节点建立加密隧道，请稍候...")}</span>`;
    pBtn.disabled = true;
    pBtn.style.opacity = "0.5";
    pBtn.style.cursor = "not-allowed";
  } else {
    pBtn.disabled = false;
    pBtn.style.opacity = "";
    pBtn.style.cursor = "";
    pBadge.style.background = "";
    pBadge.style.color = "";
    pBadge.style.borderColor = "";
    if (state.proxy_ok !== undefined) {
      if (state.proxy_ok) {
        pBadge.className = "badge available";
        pBadge.textContent = "可用";
        pIpVal.textContent = state.proxy_ip || "-";
        const latencyClass = getLatencyClass(state.proxy_latency_ms);
        pLatVal.innerHTML = `<span class="latency-val ${latencyClass}" style="margin-left:8px;">${state.proxy_latency_ms} ms</span>`;
      } else {
        pBadge.className = "badge unavailable";
        pBadge.textContent = "不可用";
        pIpVal.textContent = "-";
        pLatVal.innerHTML = `<span class="latency-val latency-poor" style="margin-left:8px; font-size:11px; max-width: 450px; display: inline-block; white-space: normal; line-height: 1.4; text-align: left;" title="${esc(state.proxy_error)}">${esc(state.proxy_error || "连接失败")}</span>`;
      }
    } else {
      pBadge.className = "badge not_checked";
      pBadge.textContent = "未检测";
      pIpVal.textContent = "-";
      if (state.last_check_message) {
        pLatVal.innerHTML = `<span style="color: var(--text-secondary); font-size: 12px;">${esc(state.last_check_message)}</span>`;
      } else {
        pLatVal.innerHTML = "";
      }
    }
  }

  updateFavPanelUI();

  // Pagination calculation
  const totalPages = Math.ceil(shown.length / pageSize) || 1;
  if (currentPage > totalPages) currentPage = totalPages;
  if (currentPage < 1) currentPage = 1;
  
  const startIndex = (currentPage - 1) * pageSize;
  const endIndex = Math.min(startIndex + pageSize, shown.length);
  currentPageNodes = shown.slice(startIndex, endIndex);

  // Render table rows
  if (currentPageNodes.length === 0) {
    $("rows").innerHTML = `<tr><td colspan="9" style="text-align: center; color: var(--text-secondary); padding: 40px 0;">未找到符合过滤条件的备选节点。</td></tr>`;
  } else {
    $("rows").innerHTML=currentPageNodes.map(n=>{
      if (!n) return '';
      const isCurrentlyActive = activeNode && n.id === activeNode.id;
      const rowClass = isCurrentlyActive ? 'class="active-row"' : '';
      
      const badgeClass = isCurrentlyActive ? 'available' : (n.probe_status || 'not_checked');
      const badgeText = isCurrentlyActive ? '<span class="badge-pulse"></span>已连接' : translateStatus(n.probe_status);
      const latencyClass = getLatencyClass(n.latency_ms);
      const latencyText = n.latency_ms ? `<span class="latency-val ${latencyClass}">${n.latency_ms} ms</span>` : "-";
      const displayLocation = n.location || translateCountry(n.country) || "-";
      
      const isTesting = testingNodeIds.has(n.id);
      const testSpinner = `<svg style="animation: spin 1s linear infinite; width: 12px; height: 12px; display: inline-block; margin-right: 4px; vertical-align: middle;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><circle cx="12" cy="12" r="10" stroke="currentColor" stroke-opacity="0.2" fill="none"></circle><path d="M4 12a8 8 0 018-8" stroke="currentColor" fill="none"></path></svg>`;
      const testBtnText = isTesting ? `${testSpinner}检测中` : '检测';
      const testBtn = `<button class="test-btn" data-node-id="${esc(n.id)}" ${isTesting ? 'disabled' : ''} onclick="testNode(this, '${esc(n.id)}', event)">${testBtnText}</button>`;
      
      // Connect button is disabled if probe status is "unavailable" and not already active, or if we are already connecting
      // Connect button is disabled if probe status is "unavailable" and not already active, or if we are already connecting
      const isUnavailable = n.probe_status === "unavailable";
      const connectBtn = isCurrentlyActive 
        ? `<button class="connect-btn" disabled style="background: var(--success-gradient); color: white; cursor: default; opacity: 1;">已连接</button>`
        : `<button class="connect-btn" ${(isUnavailable || state.is_connecting) ? 'disabled style="opacity:0.3; cursor:not-allowed;"' : ''} onclick="connectNode('${esc(n.id)}')">切换</button>`;
      
      const favoriteIds = Array.isArray(state.favorite_node_ids) ? state.favorite_node_ids : [];
      const isFav = favoriteIds.includes(n.id);
      const favBtn = isFav 
        ? `<button class="test-btn" style="color: var(--warning); border-color: rgba(245, 158, 11, 0.4); padding: 0 8px; height: 30px;" onclick="toggleFavorite('${esc(n.id)}', event)">★ 已收藏</button>`
        : `<button class="test-btn" style="color: var(--text-secondary); border-color: var(--border-color); padding: 0 8px; height: 30px;" onclick="toggleFavorite('${esc(n.id)}', event)">☆ 收藏</button>`;

      return `<tr ${rowClass}>
        <td><span class="badge ${badgeClass}">${badgeText}</span></td>
        <td class="mono" style="white-space: nowrap; max-width: 220px; overflow: hidden; text-overflow: ellipsis;" title="${esc(n.ip||n.remote_host)}:${n.remote_port||""}">${esc(n.ip||n.remote_host)}:${n.remote_port||""}</td>
        <td style="white-space: nowrap; overflow: hidden; text-overflow: ellipsis;" title="${esc(displayLocation)}">${esc(displayLocation)}</td>
        <td style="white-space: nowrap; overflow: hidden; text-overflow: ellipsis;" title="${esc(n.owner||n.as_name||"-")}">${esc(n.owner||n.as_name||"-")}</td>
        <td style="white-space: nowrap; max-width: 110px; overflow: hidden; text-overflow: ellipsis;" title="${esc(translateIpType(n.ip_type))}">${esc(translateIpType(n.ip_type))}</td>
        <td>
          <div class="table-actions">
            ${favBtn}
            ${connectBtn}
          </div>
        </td>
      </tr>`;
    }).join("");
  }

  // Render pagination controls
  $("page_start").textContent = shown.length > 0 ? startIndex + 1 : 0;
  $("page_end").textContent = endIndex;
  $("filtered_count").textContent = shown.length;
  $("current_page_val").textContent = currentPage;
  $("total_pages_val").textContent = totalPages;
  
  $("btn_first_page").disabled = currentPage === 1;
  $("btn_prev_page").disabled = currentPage === 1;
  $("btn_next_page").disabled = currentPage === totalPages;
  $("btn_last_page").disabled = currentPage === totalPages;
}

// Hook up page buttons events
$("btn_first_page").onclick = () => { currentPage = 1; render(); };
$("btn_prev_page").onclick = () => { if (currentPage > 1) { currentPage--; render(); } };
$("btn_next_page").onclick = () => {
  const shown = getFilteredNodes();
  const totalPages = Math.ceil(shown.length / pageSize) || 1;
  if (currentPage < totalPages) { currentPage++; render(); }
};
$("btn_last_page").onclick = () => {
  const shown = getFilteredNodes();
  const totalPages = Math.ceil(shown.length / pageSize) || 1;
  currentPage = totalPages;
  render();
};

async function testNode(btn, id, event){
  if (event) event.stopPropagation();
  testingNodeIds.add(id);
  render();
  
  try {
    const response = await fetch("./api/test_node", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id })
    });
    const result = await response.json();
    if (result.ok && result.node) {
      const idx = nodes.findIndex(n => n && n.id === id);
      if (idx !== -1) {
        nodes[idx] = result.node;
      }
    }
  } catch (e) {
  } finally {
    testingNodeIds.delete(id);
    render();
  }
}

async function toggleFavorite(id, event) {
  if (event) event.stopPropagation();
  try {
    const response = await fetch("./api/toggle_favorite", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id })
    });
    const result = await response.json();
    if (result.ok) {
      state.favorite_node_ids = Array.isArray(result.favorite_node_ids) ? result.favorite_node_ids : [];
      render();
    }
  } catch (e) {
    console.error("切换收藏失败", e);
  }
}

let pollInterval = null;

function startConnectionPolling() {
  if (pollInterval) clearInterval(pollInterval);
  pollInterval = setInterval(async () => {
    try {
      const resp = await fetch("./api/nodes");
      const data = await resp.json();
      nodes = Array.isArray(data.nodes) ? data.nodes : [];
      state = data.state || {};
      stableSortNodes();
      updateCountryFilter();
      render();
      
      if (!state.is_connecting) {
        clearInterval(pollInterval);
        pollInterval = null;
        try {
          await fetch("./api/test_proxy", { method: "POST" });
        } catch(pe){}
        load();
      }
    } catch(pe) {
      clearInterval(pollInterval);
      pollInterval = null;
      load();
    }
  }, 1000);
}

async function connectNode(id){
  state.is_connecting = true;
  state.active_openvpn_node_id = id;
  state.active_node_latency = "正在连接";
  state.last_check_message = "正在发送连接请求...";
  render();
  
  startConnectionPolling();
  
  try {
    const r = await fetch("./api/connect",{
      method:"POST",
      headers:{"Content-Type":"application/json"},
      body:JSON.stringify({id})
    });
    const result = await r.json();
    if (!result.ok) {
      alert("连接失败: " + (result.error || "未知错误"));
      if (pollInterval) {
        clearInterval(pollInterval);
        pollInterval = null;
      }
      state.is_connecting = false;
      render();
      return;
    }
  } catch(e) {
    alert("连接请求错误");
    if (pollInterval) {
      clearInterval(pollInterval);
      pollInterval = null;
    }
    state.is_connecting = false;
    render();
  }
}

async function disconnectNode(){
  if (!confirm("确定要断开当前的 VPN 连接吗？")) return;
  try {
    const response = await fetch("./api/disconnect", { method: "POST" });
    const result = await response.json();
    if (result.ok) {
      try {
        await fetch("./api/test_proxy", { method: "POST" });
      } catch(pe){}
      load();
    } else {
      alert("断开连接失败: " + (result.error || "未知错误"));
    }
  } catch (e) {
    alert("请求断开连接失败");
  }
}





async function load(){
  const r=await fetch("./api/nodes"); 
  const d=await r.json(); 
  nodes=Array.isArray(d.nodes) ? d.nodes : []; 
  state=d.state||{}; 
  
  stableSortNodes();
  updateCountryFilter();
  render();

  if (state.is_connecting) {
    startConnectionPolling();
  }
}
$("country_filter").onchange=()=>{ currentPage = 1; render(); };
$("ip_type_filter").onchange=()=>{ currentPage = 1; render(); };
$("status_filter").onchange=()=>{ currentPage = 1; render(); };

$("refresh").onclick=async()=>{ 
  $("refresh").disabled=true; 
  $("refresh").textContent="正在后台更新..."; 
  try{await fetch("./api/refresh_nodes",{method:"POST"}); await load();} 
  catch(e){}
  setTimeout(()=>{
    $("refresh").disabled=false; 
    $("refresh").textContent="更新节点";
  }, 3000);
};
$("btn_test_proxy").onclick = async () => {
  const btn = $("btn_test_proxy");
  const badge = $("proxy_status_badge");
  const ipVal = $("proxy_ip_val");
  const latVal = $("proxy_latency_val");
  
  btn.disabled = true;
  btn.innerHTML = `<span class="badge-pulse"></span>测试中...`;
  badge.className = "badge not_checked";
  badge.textContent = "检测中...";
  ipVal.textContent = "-";
  latVal.textContent = "";
  
  try {
    const response = await fetch("./api/test_proxy", { method: "POST" });
    const result = await response.json();
    if (result.ok) {
      badge.className = "badge available";
      badge.textContent = "可用";
      ipVal.textContent = result.ip || "-";
      
      const latencyClass = getLatencyClass(result.latency_ms);
      latVal.innerHTML = `<span class="latency-val ${latencyClass}" style="margin-left:8px;">${result.latency_ms} ms</span>`;
    } else {
      badge.className = "badge unavailable";
      badge.textContent = "不可用";
      ipVal.textContent = "-";
      latVal.innerHTML = `<span class="latency-val latency-poor" style="margin-left:8px; font-size:11px;" title="${esc(result.error)}">连接失败</span>`;
    }
  } catch (e) {
    badge.className = "badge unavailable";
    badge.textContent = "网络错误";
    ipVal.textContent = "-";
    latVal.innerHTML = `<span class="latency-val latency-poor" style="margin-left:8px; font-size:11px;">请求出错</span>`;
  } finally {
    btn.disabled = false;
    btn.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" style="width:16px; height:16px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg> 测试代理`;
  }
};

// Admin dropdown toggle & GitHub dropdown toggle
const adminBtn = $("admin_btn");
const adminDropdown = $("admin_dropdown");
const githubBtn = $("github_btn");
const githubDropdown = $("github_dropdown");

if (adminBtn && adminDropdown) {
  adminBtn.onclick = (e) => {
    e.stopPropagation();
    const isShow = adminDropdown.style.display === "block";
    adminDropdown.style.display = isShow ? "none" : "block";
    if (githubDropdown) githubDropdown.style.display = "none";
  };
}

if (githubBtn && githubDropdown) {
  githubBtn.onclick = (e) => {
    e.stopPropagation();
    const isShow = githubDropdown.style.display === "block";
    githubDropdown.style.display = isShow ? "none" : "block";
    if (adminDropdown) adminDropdown.style.display = "none";
  };
}

document.addEventListener("click", () => {
  if (adminDropdown) adminDropdown.style.display = "none";
  if (githubDropdown) githubDropdown.style.display = "none";
});

let showFavoritesOnly = false;

function toggleFavoritesView() {
  showFavoritesOnly = !showFavoritesOnly;
  currentPage = 1;
  render();
}

function updateFavPanelUI() {
  const panel = $("favorites_panel");
  if (!panel) return;
  panel.style.display = showFavoritesOnly ? "block" : "none";
  
  const btn = $("btn_favorites");
  if (btn) {
    if (showFavoritesOnly) {
      btn.classList.add("active");
    } else {
      btn.classList.remove("active");
    }
  }

  if (showFavoritesOnly && state) {
    const fallbackCheckbox = $("fav_fail_fallback_checkbox");
    if (fallbackCheckbox) {
      fallbackCheckbox.checked = !!state.fav_fail_fallback;
    }
    
    const warningDiv = $("fav_fallback_warning");
    if (warningDiv) {
      warningDiv.style.display = state.fav_fail_fallback ? "none" : "block";
    }

    const favRoutingBtn = $("btn_toggle_fav_routing");
    if (favRoutingBtn) {
      if (state.routing_mode === "favorites") {
        favRoutingBtn.textContent = "禁用仅用收藏出站";
        favRoutingBtn.style.background = "var(--danger-gradient)";
        favRoutingBtn.style.borderColor = "transparent";
        favRoutingBtn.style.color = "#ffffff";
        favRoutingBtn.style.boxShadow = "0 0 12px rgba(244, 63, 94, 0.3)";
      } else {
        favRoutingBtn.textContent = "启用仅用收藏出站";
        favRoutingBtn.style.background = "rgba(255,255,255,0.03)";
        favRoutingBtn.style.borderColor = "var(--border-color)";
        favRoutingBtn.style.color = "var(--text-primary)";
        favRoutingBtn.style.boxShadow = "none";
      }
    }
  }
}

async function toggleFavRouting() {
  if (!state) return;
  const newMode = state.routing_mode === "favorites" ? "auto" : "favorites";
  
  state.routing_mode = newMode;
  updateFavPanelUI();
  
  try {
    const res = await fetch("./api/update_routing", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        routing_mode: newMode,
        force_country: state.force_country || "",
        routing_ip_type: state.routing_ip_type || "all",
        fav_fail_fallback: state.fav_fail_fallback !== false
      })
    });
    const data = await res.json();
    if (res.ok && data.ok) {
      load();
    } else {
      alert("更新出站路由设置失败: " + (data.error || "未知错误"));
      load();
    }
  } catch (err) {
    alert("连接服务器失败，请稍后重试");
    load();
  }
}

async function handleFavFallbackChange(checked) {
  if (!state) return;
  
  if (!checked) {
    alert("⚠️ 警告：不勾选此项可能在所有收藏节点失效时造成网络彻底断开连接，无法自动切换到其他非收藏的可用节点！");
  }
  
  state.fav_fail_fallback = checked;
  updateFavPanelUI();
  
  try {
    const res = await fetch("./api/update_routing", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        routing_mode: state.routing_mode || "auto",
        force_country: state.force_country || "",
        routing_ip_type: state.routing_ip_type || "all",
        fav_fail_fallback: checked
      })
    });
    const data = await res.json();
    if (res.ok && data.ok) {
      load();
    } else {
      alert("更新失败: " + (data.error || "未知错误"));
      load();
    }
  } catch (err) {
    alert("连接服务器失败，请稍后重试");
    load();
  }
}

function selectOptionCard(groupName, value) {
  if (groupName === 'routing_mode') {
    const input = $("net_routing_mode");
    if (input) input.value = value;
    
    const cards = document.querySelectorAll("#routing_mode_group .option-card");
    cards.forEach(card => {
      if (card.getAttribute("data-value") === value) {
        card.classList.add("active");
      } else {
        card.classList.remove("active");
      }
    });
    
    handleRoutingModeChange(value);
  } else if (groupName === 'routing_ip_type') {
    const input = $("net_routing_ip_type");
    if (input) input.value = value;
    
    const cards = document.querySelectorAll("#routing_ip_type_group .option-card");
    cards.forEach(card => {
      if (card.getAttribute("data-value") === value) {
        card.classList.add("active");
      } else {
        card.classList.remove("active");
      }
    });
  }
}

function setRoutingMode(value) {
  selectOptionCard('routing_mode', value);
}

function setRoutingIpType(value) {
  selectOptionCard('routing_ip_type', value);
}

function handleRoutingModeChange(mode) {
  const countryGroup = $("net_force_country_group");
  const warningDiv = $("net_routing_warning");
  
  if (mode === "fixed_region") {
    countryGroup.style.display = "block";
    warningDiv.style.color = "var(--warning)";
    warningDiv.style.background = "rgba(245, 158, 11, 0.1)";
    warningDiv.style.border = "1px solid rgba(245, 158, 11, 0.2)";
    warningDiv.innerHTML = `⚠️ <strong>固定地区</strong>：限制仅连接选定国家的节点，且后台仅并发测速该国家的节点。如果该国的所有可用节点都失效，会造成代理中断且<strong>绝不自动切换到其他国家</strong>的节点。`;
  } else if (mode === "favorites") {
    countryGroup.style.display = "none";
    warningDiv.style.color = "var(--warning)";
    warningDiv.style.background = "rgba(245, 158, 11, 0.1)";
    warningDiv.style.border = "1px solid rgba(245, 158, 11, 0.2)";
    warningDiv.innerHTML = `⚠️ <strong>仅用收藏</strong>：只连接和切换您收藏的节点。如果所有收藏的节点均失效，系统不会自动切换到未收藏的节点。请确保收藏列表中有足够多且可用的节点。`;
  } else if (mode === "fixed_ip") {
    countryGroup.style.display = "none";
    warningDiv.style.color = "var(--warning)";
    warningDiv.style.background = "rgba(245, 158, 11, 0.1)";
    warningDiv.style.border = "1px solid rgba(245, 158, 11, 0.2)";
    warningDiv.innerHTML = `⚠️ <strong>固定IP</strong>：锁定当前连接的节点。不管该节点是否失效，系统都绝不自动切换至其他IP；如果节点由于网络故障失效，会造成代理中断（但如果OpenVPN连接意外退出，脚本将尝试为您在后台重新拉起连接同一IP）。<br><strong>提示</strong>：您可以在主页 of 节点列表中直接点击“连接”按钮来选择并锁定不同的IP节点。`;
  } else {
    countryGroup.style.display = "none";
    warningDiv.style.color = "var(--text-secondary)";
    warningDiv.style.background = "rgba(255, 255, 255, 0.02)";
    warningDiv.style.border = "1px solid rgba(255, 255, 255, 0.05)";
    warningDiv.innerHTML = `ℹ️ <strong>自动配置</strong>：全自动测试并选择最佳IP。在使用过程中，如果当前连接节点没有失效，将不再更换IP；如果当前节点失效，系统将立刻秒级自动漂移到其他最快的可用节点。`;
  }
}

function populateRoutingCountries() {
  const select = $("net_force_country");
  if (!select) return;
  const countMap = {};
  nodes.forEach(n => {
    const c = translateCountry(n.country);
    if (c) {
      countMap[c] = (countMap[c] || 0) + 1;
    }
  });
  
  const countries = Object.keys(countMap).sort();
  let html = '<option value="">请选择要锁定的国家...</option>';
  countries.forEach(c => {
    html += `<option value="${esc(c)}">${esc(c)} (${countMap[c]}个节点)</option>`;
  });
  select.innerHTML = html;
  
  if (state) {
    select.value = state.force_country ? translateCountry(state.force_country) : "";
  }
}

function openCredentialsModal() {
  $("credentials_error").style.display = "none";
  $("credentials_success").style.display = "none";
  $("credentials_form").reset();
  if (state) {
    $("cred_username").value = state.username || "";
    $("cred_password").value = "";
    $("cred_port").value = state.port || 8787;
    $("cred_suffix").value = state.secret_path || "";
  }
  $("credentials_modal").style.display = "flex";
  $("admin_dropdown").style.display = "none";
}

function closeCredentialsModal() {
  $("credentials_modal").style.display = "none";
}

async function saveCredentials(e) {
  e.preventDefault();
  const errorDivEl = $("credentials_error");
  const successDiv = $("credentials_success");
  const submitBtn = $("credentials_submit_btn");
  
  errorDivEl.style.display = "none";
  successDiv.style.display = "none";
  
  const username = $("cred_username").value.trim();
  const password = $("cred_password").value.trim();
  const port = parseInt($("cred_port").value);
  const suffix = $("cred_suffix").value.trim();
  
  if (!username || (!password && !(state && state.password_set))) {
    errorDivEl.textContent = "用户名不能为空；首次设置时密码不能为空";
    errorDivEl.style.display = "block";
    return;
  }
  
  if (isNaN(port) || port < 1 || port > 65535) {
    errorDivEl.textContent = "网页管理端口范围必须在 1 至 65535 之间";
    errorDivEl.style.display = "block";
    return;
  }
  
  if (!/^[A-Za-z0-9]+$/.test(suffix)) {
    errorDivEl.textContent = "登录安全后缀仅能由英文字母和数字组成";
    errorDivEl.style.display = "block";
    return;
  }
  
  if (state && port === state.proxy_port) {
    errorDivEl.textContent = "网页管理端口不能与代理出站端口相同";
    errorDivEl.style.display = "block";
    return;
  }
  
  submitBtn.disabled = true;
  submitBtn.textContent = "正在保存...";
  
  try {
    const res = await fetch("./api/update_credentials", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: username,
        password: password,
        port: port,
        secret_path: suffix
      })
    });
    
    const data = await res.json();
    if (res.ok && data.ok) {
      if (data.restart_needed) {
        successDiv.textContent = "保存成功！网页管理端口或路径已变更，页面将在 4 秒内自动跳转...";
        successDiv.style.display = "block";
        
        const inputs = $("credentials_form").querySelectorAll("input, button");
        inputs.forEach(el => el.disabled = true);
        
        setTimeout(() => {
          const protocol = window.location.protocol;
          const host = window.location.hostname;
          window.location.href = `${protocol}//${host}:${port}/${suffix}/`;
        }, 4000);
      } else {
        successDiv.textContent = data.reauth_required ? "账号密码保存成功，请重新登录..." : "账号密码保存成功，已即时生效！";
        successDiv.style.display = "block";
        setTimeout(() => {
          if (data.reauth_required) {
            window.location.reload();
          } else {
            closeCredentialsModal();
            load();
          }
        }, 1500);
      }
    } else {
      errorDivEl.textContent = data.error || "保存失败，请检查输入";
      errorDivEl.style.display = "block";
      submitBtn.disabled = false;
      submitBtn.textContent = "保存修改";
    }
  } catch (err) {
    errorDivEl.textContent = "连接服务器失败，请稍后重试";
    errorDivEl.style.display = "block";
    submitBtn.disabled = false;
    submitBtn.textContent = "保存修改";
  }
}

function openNetworkModal() {
  $("network_error").style.display = "none";
  $("network_success").style.display = "none";
  $("network_form").reset();
  
  if (state) {
    $("net_proxy_port").value = state.proxy_port || 7928;
    const mode = state.routing_mode || "auto";
    const ipType = state.routing_ip_type || "all";
    
    selectOptionCard('routing_mode', mode);
    selectOptionCard('routing_ip_type', ipType);
  }
  
  populateRoutingCountries();
  $("network_modal").style.display = "flex";
  $("admin_dropdown").style.display = "none";
}

function closeNetworkModal() {
  $("network_modal").style.display = "none";
}

async function saveNetwork(e) {
  e.preventDefault();
  const errorDivEl = $("network_error");
  const successDiv = $("network_success");
  const submitBtn = $("network_submit_btn");
  
  errorDivEl.style.display = "none";
  successDiv.style.display = "none";
  
  const proxyPort = parseInt($("net_proxy_port").value);
  const routingMode = $("net_routing_mode").value;
  const forceCountry = $("net_force_country").value;
  const routingIpType = $("net_routing_ip_type").value;
  
  if (isNaN(proxyPort) || proxyPort < 1024 || proxyPort > 65535) {
    errorDivEl.textContent = "代理出站端口范围必须在 1024 至 65535 之间";
    errorDivEl.style.display = "block";
    return;
  }

  if (state && proxyPort === state.port) {
    errorDivEl.textContent = "代理出站端口不能与网页管理端口相同";
    errorDivEl.style.display = "block";
    return;
  }
  
  if (routingMode === "fixed_region" && !forceCountry) {
    errorDivEl.textContent = "请选择一个要锁定的目标国家";
    errorDivEl.style.display = "block";
    return;
  }
  
  submitBtn.disabled = true;
  submitBtn.textContent = "正在保存...";
  
  try {
    const res = await fetch("./api/update_settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        proxy_port: proxyPort,
        routing_mode: routingMode,
        force_country: forceCountry,
        routing_ip_type: routingIpType
      })
    });
    
    const data = await res.json();
    if (res.ok && data.ok) {
      if (data.restart_needed) {
        successDiv.textContent = "保存成功！代理出站端口已变更，页面将在 4 秒内自动刷新...";
        successDiv.style.display = "block";
        
        const inputs = $("network_form").querySelectorAll("input, button");
        inputs.forEach(el => el.disabled = true);
        
        setTimeout(() => {
          window.location.reload();
        }, 4000);
      } else {
        successDiv.textContent = "配置保存成功，已即时生效！";
        successDiv.style.display = "block";
        setTimeout(() => {
          closeNetworkModal();
          load();
        }, 1500);
      }
    } else {
      errorDivEl.textContent = data.error || "保存失败，请检查输入";
      errorDivEl.style.display = "block";
      submitBtn.disabled = false;
      submitBtn.textContent = "保存修改";
    }
  } catch (err) {
    errorDivEl.textContent = "连接服务器失败，请稍后重试";
    errorDivEl.style.display = "block";
    submitBtn.disabled = false;
    submitBtn.textContent = "保存修改";
  }
}



function openVpsModal() {
  $("vps_recommend_modal").style.display = "flex";
}

function closeVpsModal() {
  $("vps_recommend_modal").style.display = "none";
}

async function logoutAdmin() {
  try {
    const res = await fetch("./api/logout", { method: "POST" });
    if (res.ok) {
      window.location.reload();
    }
  } catch (err) {
    console.error("退出登录失败", err);
    window.location.reload();
  }
}

// 页面加载时自动初始化数据
load();

// 每 10 秒在前台空闲时自动更新节点与状态，无需手动刷新页面
setInterval(async () => {
  if (typeof state !== "undefined" && !state.is_connecting && (!testingNodeIds || !testingNodeIds.size) && document.visibilityState === "visible") {
    try {
      const r = await fetch("./api/nodes");
      const d = await r.json();
      nodes = d.nodes || [];
      state = d.state || {};
      stableSortNodes();
      updateCountryFilter();
      render();
    } catch(e) {}
  }
}, 10000);
let gatewayPollInterval = null;

function openGatewayModal() {
  $("admin_dropdown").style.display = "none";
  $("gateway_modal").style.display = "flex";
  loadGatewayStatus();
  if (gatewayPollInterval) clearInterval(gatewayPollInterval);
  gatewayPollInterval = setInterval(loadGatewayStatus, 3000);
}

function closeGatewayModal() {
  $("gateway_modal").style.display = "none";
  if (gatewayPollInterval) {
    clearInterval(gatewayPollInterval);
    gatewayPollInterval = null;
  }
}

async function loadGatewayStatus() {
  try {
    const res = await fetch("./api/gateway_status");
    const data = await res.json();
    if (data.ok && data.services) {
      renderGatewayServices(data.services);
    }
  } catch (e) {
    console.error("加载网关状态失败", e);
  }
}

function renderGatewayServices(services) {
  const container = $("gateway_services_list");
  if (!container) return;
  
  let html = "";
  services.forEach(s => {
    const statusText = s.status === "running" ? "正在运行" : "已停止";
    const badgeClass = s.status === "running" ? "available" : "unavailable";
    const statusPulse = s.status === "running" ? '<span class="badge-pulse"></span>' : '';
    
    html += `
      <div style="background: rgba(255, 255, 255, 0.02); border: 1px solid var(--border-color); border-radius: 10px; padding: 12px 16px; display: flex; flex-direction: column; gap: 6px;">
        <div style="display: flex; justify-content: space-between; align-items: center;">
          <strong style="font-size: 14px; color: var(--text-primary);">${esc(s.name)}</strong>
          <span class="badge ${badgeClass}">${statusPulse}${statusText}</span>
        </div>
        <div style="font-size: 12px; color: var(--text-secondary);">${esc(s.details || "-")}</div>
        ${s.error ? `
          <div style="font-size: 12px; color: var(--danger); background: rgba(244,63,94,0.08); border: 1px solid rgba(244,63,94,0.15); border-radius: 6px; padding: 6px 10px; margin-top: 4px; line-height: 1.4;">
            ⚠️ 诊断原因: ${esc(s.error)}
          </div>
        ` : ''}
      </div>
    `;
  });
  container.innerHTML = html;
}

let logsPollInterval = null;
let rawLogsCache = [];

function openLogsModal() {
  $("admin_dropdown").style.display = "none";
  $("logs_modal").style.display = "flex";
  loadLogs();
  if (logsPollInterval) clearInterval(logsPollInterval);
  logsPollInterval = setInterval(loadLogs, 2500);
}

function closeLogsModal() {
  $("logs_modal").style.display = "none";
  if (logsPollInterval) {
    clearInterval(logsPollInterval);
    logsPollInterval = null;
  }
}

async function loadLogs() {
  try {
    const res = await fetch("./api/logs");
    const data = await res.json();
    if (data.logs) {
      rawLogsCache = data.logs;
      filterAndRenderLogs();
    }
  } catch (e) {
    console.error("加载日志失败", e);
  }
}

function filterAndRenderLogs() {
  const filterVal = $("log_filter_select").value;
  const term = $("log_terminal_container");
  if (!term) return;
  
  let filtered = rawLogsCache;
  if (filterVal === "proxy") {
    filtered = rawLogsCache.filter(l => l.module === "Proxy");
  } else if (filterVal === "vpn") {
    filtered = rawLogsCache.filter(l => l.module === "VPN");
  } else if (filterVal === "system") {
    filtered = rawLogsCache.filter(l => !["Proxy", "VPN"].includes(l.module));
  }
  
  if (filtered.length === 0) {
    term.innerHTML = `<div style="color: var(--text-secondary); text-align: center; margin-top: 150px;">暂无该类型日志。</div>`;
    return;
  }
  
  const linesHtml = filtered.map(l => {
    let color = "#a5b4fc";
    if (l.module === "Proxy") color = "#38bdf8";
    if (l.module === "VPN") color = "#34d399";
    if (l.level === "WARNING") color = "#fbbf24";
    if (l.level === "ERROR") color = "#f43f5e";
    
    return `<div style="color: ${color}; margin-bottom: 4px;">[${esc(l.timestamp)}] [${esc(l.level)}] [${esc(l.module)}] ${esc(l.message)}</div>`;
  }).join("");
  
  const isAtBottom = term.scrollHeight - term.clientHeight <= term.scrollTop + 50;
  
  term.innerHTML = linesHtml;
  
  if (isAtBottom) {
    term.scrollTop = term.scrollHeight;
  }
}

function copyLogContent() {
  const term = $("log_terminal_container");
  if (!term) return;
  
  const text = term.innerText || term.textContent;
  if (!text || text.includes("暂无今日") || text.includes("暂无该类型")) {
    alert("当前没有可供复制的日志。");
    return;
  }
  
  navigator.clipboard.writeText(text).then(() => {
    alert("日志内容已成功复制到剪贴板！");
  }).catch(err => {
    console.error("复制失败", err);
    const ta = document.createElement("textarea");
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand("copy");
    document.body.removeChild(ta);
    alert("日志内容已复制到剪贴板！");
  });
}

function exportLogContent() {
  const term = $("log_terminal_container");
  if (!term) return;
  
  const text = term.innerText || term.textContent;
  if (!text || text.includes("暂无今日") || text.includes("暂无该类型")) {
    alert("当前没有可供导出的日志。");
    return;
  }
  
  const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  const dateStr = new Date().toISOString().slice(0, 10);
  const filterVal = $("log_filter_select").value;
  a.download = `vpngate_log_${filterVal}_${dateStr}.txt`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
</script>
</body></html>"""

def check_proxy_health() -> dict[str, Any]:
    # 1. 检测代理服务端口是否在监听
    is_ipv6 = ":" in LOCAL_PROXY_HOST
    af = socket.AF_INET6 if is_ipv6 else socket.AF_INET
    s = None
    try:
        s = socket.socket(af, socket.SOCK_STREAM)
        s.settimeout(1.5)
        connect_host = LOCAL_PROXY_HOST
        if connect_host in ("::", "0.0.0.0", ""):
            connect_host = "::1" if is_ipv6 else "127.0.0.1"
        try:
            s.connect((connect_host, LOCAL_PROXY_PORT))
        except Exception as e:
            if connect_host == "::1":
                s.close()
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1.5)
                s.connect(("127.0.0.1", LOCAL_PROXY_PORT))
            else:
                raise e
    except Exception as e:
        diag = vpn_utils.diagnose_local_obstructions(LOCAL_PROXY_PORT, host=LOCAL_PROXY_HOST)
        diag_msg = diag[1] if diag else f"端口 {LOCAL_PROXY_PORT} 连接失败，原因: {e}"
        return {
            "ok": False,
            "error": f"代理服务未运行 ({diag_msg})"
        }
    finally:
        if s is not None:
            try:
                s.close()
            except Exception:
                pass

    # 2. 检测虚拟网卡 tun0 是否存在 (Linux 下)
    # 若已启用 FreeProxyDB 备援上游，则允许无 tun0（流量走上游 HTTP/SOCKS）
    tun_path = Path("/sys/class/net/tun0")
    fallback_enabled = False
    try:
        fb_raw = read_json(FALLBACK_UPSTREAM_FILE, {})
        fallback_enabled = isinstance(fb_raw, dict) and bool(fb_raw.get("enabled"))
    except Exception:
        fallback_enabled = False
    if sys.platform.startswith("linux") and not tun_path.exists() and not fallback_enabled:  # fallback skips
        return {
            "ok": False,
            "error": "[错误代码 3004] [ERR_ROUTE_DEV_NOT_FOUND] VPN 虚拟网卡 (tun0) 未启用，请确保当前已成功连接 VPN 节点"
        }

    # 3. 使用 curl 通过本地 SOCKS5 代理测试出口（Python urllib 不支持 socks5h）
    def _curl_check_ip(url: str) -> dict[str, Any] | None:
        proxy_hosts = []
        if LOCAL_PROXY_HOST == "::":
            proxy_hosts = ["[::1]", "127.0.0.1"]
        elif LOCAL_PROXY_HOST == "0.0.0.0":
            proxy_hosts = ["127.0.0.1"]
        elif ":" in LOCAL_PROXY_HOST:
            proxy_hosts = [f"[{LOCAL_PROXY_HOST}]", "127.0.0.1"]
        else:
            proxy_hosts = [LOCAL_PROXY_HOST]

        for p_host in proxy_hosts:
            fb_type = ""
            try:
                fb_raw = read_json(FALLBACK_UPSTREAM_FILE, {})
                if isinstance(fb_raw, dict) and fb_raw.get("enabled"):
                    fb_type = str(fb_raw.get("type") or fb_raw.get("protocol") or "").lower()
            except Exception:
                fb_type = ""
            if fb_type and not fb_type.startswith("socks"):
                proxy_url = f"http://{p_host}:{LOCAL_PROXY_PORT}"
            else:
                proxy_url = f"socks5h://{p_host}:{LOCAL_PROXY_PORT}"
            proxy_user, proxy_pass = proxy_server.get_proxy_credentials()
            cmd = [
                "curl", "-sS",
                "-w", "\n%{time_total} %{http_code}",
                "-x", proxy_url,
                url,
                "--max-time", "8",
                "--connect-timeout", "5",
            ]
            if proxy_user is not None and proxy_pass is not None:
                cmd.extend(["--proxy-user", f"{proxy_user}:{proxy_pass}"])
            try:
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                if res.returncode != 0:
                    continue
                lines = res.stdout.strip().splitlines()
                if len(lines) < 2:
                    continue
                ip = lines[0].strip()
                time_info = lines[-1].strip().split()
                if len(time_info) != 2:
                    continue
                total_time_str, http_code = time_info
                if http_code == "200" and ip and " " not in ip and len(ip) < 80:
                    latency_ms = int(float(total_time_str) * 1000)
                    return {"ok": True, "ip": ip, "latency_ms": latency_ms}
            except Exception:
                continue
        return None

    try:
        for url in (
            "http://api.ipify.org",
            "http://ifconfig.me/ip",
            "http://icanhazip.com",
            "http://ip.sb",
        ):
            result = _curl_check_ip(url)
            if result:
                return result

        # 此时外网测试失败，检测本地代理端口是否依然能连通
        port_still_listening = False
        test_sock = None
        try:
            test_sock = socket.socket(af, socket.SOCK_STREAM)
            test_sock.settimeout(1.0)
            connect_host = LOCAL_PROXY_HOST
            if connect_host in ("::", "0.0.0.0", ""):
                connect_host = "::1" if is_ipv6 else "127.0.0.1"
            try:
                test_sock.connect((connect_host, LOCAL_PROXY_PORT))
                port_still_listening = True
            except Exception:
                if connect_host == "::1":
                    test_sock.close()
                    test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    test_sock.settimeout(1.0)
                    test_sock.connect(("127.0.0.1", LOCAL_PROXY_PORT))
                    port_still_listening = True
        except Exception:
            pass
        finally:
            if test_sock is not None:
                try:
                    test_sock.close()
                except Exception:
                    pass

        if not port_still_listening:
            diag = vpn_utils.diagnose_local_obstructions(LOCAL_PROXY_PORT, host=LOCAL_PROXY_HOST)
            if diag:
                return {"ok": False, "error": f"出口连接测试失败 | 本机诊断结果: {diag[1]}"}

        return {"ok": False, "error": "出口连接测试失败（多个 IP 检测站点均无法连通，可能是当前节点失效）"}
    except Exception as e:
        return {"ok": False, "error": f"出口连接测试异常: {e}"}


def background_proxy_checker() -> None:
    global last_checker_heartbeat, is_connecting
    # 扫描器保留 5 分钟检测；从节点同样 5 分钟，但日志更轻
    time.sleep(60 if IS_SCANNER else 90)
    fail_streak = 0
    while True:
        last_checker_heartbeat = time.time()
        try:
            if is_connecting:
                time.sleep(5)
                continue

            res = check_proxy_health()
            if res["ok"]:
                fail_streak = 0
                set_state(
                    proxy_ok=True,
                    proxy_ip=res["ip"],
                    proxy_latency_ms=res["latency_ms"],
                    proxy_error=""
                )
                # 从节点减少成功日志噪音
                if IS_SCANNER:
                    log_to_json("INFO", "Proxy", f"代理可用，IP: {res['ip']}, 延迟: {res['latency_ms']} ms")
            else:
                fail_streak += 1
                error_msg = res.get("error", "未知错误")
                if active_openvpn_node_id:
                    print(f"[警告] {LOCAL_PROXY_PORT} 端口本地代理当前不可用！原因: {error_msg}", flush=True)
                    log_to_json("WARNING", "Proxy", f"代理不可用: {error_msg}")
                set_state(
                    proxy_ok=False,
                    proxy_ip="-",
                    proxy_latency_ms=0,
                    proxy_error=error_msg
                )

                # 连续失败 2 次再切换，避免偶发抖动
                if active_openvpn_node_id and fail_streak >= 2:
                    ui_cfg = load_ui_config()
                    routing_mode = ui_cfg.get("routing_mode", "auto")
                    if routing_mode != "fixed_ip":
                        with lock:
                            nodes = read_nodes()
                            active_node = next((n for n in nodes if n.get("id") == active_openvpn_node_id), None)
                            if active_node:
                                mark_blacklisted(active_node, f"代理连通性检测失败: {error_msg}")
                                active_node["probe_status"] = "unavailable"
                                write_json(NODES_FILE, nodes)
                        auto_switch_node()
                    try:
                        if not IS_SCANNER:
                            maybe_enable_proxy_fallback(force=True)
                    except Exception as _fb:
                        rate_limited_print("checker:fallback", f"[备援] checker 启用失败: {_fb}", 60.0)
                        fail_streak = 0
                    else:
                        print(f"[代理守护线程] 固定 IP 模式下代理不可用，正在尝试重启连接同一节点: {active_openvpn_node_id}", flush=True)
                        is_connecting = False
                        try:
                            connect_node(active_openvpn_node_id)
                        except Exception as e:
                            print(f"[代理守护线程] 重启固定节点失败: {e}", flush=True)
                        fail_streak = 0
        except Exception as e:
            print(f"[错误] 代理后台检测发生异常: {e}", flush=True)
            log_to_json("ERROR", "Proxy", f"检测守护线程发生异常: {e}")
        time.sleep(300)

def active_node_pinger() -> None:
    """扫描器保留延迟探测；从节点默认关闭以降低开销。"""
    global last_pinger_heartbeat
    if not IS_SCANNER and not env_bool("ENABLE_FOLLOWER_PINGER", False):
        while True:
            last_pinger_heartbeat = time.time()
            # 仅维持心跳，不做真实 ping
            if not active_openvpn_running():
                set_state(active_node_latency="无活动连接" if not is_connecting else "测试中...")
            time.sleep(300)
        return

    while True:
        last_pinger_heartbeat = time.time()
        try:
            if active_openvpn_running() and active_openvpn_node_id:
                nodes = read_nodes()
                node = next((n for n in nodes if n.get("id") == active_openvpn_node_id), None)
                if node:
                    ip = node.get("ip") or node.get("remote_host")
                    port = parse_int(node.get("remote_port"))
                    fallback = parse_int(node.get("ping"))
                    if ip:
                        latency = vpn_utils.ping_latency_ms(ip, port, fallback)
                        if latency > 0:
                            set_state(active_node_latency=f"{latency} ms")
                        else:
                            set_state(active_node_latency="检测超时")
                    else:
                        set_state(active_node_latency="检测超时")
                else:
                    set_state(active_node_latency="检测超时")
            elif is_connecting:
                set_state(active_node_latency="测试中...")
            else:
                set_state(active_node_latency="无活动连接")
        except Exception as e:
            print(f"[ERROR] active_node_pinger error: {e}", flush=True)
        time.sleep(300)


class Handler(BaseHTTPRequestHandler):
    def get_secret_path(self) -> str:
        ui_cfg = load_ui_config()
        return ui_cfg.get("secret_path", "EJsW2EeBo9lY")

    def is_authorized(self) -> bool:
        hub_token = self.headers.get("X-Nimbus-Hub-Token", "")
        if ENV_HUB_API_TOKEN and secrets.compare_digest(hub_token, ENV_HUB_API_TOKEN):
            return True

        ui_cfg = load_ui_config()
        pwd = ui_cfg.get("password")
        if not pwd:
            print("[Auth] 管理后台密码为空，已拒绝访问。请检查 ui_auth.json。", flush=True)
            return False
        
        cookie_header = self.headers.get("Cookie", "")
        cookies = {}
        if cookie_header:
            for item in cookie_header.split(";"):
                item = item.strip()
                if "=" in item:
                    k, v = item.split("=", 1)
                    cookies[k.strip()] = v.strip()
        
        session_token = cookies.get("session")
        if not session_token:
            return False
            
        with lock:
            exp_time = active_sessions.get(session_token)
            if exp_time is not None and exp_time > time.time():
                return True
        return False

    def validate_path(self) -> str:
        secret_path = self.get_secret_path()
        request_path = urllib.parse.urlsplit(self.path).path
        if not secret_path:
            return request_path
        if request_path == f"/{secret_path}":
            self.send_response(HTTPStatus.FOUND)
            self.send_header("Location", f"/{secret_path}/")
            self.end_headers()
            return ""
        prefix = f"/{secret_path}/"
        if request_path.startswith(prefix):
            return "/" + request_path[len(prefix):]
        self.send_response(HTTPStatus.NOT_FOUND)
        self.end_headers()
        return ""

    def log_message(self, format: str, *args: Any) -> None:
        print(f"[{self.log_date_time_string()}] {format % args}", flush=True)

    def send_bytes(
        self,
        body: bytes,
        content_type: str,
        status: HTTPStatus = HTTPStatus.OK,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if extra_headers:
            for key, value in extra_headers.items():
                self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def send_json(
        self,
        data: Any,
        status: HTTPStatus = HTTPStatus.OK,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        self.send_bytes(
            json.dumps(data, ensure_ascii=False).encode("utf-8"),
            "application/json; charset=utf-8",
            status,
            extra_headers=extra_headers,
        )

    def read_request_body(self, max_bytes: int = 65536) -> bytes:
        length = parse_int(self.headers.get("Content-Length"))
        if length < 0:
            raise ValueError("Content-Length 无效")
        if length > max_bytes:
            raise ValueError(f"请求体过大，最大允许 {max_bytes} 字节")
        return self.rfile.read(length) if length > 0 else b""

    def read_json_body(self, max_bytes: int = 65536) -> dict[str, Any]:
        body = self.read_request_body(max_bytes)
        if not body:
            return {}
        data = json.loads(body.decode("utf-8"))
        if not isinstance(data, dict):
            raise ValueError("请求 JSON 必须是对象")
        return data

    def proxy_listener_status(self) -> tuple[bool, str]:
        proxy_ok = False
        proxy_error = ""
        is_ipv6 = ":" in LOCAL_PROXY_HOST
        af = socket.AF_INET6 if is_ipv6 else socket.AF_INET
        s = None
        try:
            s = socket.socket(af, socket.SOCK_STREAM)
            s.settimeout(0.5)
            connect_host = LOCAL_PROXY_HOST
            if connect_host in ("::", "0.0.0.0", ""):
                connect_host = "::1" if is_ipv6 else "127.0.0.1"
            try:
                s.connect((connect_host, LOCAL_PROXY_PORT))
                proxy_ok = True
            except Exception:
                if connect_host == "::1":
                    s.close()
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(0.5)
                    s.connect(("127.0.0.1", LOCAL_PROXY_PORT))
                    proxy_ok = True
                else:
                    raise
        except Exception as exc:
            proxy_error = str(exc)
        finally:
            if s is not None:
                try:
                    s.close()
                except Exception:
                    pass
        return proxy_ok, proxy_error

    def health_payload(self, detailed: bool = False) -> dict[str, Any]:
        proxy_ok, proxy_error = self.proxy_listener_status()
        ovpn_active = active_openvpn_running()
        _st_h = get_state() or {}
        fallback_online = bool(_st_h.get("fallback_mode")) and bool(_st_h.get("proxy_ok"))
        payload: dict[str, Any] = {
            "ok": True,
            "service": "nimbus-vpngate",
            "ready": bool(proxy_ok and ovpn_active) or bool(fallback_online),
            "openvpn_active": ovpn_active,
            "proxy_listener_ready": proxy_ok,
        }
        if not detailed:
            return payload

        ui_cfg = load_ui_config()
        nodes = read_nodes()
        active_node = next((n for n in nodes if active_openvpn_node_id and n.get("id") == active_openvpn_node_id), None)
        state = get_state()
        shared_meta = read_json(SHARED_META_FILE, {}) if Path(SHARED_DATA_DIR).exists() else {}
        shared_age = 0
        try:
            if shared_meta.get("scanned_at"):
                shared_age = max(0, int(time.time() - float(shared_meta.get("scanned_at"))))
        except Exception:
            shared_age = 0
        payload.update(
            {
                "role": "scanner" if IS_SCANNER else "worker",
                "connection_enabled": ui_cfg.get("connection_enabled", True),
                "routing_mode": ui_cfg.get("routing_mode", "auto"),
                "force_country": ui_cfg.get("force_country", ""),
                "exclude_countries": sorted(ENV_EXCLUDE_COUNTRIES),
                "uptime_seconds": int(time.time() - server_start_time),
                "memory_rss_bytes": process_memory_rss_bytes(),
                "min_node_speed": MIN_NODE_SPEED,
                "max_node_latency_ms": MAX_NODE_LATENCY_MS,
                "max_node_sessions": MAX_NODE_SESSIONS,
                "proxy_host": LOCAL_PROXY_HOST,
                "proxy_port": LOCAL_PROXY_PORT,
                "ui_host": ui_cfg.get("host", UI_HOST),
                "ui_port": ui_cfg.get("port", UI_PORT),
                "active_node_id": active_openvpn_node_id,
                "active_country": node_country_code(active_node) if active_node else "",
                "active_ip_type": active_node.get("ip_type", "") if active_node else "",
                "proxy_ip": state.get("proxy_ip", ""),
                "proxy_latency_ms": state.get("proxy_latency_ms", 0),
                "proxy_listener_error": proxy_error,
                "shared_generation": int(shared_meta.get("generation") or 0),
                "shared_scanned_at": shared_meta.get("scanned_at") or 0,
                "shared_age_seconds": shared_age,
                "shared_node_count": int(shared_meta.get("node_count") or 0),
                "shared_available_count": int(shared_meta.get("available_count") or 0),
                "shared_country_total": shared_meta.get("country_total") or {},
                "shared_country_available": shared_meta.get("country_available") or {},
                "shared_scanning": bool(shared_meta.get("scanning")) or bool(is_scanning),
                "is_scanning": bool(is_scanning),
                "scan_progress": dict(scan_progress),
                "fallback_mode": bool((get_state() or {}).get("fallback_mode")),
                "fallback_proxy": str((get_state() or {}).get("fallback_proxy") or ""),
                "proxy_ok": (get_state() or {}).get("proxy_ok"),
                "last_check_message": str((get_state() or {}).get("last_check_message") or ""),
                "empty_region": bool((get_state() or {}).get("empty_region")),
                "region_fail_pause_until": region_fail_pause_until,
                "region_fail_streak": region_fail_streak,
            }
        )
        return payload

    def do_GET(self) -> None:
        global last_active_ping_time, last_active_latency, active_openvpn_node_id
        request_path = urllib.parse.urlsplit(self.path).path
        if request_path == "/healthz":
            self.send_json(
                self.health_payload(detailed=False),
                extra_headers={
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Methods": "GET, OPTIONS",
                },
            )
            return

        effective_path = self.validate_path()
        if effective_path == "": return
        
        if not self.is_authorized():
            # 从节点默认不提供 Web 页面，仅 API
            if effective_path in ("/", "/index.html"):
                if IS_SCANNER or env_bool("ENABLE_FOLLOWER_UI", False):
                    self.send_bytes(LOGIN_HTML.encode("utf-8"), "text/html; charset=utf-8")
                else:
                    self.send_json({
                        "ok": True,
                        "service": "nimbus-vpngate",
                        "role": "follower",
                        "ui_disabled": True,
                        "message": "Follower UI disabled. Use Hub or API.",
                    })
                return
            else:
                self.send_json({"error": "Unauthorized"}, HTTPStatus.UNAUTHORIZED)
                return

        if effective_path in ("/", "/index.html"):
            if IS_SCANNER or env_bool("ENABLE_FOLLOWER_UI", False):
                self.send_bytes(INDEX_HTML.encode("utf-8"), "text/html; charset=utf-8")
            else:
                self.send_json({
                    "ok": True,
                    "service": "nimbus-vpngate",
                    "role": "follower",
                    "ui_disabled": True,
                    "message": "Follower UI disabled. Use Hub or API.",
                })
        elif effective_path == "/api/health":
            self.send_json(self.health_payload(detailed=True))
        elif effective_path == "/api/nodes":
            ui_cfg = load_ui_config()
            nodes = read_nodes()
            active_node = next((n for n in nodes if active_openvpn_node_id and n.get("id") == active_openvpn_node_id), None)
            for n in nodes:
                n["active"] = (active_openvpn_node_id and n.get("id") == active_openvpn_node_id)
            if active_node:
                ip = active_node.get("ip") or active_node.get("remote_host")
                if ip:
                    now = time.time()
                    if now - last_active_ping_time > 15.0:
                        last_active_ping_time = now
                        def bg_ping(ip_addr: str, port: int, fallback: int) -> None:
                            global last_active_latency
                            try:
                                latency = vpn_utils.ping_latency_ms(ip_addr, port, fallback)
                                if latency > 0:
                                    last_active_latency = latency
                            except Exception:
                                pass
                        threading.Thread(
                            target=bg_ping, 
                            args=(ip, parse_int(active_node.get("remote_port")), parse_int(active_node.get("ping"))),
                            daemon=True
                        ).start()
                    if last_active_latency > 0:
                        active_node["latency_ms"] = last_active_latency
            nodes = apply_routing_filters(nodes, ui_cfg)
            nodes.sort(key=lambda n: (0 if n.get("active") else 1, node_preference_key(n)))
            stripped_nodes = []
            for n in nodes:
                stripped = n.copy()
                if "config_text" in stripped:
                    del stripped["config_text"]
                stripped_nodes.append(stripped)
            self.send_json({"nodes": stripped_nodes, "state": get_state()})
        elif effective_path.startswith("/configs/"):
            filename = urllib.parse.unquote(effective_path.removeprefix("/configs/"))
            with lock:
                nodes = read_nodes()
                node = next((n for n in nodes if Path(n.get("config_file", "")).name == filename), None)
            if node and node.get("config_text"):
                self.send_bytes(node["config_text"].encode("utf-8"), "application/x-openvpn-profile")
            else:
                self.send_json({"error": "not found"}, HTTPStatus.NOT_FOUND)
        elif effective_path == "/api/gateway_status":
            web_ui_status = {
                "name": "Web 管理服务",
                "status": "running",
                "details": f"监听地址: {load_ui_config().get('host', UI_HOST)}:{load_ui_config().get('port', UI_PORT)}",
                "error": ""
            }
            proxy_ok = False
            proxy_err = ""
            is_ipv6 = ":" in LOCAL_PROXY_HOST
            af = socket.AF_INET6 if is_ipv6 else socket.AF_INET
            s = None
            try:
                s = socket.socket(af, socket.SOCK_STREAM)
                s.settimeout(0.5)
                connect_host = LOCAL_PROXY_HOST
                if connect_host in ("::", "0.0.0.0", ""):
                    connect_host = "::1" if is_ipv6 else "127.0.0.1"
                try:
                    s.connect((connect_host, LOCAL_PROXY_PORT))
                    proxy_ok = True
                except Exception:
                    if connect_host == "::1":
                        s.close()
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.settimeout(0.5)
                        s.connect(("127.0.0.1", LOCAL_PROXY_PORT))
                        proxy_ok = True
                    else:
                        raise
            except Exception as e:
                diag = vpn_utils.diagnose_local_obstructions(LOCAL_PROXY_PORT, host=LOCAL_PROXY_HOST)
                proxy_err = diag[1] if diag else f"本地代理网关无法连通: {e}"
            finally:
                if s is not None:
                    try:
                        s.close()
                    except Exception:
                        pass
            proxy_gateway_status = {
                "name": "本地代理网关",
                "status": "running" if proxy_ok else "stopped",
                "details": f"监听地址: {LOCAL_PROXY_HOST}:{LOCAL_PROXY_PORT}",
                "error": proxy_err
            }
            ovpn_ok = active_openvpn_running()
            ovpn_err = ""
            ovpn_details = "未连接"
            if ovpn_ok:
                ovpn_details = f"已连接节点: {active_openvpn_node_id}"
                if sys.platform.startswith("linux"):
                    if not Path("/sys/class/net/tun0").exists():
                        ovpn_err = "[警告] 虚拟网卡 (tun0) 未启用，可能存在策略路由配置问题。"
            else:
                if active_openvpn_node_id:
                    ovpn_err = "连接已中断或 OpenVPN 核心程序异常退出。"
                    ovpn_details = f"尝试连接节点 {active_openvpn_node_id} 失败"
            openvpn_status = {
                "name": "OpenVPN 核心连接",
                "status": "running" if ovpn_ok else "stopped",
                "details": ovpn_details,
                "error": ovpn_err
            }
            now = time.time()
            server_uptime = now - server_start_time
            collector_ok = (last_collector_heartbeat > 0.0 and now - last_collector_heartbeat < (CHECK_INTERVAL_SECONDS * 1.5)) or (server_uptime < 15.0)
            collector_status = {
                "name": "节点同步守护线程",
                "status": "running" if collector_ok else "stopped",
                "details": f"上次心跳: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(last_collector_heartbeat)) if last_collector_heartbeat > 0 else '等待启动'}",
                "error": "" if collector_ok else "线程可能已异常终止，导致无法在后台拉取和测速新节点。"
            }
            checker_ok = (last_checker_heartbeat > 0.0 and now - last_checker_heartbeat < 450.0) or (server_uptime < 35.0)
            checker_status = {
                "name": "出口检测守护线程",
                "status": "running" if checker_ok else "stopped",
                "details": f"上次心跳: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(last_checker_heartbeat)) if last_checker_heartbeat > 0 else '等待启动'}",
                "error": "" if checker_ok else "线程可能已挂起或终止，导致无法实时获取代理出口状态。"
            }
            pinger_ok = (last_pinger_heartbeat > 0.0 and now - last_pinger_heartbeat < 450.0) or (server_uptime < 15.0)
            pinger_status = {
                "name": "延迟测速守护线程",
                "status": "running" if pinger_ok else "stopped",
                "details": f"上次心跳: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(last_pinger_heartbeat)) if last_pinger_heartbeat > 0 else '等待启动'}",
                "error": "" if pinger_ok else "线程可能已中止，无法实时刷新活动节点的 Ping 延迟。"
            }
            self.send_json({
                "ok": True,
                "services": [
                    web_ui_status,
                    proxy_gateway_status,
                    openvpn_status,
                    collector_status,
                    checker_status,
                    pinger_status
                ]
            })
        elif effective_path == "/api/logs":
            logs_dir = DATA_DIR / "logs"
            date_str = time.strftime("%Y-%m-%d", time.localtime())
            log_file = logs_dir / f"{date_str}.json"
            entries = []
            if log_file.exists():
                try:
                    with lock:
                        with open(log_file, "r", encoding="utf-8") as f:
                            for line in f:
                                line = line.strip()
                                if line:
                                    try:
                                        entries.append(json.loads(line))
                                    except Exception:
                                        pass
                except Exception as e:
                    print(f"[API Logs] Error reading log file: {e}", flush=True)
            self.send_json({"logs": entries})
        else:
            self.send_json({"error": "not found"}, HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        effective_path = self.validate_path()
        if effective_path == "": return
        
        if effective_path == "/api/login":
            try:
                payload = self.read_json_body()
                input_pwd = str(payload.get("password") or "")
                input_uname = str(payload.get("username") or "")
                
                ui_cfg = load_ui_config()
                expected_pwd = ui_cfg.get("password", "")
                expected_uname = ui_cfg.get("username", "admin")
                
                if expected_pwd and input_pwd == expected_pwd and input_uname == expected_uname:
                    token = uuid.uuid4().hex
                    with lock:
                        active_sessions[token] = time.time() + 30 * 24 * 3600
                    body = json.dumps({"ok": True}).encode("utf-8")
                    self.send_response(HTTPStatus.OK)
                    self.send_header("Content-Type", "application/json; charset=utf-8")
                    self.send_header("Content-Length", str(len(body)))
                    self.send_header("Cache-Control", "no-store")
                    secret_path = self.get_secret_path()
                    cookie_path = f"/{secret_path}/" if secret_path else "/"
                    self.send_header("Set-Cookie", f"session={token}; Path={cookie_path}; HttpOnly; SameSite=Lax; Max-Age=2592000")
                    self.end_headers()
                    self.wfile.write(body)
                else:
                    self.send_json({"ok": False, "error": "用户名或密码不正确，请重新输入"}, HTTPStatus.FORBIDDEN)
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        if effective_path == "/api/logout":
            try:
                cookie_header = self.headers.get("Cookie", "")
                cookies = {}
                if cookie_header:
                    for item in cookie_header.split(";"):
                        item = item.strip()
                        if "=" in item:
                            k, v = item.split("=", 1)
                            cookies[k.strip()] = v.strip()
                session_token = cookies.get("session")
                if session_token:
                    with lock:
                        active_sessions.pop(session_token, None)
                secret_path = self.get_secret_path()
                cookie_path = f"/{secret_path}/" if secret_path else "/"
                body = json.dumps({"ok": True}).encode("utf-8")
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("Set-Cookie", f"session=; Path={cookie_path}; HttpOnly; SameSite=Lax; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT")
                self.end_headers()
                self.wfile.write(body)
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        if not self.is_authorized():
            self.send_json({"error": "Unauthorized"}, HTTPStatus.UNAUTHORIZED)
            return

        if effective_path == "/api/update_credentials":
            try:
                payload = self.read_json_body()
                new_username = str(payload.get("username") or "").strip()
                new_password = str(payload.get("password") or "").strip()
                new_port = payload.get("port")
                new_suffix = str(payload.get("secret_path") or "").strip()
                
                ui_cfg = load_ui_config()
                if not new_username or (not new_password and not ui_cfg.get("password")):
                    self.send_json({"ok": False, "error": "用户名不能为空；首次设置时密码不能为空"}, HTTPStatus.BAD_REQUEST)
                    return
                
                try:
                    new_port_int = int(new_port)
                    if not (1 <= new_port_int <= 65535):
                        raise ValueError()
                except (TypeError, ValueError):
                    self.send_json({"ok": False, "error": "网页管理端口范围必须是 1 至 65535"}, HTTPStatus.BAD_REQUEST)
                    return

                if not new_suffix or not re.match(r"^[A-Za-z0-9]+$", new_suffix):
                    self.send_json({"ok": False, "error": "安全后缀仅能由英文字母和数字组成"}, HTTPStatus.BAD_REQUEST)
                    return

                expected_username = ui_cfg.get("username", "")
                expected_password = ui_cfg.get("password", "")
                expected_port = ui_cfg.get("port", 8787)
                expected_suffix = ui_cfg.get("secret_path", "EJsW2EeBo9lY")

                ui_cfg["username"] = new_username
                if new_password:
                    ui_cfg["password"] = new_password
                ui_cfg["port"] = new_port_int
                ui_cfg["secret_path"] = new_suffix
                
                auth_file = DATA_DIR / "ui_auth.json"
                reauth_required = new_username != expected_username or (new_password and new_password != expected_password)
                with lock:
                    DATA_DIR.mkdir(exist_ok=True, parents=True)
                    auth_file.write_text(json.dumps(ui_cfg, ensure_ascii=False, indent=2), encoding="utf-8")
                    if reauth_required:
                        active_sessions.clear()
                
                restart_needed = (new_port_int != expected_port or new_suffix != expected_suffix)
                if restart_needed:
                    self.send_json({"ok": True, "restart_needed": True, "reauth_required": reauth_required, "message": "配置更新成功，网页管理端口或路径已变更，将在 2 秒内重启..."})
                    
                    def restart_server():
                        time.sleep(2)
                        print("[系统] 管理后台安全配置更新，进程即将退出以触发自动重启...", flush=True)
                        os._exit(0)
                    
                    threading.Thread(target=restart_server, daemon=True).start()
                else:
                    self.send_json({"ok": True, "restart_needed": False, "reauth_required": reauth_required, "message": "账号密码配置更新成功，已即时生效！"})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        elif effective_path == "/api/update_settings":
            try:
                payload = self.read_json_body()
                
                new_proxy_port = payload.get("proxy_port")
                routing_mode = str(payload.get("routing_mode") or "auto").strip()
                force_country = str(payload.get("force_country") or "").strip()
                routing_ip_type = str(payload.get("routing_ip_type") or "all").strip()
                
                try:
                    new_proxy_port_int = int(new_proxy_port)
                    if not (1024 <= new_proxy_port_int <= 65535):
                        raise ValueError()
                except (TypeError, ValueError):
                    self.send_json({"ok": False, "error": "代理出站端口范围必须是 1024 至 65535"}, HTTPStatus.BAD_REQUEST)
                    return
                
                if routing_mode not in ("auto", "fixed_ip", "fixed_region", "favorites"):
                    self.send_json({"ok": False, "error": "无效的路由配置模式"}, HTTPStatus.BAD_REQUEST)
                    return
                if routing_ip_type not in ("all", "residential", "hosting"):
                    self.send_json({"ok": False, "error": "无效的IP出站类型过滤"}, HTTPStatus.BAD_REQUEST)
                    return
                
                ui_cfg = load_ui_config()
                expected_proxy_port = ui_cfg.get("proxy_port", 7928)
                
                if new_proxy_port_int == ui_cfg.get("port", 8787):
                    self.send_json({"ok": False, "error": "代理出站端口不能与网页管理端口相同"}, HTTPStatus.BAD_REQUEST)
                    return
                
                ui_cfg["proxy_port"] = new_proxy_port_int
                ui_cfg["routing_mode"] = routing_mode
                ui_cfg["force_country"] = force_country
                ui_cfg["routing_ip_type"] = routing_ip_type
                
                auth_file = DATA_DIR / "ui_auth.json"
                with lock:
                    DATA_DIR.mkdir(exist_ok=True, parents=True)
                    auth_file.write_text(json.dumps(ui_cfg, ensure_ascii=False, indent=2), encoding="utf-8")
                
                restart_needed = (new_proxy_port_int != expected_proxy_port)
                if restart_needed:
                    self.send_json({"ok": True, "restart_needed": True, "message": "配置更新成功，代理出站端口变更，将在 2 秒内重启..."})
                    
                    def restart_server():
                        time.sleep(2)
                        print("[系统] 代理出站端口变更，进程即将退出以触发自动重启...", flush=True)
                        os._exit(0)
                    
                    threading.Thread(target=restart_server, daemon=True).start()
                else:
                    self.send_json({"ok": True, "restart_needed": False, "message": "配置更新成功，已即时生效！"})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        elif effective_path == "/api/update_routing":
            try:
                payload = self.read_json_body()
                routing_mode = str(payload.get("routing_mode") or "auto").strip()
                force_country = str(payload.get("force_country") or "").strip()
                routing_ip_type = str(payload.get("routing_ip_type") or "all").strip()
                fav_fail_fallback = bool(payload.get("fav_fail_fallback", True))
                
                if routing_mode not in ("auto", "fixed_ip", "fixed_region", "favorites"):
                    self.send_json({"ok": False, "error": "无效的路由配置模式"}, HTTPStatus.BAD_REQUEST)
                    return
                if routing_ip_type not in ("all", "residential", "hosting"):
                    self.send_json({"ok": False, "error": "无效的IP出站类型过滤"}, HTTPStatus.BAD_REQUEST)
                    return
                
                ui_cfg = load_ui_config()
                ui_cfg["routing_mode"] = routing_mode
                ui_cfg["force_country"] = force_country
                ui_cfg["routing_ip_type"] = routing_ip_type
                ui_cfg["fav_fail_fallback"] = fav_fail_fallback
                ui_cfg.pop("enable_force_country", None)
                
                auth_file = DATA_DIR / "ui_auth.json"
                with lock:
                    DATA_DIR.mkdir(exist_ok=True, parents=True)
                    auth_file.write_text(json.dumps(ui_cfg, ensure_ascii=False, indent=2), encoding="utf-8")
                
                self.send_json({"ok": True, "message": "出站路由配置更新成功，已即时生效！"})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        elif effective_path == "/api/toggle_favorite":
            try:
                payload = self.read_json_body()
                node_id = str(payload.get("id") or "").strip()
                
                ui_cfg = load_ui_config()
                fav_ids = ui_cfg.get("favorite_node_ids", [])
                if not isinstance(fav_ids, list):
                    fav_ids = []
                
                if node_id in fav_ids:
                    fav_ids.remove(node_id)
                else:
                    fav_ids.append(node_id)
                
                ui_cfg["favorite_node_ids"] = fav_ids
                auth_file = DATA_DIR / "ui_auth.json"
                with lock:
                    DATA_DIR.mkdir(exist_ok=True, parents=True)
                    auth_file.write_text(json.dumps(ui_cfg, ensure_ascii=False, indent=2), encoding="utf-8")
                
                self.send_json({"ok": True, "favorite_node_ids": fav_ids})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        if effective_path in ("/api/scan", "/api/trigger_scan"):
            try:
                if not IS_SCANNER:
                    self.send_json({"ok": False, "error": "仅扫描器支持 /api/scan"}, HTTPStatus.BAD_REQUEST)
                    return
                if maintenance_lock.locked() or is_scanning:
                    self.send_json({"ok": True, "message": "扫描已在进行中", "running": True, "role": "scanner"})
                    return
                threading.Thread(target=maintain_valid_nodes, args=(False,), daemon=True).start()
                self.send_json({"ok": True, "message": "已触发扫描器扫描", "running": True, "role": "scanner"})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        if effective_path == "/api/check":
            try:
                # 从节点：强制同步共享 + 出口检测 + 必要时重连
                # 扫描器：force 重扫
                if IS_SCANNER:
                    message = maintain_valid_nodes(force=True)
                    self.send_json({"ok": True, "message": message, "role": "scanner"})
                else:
                    message = maintain_valid_nodes(force=True)
                    proxy = check_proxy_health()
                    if proxy.get("ok"):
                        set_state(
                            proxy_ok=True,
                            proxy_ip=proxy.get("ip"),
                            proxy_latency_ms=proxy.get("latency_ms"),
                            proxy_error="",
                            last_check_message=f"{message}；出口正常 {proxy.get('ip')}",
                        )
                        self.send_json({
                            "ok": True,
                            "message": f"{message}；出口正常 {proxy.get('ip')} ({proxy.get('latency_ms')} ms)",
                            "role": "follower",
                            "proxy": proxy,
                        })
                    else:
                        # 出口失败：先试 OpenVPN 切换，再强制备援
                        err = proxy.get("error") or "出口不可用"
                        set_state(proxy_ok=False, proxy_ip="-", proxy_latency_ms=0, proxy_error=err)
                        switched = False
                        try:
                            if active_openvpn_running() or active_openvpn_node_id:
                                auto_switch_node()
                                switched = True
                        except Exception as switch_exc:
                            err = f"{err}; 切换失败: {switch_exc}"
                        proxy2 = check_proxy_health()
                        if not proxy2.get("ok"):
                            try:
                                if maybe_enable_proxy_fallback(force=True):
                                    switched = True
                                    proxy2 = check_proxy_health()
                                    if proxy2.get("ok"):
                                        err = f"已切备援 {proxy2.get('ip')}"
                            except Exception as fb_exc:
                                err = f"{err}; 备援失败: {fb_exc}"
                        self.send_json({
                            "ok": bool(proxy2.get("ok")),
                            "message": (
                                f"{message}；出口失败后已尝试切换，现在: "
                                + (f"{proxy2.get('ip')} ({proxy2.get('latency_ms')} ms)" if proxy2.get("ok") else err)
                            ),
                            "role": "follower",
                            "proxy": proxy2 if proxy2.get("ok") else proxy,
                            "switched": switched,
                        })
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/refresh_nodes":
            try:
                if maintenance_lock.locked():
                    self.send_json({"ok": True, "message": "节点维护任务正在运行，请稍后再试", "running": True, "role": "scanner" if IS_SCANNER else "follower"})
                else:
                    # 从节点：前台快速同步共享；扫描器：后台重扫
                    if IS_SCANNER:
                        threading.Thread(target=maintain_valid_nodes, args=(False,), daemon=True).start()
                        self.send_json({"ok": True, "message": "已在后台启动扫描器更新流程", "running": True, "role": "scanner"})
                    else:
                        message = maintain_valid_nodes(force=True)
                        self.send_json({"ok": True, "message": message, "running": False, "role": "follower"})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        
        elif effective_path == "/api/retest_nodes":
            try:
                payload = self.read_json_body(max_bytes=262144) if self.command == "POST" else {}
                if not isinstance(payload, dict):
                    payload = {}
                ids = payload.get("ids") or []
                if not isinstance(ids, list):
                    ids = []
                ids = [str(x).strip() for x in ids if str(x).strip()]
                if not ids:
                    self.send_json({"ok": False, "error": "ids 不能为空", "message": "请选择要复测的节点"}, HTTPStatus.BAD_REQUEST)
                    return
                if len(ids) > 20:
                    ids = ids[:20]
                if not IS_SCANNER:
                    self.send_json({"ok": False, "error": "仅扫描器支持复测共享节点", "message": "仅扫描器支持复测共享节点"}, HTTPStatus.BAD_REQUEST)
                    return
                if is_scanning or maintenance_lock.locked():
                    self.send_json({"ok": False, "error": "扫描进行中", "message": "扫描/维护进行中，请稍后再试", "running": True})
                    return

                def _bg_retest(target_ids: list[str]) -> None:
                    global is_scanning, scan_progress
                    try:
                        is_scanning = True
                        scan_progress = {
                            "total": len(target_ids),
                            "tested": 0,
                            "current": "",
                            "current_list": [],
                            "started_at": time.time(),
                            "message": f"手动复测 {len(target_ids)} 个节点",
                        }
                        set_state(is_scanning=True, scan_progress=dict(scan_progress), last_check_message=scan_progress["message"])
                        try:
                            publish_scan_progress(force=True)
                        except Exception:
                            pass
                        tested = test_multiple_nodes(target_ids)
                        # merge into shared
                        try:
                            with lock:
                                local_nodes = read_nodes()
                            by_local = {str(n.get("id")): n for n in local_nodes if n.get("id")}
                            shared = read_json(SHARED_NODES_FILE, [])
                            if not isinstance(shared, list):
                                shared = []
                            by_shared = {str(n.get("id")): n for n in shared if isinstance(n, dict) and n.get("id")}
                            now = time.time()
                            for nid in target_ids:
                                src = by_local.get(nid) or by_shared.get(nid)
                                if not src:
                                    continue
                                sn = slim_shared_node(dict(src)) if "slim_shared_node" in globals() else dict(src)
                                sn["probed_at"] = float(src.get("probed_at") or now)
                                sn["probe_status"] = src.get("probe_status") or sn.get("probe_status")
                                sn["probe_message"] = src.get("probe_message") or sn.get("probe_message") or ""
                                sn["latency_ms"] = src.get("latency_ms") or sn.get("latency_ms") or 0
                                by_shared[nid] = sn
                            # write shared
                            out = list(by_shared.values())
                            tmp = Path(str(SHARED_NODES_FILE) + ".tmp")
                            write_json(tmp, out)
                            tmp.replace(SHARED_NODES_FILE)
                            meta = read_json(SHARED_META_FILE, {})
                            if not isinstance(meta, dict):
                                meta = {}
                            avail = sum(1 for n in out if n.get("probe_status") == "available")
                            meta["scanned_at"] = now
                            meta["node_count"] = len(out)
                            meta["available_count"] = avail
                            meta["check_interval_seconds"] = CHECK_INTERVAL_SECONDS
                            meta["next_scan_at"] = now + CHECK_INTERVAL_SECONDS
                            meta["scanning"] = False
                            meta["scan_progress"] = {
                                "total": len(target_ids),
                                "tested": len(target_ids),
                                "current": "done",
                                "current_list": [],
                                "message": f"手动复测完成 {len(target_ids)} 个",
                                "updated_at": now,
                            }
                            write_json(SHARED_META_FILE, meta)
                        except Exception as exc:
                            print(f"[retest] 写共享失败: {exc}", flush=True)
                    finally:
                        is_scanning = False
                        try:
                            scan_progress.update({"current": "done", "message": "手动复测完成"})
                            set_state(is_scanning=False, scan_progress=dict(scan_progress))
                            publish_scan_progress(force=True)
                        except Exception:
                            pass

                threading.Thread(target=_bg_retest, args=(ids,), daemon=True).start()
                self.send_json({
                    "ok": True,
                    "message": f"已开始复测 {len(ids)} 个节点",
                    "count": len(ids),
                    "running": True,
                })
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc), "message": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)

        elif effective_path == "/api/test_nodes":
            try:
                payload = self.read_json_body(max_bytes=262144)
                node_ids = payload.get("ids", [])
                tested_nodes = test_multiple_nodes(node_ids)
                self.send_json({"ok": True, "nodes": tested_nodes})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/disconnect":
            try:
                ui_cfg = load_ui_config()
                ui_cfg["connection_enabled"] = False
                auth_file = DATA_DIR / "ui_auth.json"
                with lock:
                    DATA_DIR.mkdir(exist_ok=True, parents=True)
                    auth_file.write_text(json.dumps(ui_cfg, ensure_ascii=False, indent=2), encoding="utf-8")
                
                stop_active_openvpn()
                try:
                    clear_fallback_upstream("manual_disconnect")
                except Exception:
                    pass
                with lock:
                    nodes = read_nodes()
                    for item in nodes:
                        item["active"] = False
                    write_json(NODES_FILE, nodes)
                global last_active_ping_time, last_active_latency
                last_active_ping_time = 0.0
                last_active_latency = 0
                set_state(
                    active_openvpn_node_id="",
                    fallback_mode=False,
                    fallback_proxy="",
                    fallback_proxy_id="",
                    proxy_ok=False,
                    proxy_ip="-",
                    last_check_message="手动断开连接",
                    active_node_latency="无活动连接",
                )
                self.send_json({"ok": True})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/connect":
            try:
                payload = self.read_json_body()
                self.send_json({"ok": True, "message": connect_node(str(payload.get("id") or ""))})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        
        elif effective_path == "/api/enable_fallback":
            try:
                self.read_request_body()
                if IS_SCANNER:
                    self.send_json({"ok": False, "error": "扫描器不支持启用区域备援", "message": "扫描器不支持启用区域备援"}, HTTPStatus.BAD_REQUEST)
                    return
                # 备援测活可能较慢：线程执行 + 超时，避免 Hub 一直转圈
                result_box: dict[str, Any] = {"done": False, "ok": False, "err": ""}
                def _run_fb() -> None:
                    try:
                        result_box["ok"] = bool(maybe_enable_proxy_fallback(force=True))
                    except Exception as exc:  # noqa: BLE001
                        result_box["err"] = str(exc)
                        result_box["ok"] = False
                    finally:
                        result_box["done"] = True
                th = threading.Thread(target=_run_fb, daemon=True)
                th.start()
                th.join(timeout=45.0)
                if not result_box["done"]:
                    st = get_state() or {}
                    self.send_json({
                        "ok": False,
                        "message": "备援切换超时（后台仍可能在继续），请稍后点刷新状态",
                        "timeout": True,
                        "fallback_mode": bool(st.get("fallback_mode")),
                        "fallback_proxy": st.get("fallback_proxy") or "",
                        "proxy_ip": st.get("proxy_ip") or "-",
                        "proxy_ok": st.get("proxy_ok"),
                    })
                    return
                st = get_state() or {}
                # 备援模式下 check_proxy_health 可能仍因无 tun0 误报，优先 state
                proxy = {}
                try:
                    proxy = check_proxy_health()
                except Exception as exc:  # noqa: BLE001
                    proxy = {"ok": False, "error": str(exc)}
                ok = bool(result_box["ok"]) or bool(st.get("fallback_mode") and st.get("proxy_ok"))
                msg = st.get("last_check_message") or result_box.get("err") or ("备援已启用" if ok else "备援启用失败（节点不可用或测活失败）")
                self.send_json({
                    "ok": ok,
                    "message": msg,
                    "fallback_mode": bool(st.get("fallback_mode")),
                    "fallback_proxy": st.get("fallback_proxy") or "",
                    "proxy_ip": st.get("proxy_ip") or proxy.get("ip") or "-",
                    "proxy_ok": st.get("proxy_ok") if st.get("proxy_ok") is not None else proxy.get("ok"),
                    "ready": bool((st.get("fallback_mode") and st.get("proxy_ok")) or (active_openvpn_running() and proxy.get("ok"))),
                    "proxy": proxy,
                    "error": None if ok else msg,
                })
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc), "message": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/disable_fallback":
            try:
                self.read_request_body()
                clear_fallback_upstream("manual_disable")
                set_state(
                    fallback_mode=False,
                    fallback_proxy="",
                    fallback_proxy_id="",
                    last_check_message="已关闭备援，可重新连接 OpenVPN",
                )
                try:
                    if hasattr(proxy_server, "_fallback_cache"):
                        proxy_server._fallback_cache["mtime"] = -1.0
                        proxy_server._fallback_cache["data"] = None
                except Exception:
                    pass
                self.send_json({"ok": True, "message": "已关闭备援"})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)

        elif effective_path == "/api/connect_best":
            try:
                result = connect_best_node()
                self.send_json({"ok": True, **result})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/test_node":
            try:
                payload = self.read_json_body()
                node_id = str(payload.get("id") or "")
                updated_node = test_node_by_id(node_id)
                self.send_json({"ok": True, "node": updated_node})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/test_proxy":
            try:
                self.read_request_body()
                result = check_proxy_health()
                if result["ok"]:
                    set_state(
                        proxy_ok=True,
                        proxy_ip=result["ip"],
                        proxy_latency_ms=result["latency_ms"],
                        proxy_error=""
                    )
                else:
                    set_state(
                        proxy_ok=False,
                        proxy_ip="-",
                        proxy_latency_ms=0,
                        proxy_error=result.get("error", "未知错误")
                    )
                self.send_json(result)
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        else:
            self.send_json({"error": "not found"}, HTTPStatus.NOT_FOUND)

class Tee:
    def __init__(self, file_path: str):
        Path(file_path).parent.mkdir(exist_ok=True, parents=True)
        self.file = open(file_path, "a", encoding="utf-8")
        self.stdout = sys.stdout

    def write(self, data: str) -> None:
        self.stdout.write(data)
        self.file.write(data)
        self.file.flush()

    def flush(self) -> None:
        self.stdout.flush()
        self.file.flush()

    def isatty(self) -> bool:
        return self.stdout.isatty()

    def __getattr__(self, attr: str) -> Any:
        return getattr(self.stdout, attr)

def main() -> None:
    ensure_dirs()
    kill_existing_openvpn_processes()
    
    log_file = DATA_DIR / "vpngate.log"
    tee = Tee(str(log_file))
    sys.stdout = tee
    sys.stderr = tee

    write_json(
        STATE_FILE,
        {
            "api_url": API_URL,
            "target_valid_nodes": TARGET_VALID_NODES,
            "fetch_interval_seconds": FETCH_INTERVAL_SECONDS,
            "check_interval_seconds": CHECK_INTERVAL_SECONDS,
            "local_proxy": f"http://{'[' + LOCAL_PROXY_HOST + ']' if ':' in LOCAL_PROXY_HOST else LOCAL_PROXY_HOST}:{LOCAL_PROXY_PORT}",
            "active_openvpn_node_id": "",
            "last_fetch_status": "starting",
            "last_check_message": "服务已启动，正在初始化网络并获取候选 VPN 节点...",
            "is_connecting": True,
            "active_node_latency": "正在准备",
            "blacklisted_nodes": 0,
        },
    )
    threading.Thread(target=proxy_server.start_proxy_server, args=(LOCAL_PROXY_HOST, LOCAL_PROXY_PORT), daemon=True).start()
    
    # Wait for the gateway to officially start
    print("[网关] 正在启动代理网关...", flush=True)
    gateway_ready = False
    is_ipv6 = ":" in LOCAL_PROXY_HOST
    af = socket.AF_INET6 if is_ipv6 else socket.AF_INET
    for _ in range(30):
        s = None
        try:
            s = socket.socket(af, socket.SOCK_STREAM)
            s.settimeout(0.5)
            connect_host = LOCAL_PROXY_HOST
            if connect_host in ("::", "0.0.0.0", ""):
                connect_host = "::1" if is_ipv6 else "127.0.0.1"
            try:
                s.connect((connect_host, LOCAL_PROXY_PORT))
                gateway_ready = True
                break
            except Exception:
                if connect_host == "::1":
                    try:
                        s.close()
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.settimeout(0.5)
                        s.connect(("127.0.0.1", LOCAL_PROXY_PORT))
                        gateway_ready = True
                        break
                    except Exception:
                        pass
                raise
        except Exception:
            time.sleep(0.5)
        finally:
            if s is not None:
                try:
                    s.close()
                except Exception:
                    pass
            
    if gateway_ready:
        print("[网关] 代理网关已成功启动监听，启动同步与检测脚本...", flush=True)
    else:
        print("[警告] 代理网关启动超时，继续执行脚本...", flush=True)

    role = "scanner" if IS_SCANNER else "follower"
    print(f"[角色] 当前容器角色: {role}", flush=True)
    threading.Thread(target=collector_loop, daemon=True).start()
    threading.Thread(target=background_proxy_checker, daemon=True).start()
    # 从节点默认启轻量 pinger（内部空转/少动作）；扫描器启完整 pinger
    threading.Thread(target=active_node_pinger, daemon=True).start()
    
    ui_cfg = load_ui_config()
    ui_host = ui_cfg.get("host", UI_HOST)
    ui_port = bounded_int(ui_cfg.get("port"), UI_PORT, 1, 65535)
    
    print(f"UI: http://{ui_host}:{ui_port}/", flush=True)
    print(f"Proxy: http://{LOCAL_PROXY_HOST}:{LOCAL_PROXY_PORT}", flush=True)
    DualStackHTTPServer((ui_host, ui_port), Handler).serve_forever()

if __name__ == "__main__":
    main()

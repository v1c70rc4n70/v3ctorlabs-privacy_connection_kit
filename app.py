#!/usr/bin/env python3
"""Desktop dashboard for local proxy, Tor and VPN profile management.

The app intentionally avoids shipping public proxy lists. Free proxies are
frequently logged, injected or unstable; import only sources you trust.
"""

from __future__ import annotations

import argparse
import base64
import csv
import dataclasses
import hashlib
import json
import math
import os
import queue
import shutil
import shlex
import socket
import stat
import subprocess
import sys
import threading
import time
import tkinter as tk
import uuid
import webbrowser
from datetime import datetime
from html import escape
from dataclasses import dataclass, field
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog, ttk
from typing import Any
from urllib.parse import urlencode
from urllib import request
from urllib.error import URLError

BRAND_NAME = "v3ctorlabs"
APP_NAME = f"{BRAND_NAME} Privacy Connection Dashboard"
STRIPE_PAYMENT_LINK_ENV = "V3CTORLABS_STRIPE_PAYMENT_LINK"
STRIPE_DASHBOARD_LINK = "https://dashboard.stripe.com/payment-links"
STRIPE_PAYMENT_METHODS = (
    "Tarjeta credito/debito · Visa / Mastercard",
    "SEPA Direct Debit · EUR",
    "Bizum · Espana · si esta habilitado en Stripe",
    "Stablecoin / USDC en red Solana · solo cuentas Stripe elegibles",
)
EXTERNAL_CRYPTO_LINK_ENVS = {
    "Bitcoin": "V3CTORLABS_BITCOIN_PAYMENT_LINK",
    "Solana": "V3CTORLABS_SOLANA_PAYMENT_LINK",
}
APP_DIR = Path.home() / ".local" / "share" / "privacy-connection-dashboard"
PAYMENT_STATE_FILE = APP_DIR / "payment-state.json"
LIFETIME_MINIMUM_EUR = 5
DEFAULT_IP_HISTORY_LIMIT = 500
CONFIG_FILE = APP_DIR / "profiles.json"
ENCRYPTED_CONFIG_FILE = APP_DIR / "profiles.enc"
SALT_FILE = APP_DIR / "salt.bin"
IP_HISTORY_FILE = APP_DIR / "ip_history.json"
MAP_HTML_FILE = APP_DIR / "public-ip-map.html"
GLOBE_HTML_FILE = APP_DIR / "ip-globe.html"
AUDIT_LOG_FILE = APP_DIR / "v3ctorlabs-registro.log"
LOCAL_TELEMETRY_FILE = APP_DIR / "local-telemetry.json"
ONBOARDING_FILE = APP_DIR / "onboarding.json"
PROXYCHAINS_CONFIG_FILE = APP_DIR / "proxychains.conf"
TOR_CONTROL_PASSWORD_FILE = APP_DIR / "tor-control-password"
TOR_COOKIE_PATHS = (
    Path("/run/tor/control.authcookie"),
    Path("/var/lib/tor/control_auth_cookie"),
    Path.home() / ".tor" / "control_auth_cookie",
)

TOR_SOCKS_PORTS = (9050, 9150)
IP_CHECK_URL = "https://api.ipify.org?format=json"

PROFILE_TYPES = (
    "http",
    "https",
    "socks4",
    "socks5",
    "tor",
    "wireguard",
    "openvpn",
)

FREE_PROXY_SOURCES = ("Todas", "HProxy", "ProxyScrape", "Litport", "Databay")
DISCOVERY_PROTOCOLS = ("all", "http", "https", "socks4", "socks5")
DISCOVERY_ANONYMITY = ("elite", "anonymous", "elite,anonymous", "all")
PROTON_MODES = ("fastest", "country", "secure-core", "tor", "p2p", "random")
PROXY_USE_CASES = (
    "Navegador rapido",
    "Terminal con env",
    "ProxyChains app",
    "Tor/torsocks",
    "VPN completa",
    "OSINT ligero",
    "Descargas aisladas",
)
CONNECTION_MODE_CONFIGS: dict[str, dict[str, str]] = {
    "default": {
        "label": "DEFAULT",
        "description": "Equilibrada: elite/anonymous, uptime 80% y latencia hasta 800 ms.",
        "anonymity": "elite,anonymous",
        "min_uptime": "80",
        "max_latency": "800",
        "protocol": "all",
    },
    "pro": {
        "label": "PRO",
        "description": "Restrictiva: prioriza elite, uptime 90% y latencia hasta 500 ms.",
        "anonymity": "elite",
        "min_uptime": "90",
        "max_latency": "500",
        "protocol": "socks5",
    },
    "aggressive": {
        "label": "AGRESIVA",
        "description": "Amplia: acepta todos los protocolos y prioriza encontrar una ruta operativa.",
        "anonymity": "all",
        "min_uptime": "60",
        "max_latency": "1500",
        "protocol": "all",
    },
}
PROXY_TYPE_GUIDE: dict[str, dict[str, str]] = {
    "HTTP": {
        "profile_type": "http",
        "protocol": "http",
        "anonymity": "anonymous",
        "use_case": "Terminal con env",
        "title": "HTTP proxy",
        "summary": "Proxy web simple. La app habla con el proxy en HTTP; el destino puede seguir usando HTTPS.",
        "best_for": "Pruebas rapidas, APIs, herramientas CLI con HTTP_PROXY y trafico no sensible.",
        "caution": "No aporta cifrado entre tu app y el proxy. Evita credenciales y sesiones personales.",
        "command_hint": "export HTTP_PROXY=http://host:puerto",
    },
    "HTTPS": {
        "profile_type": "https",
        "protocol": "https",
        "anonymity": "elite,anonymous",
        "use_case": "Navegador rapido",
        "title": "HTTPS / CONNECT",
        "summary": "Proxy HTTP con tunel CONNECT para sitios HTTPS. Comun en navegadores y clientes web.",
        "best_for": "Navegacion rapida, APIs HTTPS, comprobaciones de IP y uso general ligero.",
        "caution": "El operador ve destinos, tiempos y volumen. TLS protege el contenido hacia el sitio final.",
        "command_hint": "chromium --proxy-server=https://host:puerto",
    },
    "SOCKS4": {
        "profile_type": "socks4",
        "protocol": "socks4",
        "anonymity": "anonymous",
        "use_case": "ProxyChains app",
        "title": "SOCKS4",
        "summary": "Proxy TCP antiguo, util por compatibilidad con herramientas legacy.",
        "best_for": "Apps antiguas, pruebas de socket y cadenas simples donde SOCKS5 no esta disponible.",
        "caution": "DNS remoto y autenticacion son limitados. No es la opcion moderna recomendada.",
        "command_hint": "socks4 host puerto en proxychains.conf",
    },
    "SOCKS5": {
        "profile_type": "socks5",
        "protocol": "socks5",
        "anonymity": "elite,anonymous",
        "use_case": "ProxyChains app",
        "title": "SOCKS5 / socks5h",
        "summary": "Proxy TCP flexible. Con socks5h el DNS se resuelve por el proxy y reduce fugas.",
        "best_for": "ProxyChains, Chromium, SSH, herramientas TCP y separacion por aplicacion.",
        "caution": "No cifra por si mismo. Dependes de TLS o del protocolo de la app.",
        "command_hint": "ALL_PROXY=socks5h://host:puerto",
    },
    "Tor": {
        "profile_type": "tor",
        "protocol": "socks5",
        "anonymity": "elite",
        "use_case": "Tor/torsocks",
        "title": "Tor local",
        "summary": "Circuitos Tor con salida publica y cambio de identidad mediante NEWNYM cuando Tor lo permite.",
        "best_for": "Privacidad por aplicacion, investigacion separada de identidad personal y torsocks.",
        "caution": "No mezcles cuentas personales, cookies o perfiles de navegador reales.",
        "command_hint": "torsocks curl https://check.torproject.org/api/ip",
    },
    "WireGuard VPN": {
        "profile_type": "wireguard",
        "protocol": "all",
        "anonymity": "elite,anonymous",
        "use_case": "VPN completa",
        "title": "WireGuard VPN",
        "summary": "Tunel VPN moderno y rapido para todo el sistema cuando se importa un .conf.",
        "best_for": "Conexion completa del equipo, baja latencia y perfiles de proveedores como Proton/Surfshark.",
        "caution": "Requiere permisos del sistema y una configuracion de proveedor confiable.",
        "command_hint": "VPN facil -> elegir .conf -> nmcli connection up",
    },
    "OpenVPN": {
        "profile_type": "openvpn",
        "protocol": "all",
        "anonymity": "elite,anonymous",
        "use_case": "VPN completa",
        "title": "OpenVPN",
        "summary": "Tunel VPN muy compatible, normalmente mediante archivo .ovpn.",
        "best_for": "Proveedores VPN tradicionales, redes corporativas y compatibilidad amplia.",
        "caution": "Puede ser mas lento que WireGuard y puede pedir credenciales externas.",
        "command_hint": "VPN facil -> elegir .ovpn -> nmcli connection up",
    },
    "Transparente": {
        "profile_type": "",
        "protocol": "http",
        "anonymity": "all",
        "use_case": "OSINT ligero",
        "title": "Proxy transparente",
        "summary": "Puede reenviar cabeceras como X-Forwarded-For y revelar tu IP real.",
        "best_for": "Cache, redes internas, depuracion o pruebas donde no necesitas ocultar origen.",
        "caution": "No sirve para anonimato. Usalo solo con plena conciencia de que puede exponer tu IP.",
        "command_hint": "Selecciona anon=all solo si quieres incluirlos en busquedas.",
    },
    "Anonymous": {
        "profile_type": "",
        "protocol": "all",
        "anonymity": "anonymous",
        "use_case": "Navegador rapido",
        "title": "Anonymous",
        "summary": "Oculta tu IP real en pruebas de cabeceras, pero suele revelar que usas proxy.",
        "best_for": "Pruebas no sensibles y navegacion donde aceptas que el destino detecte proxy.",
        "caution": "No garantiza ausencia de logs, DNS leaks, WebRTC o fingerprinting.",
        "command_hint": "Filtro de busqueda: anon=anonymous",
    },
    "Elite": {
        "profile_type": "",
        "protocol": "all",
        "anonymity": "elite",
        "use_case": "OSINT ligero",
        "title": "Elite / high anonymous",
        "summary": "No muestra tu IP ni cabeceras obvias de proxy en las pruebas de la fuente.",
        "best_for": "Seleccion prioritaria cuando uses proxies gratuitos con mejor postura de privacidad.",
        "caution": "Elite no significa seguro: revisa IP visible, DNS, WebRTC y reputacion.",
        "command_hint": "Filtro de busqueda: anon=elite",
    },
    "Reverse": {
        "profile_type": "",
        "protocol": "all",
        "anonymity": "",
        "use_case": "Terminal con env",
        "title": "Reverse / proxy inverso",
        "summary": "Se coloca delante de un servidor para publicar, proteger, balancear o cachear servicios.",
        "best_for": "Nginx, Caddy, Cloudflare Tunnel, gateways internos y proteccion de backend.",
        "caution": "No anonimiza al cliente que navega; es una pieza de infraestructura de servidor.",
        "command_hint": "No se aplica como proxy cliente en este dashboard.",
    },
    "Rotativo": {
        "profile_type": "",
        "protocol": "all",
        "anonymity": "elite,anonymous",
        "use_case": "Descargas aisladas",
        "title": "Proxy rotativo",
        "summary": "Cambia IP por peticion o intervalo, segun proveedor o lista usada.",
        "best_for": "Reparto de carga, resiliencia de pruebas y separacion de sesiones temporales.",
        "caution": "Puede romper logins, elevar bloqueos y dejar trazas incoherentes.",
        "command_hint": "Busca varios proxies y alterna perfiles; Tor usa NEWNYM por intervalo.",
    },
    "Residencial": {
        "profile_type": "",
        "protocol": "all",
        "anonymity": "elite,anonymous",
        "use_case": "Navegador rapido",
        "title": "Residencial",
        "summary": "Salida por IP de ISP residencial, normalmente con mejor reputacion que datacenter.",
        "best_for": "Accesos donde la reputacion de datacenter genera falsos positivos.",
        "caution": "Usa proveedores con consentimiento claro y condiciones legales limpias.",
        "command_hint": "Importa lista del proveedor y marca notas=residencial.",
    },
    "Datacenter": {
        "profile_type": "",
        "protocol": "all",
        "anonymity": "elite,anonymous",
        "use_case": "Descargas aisladas",
        "title": "Datacenter",
        "summary": "IP de centro de datos: rapida, barata y mas facil de detectar.",
        "best_for": "Descargas, pruebas, automatizacion no sensible y comprobaciones de conectividad.",
        "caution": "Muchos servicios la bloquean o la tratan como riesgo alto.",
        "command_hint": "Filtra por velocidad y uptime, despues verifica IP visible.",
    },
}
COUNTRY_CHOICES = (
    "",
    "ES - Spain",
    "PT - Portugal",
    "FR - France",
    "DE - Germany",
    "NL - Netherlands",
    "IT - Italy",
    "GB - United Kingdom",
    "IE - Ireland",
    "CH - Switzerland",
    "SE - Sweden",
    "NO - Norway",
    "US - United States",
    "CA - Canada",
    "MX - Mexico",
    "BR - Brazil",
    "AR - Argentina",
    "CL - Chile",
    "CO - Colombia",
    "JP - Japan",
    "SG - Singapore",
    "AU - Australia",
)
LAX_DATA_PROTECTION_COUNTRIES: dict[str, str] = {
    "AF": "Sin ley integral aparente",
    "BD": "Sin ley nacional integral; borradores reportados",
    "BI": "Sin ley integral aparente",
    "CF": "Sin ley integral aparente",
    "KM": "Sin ley integral aparente",
    "DJ": "Sin ley integral aparente",
    "ER": "Sin ley integral aparente",
    "FJ": "Sin ley integral aparente",
    "HT": "Sin ley integral aparente",
    "IR": "Sin ley nacional integral",
    "IQ": "Sin ley nacional integral",
    "KI": "Sin ley integral aparente",
    "LY": "Sin ley integral aparente",
    "MH": "Sin ley integral aparente",
    "FM": "Sin ley integral aparente",
    "NR": "Sin ley integral aparente",
    "PW": "Sin ley integral aparente",
    "PK": "Sin ley nacional integral; borradores reportados",
    "PG": "Sin ley integral aparente",
    "SB": "Sin ley integral aparente",
    "SS": "Sin ley integral aparente",
    "SD": "Sin ley integral aparente",
    "SR": "Sin ley integral aparente",
    "TL": "Sin ley integral aparente",
    "TO": "Sin ley integral aparente",
    "TV": "Sin ley integral aparente",
    "US": "Regimen federal sectorial/estatal, no ley federal integral",
    "VU": "Sin ley integral aparente",
    "VE": "Sin ley integral aparente",
    "WS": "Sin ley integral aparente",
}


try:
    from cryptography.fernet import Fernet, InvalidToken
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    HAS_CRYPTOGRAPHY = True
except Exception:  # pragma: no cover - optional dependency
    Fernet = None
    InvalidToken = Exception
    PBKDF2HMAC = None
    hashes = None
    HAS_CRYPTOGRAPHY = False


def now_ms() -> int:
    return int(time.time() * 1000)


def chmod_private(path: Path) -> None:
    try:
        if path.is_dir():
            path.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
        else:
            path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass


def safe_id(prefix: str = "profile") -> str:
    return f"{prefix}-{now_ms()}-{uuid.uuid4().hex[:8]}"


def shell_join(parts: list[str]) -> str:
    return " ".join(shlex.quote(part) for part in parts)


def local_now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def parse_iso(value: str) -> datetime | None:
    try:
        return datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None


def human_duration(seconds: float) -> str:
    seconds = max(0, int(seconds))
    days, seconds = divmod(seconds, 86400)
    hours, seconds = divmod(seconds, 3600)
    minutes, seconds = divmod(seconds, 60)
    if days:
        return f"{days}d {hours}h"
    if hours:
        return f"{hours}h {minutes}m"
    if minutes:
        return f"{minutes}m {seconds}s"
    return f"{seconds}s"


def country_code(value: str) -> str:
    text = value.strip()
    if " - " in text:
        return text.split(" - ", 1)[0].strip().upper()
    return text.upper()


@dataclass
class ConnectionProfile:
    id: str
    name: str
    type: str
    host: str = ""
    port: int = 0
    country: str = ""
    source: str = ""
    provider: str = ""
    anonymity: str = ""
    uptime_pct: float | None = None
    source_latency_ms: int | None = None
    speed_label: str = ""
    last_checked: str = ""
    geo_city: str = ""
    geo_region: str = ""
    geo_country: str = ""
    geo_latitude: float | None = None
    geo_longitude: float | None = None
    geo_isp: str = ""
    geo_asn: str = ""
    geo_flags: str = ""
    geo_checked_at: str = ""
    config_path: str = ""
    status: str = "sin probar"
    latency_ms: int | None = None
    last_test: str = ""
    notes: str = ""
    active: bool = False
    created_at: int = field(default_factory=now_ms)

    @property
    def endpoint(self) -> str:
        if self.type == "tor":
            return "127.0.0.1:9050/9150"
        if self.type in {"wireguard", "openvpn"}:
            return self.config_path or "sin perfil"
        if self.host and self.port:
            return f"{self.host}:{self.port}"
        return "sin host"

    @property
    def proxy_url(self) -> str:
        if self.type == "tor":
            port = self.port or 9050
            return f"socks5h://127.0.0.1:{port}"
        if self.type in {"http", "https", "socks4", "socks5"} and self.host and self.port:
            scheme = "socks5h" if self.type == "socks5" else self.type
            return f"{scheme}://{self.host}:{self.port}"
        return ""

    @property
    def browser_proxy_url(self) -> str:
        if self.type == "tor":
            port = self.port or 9050
            return f"socks5://127.0.0.1:{port}"
        if self.type in {"socks4", "socks5"} and self.host and self.port:
            return f"{self.type}://{self.host}:{self.port}"
        if self.type in {"http", "https"} and self.host and self.port:
            return f"{self.type}://{self.host}:{self.port}"
        return ""

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "ConnectionProfile":
        values = {field.name for field in dataclasses.fields(cls)}
        filtered = {key: value for key, value in raw.items() if key in values}
        filtered.setdefault("id", safe_id())
        filtered.setdefault("name", filtered.get("host") or "Perfil")
        filtered.setdefault("type", "http")
        try:
            filtered["port"] = int(filtered.get("port") or 0)
        except (TypeError, ValueError):
            filtered["port"] = 0
        if filtered["type"] not in PROFILE_TYPES:
            filtered["type"] = "http"
        return cls(**filtered)

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


class ProfileStore:
    def __init__(self, app_dir: Path = APP_DIR) -> None:
        self.app_dir = app_dir
        self.config_file = CONFIG_FILE
        self.encrypted_file = ENCRYPTED_CONFIG_FILE
        self.salt_file = SALT_FILE
        self.app_dir.mkdir(parents=True, exist_ok=True)
        chmod_private(self.app_dir)

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        if not HAS_CRYPTOGRAPHY:
            raise RuntimeError("cryptography no esta instalado")
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=390_000,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))

    def _salt(self) -> bytes:
        if self.salt_file.exists():
            return self.salt_file.read_bytes()
        salt = os.urandom(16)
        self.salt_file.write_bytes(salt)
        chmod_private(self.salt_file)
        return salt

    def load(self, password: str | None = None) -> tuple[list[ConnectionProfile], bool, str]:
        if self.encrypted_file.exists() and HAS_CRYPTOGRAPHY and password:
            try:
                key = self._derive_key(password, self._salt())
                data = Fernet(key).decrypt(self.encrypted_file.read_bytes())
                raw = json.loads(data.decode("utf-8"))
                return [ConnectionProfile.from_dict(item) for item in raw], True, "Cargado cifrado."
            except (InvalidToken, json.JSONDecodeError, OSError) as exc:
                return [], True, f"No se pudo descifrar: {exc}"
        if CONFIG_FILE.exists():
            try:
                raw = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
                return [ConnectionProfile.from_dict(item) for item in raw], False, "Cargado sin cifrar."
            except (json.JSONDecodeError, OSError) as exc:
                return [], False, f"No se pudo cargar: {exc}"
        if self.encrypted_file.exists() and HAS_CRYPTOGRAPHY:
            if not password:
                return [], True, "Modo sin contrasena: profiles.enc existe pero no se abre automaticamente."
            try:
                key = self._derive_key(password, self._salt())
                data = Fernet(key).decrypt(self.encrypted_file.read_bytes())
                raw = json.loads(data.decode("utf-8"))
                return [ConnectionProfile.from_dict(item) for item in raw], True, "Cargado cifrado."
            except (InvalidToken, json.JSONDecodeError, OSError) as exc:
                return [], True, f"No se pudo descifrar: {exc}"
        return [], False, "Sin configuracion previa."

    def save_plain(self, profiles: list[ConnectionProfile]) -> None:
        payload = json.dumps([profile.to_dict() for profile in profiles], indent=2, sort_keys=True)
        CONFIG_FILE.write_text(payload, encoding="utf-8")
        chmod_private(CONFIG_FILE)

    def save_encrypted(self, profiles: list[ConnectionProfile], password: str) -> None:
        if not HAS_CRYPTOGRAPHY:
            raise RuntimeError("Instala cryptography para guardar cifrado: python3 -m pip install cryptography")
        key = self._derive_key(password, self._salt())
        payload = json.dumps([profile.to_dict() for profile in profiles], sort_keys=True).encode("utf-8")
        self.encrypted_file.write_bytes(Fernet(key).encrypt(payload))
        chmod_private(self.encrypted_file)
        if CONFIG_FILE.exists():
            CONFIG_FILE.unlink()


def parse_proxy_line(line: str, source: str = "") -> ConnectionProfile | None:
    text = line.strip()
    if not text or text.startswith("#"):
        return None

    protocol = "http"
    country = ""
    host = ""
    port = 0

    if "," in text:
        row = next(csv.reader([text]))
        values = [part.strip() for part in row]
        if len(values) >= 4:
            country, protocol, host, port_text = values[:4]
        elif len(values) >= 2:
            host, port_text = values[:2]
            protocol = values[2] if len(values) > 2 else protocol
        else:
            return None
    else:
        if "://" in text:
            protocol, text = text.split("://", 1)
        if "@" in text:
            text = text.rsplit("@", 1)[-1]
        if ":" not in text:
            return None
        host, port_text = text.rsplit(":", 1)

    protocol = protocol.lower().replace("socks5h", "socks5")
    if protocol not in {"http", "https", "socks4", "socks5"}:
        protocol = "http"
    try:
        port = int(port_text)
    except (TypeError, ValueError):
        return None
    if not host or not (1 <= port <= 65535):
        return None

    return ConnectionProfile(
        id=safe_id("proxy"),
        name=f"{protocol.upper()} {host}:{port}",
        type=protocol,
        host=host,
        port=port,
        country=country,
        source=source,
    )


def first_value(raw: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = raw.get(key)
        if value not in (None, ""):
            return value
    return None


def to_int(value: Any) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(float(str(value).strip().replace("ms", "")))
    except ValueError:
        return None


def to_float(value: Any) -> float | None:
    if value in (None, ""):
        return None
    try:
        return float(str(value).strip().replace("%", ""))
    except ValueError:
        return None


def speed_from_latency(latency_ms: int | None) -> str:
    if latency_ms is None:
        return ""
    if latency_ms < 500:
        return "rapido"
    if latency_ms < 1500:
        return "medio"
    return "lento"


def normalize_protocol(value: Any) -> str:
    if isinstance(value, list):
        supported = [str(item).lower() for item in value if str(item).lower() in {"http", "https", "socks4", "socks5"}]
        if "https" in supported:
            return "https"
        if "http" in supported:
            return "http"
        if "socks5" in supported:
            return "socks5"
        if "socks4" in supported:
            return "socks4"
        return ""
    protocol = str(value or "http").lower().replace("socks5h", "socks5")
    if protocol == "socks":
        protocol = "socks5"
    return protocol if protocol in {"http", "https", "socks4", "socks5"} else ""


def extract_json_rows(raw: Any) -> list[Any]:
    if isinstance(raw, list):
        return raw
    if not isinstance(raw, dict):
        return []
    for key in ("proxies", "items", "results"):
        value = raw.get(key)
        if isinstance(value, list):
            return value
    data = raw.get("data")
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ("data", "proxies", "items", "results"):
            value = data.get(key)
            if isinstance(value, list):
                return value
    return []


def profile_from_proxy_record(record: dict[str, Any], source: str = "", provider: str = "") -> ConnectionProfile | None:
    connect_string = first_value(record, "connect_string", "proxy", "server", "url")
    parsed = parse_proxy_line(str(connect_string), source=source) if connect_string else None

    host = first_value(record, "host", "ip", "address", "proxy_ip")
    port = first_value(record, "port", "proxy_port")
    protocol = first_value(record, "protocol", "type", "protocols")
    if parsed:
        host = host or parsed.host
        port = port or parsed.port
        protocol = protocol or parsed.type

    protocol_text = normalize_protocol(protocol)
    port_int = to_int(port)
    if not host or not protocol_text or port_int is None or not (1 <= port_int <= 65535):
        return None

    latency = to_int(first_value(record, "latency_ms", "latency", "responseTimeMs", "timeout", "speed_ms"))
    speed_seconds = to_float(first_value(record, "speed"))
    if latency is None and speed_seconds is not None:
        latency = int(speed_seconds * 1000)

    uptime = to_float(
        first_value(record, "uptime_pct", "uptime_percent", "uptimeRating", "uptime", "uptime_24h", "uptime_7d")
    )
    anonymity = str(first_value(record, "anonymity", "anonymityLevel", "anon") or "").lower()
    country = str(first_value(record, "country", "country_code", "geoCountry", "countryCode") or "")
    last_checked = str(first_value(record, "last_checked", "checked", "checked_at", "pingAt", "updated_at") or "")
    status = str(first_value(record, "status", "is_valid") or "sin probar")
    if status == "1" or status.lower() == "true":
        status = "fuente ok"

    return ConnectionProfile(
        id=safe_id("proxy"),
        name=f"{protocol_text.upper()} {host}:{port_int}",
        type=protocol_text,
        host=str(host),
        port=port_int,
        country=country.upper(),
        source=source,
        provider=provider,
        anonymity=anonymity,
        uptime_pct=uptime,
        source_latency_ms=latency,
        speed_label=str(first_value(record, "speed_label", "speedLabel") or speed_from_latency(latency)),
        last_checked=last_checked,
        status=status,
    )


def import_proxy_text(text: str, source: str = "", is_json: bool = False) -> list[ConnectionProfile]:
    profiles: list[ConnectionProfile] = []
    if is_json:
        raw = json.loads(text)
        for item in extract_json_rows(raw):
            if isinstance(item, str):
                profile = parse_proxy_line(item, source=source)
            elif isinstance(item, dict):
                profile = profile_from_proxy_record(item, source=source) or ConnectionProfile.from_dict(
                    {**item, "source": item.get("source") or source}
                )
            else:
                profile = None
            if profile:
                profiles.append(profile)
        return profiles

    for line in text.splitlines():
        profile = parse_proxy_line(line, source=source)
        if profile:
            profiles.append(profile)
    return profiles


def import_proxy_file(path: Path) -> list[ConnectionProfile]:
    text = path.read_text(encoding="utf-8", errors="replace")
    return import_proxy_text(text, source=str(path), is_json=path.suffix.lower() == ".json")


@dataclass
class DiscoveryOptions:
    source: str = "Todas"
    protocol: str = "all"
    country: str = ""
    anonymity: str = "elite"
    min_uptime: int = 80
    max_latency_ms: int = 1500
    limit: int = 200
    lax_data_law_only: bool = False


class FreeProxyDiscovery:
    @staticmethod
    def urls(options: DiscoveryOptions) -> list[tuple[str, str]]:
        sources = [options.source] if options.source != "Todas" else [item for item in FREE_PROXY_SOURCES if item != "Todas"]
        return [(source, FreeProxyDiscovery.url_for(source, options)) for source in sources]

    @staticmethod
    def url_for(source: str, options: DiscoveryOptions) -> str:
        protocol = "" if options.protocol == "all" else options.protocol
        anonymity = "" if options.anonymity == "all" else options.anonymity
        country = country_code(options.country)

        if source == "HProxy":
            query = {
                "format": "json",
                "protocol": protocol or "http,https,socks4,socks5",
                "min_uptime_pct": str(options.min_uptime),
                "max_latency_ms": str(options.max_latency_ms),
                "sort": "uptime",
                "limit": str(options.limit),
            }
            if anonymity:
                query["anonymity"] = anonymity
            if country:
                query["country"] = country
            return f"https://hproxy.com/api/proxy-list?{urlencode(query)}"

        if source == "ProxyScrape":
            query = {
                "request": "displayproxies",
                "format": "json",
                "proxy_format": "protocolipport",
                "protocol": protocol or "all",
                "timeout": str(options.max_latency_ms),
                "limit": str(min(options.limit, 2000)),
                "skip": "0",
            }
            if anonymity:
                query["anonymity"] = anonymity
            if country:
                query["country"] = country
            return f"https://api.proxyscrape.com/v4/free-proxy-list/get?{urlencode(query)}"

        if source == "Litport":
            query = {
                "sortBy": "responseTimeMs_asc",
                "uptimeRating": str(options.min_uptime),
                "responseTimeMs": str(options.max_latency_ms),
                "limit": str(min(options.limit, 1000)),
            }
            if protocol:
                query["protocol"] = protocol
            if anonymity and "," not in anonymity:
                query["anonymityLevel"] = anonymity
            if country:
                query["country"] = country
            return f"https://litport.net/api/free-proxy?{urlencode(query)}"

        if source == "Databay":
            query = {
                "format": "json",
            }
            if options.max_latency_ms < 500:
                query["speed"] = "fast"
            elif options.max_latency_ms < 1500:
                query["speed"] = "medium"
            if protocol:
                query["protocol"] = protocol
            if anonymity and "," not in anonymity:
                query["anonymity"] = anonymity
            if country:
                query["country"] = country
            return f"https://databay.com/api/v1/proxy-list?{urlencode(query)}"

        raise ValueError(f"Fuente no soportada: {source}")

    @staticmethod
    def fetch(options: DiscoveryOptions) -> tuple[list[ConnectionProfile], list[str]]:
        profiles: list[ConnectionProfile] = []
        errors: list[str] = []
        for provider, url in FreeProxyDiscovery.urls(options):
            try:
                req = request.Request(url, headers={"User-Agent": f"{APP_NAME}/1.0"})
                with request.urlopen(req, timeout=18) as response:
                    content_type = response.headers.get("Content-Type", "")
                    text = response.read(3_000_000).decode("utf-8", errors="replace")
                is_json = "json" in content_type or text.lstrip().startswith(("{", "["))
                found = import_proxy_text(text, source=url, is_json=is_json)
                for profile in found:
                    profile.provider = profile.provider or provider
                profiles.extend(found)
            except Exception as exc:
                errors.append(f"{provider}: {exc}")

        filtered = FreeProxyDiscovery.filter_profiles(profiles, options)
        filtered.sort(
            key=lambda item: (
                -(item.uptime_pct if item.uptime_pct is not None else -1),
                item.source_latency_ms if item.source_latency_ms is not None else 999_999,
                item.provider,
            )
        )
        return filtered[: options.limit], errors

    @staticmethod
    def filter_profiles(profiles: list[ConnectionProfile], options: DiscoveryOptions) -> list[ConnectionProfile]:
        wanted_anonymity = {item.strip() for item in options.anonymity.split(",") if item.strip()}
        if "all" in wanted_anonymity:
            wanted_anonymity = set()
        filtered = []
        seen: set[tuple[str, str, int]] = set()
        for profile in profiles:
            if options.protocol != "all" and profile.type != options.protocol:
                continue
            selected_country = country_code(options.country)
            if selected_country and profile.country.upper() != selected_country:
                continue
            if options.lax_data_law_only and not selected_country:
                if profile.country.upper() not in LAX_DATA_PROTECTION_COUNTRIES:
                    continue
            if wanted_anonymity and profile.anonymity and profile.anonymity not in wanted_anonymity:
                continue
            if profile.uptime_pct is not None and profile.uptime_pct < options.min_uptime:
                continue
            if profile.source_latency_ms is not None and profile.source_latency_ms > options.max_latency_ms:
                continue
            key = (profile.type, profile.host, profile.port)
            if key in seen:
                continue
            seen.add(key)
            filtered.append(profile)
        return filtered


@dataclass
class IpGeoSnapshot:
    ip: str
    provider: str = ""
    observed_at: str = field(default_factory=local_now_iso)
    country: str = ""
    country_code: str = ""
    region: str = ""
    city: str = ""
    district: str = ""
    neighborhood: str = ""
    street: str = ""
    road: str = ""
    square: str = ""
    postal_code: str = ""
    address_precision: str = ""
    latitude: float | None = None
    longitude: float | None = None
    timezone: str = ""
    isp: str = ""
    org: str = ""
    company: str = ""
    company_type: str = ""
    company_domain: str = ""
    network_cidr: str = ""
    asn: str = ""
    reverse_dns: str = ""
    currency: str = ""
    is_mobile: bool = False
    is_proxy: bool = False
    is_vpn: bool = False
    is_tor: bool = False
    is_hosting: bool = False
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def location_line(self) -> str:
        parts = [part for part in (self.city, self.region, self.country_code or self.country) if part]
        return ", ".join(parts) or "sin ubicacion"

    @property
    def address_line(self) -> str:
        parts = [part for part in (self.square, self.road or self.street, self.neighborhood, self.district, self.postal_code) if part]
        return " · ".join(parts) or "detalle de calle no disponible"

    @property
    def full_location_line(self) -> str:
        return f"{self.location_line} · {self.address_line}"

    @property
    def flags_line(self) -> str:
        flags = []
        if self.is_proxy:
            flags.append("proxy")
        if self.is_vpn:
            flags.append("vpn")
        if self.is_tor:
            flags.append("tor")
        if self.is_hosting:
            flags.append("hosting")
        if self.is_mobile:
            flags.append("mobile")
        return ", ".join(flags) if flags else "sin flags de anonimato"

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "IpGeoSnapshot":
        values = {field.name for field in dataclasses.fields(cls)}
        filtered = {key: value for key, value in raw.items() if key in values}
        return cls(**filtered)


class IpHistoryStore:
    def __init__(self, path: Path = IP_HISTORY_FILE) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        chmod_private(self.path.parent)

    def load(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            return raw if isinstance(raw, list) else []
        except (json.JSONDecodeError, OSError):
            return []

    def save(self, history: list[dict[str, Any]]) -> None:
        self.path.write_text(json.dumps(history, indent=2, sort_keys=True), encoding="utf-8")
        chmod_private(self.path)

    def record(self, snapshot: IpGeoSnapshot) -> tuple[list[dict[str, Any]], bool]:
        history = self.load()
        try:
            max_entries = max(10, int(os.environ.get("V3CTORLABS_MAX_IP_HISTORY", str(DEFAULT_IP_HISTORY_LIMIT))))
        except ValueError:
            max_entries = DEFAULT_IP_HISTORY_LIMIT
        changed = True
        if history and history[-1].get("ip") == snapshot.ip:
            history[-1]["last_seen"] = snapshot.observed_at
            history[-1]["observations"] = int(history[-1].get("observations") or 0) + 1
            history[-1]["snapshot"] = snapshot.to_dict()
            changed = False
        else:
            history.append(
                {
                    "ip": snapshot.ip,
                    "first_seen": snapshot.observed_at,
                    "last_seen": snapshot.observed_at,
                    "observations": 1,
                    "snapshot": snapshot.to_dict(),
                }
            )
        if len(history) > max_entries:
            history = history[-max_entries:]
        self.save(history)
        return history, changed


class IpGeoService:
    @staticmethod
    def fetch_json(url: str, timeout: float = 10.0) -> dict[str, Any]:
        req = request.Request(url, headers={"User-Agent": f"{APP_NAME}/1.0"})
        with request.urlopen(req, timeout=timeout) as response:
            return json.loads(response.read(2_000_000).decode("utf-8", errors="replace"))

    @staticmethod
    def lookup(target: str = "my") -> IpGeoSnapshot:
        target = target.strip() or "my"
        try:
            return IpGeoService.enrich_address(IpGeoService.lookup_ipaddress_to(target))
        except Exception:
            return IpGeoService.enrich_address(IpGeoService.lookup_ip_api("" if target == "my" else target))

    @staticmethod
    def lookup_ipaddress_to(target: str) -> IpGeoSnapshot:
        raw = IpGeoService.fetch_json(f"https://ipaddress.to/api/lookup/{target}")
        if not raw.get("success", True):
            raise RuntimeError(str(raw))
        location = raw.get("location") or {}
        asn = raw.get("asn") or {}
        company = raw.get("company") or {}
        return IpGeoSnapshot(
            ip=str(raw.get("ip") or ""),
            provider="IPAddress.to",
            country=str(location.get("country") or ""),
            country_code=str(location.get("country_code") or ""),
            region=str(location.get("state") or location.get("region") or ""),
            city=str(location.get("city") or ""),
            district=str(location.get("district") or ""),
            neighborhood=str(location.get("neighborhood") or location.get("neighbourhood") or ""),
            street=str(location.get("street") or ""),
            road=str(location.get("road") or ""),
            square=str(location.get("square") or ""),
            postal_code=str(location.get("postal_code") or location.get("postalCode") or location.get("zip") or ""),
            address_precision="IP provider coordinates; street fields estimated if enriched",
            latitude=to_float(location.get("latitude")),
            longitude=to_float(location.get("longitude")),
            timezone=str(location.get("timezone") or ""),
            isp=str(raw.get("isp") or asn.get("org") or company.get("name") or ""),
            org=str(asn.get("org") or company.get("name") or ""),
            company=str(company.get("name") or ""),
            company_type=str(company.get("type") or ""),
            company_domain=str(company.get("domain") or ""),
            network_cidr=str(company.get("network") or ""),
            asn=str(asn.get("asn") or ""),
            reverse_dns=str(raw.get("rdns") or ""),
            currency=str((location.get("currency") or {}).get("code") or ""),
            is_proxy=bool(raw.get("is_proxy")),
            is_vpn=bool(raw.get("is_vpn")),
            is_tor=bool(raw.get("is_tor")),
            is_hosting=bool(raw.get("is_hosting")),
            raw=raw,
        )

    @staticmethod
    def enrich_address(snapshot: IpGeoSnapshot) -> IpGeoSnapshot:
        """Add approximate OSM address labels; IP geolocation is never an exact address."""
        if snapshot.latitude is None or snapshot.longitude is None:
            return snapshot
        params = urlencode(
            {
                "format": "jsonv2",
                "lat": snapshot.latitude,
                "lon": snapshot.longitude,
                "zoom": 18,
                "addressdetails": 1,
            }
        )
        try:
            raw = IpGeoService.fetch_json(
                f"https://nominatim.openstreetmap.org/reverse?{params}", timeout=8.0
            )
            address = raw.get("address") or {}
            snapshot.district = str(address.get("city_district") or address.get("district") or snapshot.district)
            snapshot.neighborhood = str(
                address.get("neighbourhood") or address.get("suburb") or address.get("quarter") or snapshot.neighborhood
            )
            snapshot.street = str(address.get("road") or address.get("street") or snapshot.street)
            snapshot.road = str(address.get("road") or address.get("highway") or snapshot.road)
            snapshot.square = str(address.get("square") or "")
            snapshot.postal_code = str(address.get("postcode") or snapshot.postal_code)
            snapshot.address_precision = "estimada por coordenadas IP + OpenStreetMap; no es domicilio exacto"
            snapshot.raw["reverse_geocode"] = {
                "provider": "OpenStreetMap Nominatim",
                "display_name": raw.get("display_name", ""),
                "address": address,
            }
        except Exception:
            snapshot.address_precision = snapshot.address_precision or "calle/barrio no disponible"
        return snapshot


    @staticmethod
    def lookup_ip_api(target: str = "") -> IpGeoSnapshot:
        query = target.strip()
        fields = (
            "status,message,continent,continentCode,country,countryCode,region,regionName,city,"
            "district,zip,lat,lon,timezone,offset,currency,isp,org,as,asname,reverse,mobile,proxy,hosting,query"
        )
        url = f"http://ip-api.com/json/{query}?{urlencode({'fields': fields})}"
        raw = IpGeoService.fetch_json(url)
        if raw.get("status") == "fail":
            raise RuntimeError(str(raw.get("message") or raw))
        return IpGeoSnapshot(
            ip=str(raw.get("query") or ""),
            provider="ip-api.com",
            country=str(raw.get("country") or ""),
            country_code=str(raw.get("countryCode") or ""),
            region=str(raw.get("regionName") or raw.get("region") or ""),
            city=str(raw.get("city") or ""),
            district=str(raw.get("district") or ""),
            postal_code=str(raw.get("zip") or ""),
            address_precision="IP provider coordinates; street fields estimated if enriched",
            latitude=to_float(raw.get("lat")),
            longitude=to_float(raw.get("lon")),
            timezone=str(raw.get("timezone") or ""),
            isp=str(raw.get("isp") or ""),
            org=str(raw.get("org") or ""),
            company=str(raw.get("org") or ""),
            asn=str(raw.get("as") or raw.get("asname") or ""),
            reverse_dns=str(raw.get("reverse") or ""),
            currency=str(raw.get("currency") or ""),
            is_mobile=bool(raw.get("mobile")),
            is_proxy=bool(raw.get("proxy")),
            is_hosting=bool(raw.get("hosting")),
            raw=raw,
        )


class LocalNetworkService:
    """Read-only local network facts; never changes routes, Wi-Fi or DNS."""

    @staticmethod
    def _command(command: list[str], timeout: float = 3.0) -> str:
        try:
            completed = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return (completed.stdout or "").strip()
        except (OSError, subprocess.SubprocessError):
            return ""

    @staticmethod
    def snapshot() -> dict[str, Any]:
        interfaces: list[dict[str, str]] = []
        raw_addresses = LocalNetworkService._command(["ip", "-j", "address"])
        if raw_addresses:
            try:
                for item in json.loads(raw_addresses):
                    name = str(item.get("ifname") or "")
                    if not name or name == "lo":
                        continue
                    addresses = []
                    for info in item.get("addr_info") or []:
                        address = str(info.get("local") or "")
                        if address:
                            addresses.append(address)
                    interfaces.append(
                        {
                            "name": name,
                            "state": str(item.get("operstate") or "unknown"),
                            "kind": "wifi" if name.startswith(("wl", "wlan")) else "ethernet/other",
                            "addresses": ", ".join(addresses),
                        }
                    )
            except (json.JSONDecodeError, TypeError, ValueError):
                pass

        route = LocalNetworkService._command(["ip", "route", "get", "1.1.1.1"])
        route_parts = route.split()
        dev_index = route_parts.index("dev") if "dev" in route_parts else -1
        src_index = route_parts.index("src") if "src" in route_parts else -1
        route_device = route_parts[dev_index + 1] if dev_index >= 0 and dev_index + 1 < len(route_parts) else ""
        source_ip = route_parts[src_index + 1] if src_index >= 0 and src_index + 1 < len(route_parts) else ""
        ssid = LocalNetworkService._command(["iwgetid", "-r"])
        wifi_interface = next(
            (item["name"] for item in interfaces if item["kind"] == "wifi" and item["state"] == "UP"),
            "",
        )
        nmcli = LocalNetworkService._command(
            ["nmcli", "-t", "-f", "DEVICE,TYPE,STATE,CONNECTION", "device"], timeout=4.0
        )
        connections = []
        for line in nmcli.splitlines():
            fields = line.split(":")
            if len(fields) >= 4:
                connections.append(
                    {
                        "device": fields[0],
                        "type": fields[1],
                        "state": fields[2],
                        "connection": ":".join(fields[3:]),
                    }
                )
        dns_servers: list[str] = []
        try:
            for line in Path("/etc/resolv.conf").read_text(encoding="utf-8").splitlines():
                if line.startswith("nameserver "):
                    dns_servers.append(line.split(None, 1)[1].strip())
        except OSError:
            pass
        return {
            "observed_at": local_now_iso(),
            "hostname": socket.gethostname(),
            "route_device": route_device,
            "source_ip": source_ip,
            "wifi_interface": wifi_interface,
            "wifi_ssid": ssid,
            "dns_servers": dns_servers,
            "interfaces": interfaces,
            "connections": connections,
            "route_raw": route,
            "scope_note": "Proxy de app/navegador no cubre todo el PC; VPN de NetworkManager si puede cubrir toda la ruta.",
        }

    @staticmethod
    def save(snapshot: dict[str, Any]) -> None:
        try:
            APP_DIR.mkdir(parents=True, exist_ok=True)
            LOCAL_TELEMETRY_FILE.write_text(json.dumps(snapshot, indent=2, sort_keys=True), encoding="utf-8")
            chmod_private(LOCAL_TELEMETRY_FILE)
        except OSError:
            pass


class OnboardingStore:
    STEPS = (
        "telemetry",
        "public_ip",
        "profile_test",
        "scope_check",
        "fingerprint",
        "improvements",
    )

    @staticmethod
    def load() -> dict[str, Any]:
        if not ONBOARDING_FILE.exists():
            return {"sessions": 0, "completed": [], "last_seen": ""}
        try:
            raw = json.loads(ONBOARDING_FILE.read_text(encoding="utf-8"))
            return raw if isinstance(raw, dict) else {"sessions": 0, "completed": [], "last_seen": ""}
        except (OSError, json.JSONDecodeError):
            return {"sessions": 0, "completed": [], "last_seen": ""}

    @staticmethod
    def save(state: dict[str, Any]) -> None:
        try:
            APP_DIR.mkdir(parents=True, exist_ok=True)
            ONBOARDING_FILE.write_text(json.dumps(state, indent=2, sort_keys=True), encoding="utf-8")
            chmod_private(ONBOARDING_FILE)
        except OSError:
            pass


class PaymentStateStore:
    @staticmethod
    def load() -> dict[str, Any]:
        if not PAYMENT_STATE_FILE.exists():
            return {}
        try:
            raw = json.loads(PAYMENT_STATE_FILE.read_text(encoding="utf-8"))
            return raw if isinstance(raw, dict) else {}
        except (OSError, json.JSONDecodeError):
            return {}

    @staticmethod
    def save(state: dict[str, Any]) -> None:
        try:
            APP_DIR.mkdir(parents=True, exist_ok=True)
            PAYMENT_STATE_FILE.write_text(json.dumps(state, indent=2, sort_keys=True), encoding="utf-8")
            chmod_private(PAYMENT_STATE_FILE)
        except OSError:
            pass

class MapWriter:
    @staticmethod
    def snapshot_point(snapshot: IpGeoSnapshot, label: str = "IP publica") -> dict[str, Any] | None:
        if snapshot.latitude is None or snapshot.longitude is None:
            return None
        return {
            "kind": label,
            "ip": snapshot.ip,
            "lat": snapshot.latitude,
            "lon": snapshot.longitude,
            "location": snapshot.full_location_line,
            "country": snapshot.country_code or snapshot.country,
            "network": f"ASN {snapshot.asn or '-'} · {snapshot.isp or snapshot.org or '-'}",
            "flags": snapshot.flags_line,
            "seen": snapshot.observed_at,
            "precision": snapshot.address_precision,
        }

    @staticmethod
    def profile_point(profile: ConnectionProfile) -> dict[str, Any] | None:
        if profile.geo_latitude is None or profile.geo_longitude is None:
            return None
        return {
            "kind": profile.type.upper(),
            "ip": profile.host,
            "lat": profile.geo_latitude,
            "lon": profile.geo_longitude,
            "location": ", ".join(part for part in (profile.geo_city, profile.geo_region, profile.geo_country or profile.country) if part),
            "country": profile.geo_country or profile.country,
            "network": f"ASN {profile.geo_asn or '-'} · {profile.geo_isp or '-'}",
            "flags": profile.geo_flags or profile.anonymity or "-",
            "seen": profile.geo_checked_at or profile.last_checked,
        }

    @staticmethod
    def write(snapshot: IpGeoSnapshot, history: list[dict[str, Any]] | None = None) -> Path:
        lat = snapshot.latitude
        lon = snapshot.longitude
        if lat is None or lon is None:
            raise ValueError("La IP no tiene coordenadas para mapa.")
        bbox = f"{lon - 0.08},{lat - 0.05},{lon + 0.08},{lat + 0.05}"
        iframe = (
            "https://www.openstreetmap.org/export/embed.html?"
            + urlencode({"bbox": bbox, "layer": "mapnik", "marker": f"{lat},{lon}"})
        )
        rows = []
        for item in (history or [])[-25:]:
            snap = item.get("snapshot") or {}
            first_seen = item.get("first_seen", "")
            last_seen = item.get("last_seen", "")
            rows.append(
                "<tr>"
                f"<td>{escape(str(item.get('ip', '')))}</td>"
                f"<td>{escape(str(snap.get('city', '')))}</td>"
                f"<td>{escape(str(snap.get('country_code', '')))}</td>"
                f"<td>{escape(str(snap.get('region', '')))}</td>"
                f"<td>{escape(str(snap.get('neighborhood', '') or snap.get('district', '')))}</td>"
                f"<td>{escape(str(snap.get('road', '') or snap.get('street', '')))}</td>"
                f"<td>{escape(str(snap.get('isp', '') or snap.get('org', '')))}</td>"
                f"<td>{escape(str(first_seen))}</td>"
                f"<td>{escape(str(last_seen))}</td>"
                "</tr>"
            )
        html = f"""<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <title>{escape(APP_NAME)} - mapa IP</title>
  <style>
    :root {{ color-scheme: dark; }}
    body {{
      margin: 0;
      font-family: Inter, ui-sans-serif, system-ui, sans-serif;
      color: #ecfeff;
      background:
        linear-gradient(rgba(29,242,255,.05) 1px, transparent 1px),
        linear-gradient(90deg, rgba(255,79,216,.045) 1px, transparent 1px),
        radial-gradient(circle at 22% 8%, rgba(255,79,216,.25), transparent 28%),
        radial-gradient(circle at 88% 18%, rgba(66,255,191,.18), transparent 26%),
        #040711;
      background-size: 42px 42px, 42px 42px, auto, auto, auto;
    }}
    header {{ padding: 18px 22px; background: rgba(8,14,30,.86); border-bottom: 1px solid #1df2ff; box-shadow: 0 0 32px rgba(29,242,255,.18); }}
    h1 {{ font-size: 21px; margin: 0 0 4px; color: #42ffbf; text-shadow: 0 0 18px rgba(66,255,191,.35); }}
    .meta {{ color: #7be7ff; font-weight: 700; }}
    iframe {{ width: 100%; height: 64vh; border: 0; display: block; filter: contrast(1.05) saturate(1.12); }}
    section {{ padding: 16px 20px; }}
    h2 {{ color: #ff4fd8; }}
    table {{ width: 100%; border-collapse: collapse; background: rgba(7,17,31,.86); border: 1px solid rgba(29,242,255,.32); }}
    th, td {{ padding: 9px 10px; border-bottom: 1px solid rgba(123,231,255,.18); text-align: left; }}
    th {{ color: #42ffbf; background: rgba(16,26,51,.94); }}
  </style>
</head>
<body>
  <header>
    <h1>{escape(snapshot.ip)} - {escape(snapshot.full_location_line)}</h1>
    <div class="meta">{escape(snapshot.provider)} · ISP {escape(snapshot.isp)} · {escape(snapshot.flags_line)} · {escape(snapshot.address_precision)}</div>
  </header>
  <iframe src="{escape(iframe)}"></iframe>
  <section>
    <h2>Historial observado</h2>
    <table>
      <thead><tr><th>IP</th><th>Ciudad</th><th>País</th><th>Región</th><th>Barrio/distrito</th><th>Calle/carretera</th><th>ISP</th><th>Primer visto</th><th>Último visto</th></tr></thead>
      <tbody>{''.join(rows)}</tbody>
    </table>
  </section>
</body>
</html>
"""
        MAP_HTML_FILE.write_text(html, encoding="utf-8")
        chmod_private(MAP_HTML_FILE)
        return MAP_HTML_FILE

    @staticmethod
    def write_globe(points: list[dict[str, Any]], current_ip: str = "") -> Path:
        payload = json.dumps(points, ensure_ascii=True)
        point_count = len(points)
        history_count = sum(1 for point in points if point.get("kind") == "Historial")
        proxy_count = sum(1 for point in points if point.get("kind") not in {"Historial", "IP publica"})
        live_status = "LINK LIVE MAP" if current_ip else "MAPA EN ESPERA"
        rows = []
        for index, point in enumerate(points):
            opacity = str(point.get("opacity", 1))
            rows.append(
                f"<tr data-index=\"{index}\" style=\"opacity:{escape(opacity)}\">"
                f"<td>{escape(str(point.get('kind', '')))}</td>"
                f"<td>{escape(str(point.get('ip', '')))}</td>"
                f"<td>{escape(str(point.get('location', '')))}</td>"
                f"<td>{escape(str(point.get('network', '')))}</td>"
                f"<td>{escape(str(point.get('flags', '')))}</td>"
                f"<td>{escape(str(point.get('seen', '')))}</td>"
                "</tr>"
            )
        html = f"""<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{escape(APP_NAME)} - globo IP</title>
  <style>
    :root {{ color-scheme: dark; }}
    body {{
      margin: 0;
      font-family: Inter, ui-sans-serif, system-ui, sans-serif;
      background:
        linear-gradient(rgba(29,242,255,.045) 1px, transparent 1px),
        linear-gradient(90deg, rgba(255,79,216,.035) 1px, transparent 1px),
        radial-gradient(circle at 16% 12%, rgba(255,79,216,.22), transparent 30%),
        radial-gradient(circle at 82% 6%, rgba(66,255,191,.16), transparent 28%),
        #030611;
      background-size: 46px 46px, 46px 46px, auto, auto, auto;
      color: #ecfeff;
    }}
    header {{
      display: grid;
      grid-template-columns: 1fr auto;
      gap: 14px;
      align-items: center;
      padding: 18px 22px;
      background: rgba(5,8,20,.9);
      border-bottom: 1px solid rgba(29,242,255,.58);
      box-shadow: 0 0 42px rgba(29,242,255,.18);
    }}
    h1 {{ margin: 0; font-size: 24px; color: #42ffbf; text-shadow: 0 0 18px rgba(66,255,191,.42); }}
    .warning {{ margin-top: 6px; color: #ff4fd8; font-weight: 800; }}
    .live-badge {{ display: inline-block; margin-top: 10px; padding: 7px 11px; color: #06130d; background: #56ff9a; font-weight: 900; letter-spacing: .04em; box-shadow: 0 0 22px rgba(86,255,154,.5); animation: livePulse 1.4s ease-in-out infinite; }}
    @keyframes livePulse {{ 0%, 100% {{ transform: scale(1); opacity: .86; }} 50% {{ transform: scale(1.025); opacity: 1; }} }}
    .hud {{ display: flex; gap: 10px; flex-wrap: wrap; justify-content: flex-end; }}
    .metric {{ min-width: 92px; padding: 8px 10px; border: 1px solid rgba(29,242,255,.42); background: rgba(11,16,32,.74); box-shadow: inset 0 0 18px rgba(29,242,255,.08); }}
    .metric b {{ display: block; color: #42ffbf; font-size: 18px; }}
    .metric span {{ color: #7be7ff; font-size: 11px; text-transform: uppercase; letter-spacing: 0; }}
    main {{ display: grid; grid-template-columns: minmax(420px, 58vw) 1fr; min-height: calc(100vh - 96px); }}
    canvas {{ width: 100%; height: 100%; min-height: 700px; display: block; background: #02040c; cursor: grab; }}
    canvas:active {{ cursor: grabbing; }}
    aside {{
      padding: 16px;
      overflow: auto;
      border-left: 1px solid rgba(29,242,255,.42);
      background: rgba(7,17,31,.92);
      box-shadow: inset 18px 0 44px rgba(0,0,0,.28);
    }}
    #detail {{ min-height: 132px; padding: 14px; background: rgba(11,16,32,.96); border: 1px solid rgba(255,79,216,.45); margin-bottom: 14px; box-shadow: 0 0 26px rgba(255,79,216,.12); line-height: 1.45; }}
    #detail strong {{ color: #42ffbf; font-size: 16px; }}
    #map {{ width: 100%; height: 330px; border: 1px solid rgba(29,242,255,.44); margin-bottom: 14px; background: #081525; filter: saturate(1.1) contrast(1.08); }}
    a {{ color: #7be7ff; font-weight: 800; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 13px; background: rgba(5,8,20,.62); }}
    tr:hover {{ background: rgba(29,242,255,.08); }}
    th, td {{ padding: 9px 8px; border-bottom: 1px solid rgba(123,231,255,.16); text-align: left; vertical-align: top; }}
    th {{ color: #42ffbf; position: sticky; top: 0; background: #0b1020; box-shadow: 0 1px 0 rgba(29,242,255,.35); }}
    @media (max-width: 900px) {{
      header {{ grid-template-columns: 1fr; }}
      .hud {{ justify-content: flex-start; }}
      main {{ grid-template-columns: 1fr; }}
      canvas {{ min-height: 520px; }}
      aside {{ border-left: 0; border-top: 1px solid rgba(29,242,255,.42); }}
    }}
  </style>
</head>
<body>
  <header>
    <div>
      <h1>IP visible publicada: {escape(current_ip or "sin consultar")}</h1>
      <div class="live-badge">● {escape(live_status)} · GEO ROUTE ACTIVE</div>
      <div class="warning">Aviso: la IP pública visible puede exponer ubicación aproximada, ISP/ASN y señales de proxy/VPN/Tor.</div>
    </div>
    <div class="hud">
      <div class="metric"><b>{point_count}</b><span>nodos geo</span></div>
      <div class="metric"><b>{history_count}</b><span>historial</span></div>
      <div class="metric"><b>{proxy_count}</b><span>proxies</span></div>
    </div>
  </header>
  <main>
    <canvas id="globe"></canvas>
    <aside>
      <div id="detail">Pulsa un punto del globo para ver detalle.</div>
      <iframe id="map" title="Mapa con zoom"></iframe>
      <table>
        <thead><tr><th>Tipo</th><th>IP</th><th>Ubicación</th><th>Red</th><th>Flags</th><th>Visto</th></tr></thead>
        <tbody>{''.join(rows)}</tbody>
      </table>
    </aside>
  </main>
  <script>
    const points = {payload};
    const canvas = document.getElementById('globe');
    const ctx = canvas.getContext('2d');
    const detail = document.getElementById('detail');
    const map = document.getElementById('map');
    let angle = 0, tilt = -0.38, dragging = false, lastX = 0, lastY = 0, zoom = 1, hover = null;
    const stars = Array.from({{length: 220}}, (_, i) => ({{
      x: (Math.sin(i * 12.9898) * 43758.5453 % 1 + 1) % 1,
      y: (Math.sin(i * 78.233) * 24634.6345 % 1 + 1) % 1,
      r: 0.45 + ((i * 37) % 100) / 90,
      a: 0.24 + ((i * 53) % 100) / 155
    }}));
    function mapUrl(pt, span=0.18) {{
      const lat = Number(pt.lat), lon = Number(pt.lon);
      const bbox = [lon-span, lat-span*.62, lon+span, lat+span*.62].join(',');
      return 'https://www.openstreetmap.org/export/embed.html?' + new URLSearchParams({{bbox, layer:'mapnik', marker:`${{lat}},${{lon}}`}});
    }}
    function googleUrl(pt) {{
      return `https://www.google.com/maps/search/?api=1&query=${{encodeURIComponent(pt.lat + ',' + pt.lon)}}`;
    }}
    function showPoint(pt) {{
      detail.innerHTML = `<strong>${{pt.kind}} · ${{pt.ip}}</strong><br>${{pt.location}}<br>${{pt.network}}<br>${{pt.flags}}<br><small>${{pt.precision || 'precision geografica limitada'}}</small><br>${{pt.seen || ''}}<br><a href="${{googleUrl(pt)}}" target="_blank" rel="noreferrer">Abrir en Google Maps</a>`;
      map.src = mapUrl(pt);
    }}
    function resize() {{
      canvas.width = canvas.clientWidth * devicePixelRatio;
      canvas.height = canvas.clientHeight * devicePixelRatio;
      ctx.setTransform(devicePixelRatio, 0, 0, devicePixelRatio, 0, 0);
      draw();
    }}
    function project(lat, lon) {{
      const rad = Math.PI / 180;
      const phi = lat * rad, lam = lon * rad + angle;
      const x = Math.cos(phi) * Math.sin(lam);
      const y = Math.sin(phi) * Math.cos(tilt) - Math.cos(phi) * Math.cos(lam) * Math.sin(tilt);
      const z = Math.sin(phi) * Math.sin(tilt) + Math.cos(phi) * Math.cos(lam) * Math.cos(tilt);
      const r = Math.min(canvas.clientWidth, canvas.clientHeight) * 0.43 * zoom;
      return {{ x: canvas.clientWidth / 2 + x * r, y: canvas.clientHeight / 2 - y * r, z, r }};
    }}
    function drawBackdrop() {{
      ctx.fillStyle = '#02040c';
      ctx.fillRect(0, 0, canvas.clientWidth, canvas.clientHeight);
      const t = performance.now() * 0.0004;
      for (const s of stars) {{
        const px = (s.x * canvas.clientWidth + Math.sin(t + s.y * 7) * 8) % canvas.clientWidth;
        const py = s.y * canvas.clientHeight;
        ctx.globalAlpha = s.a;
        ctx.beginPath(); ctx.arc(px, py, s.r, 0, Math.PI * 2);
        ctx.fillStyle = '#dffcff'; ctx.fill();
      }}
      ctx.globalAlpha = 1;
      ctx.strokeStyle = 'rgba(29,242,255,.045)';
      ctx.lineWidth = 1;
      for (let y = 0; y < canvas.clientHeight; y += 18) {{
        ctx.beginPath(); ctx.moveTo(0, y + (t * 90 % 18)); ctx.lineTo(canvas.clientWidth, y + (t * 90 % 18)); ctx.stroke();
      }}
    }}
    function drawShell(cx, cy, r) {{
      for (let i = 4; i >= 1; i--) {{
        ctx.beginPath(); ctx.arc(cx, cy, r + i * 11, 0, Math.PI * 2);
        ctx.strokeStyle = `rgba(29,242,255,${{0.035 * i}})`;
        ctx.lineWidth = 2;
        ctx.stroke();
      }}
      const g = ctx.createRadialGradient(cx-r*.36, cy-r*.45, r*.06, cx, cy, r);
      g.addColorStop(0, '#66e7ff'); g.addColorStop(.24, '#236fb5'); g.addColorStop(.62, '#102d58'); g.addColorStop(1, '#040914');
      ctx.beginPath(); ctx.arc(cx,cy,r,0,Math.PI*2); ctx.fillStyle=g; ctx.fill();
      const night = ctx.createRadialGradient(cx+r*.48, cy+r*.08, r*.05, cx+r*.26, cy+r*.02, r*1.12);
      night.addColorStop(0, 'rgba(0,0,0,.04)'); night.addColorStop(.56, 'rgba(0,0,0,.42)'); night.addColorStop(1, 'rgba(0,0,0,.78)');
      ctx.beginPath(); ctx.arc(cx,cy,r,0,Math.PI*2); ctx.fillStyle=night; ctx.fill();
      ctx.strokeStyle = '#1df2ff'; ctx.lineWidth = 2.4; ctx.shadowBlur = 18; ctx.shadowColor = '#1df2ff'; ctx.stroke(); ctx.shadowBlur = 0;
    }}
    function drawReticle(cx, cy, r) {{
      ctx.strokeStyle = 'rgba(255,79,216,.38)';
      ctx.lineWidth = 1;
      ctx.setLineDash([8, 10]);
      ctx.beginPath(); ctx.arc(cx, cy, r * 1.14, 0, Math.PI * 2); ctx.stroke();
      ctx.setLineDash([]);
      ctx.strokeStyle = 'rgba(66,255,191,.42)';
      for (let i = 0; i < 4; i++) {{
        const a = performance.now() * 0.00028 + i * Math.PI / 2;
        ctx.beginPath();
        ctx.arc(cx, cy, r * (1.02 + i * .035), a, a + .58);
        ctx.stroke();
      }}
      ctx.fillStyle = 'rgba(66,255,191,.92)';
      ctx.font = '700 12px Inter, system-ui';
      ctx.fillText('v3ctorlabs geo-core', cx - r, cy + r + 28);
      ctx.fillStyle = 'rgba(123,231,255,.78)';
      ctx.fillText('drag rotate · wheel zoom · click node', cx - r, cy + r + 46);
    }}
    function drawGrid(r, cx, cy) {{
      ctx.strokeStyle = 'rgba(160,199,245,.22)';
      ctx.lineWidth = 1;
      for (let lat=-60; lat<=60; lat+=30) {{
        ctx.beginPath();
        for (let lon=-180; lon<=180; lon+=4) {{
          const p = project(lat, lon);
          if (p.z < -0.15) continue;
          if (lon === -180) ctx.moveTo(p.x,p.y); else ctx.lineTo(p.x,p.y);
        }}
        ctx.stroke();
      }}
      for (let lon=-150; lon<=180; lon+=30) {{
        ctx.beginPath();
        let started = false;
        for (let lat=-80; lat<=80; lat+=3) {{
          const p = project(lat, lon);
          if (p.z < -0.15) {{ started = false; continue; }}
          if (!started) {{ ctx.moveTo(p.x,p.y); started = true; }} else ctx.lineTo(p.x,p.y);
        }}
        ctx.stroke();
      }}
    }}
    function draw() {{
      drawBackdrop();
      const cx = canvas.clientWidth/2, cy = canvas.clientHeight/2;
      const r = Math.min(canvas.clientWidth, canvas.clientHeight) * 0.43 * zoom;
      points.forEach(pt => pt._screen = {{visible:false}});
      drawShell(cx,cy,r);
      drawGrid(r,cx,cy);
      const visible = [];
      points.forEach((pt, i) => {{
        const p = project(Number(pt.lat), Number(pt.lon));
        if (p.z < 0) return;
        pt._screen = {{x:p.x,y:p.y,z:p.z,visible:true,i}};
        visible.push(pt);
      }});
      const origin = visible.find(pt => pt.kind === 'IP publica') || visible[0];
      if (origin && origin._screen) {{
        const pulse = (performance.now() % 1800) / 1800;
        for (const pt of visible) {{
          if (pt === origin || !pt._screen) continue;
          const alpha = 0.1 + 0.35 * Math.min(origin._screen.z, pt._screen.z);
          ctx.strokeStyle = `rgba(29,242,255,${{alpha}})`;
          ctx.lineWidth = pt.kind === 'Historial' ? 1 : 1.6;
          ctx.beginPath();
          const mx = (origin._screen.x + pt._screen.x) / 2;
          const my = (origin._screen.y + pt._screen.y) / 2 - r * (.08 + pulse * .08);
          ctx.moveTo(origin._screen.x, origin._screen.y);
          ctx.quadraticCurveTo(mx, my, pt._screen.x, pt._screen.y);
          ctx.stroke();
        }}
      }}
      visible.forEach((pt, i) => {{
        const p = pt._screen;
        const pulse = 1 + Math.sin(performance.now() * 0.004 + i) * 0.22;
        const base = pt.kind === 'IP publica' ? 8 : pt.kind === 'Historial' ? 4 : 5;
        const size = base * pulse;
        ctx.globalAlpha = Number(pt.opacity ?? 1);
        ctx.beginPath(); ctx.arc(p.x,p.y,size+8,0,Math.PI*2);
        ctx.fillStyle = pt.kind === 'IP publica' ? 'rgba(255,79,216,.12)' : 'rgba(29,242,255,.10)';
        ctx.fill();
        ctx.beginPath(); ctx.arc(p.x,p.y,size,0,Math.PI*2);
        ctx.fillStyle = pt.kind === 'IP publica' ? '#ff4fd8' : pt.kind === 'Historial' ? '#8a96aa' : '#42ffbf';
        ctx.shadowBlur = 22; ctx.shadowColor = ctx.fillStyle; ctx.fill(); ctx.shadowBlur = 0;
        ctx.globalAlpha = 1;
        if (pt === hover) {{
          ctx.strokeStyle = '#ffffff'; ctx.lineWidth = 2;
          ctx.beginPath(); ctx.arc(p.x,p.y,size+9,0,Math.PI*2); ctx.stroke();
        }}
      }});
      drawReticle(cx, cy, r);
    }}
    function tick() {{ if (!dragging) angle += 0.0025; draw(); requestAnimationFrame(tick); }}
    canvas.addEventListener('mousedown', e => {{ dragging = true; lastX = e.clientX; lastY = e.clientY; }});
    addEventListener('mouseup', () => dragging = false);
    canvas.addEventListener('mousemove', e => {{
      const rect = canvas.getBoundingClientRect();
      const x = e.clientX - rect.left, y = e.clientY - rect.top;
      hover = null;
      for (const pt of points) {{
        if (!pt._screen || !pt._screen.visible) continue;
        if (Math.hypot(pt._screen.x - x, pt._screen.y - y) < 18) {{ hover = pt; break; }}
      }}
      if (!dragging) return;
      angle += (e.clientX - lastX) * 0.006;
      tilt = Math.max(-0.9, Math.min(0.65, tilt + (e.clientY - lastY) * 0.004));
      lastX = e.clientX; lastY = e.clientY; draw();
    }});
    canvas.addEventListener('wheel', e => {{
      e.preventDefault();
      zoom = Math.max(.72, Math.min(1.7, zoom + (e.deltaY < 0 ? .06 : -.06)));
      draw();
    }}, {{passive:false}});
    canvas.addEventListener('click', e => {{
      const rect = canvas.getBoundingClientRect();
      const x = e.clientX - rect.left, y = e.clientY - rect.top;
      let hit = null, dist = 999;
      for (const pt of points) {{
        if (!pt._screen || !pt._screen.visible) continue;
        const d = Math.hypot(pt._screen.x - x, pt._screen.y - y);
        if (d < 16 && d < dist) {{ hit = pt; dist = d; }}
      }}
      if (hit) showPoint(hit);
    }});
    document.querySelectorAll('tbody tr').forEach(row => row.addEventListener('click', () => {{
      const pt = points[Number(row.dataset.index)];
      if (pt) showPoint(pt);
    }}));
    addEventListener('resize', resize);
    resize(); if (points[0]) showPoint(points[0]); tick();
  </script>
</body>
</html>
"""
        GLOBE_HTML_FILE.write_text(html, encoding="utf-8")
        chmod_private(GLOBE_HTML_FILE)
        return GLOBE_HTML_FILE


class TorController:
    @staticmethod
    def saved_password() -> str:
        try:
            if TOR_CONTROL_PASSWORD_FILE.exists():
                return TOR_CONTROL_PASSWORD_FILE.read_text(encoding="utf-8").strip()
        except OSError:
            return ""
        return ""

    @staticmethod
    def cookie_auth_hex() -> str:
        for path in TOR_COOKIE_PATHS:
            try:
                if path.exists():
                    return path.read_bytes().hex()
            except OSError:
                continue
        return ""

    @staticmethod
    def signal_newnym(host: str = "127.0.0.1", port: int = 9051, password: str = "") -> tuple[bool, str]:
        password = password or TorController.saved_password()
        try:
            with socket.create_connection((host, port), timeout=5.0) as sock:
                reader = sock.makefile("rwb", buffering=0)
                cookie_hex = "" if password else TorController.cookie_auth_hex()
                if password:
                    auth = f'AUTHENTICATE "{password}"\r\n'
                elif cookie_hex:
                    auth = f"AUTHENTICATE {cookie_hex}\r\n"
                else:
                    auth = "AUTHENTICATE\r\n"
                reader.write(auth.encode("utf-8"))
                response = reader.readline().decode("utf-8", errors="replace").strip()
                if not response.startswith("250"):
                    return False, f"AUTH falló: {response}"
                reader.write(b"SIGNAL NEWNYM\r\n")
                response = reader.readline().decode("utf-8", errors="replace").strip()
                if not response.startswith("250"):
                    return False, f"NEWNYM falló: {response}"
                return True, "Tor recibió SIGNAL NEWNYM"
        except OSError as exc:
            return False, f"No conecta con Tor ControlPort {host}:{port}: {exc}"


class ConnectionTester:
    @staticmethod
    def test_socket(host: str, port: int, timeout: float = 5.0) -> tuple[bool, int | None, str]:
        start = time.monotonic()
        try:
            with socket.create_connection((host, port), timeout=timeout):
                latency = int((time.monotonic() - start) * 1000)
                return True, latency, "Socket accesible"
        except OSError as exc:
            return False, None, str(exc)

    @staticmethod
    def test_http_proxy(profile: ConnectionProfile, timeout: float = 8.0) -> tuple[bool, int | None, str]:
        if not profile.proxy_url:
            return False, None, "Perfil sin proxy_url"
        start = time.monotonic()
        opener = request.build_opener(
            request.ProxyHandler({"http": profile.proxy_url, "https": profile.proxy_url})
        )
        req = request.Request(IP_CHECK_URL, headers={"User-Agent": f"{APP_NAME}/1.0"})
        try:
            with opener.open(req, timeout=timeout) as response:
                body = response.read(256).decode("utf-8", errors="replace")
                latency = int((time.monotonic() - start) * 1000)
                return True, latency, f"IP externa: {body}"
        except URLError as exc:
            return False, None, f"Fallo HTTP: {exc}"
        except OSError as exc:
            return False, None, f"Fallo red: {exc}"

    @staticmethod
    def test_tor() -> tuple[bool, int | None, str]:
        results = []
        for port in TOR_SOCKS_PORTS:
            ok, latency, detail = ConnectionTester.test_socket("127.0.0.1", port, timeout=2.0)
            results.append((port, ok, latency, detail))
            if ok:
                return True, latency, f"Tor SOCKS local activo en 127.0.0.1:{port}"
        return False, None, "; ".join(f"{port}: {detail}" for port, _, _, detail in results)

    @staticmethod
    def test_profile(profile: ConnectionProfile) -> tuple[bool, int | None, str]:
        if profile.type in {"http", "https"}:
            return ConnectionTester.test_http_proxy(profile)
        if profile.type in {"socks4", "socks5"}:
            return ConnectionTester.test_socket(profile.host, profile.port)
        if profile.type == "tor":
            return ConnectionTester.test_tor()
        if profile.type in {"wireguard", "openvpn"}:
            path = Path(profile.config_path).expanduser()
            if path.exists():
                return True, None, f"Perfil encontrado: {path}"
            return False, None, "No existe el archivo de configuracion VPN"
        return False, None, "Tipo no soportado"


class CommandBuilder:
    @staticmethod
    def proxy_environment(profile: ConnectionProfile) -> str:
        if not profile.proxy_url:
            return "# Este perfil no expone proxy_url"
        proxy = shlex.quote(profile.proxy_url)
        return "\n".join(
            [
                f"export HTTP_PROXY={proxy}",
                f"export HTTPS_PROXY={proxy}",
                f"export ALL_PROXY={proxy}",
                "export NO_PROXY=localhost,127.0.0.1,::1",
            ]
        )

    @staticmethod
    def browser_command(profile: ConnectionProfile) -> str:
        if not profile.browser_proxy_url:
            return "# Este perfil no se puede pasar como proxy a Chromium"
        return shell_join(["chromium", f"--proxy-server={profile.browser_proxy_url}"])

    @staticmethod
    def proxychains_line(profile: ConnectionProfile) -> str:
        if profile.type == "tor":
            return f"socks5 127.0.0.1 {profile.port or 9050}"
        if profile.type in {"http", "https"} and profile.host and profile.port:
            return f"http {profile.host} {profile.port}"
        if profile.type in {"socks4", "socks5"} and profile.host and profile.port:
            return f"{profile.type} {profile.host} {profile.port}"
        return "# Perfil no compatible con ProxyChains"

    @staticmethod
    def proxychains_snippet(profile: ConnectionProfile) -> str:
        return "\n".join(
            [
                f"# {PROXYCHAINS_CONFIG_FILE}",
                "strict_chain",
                "proxy_dns",
                "tcp_read_time_out 15000",
                "tcp_connect_time_out 8000",
                "[ProxyList]",
                CommandBuilder.proxychains_line(profile),
            ]
        )

    @staticmethod
    def proxychains_command(profile: ConnectionProfile) -> str:
        if not profile.proxy_url:
            return "# Perfil no compatible con ProxyChains"
        return shell_join(["proxychains4", "-f", str(PROXYCHAINS_CONFIG_FILE), "chromium"])

    @staticmethod
    def torsocks_command(profile: ConnectionProfile) -> str:
        if profile.type != "tor":
            return "# torsocks/torify solo aplica a perfiles Tor"
        return "\n".join(
            [
                shell_join(["torsocks", "curl", "https://check.torproject.org/api/ip"]),
                shell_join(["torify", "curl", "https://check.torproject.org/api/ip"]),
            ]
        )

    @staticmethod
    def vpn_up(profile: ConnectionProfile) -> str:
        path = str(Path(profile.config_path).expanduser())
        if profile.type == "wireguard":
            return shell_join(["pkexec", "wg-quick", "up", path])
        if profile.type == "openvpn":
            return shell_join(["pkexec", "openvpn", "--config", path])
        return "# No es un perfil VPN"

    @staticmethod
    def vpn_down(profile: ConnectionProfile) -> str:
        path = str(Path(profile.config_path).expanduser())
        if profile.type == "wireguard":
            return shell_join(["pkexec", "wg-quick", "down", path])
        if profile.type == "openvpn":
            return "# OpenVPN se detiene cerrando el proceso lanzado"
        return "# No es un perfil VPN"


class Dashboard(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title(APP_NAME)
        self.geometry("1440x980")
        self.minsize(1180, 820)
        self.store = ProfileStore()
        self.profiles: list[ConnectionProfile] = []
        self.selected_id: str | None = None
        self.task_queue: queue.Queue[tuple[str, Any]] = queue.Queue()
        self.active_process: subprocess.Popen[str] | None = None
        self.ip_history_store = IpHistoryStore()
        self.current_snapshot: IpGeoSnapshot | None = None
        self.local_snapshot: dict[str, Any] = {}
        self.onboarding_state = OnboardingStore.load()
        self.payment_state = PaymentStateStore.load()
        self.tor_rotation_active = False
        self.globe_angle = 0.0
        self.connection_phase = 0.0
        self.connection_mode = "default"
        self.connection_live = False
        self.recent_log_lines: list[str] = []

        self._configure_theme()
        self._build_ui()
        self._load_initial()
        self.after(150, self._drain_queue)
        self.after(80, self.animate_dashboard_globe)

    def _configure_theme(self) -> None:
        self.configure(bg="#050814")
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("TFrame", background="#050814")
        style.configure("TLabel", background="#050814", foreground="#d9faff")
        style.configure("TButton", padding=(10, 6), background="#111a33", foreground="#ecfeff", bordercolor="#1df2ff")
        style.map(
            "TButton",
            background=[("active", "#162a4f"), ("pressed", "#091020")],
            foreground=[("active", "#42ffbf")],
        )
        style.configure("TEntry", fieldbackground="#07111f", foreground="#ecfeff", insertcolor="#ecfeff")
        style.configure("TCombobox", fieldbackground="#07111f", background="#101a33", foreground="#ecfeff")
        style.configure(
            "Treeview",
            rowheight=30,
            font=("Inter", 10),
            background="#07111f",
            fieldbackground="#07111f",
            foreground="#dffcff",
            bordercolor="#1df2ff",
        )
        style.configure(
            "Treeview.Heading",
            font=("Inter", 10, "bold"),
            background="#101a33",
            foreground="#42ffbf",
            bordercolor="#ff4fd8",
        )
        style.map("Treeview", background=[("selected", "#33205f")], foreground=[("selected", "#ffffff")])
        style.configure("Panel.TFrame", background="#0b1020", relief="solid", borderwidth=1, bordercolor="#1df2ff")
        style.configure("Header.TLabel", background="#050814", foreground="#42ffbf", font=("Inter", 18, "bold"))
        style.configure("Muted.TLabel", background="#050814", foreground="#7be7ff")
        style.configure("Status.TLabel", background="#0b1020", foreground="#ff4fd8", font=("Inter", 10, "bold"))
        style.configure("Alert.TLabel", background="#1b0d2b", foreground="#ff4fd8", font=("Inter", 17, "bold"))
        style.configure("AlertSub.TLabel", background="#1b0d2b", foreground="#42ffbf", font=("Inter", 10, "bold"))
        style.configure("Success.TLabel", background="#062b20", foreground="#42ffbf", font=("Inter", 17, "bold"))
        style.configure("SuccessSub.TLabel", background="#062b20", foreground="#b8ffe8", font=("Inter", 10, "bold"))
        style.configure("TCheckbutton", background="#0b1020", foreground="#d9faff")
        style.map("TCheckbutton", background=[("active", "#111a33")], foreground=[("active", "#42ffbf")])
        self.apply_connection_palette("default", live=False)

    def apply_connection_palette(self, mode: str, live: bool = False) -> None:
        palettes = {
            "default": {
                "root": "#050814", "panel": "#0b1020", "field": "#07111f", "canvas": "#02040c",
                "text": "#d9faff", "muted": "#7be7ff", "accent": "#42ffbf", "secondary": "#1df2ff",
                "alert_bg": "#1b0d2b", "alert": "#ff4fd8",
            },
            "pro": {
                "root": "#07110d", "panel": "#0b1d18", "field": "#0a1715", "canvas": "#020a08",
                "text": "#e6fff1", "muted": "#9ee8bf", "accent": "#b7ff4a", "secondary": "#4dffc8",
                "alert_bg": "#182610", "alert": "#d7ff57",
            },
            "aggressive": {
                "root": "#140806", "panel": "#24100c", "field": "#170b09", "canvas": "#080302",
                "text": "#fff0e6", "muted": "#ffb38a", "accent": "#ff7a45", "secondary": "#ffbd4a",
                "alert_bg": "#32100d", "alert": "#ff5364",
            },
        }
        palette = palettes.get(mode, palettes["default"])
        if live:
            palette = dict(palette)
            palette["accent"] = "#56ff9a"
            palette["secondary"] = "#9dffcf"
            palette["alert_bg"] = "#063322"
            palette["alert"] = "#56ff9a"
        self.configure(bg=palette["root"])
        style = ttk.Style(self)
        style.configure("TFrame", background=palette["root"])
        style.configure("TLabel", background=palette["root"], foreground=palette["text"])
        style.configure("TButton", background=palette["panel"], foreground=palette["text"], bordercolor=palette["secondary"])
        style.map("TButton", background=[("active", palette["alert_bg"]), ("pressed", palette["field"])], foreground=[("active", palette["accent"])])
        style.configure("TEntry", fieldbackground=palette["field"], foreground=palette["text"], insertcolor=palette["text"])
        style.configure("TCombobox", fieldbackground=palette["field"], background=palette["panel"], foreground=palette["text"])
        style.configure("Treeview", background=palette["field"], fieldbackground=palette["field"], foreground=palette["text"], bordercolor=palette["secondary"])
        style.configure("Treeview.Heading", background=palette["panel"], foreground=palette["accent"], bordercolor=palette["alert"])
        style.map("Treeview", background=[("selected", palette["alert_bg"])], foreground=[("selected", "#ffffff")])
        style.configure("Panel.TFrame", background=palette["panel"], bordercolor=palette["secondary"])
        style.configure("Header.TLabel", background=palette["root"], foreground=palette["accent"])
        style.configure("Muted.TLabel", background=palette["root"], foreground=palette["muted"])
        style.configure("Status.TLabel", background=palette["panel"], foreground=palette["alert"])
        style.configure("Alert.TLabel", background=palette["alert_bg"], foreground=palette["alert"])
        style.configure("AlertSub.TLabel", background=palette["alert_bg"], foreground=palette["accent"])
        style.configure("Success.TLabel", background="#063322", foreground="#56ff9a")
        style.configure("SuccessSub.TLabel", background="#063322", foreground="#b8ffe8")
        style.configure("TCheckbutton", background=palette["panel"], foreground=palette["text"])
        style.map("TCheckbutton", background=[("active", palette["alert_bg"])], foreground=[("active", palette["accent"])])
        self.palette = palette
        if hasattr(self, "globe_canvas"):
            self.globe_canvas.configure(bg=palette["canvas"])
        if hasattr(self, "console"):
            self.console.configure(bg=palette["field"], fg=palette["accent"], insertbackground=palette["alert"])

    def _build_ui(self) -> None:
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)

        header = ttk.Frame(self, padding=(18, 14, 18, 6))
        header.grid(row=0, column=0, sticky="ew")
        header.columnconfigure(0, weight=1)

        ttk.Label(header, text=APP_NAME, style="Header.TLabel").grid(row=0, column=0, sticky="w")
        self.crypto_label = ttk.Label(header, text="", style="Muted.TLabel")
        self.crypto_label.grid(row=1, column=0, sticky="w", pady=(3, 0))

        toolbar = ttk.Frame(header)
        toolbar.grid(row=0, column=1, rowspan=2, sticky="e")
        ttk.Button(toolbar, text="Importar proxies", command=self.import_proxies).grid(row=0, column=0, padx=4)
        ttk.Button(toolbar, text="Importar URL", command=self.import_proxy_url).grid(row=0, column=1, padx=4)
        ttk.Button(toolbar, text="Probar seleccionado", command=self.test_selected).grid(row=0, column=2, padx=4)
        ttk.Button(toolbar, text="Activar perfil", command=self.activate_selected).grid(row=0, column=3, padx=4)
        ttk.Button(toolbar, text="Guardar", command=self.save_plain).grid(row=0, column=4, padx=4)
        self.connection_mode_var = tk.StringVar(value="MODO DEFAULT · listo")
        ttk.Label(toolbar, textvariable=self.connection_mode_var, style="Status.TLabel").grid(
            row=1, column=0, columnspan=2, sticky="e", padx=4, pady=(6, 0)
        )
        ttk.Button(toolbar, text="Default 1-click", command=lambda: self.quick_connect("default")).grid(
            row=1, column=2, padx=4, pady=(6, 0)
        )
        ttk.Button(toolbar, text="Pro 1-click", command=lambda: self.quick_connect("pro")).grid(
            row=1, column=3, padx=4, pady=(6, 0)
        )
        ttk.Button(toolbar, text="Agresiva 1-click", command=lambda: self.quick_connect("aggressive")).grid(
            row=1, column=4, padx=4, pady=(6, 0)
        )

        body = ttk.Frame(self, padding=(18, 8, 18, 18))
        body.grid(row=1, column=0, sticky="nsew")
        body.columnconfigure(0, weight=3)
        body.columnconfigure(1, weight=2)
        body.rowconfigure(0, weight=1)

        left = ttk.Frame(body, style="Panel.TFrame", padding=10)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        left.rowconfigure(1, weight=1)
        left.columnconfigure(0, weight=1)

        discovery = ttk.Frame(left, padding=(0, 0, 0, 10))
        discovery.grid(row=0, column=0, columnspan=2, sticky="ew")
        discovery.columnconfigure(1, weight=1)
        discovery.columnconfigure(5, weight=1)
        discovery.columnconfigure(8, weight=1)

        self.discovery_fields: dict[str, tk.Variable] = {
            "source": tk.StringVar(value="Todas"),
            "protocol": tk.StringVar(value="all"),
            "country": tk.StringVar(),
            "anonymity": tk.StringVar(value="elite,anonymous"),
            "min_uptime": tk.StringVar(value="80"),
            "max_latency": tk.StringVar(value="800"),
            "limit": tk.StringVar(value="100"),
            "lax_data_law_only": tk.BooleanVar(value=False),
        }

        ttk.Label(discovery, text="Fuente").grid(row=0, column=0, sticky="w", padx=(0, 5))
        ttk.Combobox(
            discovery,
            textvariable=self.discovery_fields["source"],
            values=FREE_PROXY_SOURCES,
            state="readonly",
            width=12,
        ).grid(row=0, column=1, sticky="ew", padx=(0, 8))
        ttk.Label(discovery, text="Protocolo").grid(row=0, column=2, sticky="w", padx=(0, 5))
        ttk.Combobox(
            discovery,
            textvariable=self.discovery_fields["protocol"],
            values=DISCOVERY_PROTOCOLS,
            state="readonly",
            width=9,
        ).grid(row=0, column=3, sticky="w", padx=(0, 8))
        ttk.Label(discovery, text="Pais").grid(row=0, column=4, sticky="w", padx=(0, 5))
        ttk.Combobox(
            discovery,
            textvariable=self.discovery_fields["country"],
            values=COUNTRY_CHOICES,
            width=16,
        ).grid(
            row=0, column=5, sticky="ew", padx=(0, 8)
        )
        ttk.Button(discovery, text="Mapa pais", command=self.open_country_map).grid(row=0, column=6, sticky="ew", padx=(0, 8))
        ttk.Label(discovery, text="Anon").grid(row=0, column=7, sticky="w", padx=(0, 5))
        ttk.Combobox(
            discovery,
            textvariable=self.discovery_fields["anonymity"],
            values=DISCOVERY_ANONYMITY,
            state="readonly",
            width=14,
        ).grid(row=0, column=8, sticky="ew", padx=(0, 8))

        ttk.Label(discovery, text="Uptime %").grid(row=1, column=0, sticky="w", pady=(8, 0), padx=(0, 5))
        ttk.Entry(discovery, textvariable=self.discovery_fields["min_uptime"], width=8).grid(
            row=1, column=1, sticky="w", pady=(8, 0), padx=(0, 8)
        )
        ttk.Label(discovery, text="Max ms").grid(row=1, column=2, sticky="w", pady=(8, 0), padx=(0, 5))
        ttk.Entry(discovery, textvariable=self.discovery_fields["max_latency"], width=8).grid(
            row=1, column=3, sticky="w", pady=(8, 0), padx=(0, 8)
        )
        ttk.Label(discovery, text="Limite").grid(row=1, column=4, sticky="w", pady=(8, 0), padx=(0, 5))
        ttk.Entry(discovery, textvariable=self.discovery_fields["limit"], width=8).grid(
            row=1, column=5, sticky="w", pady=(8, 0), padx=(0, 8)
        )
        ttk.Button(discovery, text="Buscar proxies gratis", command=self.fetch_free_proxies).grid(
            row=1, column=6, columnspan=2, sticky="ew", pady=(8, 0), padx=(0, 5)
        )
        ttk.Button(discovery, text="Defaults rapidos", command=self.set_fast_defaults).grid(
            row=1, column=8, sticky="ew", pady=(8, 0)
        )
        ttk.Checkbutton(
            discovery,
            text="Solo paises con proteccion de datos laxa/sin ley integral",
            variable=self.discovery_fields["lax_data_law_only"],
        ).grid(row=2, column=0, columnspan=9, sticky="w", pady=(8, 0))

        columns = (
            "active",
            "name",
            "type",
            "endpoint",
            "country",
            "law_risk",
            "anonymity",
            "uptime",
            "source_latency",
            "provider",
            "status",
            "latency",
        )
        self.tree = ttk.Treeview(left, columns=columns, show="headings", selectmode="browse")
        headings = {
            "active": "Act.",
            "name": "Nombre",
            "type": "Tipo",
            "endpoint": "Destino",
            "country": "Pais",
            "law_risk": "Ley datos",
            "anonymity": "Anon",
            "uptime": "Uptime",
            "source_latency": "Fuente ms",
            "provider": "Proveedor",
            "status": "Estado",
            "latency": "Test ms",
        }
        widths = {
            "active": 46,
            "name": 170,
            "type": 76,
            "endpoint": 170,
            "country": 56,
            "law_risk": 78,
            "anonymity": 86,
            "uptime": 72,
            "source_latency": 82,
            "provider": 96,
            "status": 110,
            "latency": 72,
        }
        for col in columns:
            self.tree.heading(col, text=headings[col])
            self.tree.column(col, width=widths[col], minwidth=widths[col], stretch=col in {"name", "endpoint"})
        self.tree.grid(row=1, column=0, sticky="nsew")
        self.tree.bind("<<TreeviewSelect>>", self.on_select)

        scrollbar = ttk.Scrollbar(left, orient="vertical", command=self.tree.yview)
        scrollbar.grid(row=1, column=1, sticky="ns")
        self.tree.configure(yscrollcommand=scrollbar.set)

        action_row = ttk.Frame(left, padding=(0, 10, 0, 0))
        action_row.grid(row=2, column=0, columnspan=2, sticky="ew")
        ttk.Button(action_row, text="Nuevo", command=self.new_profile).pack(side="left", padx=(0, 6))
        ttk.Button(action_row, text="Duplicar Tor", command=self.add_tor_profile).pack(side="left", padx=6)
        ttk.Button(action_row, text="Eliminar", command=self.delete_selected).pack(side="left", padx=6)
        ttk.Button(action_row, text="Guia proxies", command=self.show_proxy_guide).pack(side="left", padx=6)
        ttk.Button(action_row, text="Todos tipos", command=self.apply_all_proxy_types).pack(side="left", padx=6)
        ttk.Button(action_row, text="Guia inicial", command=self.show_first_use_guide).pack(side="left", padx=6)
        ttk.Button(action_row, text="PC / Wi-Fi", command=self.show_local_telemetry).pack(side="left", padx=6)
        ttk.Button(action_row, text="Comandos", command=self.show_commands).pack(side="right")

        right = ttk.Frame(body, padding=0)
        right.grid(row=0, column=1, sticky="nsew")
        right.rowconfigure(2, weight=1)
        right.columnconfigure(0, weight=1)

        ip_panel = ttk.Frame(right, style="Panel.TFrame", padding=12)
        ip_panel.grid(row=0, column=0, sticky="ew")
        ip_panel.columnconfigure(1, weight=1)
        ip_panel.columnconfigure(3, weight=1)
        ip_panel.columnconfigure(4, weight=0)
        self.ip_vars: dict[str, tk.Variable] = {
            "ip": tk.StringVar(value="IP publica: sin consultar"),
            "public_notice": tk.StringVar(value="PUBLICANDO AHORA: esta es la IP que ven webs y servicios externos."),
            "location": tk.StringVar(value="Ubicacion: sin consultar"),
            "network": tk.StringVar(value="Red: sin consultar"),
            "flags": tk.StringVar(value="Flags: sin consultar"),
            "since_change": tk.StringVar(value="Desde cambio: -"),
            "anon_state": tk.StringVar(value="ANON OFF - IP REAL VISIBLE"),
            "tor_interval": tk.StringVar(value="10"),
            "tor_control_port": tk.StringVar(value="9051"),
            "proton_mode": tk.StringVar(value="fastest"),
            "vpn_country": tk.StringVar(),
            "surfshark_location": tk.StringVar(),
            "proxy_use": tk.StringVar(value="Navegador rapido"),
        }
        self.local_vars: dict[str, tk.Variable] = {
            "summary": tk.StringVar(value="PC / Wi-Fi: recopilando telemetria local..."),
            "scope": tk.StringVar(value="Alcance: pendiente de comprobar"),
        }
        self.ip_alert_label = ttk.Label(ip_panel, textvariable=self.ip_vars["ip"], style="Alert.TLabel", padding=(10, 8))
        self.ip_alert_label.grid(
            row=0, column=0, columnspan=4, sticky="ew"
        )
        self.ip_alert_sub_label = ttk.Label(
            ip_panel,
            textvariable=self.ip_vars["public_notice"],
            style="AlertSub.TLabel",
            padding=(10, 4),
        )
        self.ip_alert_sub_label.grid(row=1, column=0, columnspan=4, sticky="ew")
        ttk.Label(ip_panel, textvariable=self.ip_vars["location"]).grid(row=2, column=0, columnspan=4, sticky="w", pady=(4, 0))
        ttk.Label(ip_panel, textvariable=self.ip_vars["network"]).grid(row=3, column=0, columnspan=4, sticky="w", pady=(3, 0))
        ttk.Label(ip_panel, textvariable=self.ip_vars["flags"]).grid(row=4, column=0, columnspan=4, sticky="w", pady=(3, 0))
        ttk.Label(ip_panel, textvariable=self.ip_vars["since_change"]).grid(row=5, column=0, columnspan=4, sticky="w", pady=(3, 8))
        ttk.Button(ip_panel, text="Refrescar IP", command=self.refresh_public_ip).grid(row=6, column=0, sticky="ew", padx=(0, 5))
        ttk.Button(ip_panel, text="Mapa IP", command=self.open_public_ip_map).grid(row=6, column=1, sticky="ew", padx=5)
        ttk.Button(ip_panel, text="Globo IPs", command=self.open_ip_globe).grid(row=6, column=2, sticky="ew", padx=5)
        ttk.Button(ip_panel, text="Historial IP", command=self.show_ip_history).grid(row=6, column=3, sticky="ew", padx=(5, 0))
        ttk.Button(ip_panel, text="Geo IP seleccionada", command=self.lookup_selected_profile_ip).grid(row=7, column=0, sticky="ew", pady=(6, 0), padx=(0, 5))
        ttk.Button(ip_panel, text="Detalle conexion", command=self.show_connection_detail).grid(row=7, column=1, sticky="ew", pady=(6, 0), padx=5)
        ttk.Button(ip_panel, text="Conectar Tor", command=self.connect_tor_fast).grid(row=7, column=2, sticky="ew", pady=(6, 0), padx=5)
        ttk.Button(ip_panel, text="VPN facil", command=self.vpn_easy_connect).grid(row=7, column=3, sticky="ew", pady=(6, 0), padx=(5, 0))
        ttk.Label(ip_panel, text="Rotar Tor min").grid(row=8, column=0, sticky="w", pady=(9, 0))
        ttk.Entry(ip_panel, textvariable=self.ip_vars["tor_interval"], width=6).grid(row=8, column=1, sticky="w", pady=(9, 0))
        ttk.Label(ip_panel, text="ControlPort").grid(row=8, column=2, sticky="e", pady=(9, 0), padx=(8, 5))
        ttk.Entry(ip_panel, textvariable=self.ip_vars["tor_control_port"], width=7).grid(row=8, column=3, sticky="w", pady=(9, 0))
        ttk.Button(ip_panel, text="NEWNYM", command=self.rotate_tor_once).grid(row=9, column=2, sticky="ew", pady=(6, 0), padx=5)
        ttk.Button(ip_panel, text="Auto Tor on/off", command=self.toggle_tor_rotation).grid(
            row=9, column=3, sticky="ew", pady=(6, 0), padx=(5, 0)
        )
        self.anon_state_label = ttk.Label(ip_panel, textvariable=self.ip_vars["anon_state"], style="Alert.TLabel", padding=(10, 6))
        self.anon_state_label.grid(
            row=10, column=0, columnspan=4, sticky="ew", pady=(10, 0)
        )
        ttk.Label(ip_panel, text="Uso").grid(row=11, column=0, sticky="w", pady=(8, 0))
        ttk.Combobox(
            ip_panel,
            textvariable=self.ip_vars["proxy_use"],
            values=PROXY_USE_CASES,
            state="readonly",
            width=16,
        ).grid(row=11, column=1, sticky="ew", pady=(8, 0), padx=(0, 5))
        ttk.Button(ip_panel, text="Aplicar uso", command=self.apply_proxy_use).grid(row=11, column=2, sticky="ew", pady=(8, 0), padx=5)
        ttk.Button(ip_panel, text="Anon OFF", command=self.disconnect_anonymous).grid(row=11, column=3, sticky="ew", pady=(8, 0), padx=(5, 0))
        ttk.Label(ip_panel, text="Proton").grid(row=12, column=0, sticky="w", pady=(8, 0))
        ttk.Combobox(
            ip_panel,
            textvariable=self.ip_vars["proton_mode"],
            values=PROTON_MODES,
            state="readonly",
            width=12,
        ).grid(row=12, column=1, sticky="ew", pady=(8, 0), padx=(0, 5))
        ttk.Entry(ip_panel, textvariable=self.ip_vars["vpn_country"], width=7).grid(
            row=12, column=2, sticky="ew", pady=(8, 0), padx=5
        )
        ttk.Button(ip_panel, text="Proton ON/OFF", command=self.toggle_proton).grid(row=12, column=3, sticky="ew", pady=(8, 0), padx=(5, 0))
        ttk.Label(ip_panel, text="Surfshark").grid(row=13, column=0, sticky="w", pady=(8, 0))
        ttk.Entry(ip_panel, textvariable=self.ip_vars["surfshark_location"]).grid(
            row=13, column=1, columnspan=2, sticky="ew", pady=(8, 0), padx=(0, 5)
        )
        ttk.Button(ip_panel, text="Surfshark ON/OFF", command=self.toggle_surfshark).grid(
            row=13, column=3, sticky="ew", pady=(8, 0), padx=(5, 0)
        )
        ttk.Label(ip_panel, textvariable=self.local_vars["summary"], style="Muted.TLabel").grid(
            row=14, column=0, columnspan=4, sticky="w", pady=(10, 0)
        )
        ttk.Label(ip_panel, textvariable=self.local_vars["scope"], style="Muted.TLabel").grid(
            row=15, column=0, columnspan=4, sticky="w", pady=(3, 0)
        )
        ttk.Button(ip_panel, text="Huella digital", command=self.show_fingerprint_report).grid(
            row=16, column=0, columnspan=2, sticky="ew", pady=(8, 0), padx=(0, 5)
        )
        ttk.Button(ip_panel, text="Aplicar mejoras", command=self.apply_all_improvements).grid(
            row=16, column=2, columnspan=2, sticky="ew", pady=(8, 0), padx=(5, 0)
        )
        self.live_map_button = ttk.Button(ip_panel, text="MAPA LINK LIVE", command=self.open_live_map)
        self.live_map_button.grid(row=17, column=0, columnspan=4, sticky="ew", pady=(8, 0))
        self.globe_canvas = tk.Canvas(ip_panel, width=230, height=230, bg="#07111f", highlightthickness=0)
        self.globe_canvas.grid(row=0, column=4, rowspan=18, sticky="nse", padx=(12, 0))

        editor = ttk.Frame(right, style="Panel.TFrame", padding=16)
        editor.grid(row=1, column=0, sticky="ew", pady=(10, 0))
        editor.columnconfigure(1, weight=1)

        self.fields: dict[str, tk.Variable] = {
            "name": tk.StringVar(),
            "type": tk.StringVar(value="http"),
            "host": tk.StringVar(),
            "port": tk.StringVar(),
            "country": tk.StringVar(),
            "anonymity": tk.StringVar(),
            "uptime_pct": tk.StringVar(),
            "source_latency_ms": tk.StringVar(),
            "provider": tk.StringVar(),
            "config_path": tk.StringVar(),
            "source": tk.StringVar(),
            "notes": tk.StringVar(),
        }

        self._label_entry(editor, 0, "Nombre", "name")
        ttk.Label(editor, text="Tipo").grid(row=1, column=0, sticky="w", pady=5)
        ttk.Combobox(editor, textvariable=self.fields["type"], values=PROFILE_TYPES, state="readonly").grid(
            row=1, column=1, sticky="ew", pady=5
        )
        self._label_entry(editor, 2, "Host", "host")
        self._label_entry(editor, 3, "Puerto", "port")
        self._label_entry(editor, 4, "Pais", "country")
        self._label_entry(editor, 5, "Anonimato", "anonymity")
        self._label_entry(editor, 6, "Uptime %", "uptime_pct")
        self._label_entry(editor, 7, "Latencia fuente", "source_latency_ms")
        self._label_entry(editor, 8, "Proveedor", "provider")
        self._label_entry(editor, 9, "Perfil VPN", "config_path")
        ttk.Button(editor, text="Elegir archivo", command=self.choose_vpn_file).grid(row=9, column=2, padx=(8, 0))
        self._label_entry(editor, 10, "Fuente", "source")
        self._label_entry(editor, 11, "Notas", "notes")

        editor_actions = ttk.Frame(editor)
        editor_actions.grid(row=12, column=0, columnspan=3, sticky="ew", pady=(12, 0))
        ttk.Button(editor_actions, text="Aplicar cambios", command=self.apply_editor).pack(side="left")
        ttk.Button(editor_actions, text="Probar ahora", command=self.test_selected).pack(side="left", padx=8)
        ttk.Button(editor_actions, text="Conectar VPN", command=self.connect_vpn).pack(side="right")
        ttk.Button(editor_actions, text="Desconectar VPN", command=self.disconnect_vpn).pack(side="right", padx=8)

        chain_actions = ttk.Frame(editor)
        chain_actions.grid(row=13, column=0, columnspan=3, sticky="ew", pady=(8, 0))
        ttk.Button(chain_actions, text="Escribir ProxyChains", command=self.write_proxychains_config).pack(side="left")
        ttk.Button(chain_actions, text="Chromium ProxyChains", command=self.launch_proxychains_chromium).pack(
            side="left", padx=8
        )
        ttk.Button(chain_actions, text="Chromium torsocks", command=self.launch_torsocks_chromium).pack(side="left")

        console_panel = ttk.Frame(right, style="Panel.TFrame", padding=12)
        console_panel.grid(row=2, column=0, sticky="nsew", pady=(10, 0))
        console_panel.rowconfigure(1, weight=1)
        console_panel.columnconfigure(0, weight=1)
        self.log_status_var = tk.StringVar(value="Ultimo estado: esperando una accion")
        ttk.Label(console_panel, textvariable=self.log_status_var, style="Status.TLabel").grid(row=0, column=0, sticky="w")
        self.console = tk.Text(
            console_panel,
            height=5,
            wrap="word",
            relief="flat",
            bg="#050814",
            fg="#42ffbf",
            insertbackground="#ff4fd8",
            font=("DejaVu Sans Mono", 10),
        )
        self.console.grid(row=1, column=0, sticky="nsew", pady=(8, 0))
        self.console.configure(state="disabled")
        ttk.Button(console_panel, text="Abrir log completo", command=self.show_full_log).grid(
            row=2, column=0, sticky="e", pady=(8, 0)
        )
        self.bind_all("<ButtonPress-1>", self._log_button_click, add="+")

    def _label_entry(self, parent: ttk.Frame, row: int, label: str, key: str) -> None:
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", pady=5)
        ttk.Entry(parent, textvariable=self.fields[key]).grid(row=row, column=1, columnspan=2, sticky="ew", pady=5)

    def _load_initial(self) -> None:
        profiles, encrypted, message = self.store.load(password=None)
        self.profiles = profiles
        if not self.profiles:
            self.add_tor_profile(log=False)
        self.crypto_label.configure(
            text=f"{BRAND_NAME} // modo rapido sin contrasenas de app. Tor usa credencial local guardada; VPN puede pedir permisos del sistema."
        )
        self.log(message)
        self.refresh_tree()
        self.refresh_public_ip()
        self.refresh_local_telemetry()
        self.ensure_trial_window()
        self.after(500, self.maybe_show_onboarding)

    def log(self, message: str) -> None:
        stamp = time.strftime("%H:%M:%S")
        line = f"[{stamp}] [{BRAND_NAME}] {message}"
        self.recent_log_lines.append(line)
        self.recent_log_lines = self.recent_log_lines[-5:]
        if hasattr(self, "console"):
            self.console.configure(state="normal")
            self.console.delete("1.0", "end")
            self.console.insert("end", "\n".join(self.recent_log_lines) + "\n")
            self.console.see("end")
            self.console.configure(state="disabled")
        if hasattr(self, "log_status_var"):
            self.log_status_var.set(f"Ultimo estado: {message}")
        try:
            APP_DIR.mkdir(parents=True, exist_ok=True)
            with AUDIT_LOG_FILE.open("a", encoding="utf-8") as handle:
                handle.write(f"{local_now_iso()} [{BRAND_NAME}] {message}\n")
            chmod_private(AUDIT_LOG_FILE)
        except OSError:
            pass

    def _log_button_click(self, event: tk.Event) -> None:
        widget = event.widget
        try:
            if widget.winfo_class() != "TButton":
                return
            label = str(widget.cget("text") or "boton")
            self.log(f"CLICK: {label}")
        except (tk.TclError, AttributeError):
            return

    def show_full_log(self) -> None:
        try:
            content = AUDIT_LOG_FILE.read_text(encoding="utf-8")
        except OSError:
            content = "Todavia no hay log persistente."
        self.show_text_window("Registro completo v3ctorlabs", content)

    def refresh_local_telemetry(self) -> None:
        self.log("Leyendo interfaces, Wi-Fi, ruta y DNS locales (solo lectura)...")

        def worker() -> None:
            snapshot = LocalNetworkService.snapshot()
            LocalNetworkService.save(snapshot)
            self.task_queue.put(("local_telemetry_result", snapshot))

        threading.Thread(target=worker, daemon=True).start()

    def update_local_telemetry(self, snapshot: dict[str, Any]) -> None:
        self.local_snapshot = snapshot
        interface_count = len(snapshot.get("interfaces") or [])
        route = snapshot.get("route_device") or "sin ruta detectada"
        wifi = snapshot.get("wifi_ssid") or snapshot.get("wifi_interface") or "Wi-Fi no expuesta"
        dns = ", ".join(snapshot.get("dns_servers") or []) or "DNS no leido"
        self.local_vars["summary"].set(
            f"PC / Wi-Fi: {wifi} · salida {route} · {interface_count} interfaz(es) · DNS {dns}"
        )
        self.local_vars["scope"].set(
            "Alcance: proxy = app/navegador seleccionado · VPN = ruta del PC si NetworkManager la activa"
        )
        self.log(
            f"Telemetria local: salida={route}, wifi={wifi}, dns={dns}, interfaces={interface_count}."
        )

    def show_local_telemetry(self) -> None:
        snapshot = self.local_snapshot or LocalNetworkService.snapshot()
        lines = [
            "TELEMETRIA LOCAL v3ctorlabs",
            f"Observado: {snapshot.get('observed_at', '-')}",
            f"Hostname: {snapshot.get('hostname', '-')}",
            f"Interfaz de salida: {snapshot.get('route_device', '-')}",
            f"IP local de salida: {snapshot.get('source_ip', '-')}",
            f"Wi-Fi: {snapshot.get('wifi_ssid') or snapshot.get('wifi_interface') or 'no detectada'}",
            f"DNS activos leidos: {', '.join(snapshot.get('dns_servers') or []) or '-'}",
            "",
            "INTERFACES (sin mostrar MAC)",
        ]
        for item in snapshot.get("interfaces") or []:
            lines.append(
                f"- {item.get('name', '-')} · {item.get('kind', '-')} · {item.get('state', '-')} · {item.get('addresses', '-') }"
            )
        lines.extend(
            [
                "",
                "CONEXIONES NETWORKMANAGER",
            ]
        )
        for item in snapshot.get("connections") or []:
            lines.append(
                f"- {item.get('device', '-')} · {item.get('type', '-')} · {item.get('state', '-')} · {item.get('connection', '-') }"
            )
        lines.extend(
            [
                "",
                "ALCANCE REAL",
                "- Proxy HTTP/SOCKS: solo la app o navegador que lo use.",
                "- ProxyChains/torsocks: apps lanzadas desde ese comando.",
                "- VPN WireGuard/OpenVPN via NetworkManager: puede cubrir la ruta completa del PC.",
                "- El dashboard no cambia la Wi-Fi ni las rutas sin una accion explicita de VPN.",
            ]
        )
        self.show_text_window("PC / Wi-Fi / alcance", "\n".join(lines))

    def fingerprint_report(self) -> str:
        snapshot = self.current_snapshot
        local = self.local_snapshot
        history = self.ip_history_store.load()
        lines = [
            "HUELLA DIGITAL DE CONEXION",
            "Este informe separa observables medidos por el dashboard de datos que una web podria obtener en un navegador.",
            "",
            "MEDIDO AHORA",
            f"- IP publica: {snapshot.ip if snapshot else 'pendiente'}",
            f"- Geolocalizacion: {snapshot.location_line if snapshot else 'pendiente'}",
            f"- ASN/ISP/organizacion: {(snapshot.asn if snapshot else '-') or '-'} / {(snapshot.isp if snapshot else '-') or '-'} / {(snapshot.org if snapshot else '-') or '-'}",
            f"- Reverse DNS: {(snapshot.reverse_dns if snapshot else '-') or '-'}",
            f"- Flags proxy/VPN/Tor/hosting: {snapshot.flags_line if snapshot else 'pendiente'}",
            f"- Zona horaria y moneda geo: {(snapshot.timezone if snapshot else '-') or '-'} / {(snapshot.currency if snapshot else '-') or '-'}",
            f"- DNS local configurado: {', '.join(local.get('dns_servers') or []) or 'no medido'}",
            f"- Historial de IPs guardado: {len(history)} entrada(s)",
            "",
            "PUEDE EXPONER UN NAVEGADOR",
            "- Cabeceras HTTP, User-Agent, idioma, zona horaria y tamano de pantalla.",
            "- Cookies, almacenamiento local, sesiones iniciadas y WebRTC.",
            "- Canvas/WebGL, fuentes, APIs disponibles y patrones de uso.",
            "- DNS, fugas IPv6 o conexiones fuera del proxy si el modo no cubre toda la app.",
            "",
            "MITIGACION PRACTICA",
            "- Para una app: usa SOCKS5/socks5h, ProxyChains o torsocks segun compatibilidad.",
            "- Para todo el PC: usa una VPN de confianza y comprueba IP, DNS e IPv6 despues.",
            "- Para Tor: perfil Tor + navegador limpio; no mezcles cuentas personales.",
            "- Los proxies gratuitos pueden registrar, inyectar o falsear datos: no los uses para credenciales.",
            "",
            "NO MEDIDO POR ESTE DASHBOARD",
            "- Fingerprint real de Chrome/Firefox, WebRTC, canvas y cookies del navegador.",
            "- No se promete anonimato total; se muestran señales y limites verificables.",
        ]
        return "\n".join(lines)

    def show_fingerprint_report(self) -> None:
        self.show_text_window("Huella digital que dejas", self.fingerprint_report())
        self.log("Informe de huella digital consultado: medido vs no medido.")

    def improvement_report(self) -> str:
        history = self.ip_history_store.load()
        tested = [profile for profile in self.profiles if profile.status not in {"Nuevo", "Pendiente"}]
        suggestions = []
        if not self.current_snapshot:
            suggestions.append("Refresca la IP publica antes de activar una ruta anonima.")
        if not history or len(history) < 2:
            suggestions.append("Repite el test despues de cada cambio para construir un historial de IP util.")
        if not tested:
            suggestions.append("Prueba al menos un perfil antes de lanzarlo en un navegador.")
        if not self.local_snapshot.get("dns_servers"):
            suggestions.append("Revisa DNS con una prueba externa despues de conectar VPN/Tor.")
        suggestions.extend(
            [
                "Compara latencia, uptime y reputacion; no selecciones por pais solamente.",
                "Separa perfiles para navegador, terminal y ProxyChains para no mezclar alcance.",
                "Tras cada cambio: IP visible -> DNS -> WebRTC del navegador -> logs del servicio.",
            ]
        )
        return "\n".join(
            [
                "ANALISIS DE MEJORAS v3ctorlabs",
                f"Sesiones guiadas: {self.onboarding_state.get('sessions', 0)} / 100",
                f"Historial IP: {len(history)} cambio(s) observado(s)",
                f"Perfiles con test: {len(tested)} / {len(self.profiles)}",
                "",
                "RECOMENDACIONES",
                *[f"- {item}" for item in suggestions],
                "",
                "MEMORIA LOCAL",
                f"- Registro: {AUDIT_LOG_FILE}",
                f"- Telemetria: {LOCAL_TELEMETRY_FILE}",
                f"- Guia: {ONBOARDING_FILE}",
            ]
        )

    def show_improvement_report(self) -> None:
        self.show_text_window("Ambitos de mejora", self.improvement_report())
        self.log("Analisis de mejoras generado con historial y tests locales.")

    def apply_all_improvements(self) -> None:
        """Apply safe local improvements, then start the verification cycle."""
        applied: list[str] = []
        self.log("MEJORAS: iniciando analisis y aplicacion automatica...")

        # Keep discovery broad enough to find a usable route while retaining
        # the safer default anonymity and latency filters.
        self.set_fast_defaults()
        applied.append("filtros rapidos y anonimato elite/anonymous")

        if not self.profiles:
            self.add_tor_profile(log=False)
            applied.append("perfil Tor local")
            self.log("MEJORA APLICADA: perfil Tor local creado.")

        profile = self.select_profile_for_mode("default")
        if profile:
            self.log(f"MEJORA: perfil seleccionado para verificar: {profile.name} ({profile.type}).")
            if profile.type in {"http", "https", "socks4", "socks5", "tor"}:
                self.activate_selected()
                if self.write_proxychains_config():
                    applied.append("ProxyChains local")
                self.test_selected()
                applied.append(f"test de conectividad de {profile.name}")
            elif profile.type in {"wireguard", "openvpn"}:
                self.log(
                    "MEJORA PENDIENTE: VPN detectada; pulsa VPN facil para activar la ruta del PC "
                    "con permisos de NetworkManager."
                )
            self.save_plain()
            applied.append("perfiles guardados localmente")
        else:
            self.log("MEJORA PENDIENTE: no hay un perfil seleccionable para probar.")

        self.refresh_local_telemetry()
        self.refresh_public_ip()
        applied.extend(["telemetria local", "IP publica e historial"])
        self.log(
            "MEJORAS APLICADAS: " + ", ".join(applied) + "."
        )
        self.log(
            "MEJORA PENDIENTE: verifica DNS, IPv6 y WebRTC desde el navegador; "
            "el dashboard no puede validarlos por si solo."
        )
        self.after(650, self.show_improvement_report)

    def maybe_show_onboarding(self) -> None:
        sessions = int(self.onboarding_state.get("sessions") or 0) + 1
        self.onboarding_state["sessions"] = sessions
        self.onboarding_state["last_seen"] = local_now_iso()
        OnboardingStore.save(self.onboarding_state)
        if sessions <= 100:
            self.show_first_use_guide(auto=True)

    def show_first_use_guide(self, auto: bool = False) -> None:
        window = tk.Toplevel(self)
        window.title("v3ctorlabs // guia de primeros 100 usos")
        window.geometry("760x520")
        window.configure(bg="#050814")
        window.transient(self)
        window.columnconfigure(1, weight=1)
        window.rowconfigure(1, weight=1)
        ttk.Label(window, text="GUIA RAPIDA: configura -> testa -> verifica -> mejora", style="Header.TLabel").grid(
            row=0, column=0, columnspan=2, sticky="w", padx=16, pady=14
        )
        steps = [
            ("1. PC / Wi-Fi", "Lee interfaces, Wi-Fi, ruta y DNS. No modifica la red."),
            ("2. IP publica", "Consulta la IP visible, geolocalizacion, ASN y flags."),
            ("3. Perfil", "Selecciona un proxy/Tor y ejecuta el test de conectividad."),
            ("4. Alcance", "Decide: navegador/app, ProxyChains/torsocks o VPN para todo el PC."),
            ("5. Huella", "Revisa que queda expuesto y comprueba fugas en el navegador."),
            ("6. Mejora", "Lee el historial y repite el ciclo despues de cada cambio."),
        ]
        listbox = tk.Listbox(window, width=24, bg="#07111f", fg="#d9faff", selectbackground="#33205f", relief="flat")
        listbox.grid(row=1, column=0, sticky="ns", padx=(16, 10), pady=(0, 10))
        text = tk.Text(window, wrap="word", bg="#07111f", fg="#d9faff", insertbackground="#ff4fd8", relief="flat")
        text.grid(row=1, column=1, sticky="nsew", padx=(0, 16), pady=(0, 10))
        for title, _ in steps:
            listbox.insert("end", title)

        def render(index: int) -> None:
            index = max(0, min(index, len(steps) - 1))
            listbox.selection_clear(0, "end")
            listbox.selection_set(index)
            title, description = steps[index]
            completed = title.split(". ", 1)[0] in self.onboarding_state.get("completed", [])
            text.configure(state="normal")
            text.delete("1.0", "end")
            text.insert("end", f"{title}\n\n{description}\n\nEstado: {'COMPLETADO' if completed else 'pendiente'}\n\n")
            text.insert("end", "Orden recomendado:\n1. Configura el tipo y uso.\n2. Ejecuta el test.\n3. Refresca IP y mapas.\n4. Comprueba DNS/WebRTC en el navegador.\n5. Guarda el resultado en el registro.\n")
            text.configure(state="disabled")

        def run_step() -> None:
            index = listbox.curselection()[0] if listbox.curselection() else 0
            step_key = str(index + 1)
            if index == 0:
                self.refresh_local_telemetry()
            elif index == 1:
                self.refresh_public_ip()
            elif index == 2:
                self.test_selected()
            elif index == 3:
                self.show_local_telemetry()
            elif index == 4:
                self.show_fingerprint_report()
            else:
                self.show_improvement_report()
            completed = set(self.onboarding_state.get("completed") or [])
            completed.add(step_key)
            self.onboarding_state["completed"] = sorted(completed)
            OnboardingStore.save(self.onboarding_state)
            self.log(f"Guia primeros usos: paso {step_key} ejecutado.")
            if index < len(steps) - 1:
                self.log(f"Guia: avanzando automaticamente al paso {index + 2}.")
                window.after(280, lambda: render(index + 1))
            else:
                self.complete_connection_flow()
                self.log("Guia: sexto paso finalizado; esperando confirmacion de IP publica.")
                window.after(1200, self.show_connection_success)
                render(index)

        listbox.bind("<<ListboxSelect>>", lambda _event: render(listbox.curselection()[0] if listbox.curselection() else 0))
        actions = ttk.Frame(window)
        actions.grid(row=2, column=0, columnspan=2, sticky="ew", padx=16, pady=(0, 14))
        ttk.Button(actions, text="Ejecutar paso", command=run_step).pack(side="left")
        ttk.Button(actions, text="Aplicar mejoras", command=self.apply_all_improvements).pack(side="left", padx=8)
        ttk.Button(actions, text="Cerrar", command=window.destroy).pack(side="right")
        render(0)
        if auto:
            self.log(f"Sesion guiada {self.onboarding_state.get('sessions', 0)}/100 abierta.")

    def update_ip_summary(
        self,
        snapshot: IpGeoSnapshot,
        history: list[dict[str, Any]] | None = None,
        changed: bool = False,
    ) -> None:
        self.current_snapshot = snapshot
        protected = snapshot.is_tor or snapshot.is_vpn or snapshot.is_proxy
        ip_prefix = "IP PUBLICA CAMBIADA" if changed else "IP publica"
        protection_label = "SI" if protected else "NO"
        self.ip_vars["ip"].set(
            f"IP PROTEGIDA: {protection_label} · {ip_prefix}: {snapshot.ip} ({snapshot.provider})"
        )
        self.ip_vars["location"].set(
            f"Ubicacion: {snapshot.full_location_line} · {snapshot.latitude}, {snapshot.longitude} · {snapshot.timezone}"
        )
        self.ip_vars["network"].set(
            f"Red: ASN {snapshot.asn or '-'} · ISP {snapshot.isp or '-'} · Empresa {snapshot.company or snapshot.org or '-'} · rDNS {snapshot.reverse_dns or '-'}"
        )
        self.ip_vars["flags"].set(f"Flags: {snapshot.flags_line} · moneda {snapshot.currency or '-'}")
        if snapshot.is_tor:
            self.ip_vars["anon_state"].set("ANON ON - TOR DETECTADO")
        elif snapshot.is_vpn or snapshot.is_proxy:
            self.ip_vars["anon_state"].set("ANON ON - VPN/PROXY DETECTADO")
        elif snapshot.is_hosting:
            self.ip_vars["anon_state"].set("ANON PARCIAL - SALIDA HOSTING")
        else:
            self.ip_vars["anon_state"].set("ANON OFF - IP REAL VISIBLE")
        if protected:
            self.ip_alert_label.configure(style="Success.TLabel")
            self.ip_alert_sub_label.configure(style="SuccessSub.TLabel")
            self.anon_state_label.configure(style="Success.TLabel")
            self.ip_vars["public_notice"].set(
                "LINK LIVE · SALIDA PROTEGIDA DETECTADA · IP visible actualizada · verifica DNS/WebRTC"
            )
            self.live_map_button.configure(text="● MAPA LINK LIVE · GEO ROUTE ACTIVE")
        else:
            self.ip_alert_label.configure(style="Alert.TLabel")
            self.ip_alert_sub_label.configure(style="AlertSub.TLabel")
            self.anon_state_label.configure(style="Alert.TLabel")
            self.ip_vars["public_notice"].set(
                "PUBLICANDO AHORA: esta es la IP que ven webs y servicios externos."
            )
            self.live_map_button.configure(text="MAPA LINK LIVE · STANDBY")
        history = history if history is not None else self.ip_history_store.load()
        if history:
            first_seen = parse_iso(str(history[-1].get("first_seen") or ""))
            if first_seen:
                elapsed = datetime.now().astimezone() - first_seen
                self.ip_vars["since_change"].set(
                    f"Desde cambio: {human_duration(elapsed.total_seconds())} · Historial IP: {len(history)}/{DEFAULT_IP_HISTORY_LIMIT} max"
                )
        else:
            self.ip_vars["since_change"].set(f"Desde cambio: - · Historial IP: 0/{DEFAULT_IP_HISTORY_LIMIT} max")

    def ensure_trial_window(self) -> None:
        if self.payment_state.get("trial_started"):
            return
        started = datetime.now().astimezone()
        expires = started.timestamp() + (14 * 86400)
        self.payment_state.update(
            {
                "trial_started": started.isoformat(timespec="seconds"),
                "trial_expires": datetime.fromtimestamp(expires).astimezone().isoformat(timespec="seconds"),
                "lifetime_paid": False,
            }
        )
        PaymentStateStore.save(self.payment_state)
        self.log("Prueba de 14 dias activada. Despues: pago unico lifetime desde 5 EUR.")

    def payment_status_text(self) -> str:
        if self.payment_state.get("lifetime_paid"):
            return "LIFETIME ACTIVO · pago Stripe confirmado"
        expires = parse_iso(str(self.payment_state.get("trial_expires") or ""))
        if expires:
            remaining = max(0, int((expires - datetime.now().astimezone()).total_seconds()))
            return f"PRUEBA ACTIVA · quedan {human_duration(remaining)} · luego lifetime desde 5 EUR"
        return "PRUEBA pendiente · lifetime desde 5 EUR"

    def payment_methods_text(self) -> str:
        lines = [
            "KAFE-LIFETIME · PAGO UNICO DESDE 5,00 EUR",
            "",
            "METODOS EN STRIPE CHECKOUT",
            *[f"- {method}" for method in STRIPE_PAYMENT_METHODS],
            "",
            "CRIPTO",
            "- Bitcoin nativo: requiere un procesador o enlace externo; no se anuncia como Stripe Checkout.",
            "- Solana: Stripe documenta stablecoins, no una promesa general de SOL nativo.",
            "",
            "La pagina Stripe solo mostrara los metodos que tu cuenta, pais, moneda y enlace tengan habilitados.",
            "Bizum necesita cuenta/cliente compatible en Espana y SEPA usa una cuenta bancaria EUR.",
            "",
            self.payment_status_text(),
        ]
        return "\n".join(lines)

    def show_payment_methods(self) -> None:
        lines = [self.payment_methods_text(), "", "CONFIGURACION OPCIONAL EXTERNA"]
        for label, env_name in EXTERNAL_CRYPTO_LINK_ENVS.items():
            lines.append(f"- {label}: {os.environ.get(env_name, '').strip() or 'no configurado'} ({env_name})")
        lines.extend(
            [
                "",
                f"Stripe Dashboard: {STRIPE_DASHBOARD_LINK}",
                "Activa metodos en Settings > Payments > Payment methods.",
            ]
        )
        self.show_text_window("Metodos de pago kafe-lifetime", "\n".join(lines))
        self.log("Metodos de pago kafe-lifetime consultados.")

    def apply_connection_mode(self, mode: str) -> None:
        config = CONNECTION_MODE_CONFIGS[mode]
        self.connection_mode = mode
        self.connection_live = False
        self.connection_mode_var.set(f"MODO {config['label']} · CONNECTING")
        self.discovery_fields["source"].set("Todas")
        self.discovery_fields["protocol"].set(config["protocol"])
        self.discovery_fields["anonymity"].set(config["anonymity"])
        self.discovery_fields["min_uptime"].set(config["min_uptime"])
        self.discovery_fields["max_latency"].set(config["max_latency"])
        self.apply_connection_palette(mode, live=False)
        self.log(f"MODO {config['label']}: {config['description']}")

    def select_profile_for_mode(self, mode: str) -> ConnectionProfile | None:
        if not self.profiles:
            self.add_tor_profile(log=False)
        profiles = list(self.profiles)
        if mode == "pro":
            candidates = [item for item in profiles if item.type in {"tor", "socks5", "wireguard", "openvpn"}]
            candidates.sort(key=lambda item: (0 if item.type == "tor" else 1, item.latency_ms or 999999))
        elif mode == "aggressive":
            candidates = sorted(
                profiles,
                key=lambda item: (0 if item.status == "ok" else 1, item.latency_ms or 999999),
            )
        else:
            candidates = [item for item in profiles if item.active] or profiles
        selected = candidates[0] if candidates else None
        if selected:
            self.selected_id = selected.id
            for item in self.profiles:
                item.active = item.id == selected.id
            self.refresh_tree()
            self.on_select()
        return selected

    def quick_connect(self, mode: str) -> None:
        if mode not in CONNECTION_MODE_CONFIGS:
            return
        self.apply_connection_mode(mode)
        profile = self.select_profile_for_mode(mode)
        if not profile:
            self.connection_mode_var.set(f"MODO {CONNECTION_MODE_CONFIGS[mode]['label']} · SIN PERFIL")
            self.log("CONNECT FAIL: no hay perfil disponible para el modo rapido.")
            return
        self.log(f"CONNECTING 1-click: modo={mode}, perfil={profile.name}, tipo={profile.type}.")
        self.complete_connection_flow()

    def open_coffee_link(self) -> None:
        payment_url = os.environ.get(STRIPE_PAYMENT_LINK_ENV, "").strip()
        if not payment_url:
            self.show_text_window(
                "Stripe lifetime",
                "Configura tu enlace real de Stripe antes de cobrar:\n\n"
                f"export {STRIPE_PAYMENT_LINK_ENV}=https://buy.stripe.com/TU_LINK_REAL\n\n"
                "En Stripe crea un Payment Link de tipo Customers choose what to pay,"
                " one-off, minimo 5 EUR y sin maximo configurado.\n\n"
                + self.payment_methods_text()
                + "\n\n"
                f"Abrir Stripe: {STRIPE_DASHBOARD_LINK}\n\n"
                "Configura el enlace en la variable de entorno y vuelve a abrir la app.",
            )
            self.log("Stripe no configurado: falta V3CTORLABS_STRIPE_PAYMENT_LINK.")
            return
        webbrowser.open(payment_url)
        self.log(f"Checkout Stripe lifetime abierto: minimo {LIFETIME_MINIMUM_EUR} EUR.")

    def complete_connection_flow(self) -> None:
        profile = self.get_selected()
        if profile and profile.type == "tor":
            self.connect_tor_fast()
        elif profile and profile.type in {"http", "https", "socks4", "socks5"}:
            self.activate_selected()
            self.test_selected()
            self.log("LINK LIVE preparado para app/navegador mediante el perfil seleccionado.")
        elif profile and profile.type in {"wireguard", "openvpn"}:
            self.log("Perfil VPN seleccionado: pulsa VPN facil para cubrir la ruta del PC.")
        else:
            self.log("No hay perfil de conexion seleccionado; se completo la guia de verificacion.")
        self.after(4500, self.refresh_public_ip)

    def show_connection_success(self) -> None:
        window = tk.Toplevel(self)
        window.title("v3ctorlabs // LINK LIVE")
        window.geometry("700x400")
        window.configure(bg="#062b20")
        window.transient(self)
        ttk.Label(window, text="LINK LIVE", style="Success.TLabel", padding=(18, 14)).pack(fill="x", padx=18, pady=(18, 10))
        ttk.Label(
            window,
            text="\N{THUMBS UP SIGN}  Conexion completada\n\N{CLAPPING HANDS SIGN}  \N{CLAPPING HANDS SIGN}  \N{CLAPPING HANDS SIGN}",
            style="SuccessSub.TLabel",
            justify="center",
            padding=(12, 12),
        ).pack(fill="x", padx=18)
        ttk.Label(
            window,
            text="La salida protegida se detecta en verde. Comprueba IP, DNS y WebRTC para validar el resultado.",
            style="SuccessSub.TLabel",
            wraplength=500,
            justify="center",
            padding=(12, 12),
        ).pack(fill="x", padx=18)
        ttk.Label(
            window,
            text=self.payment_status_text(),
            style="SuccessSub.TLabel",
            justify="center",
            padding=(12, 6),
        ).pack(fill="x", padx=18)
        actions = ttk.Frame(window)
        actions.pack(fill="x", padx=18, pady=18)
        ttk.Button(actions, text="Mapa LINK LIVE", command=self.open_live_map).pack(side="left")
        ttk.Button(actions, text="Metodos de pago", command=self.show_payment_methods).pack(side="left", padx=8)
        ttk.Button(actions, text="Pagar lifetime 5+ EUR", command=self.open_coffee_link).pack(side="left")
        ttk.Button(actions, text="Ver huella", command=self.show_fingerprint_report).pack(side="left", padx=8)
        ttk.Button(actions, text="Cerrar", command=window.destroy).pack(side="right")
        self.log("ALERTA LINK LIVE: guia completada, conexion preparada y estado visual verde.")

    def animate_dashboard_globe(self) -> None:
        canvas = getattr(self, "globe_canvas", None)
        if not canvas:
            return
        self.globe_angle += 0.045
        self.connection_phase = (self.connection_phase + 0.035) % 1.0
        self.draw_dashboard_globe()
        self.after(80, self.animate_dashboard_globe)

    def draw_dashboard_globe(self) -> None:
        canvas = self.globe_canvas
        canvas.delete("all")
        width = int(canvas.winfo_width() or 230)
        height = int(canvas.winfo_height() or 230)
        cx, cy = width / 2, height / 2
        radius = min(width, height) * 0.42
        state = self.ip_vars["anon_state"].get()
        outline = "#42ffbf" if "ON" in state else "#ff4fd8"
        fill = "#0c315b" if "ON" in state else "#451536"
        canvas.create_rectangle(0, 0, width, height, fill="#02040c", outline="")
        for i in range(34):
            x = (i * 67 + int(self.globe_angle * 900)) % max(width, 1)
            y = (i * 43) % max(height, 1)
            color = "#7be7ff" if i % 3 else "#ff4fd8"
            canvas.create_oval(x, y, x + 1.5, y + 1.5, fill=color, outline="")
        for ring in range(5, 0, -1):
            pad = ring * 6
            canvas.create_oval(
                cx - radius - pad,
                cy - radius - pad,
                cx + radius + pad,
                cy + radius + pad,
                outline="#12385a" if ring % 2 else "#3c1d58",
                width=1,
            )
        canvas.create_oval(cx - radius, cy - radius, cx + radius, cy + radius, fill=fill, outline=outline, width=3)
        canvas.create_oval(
            cx - radius * 0.72,
            cy - radius * 0.82,
            cx + radius * 0.18,
            cy + radius * 0.05,
            fill="#235f9b" if "ON" in state else "#78305b",
            outline="",
        )
        canvas.create_oval(
            cx - radius * 0.96,
            cy - radius * 0.96,
            cx + radius * 0.96,
            cy + radius * 0.96,
            outline="#1df2ff",
            width=1,
        )
        for lat in range(-60, 90, 30):
            points = []
            for lon in range(-180, 181, 12):
                x, y, z = self.project_dashboard_point(lat, lon, cx, cy, radius)
                if z >= -0.1:
                    points.extend([x, y])
            if len(points) >= 4:
                canvas.create_line(*points, fill="#7be7ff", width=1)
        for lon in range(-150, 181, 30):
            points = []
            for lat in range(-80, 81, 8):
                x, y, z = self.project_dashboard_point(lat, lon, cx, cy, radius)
                if z >= -0.1:
                    points.extend([x, y])
            if len(points) >= 4:
                canvas.create_line(*points, fill="#255f88", width=1)
        visible_points: list[tuple[dict[str, Any], float, float, float]] = []
        for point in self.globe_points()[:80]:
            try:
                lat = float(point["lat"])
                lon = float(point["lon"])
            except (KeyError, TypeError, ValueError):
                continue
            x, y, z = self.project_dashboard_point(lat, lon, cx, cy, radius)
            if z < 0:
                continue
            visible_points.append((point, x, y, z))
        origin = next((item for item in visible_points if item[0].get("kind") == "IP publica"), None)
        if origin:
            _, ox, oy, _ = origin
            for route_index, (point, x, y, z) in enumerate(visible_points):
                if point.get("kind") == "IP publica":
                    continue
                canvas.create_line(ox, oy, x, y, fill="#1df2ff", width=1)
                packet = (self.connection_phase + route_index * 0.17) % 1.0
                px = ox + (x - ox) * packet
                py = oy + (y - oy) * packet
                canvas.create_oval(px - 2.5, py - 2.5, px + 2.5, py + 2.5, fill="#ffffff", outline="#42ffbf")
        for index, (point, x, y, z) in enumerate(visible_points):
            color = "#ff4fd8" if point.get("kind") == "IP publica" else "#42ffbf"
            size = 6 if point.get("kind") == "IP publica" else 3
            pulse = 2 + abs(math.sin(self.globe_angle * 2.5 + index)) * 4
            canvas.create_oval(x - size - pulse, y - size - pulse, x + size + pulse, y + size + pulse, outline=color, width=1)
            canvas.create_oval(x - size, y - size, x + size, y + size, fill=color, outline="")
        canvas.create_arc(
            cx - radius * 1.17,
            cy - radius * 1.17,
            cx + radius * 1.17,
            cy + radius * 1.17,
            start=(self.globe_angle * 50) % 360,
            extent=75,
            outline="#ff4fd8",
            width=2,
            style="arc",
        )
        canvas.create_text(cx, height - 28, text="v3ctorlabs geo-core", fill="#42ffbf", font=("Inter", 10, "bold"))
        canvas.create_text(cx, height - 13, text=state.split(" - ", 1)[0], fill=outline, font=("Inter", 9, "bold"))
        canvas.create_text(
            cx,
            14,
            text="LINK LIVE" if self.current_snapshot else "LINK STANDBY",
            fill="#42ffbf" if self.current_snapshot else "#ff4fd8",
            font=("DejaVu Sans Mono", 8, "bold"),
        )

    def project_dashboard_point(self, lat: float, lon: float, cx: float, cy: float, radius: float) -> tuple[float, float, float]:
        phi = math.radians(lat)
        lam = math.radians(lon) + self.globe_angle
        tilt = -0.35
        x = math.cos(phi) * math.sin(lam)
        y = math.sin(phi) * math.cos(tilt) - math.cos(phi) * math.cos(lam) * math.sin(tilt)
        z = math.sin(phi) * math.sin(tilt) + math.cos(phi) * math.cos(lam) * math.cos(tilt)
        return cx + x * radius, cy - y * radius, z

    def refresh_public_ip(self) -> None:
        self.log("Consultando IP publica y geolocalizacion...")

        def worker() -> None:
            try:
                snapshot = IpGeoService.lookup("my")
                history, changed = self.ip_history_store.record(snapshot)
                self.task_queue.put(("ip_lookup_result", ("public", snapshot, history, changed, "")))
            except Exception as exc:
                self.task_queue.put(("ip_lookup_result", ("public", None, [], False, str(exc))))

        threading.Thread(target=worker, daemon=True).start()

    def lookup_selected_profile_ip(self) -> None:
        profile = self.get_selected()
        if not profile or not profile.host:
            messagebox.showinfo(APP_NAME, "Selecciona un proxy con IP/host.")
            return
        self.log(f"Geolocalizando IP seleccionada: {profile.host}...")

        def worker() -> None:
            try:
                snapshot = IpGeoService.lookup(profile.host)
                self.task_queue.put(("ip_lookup_result", ("selected", snapshot, [], False, "", profile.id)))
            except Exception as exc:
                self.task_queue.put(("ip_lookup_result", ("selected", None, [], False, str(exc), profile.id)))

        threading.Thread(target=worker, daemon=True).start()

    def open_public_ip_map(self) -> None:
        if not self.current_snapshot:
            self.refresh_public_ip()
            return
        try:
            path = MapWriter.write(self.current_snapshot, self.ip_history_store.load())
        except ValueError as exc:
            messagebox.showinfo(APP_NAME, str(exc))
            return
        webbrowser.open(path.as_uri())
        self.log(f"Mapa generado: {path}")

    def globe_points(self) -> list[dict[str, Any]]:
        points: list[dict[str, Any]] = []
        if self.current_snapshot:
            point = MapWriter.snapshot_point(self.current_snapshot)
            if point:
                point["opacity"] = 1
                points.append(point)
        history = self.ip_history_store.load()
        total_history = max(1, len(history))
        for index, item in enumerate(history):
            snap = item.get("snapshot") or {}
            try:
                snapshot = IpGeoSnapshot.from_dict(snap)
            except TypeError:
                continue
            point = MapWriter.snapshot_point(snapshot, label="Historial")
            if point:
                point["seen"] = f"{item.get('first_seen', '')} -> {item.get('last_seen', '')}"
                age = total_history - index - 1
                point["opacity"] = max(0.18, 0.72 - age * 0.08)
                points.append(point)
        for profile in self.profiles:
            point = MapWriter.profile_point(profile)
            if point:
                point["opacity"] = 0.9
                points.append(point)
        unique = {}
        for point in points:
            unique[(point.get("kind"), point.get("ip"), point.get("lat"), point.get("lon"))] = point
        return list(unique.values())

    def open_ip_globe(self) -> None:
        points = self.globe_points()
        if not points:
            messagebox.showinfo(APP_NAME, "Primero refresca la IP publica o geolocaliza un proxy.")
            return
        current_ip = self.current_snapshot.ip if self.current_snapshot else ""
        path = MapWriter.write_globe(points, current_ip=current_ip)
        webbrowser.open(path.as_uri())
        self.log(f"Globo interactivo generado: {path}")

    def open_live_map(self) -> None:
        if not self.current_snapshot:
            self.log("LINK LIVE MAP: falta IP publica; refrescando antes de abrir el mapa.")
            self.refresh_public_ip()
            return
        points = self.globe_points()
        path = MapWriter.write_globe(points, current_ip=self.current_snapshot.ip)
        webbrowser.open(path.as_uri())
        self.log(
            f"LINK LIVE MAP abierto: IP={self.current_snapshot.ip} · nodos={len(points)} · modo={self.connection_mode}."
        )

    def open_country_map(self) -> None:
        selected_country = self.discovery_fields["country"].get().strip()
        if not selected_country:
            profile = self.get_selected()
            selected_country = profile.country if profile else ""
        if not selected_country:
            messagebox.showinfo(APP_NAME, "Selecciona un pais primero.")
            return
        query = selected_country.split(" - ", 1)[-1] if " - " in selected_country else selected_country
        webbrowser.open("https://www.openstreetmap.org/search?" + urlencode({"query": query}))
        self.log(f"Mapa de pais abierto: {query}")

    def show_connection_detail(self) -> None:
        snapshot = self.current_snapshot
        profile = self.get_selected()
        lines = []
        if snapshot:
            history = self.ip_history_store.load()
            lines.extend(
                [
                    f"IP PROTEGIDA: {'SI' if (snapshot.is_tor or snapshot.is_vpn or snapshot.is_proxy) else 'NO'}",
                    f"IP PUBLICA VISIBLE: {snapshot.ip}",
                    f"Direccion geo completa estimada: {snapshot.full_location_line}",
                    f"Historial IPs: {len(history)}/{DEFAULT_IP_HISTORY_LIMIT} max",
                    f"Ubicacion: {snapshot.location_line}",
                    f"Region: {snapshot.region or '-'}",
                    f"Barrio/distrito: {snapshot.neighborhood or snapshot.district or '-'}",
                    f"Plaza: {snapshot.square or '-'}",
                    f"Calle: {snapshot.street or '-'}",
                    f"Carretera/road: {snapshot.road or '-'}",
                    f"Codigo postal: {snapshot.postal_code or '-'}",
                    f"Precision: {snapshot.address_precision or 'no disponible'}",
                    f"Coordenadas: {snapshot.latitude}, {snapshot.longitude}",
                    f"Zona horaria: {snapshot.timezone}",
                    f"ASN: {snapshot.asn}",
                    f"ISP: {snapshot.isp}",
                    f"Organizacion: {snapshot.org}",
                    f"Empresa registrada: {snapshot.company or '-'} ({snapshot.company_type or '-'})",
                    f"Dominio empresa: {snapshot.company_domain or '-'}",
                    f"Red CIDR: {snapshot.network_cidr or '-'}",
                    f"Reverse DNS: {snapshot.reverse_dns}",
                    f"Flags: {snapshot.flags_line}",
                    f"Proveedor geo: {snapshot.provider}",
                    "",
                ]
            )
        if profile:
            lines.extend(
                [
                    f"Perfil seleccionado: {profile.name}",
                    f"Tipo: {profile.type}",
                    f"Endpoint: {profile.endpoint}",
                    f"Proxy URL: {profile.proxy_url or '-'}",
                    f"Anonimato fuente: {profile.anonymity or '-'}",
                    f"Uptime fuente: {profile.uptime_pct if profile.uptime_pct is not None else '-'}",
                    f"Latencia fuente: {profile.source_latency_ms if profile.source_latency_ms is not None else '-'} ms",
                    f"Proveedor lista: {profile.provider or '-'}",
                    f"Pais ley datos: {LAX_DATA_PROTECTION_COUNTRIES.get(profile.country.upper(), 'sin marca laxa')}",
                    f"Geo proxy: {profile.geo_city}, {profile.geo_region}, {profile.geo_country}",
                    f"ASN proxy: {profile.geo_asn or '-'}",
                    f"ISP proxy: {profile.geo_isp or '-'}",
                ]
            )
        if not lines:
            lines.append("Sin datos todavia. Pulsa Refrescar IP.")
        self.show_text_window("Detalle de conexion", "\n".join(lines))

    def proxy_guide_text(self, key: str) -> str:
        guide = PROXY_TYPE_GUIDE[key]
        profile_type = guide.get("profile_type") or "no aplica como perfil cliente"
        anonymity = guide.get("anonymity") or "no aplica"
        return "\n".join(
            [
                f"{guide['title']}",
                "",
                f"Resumen: {guide['summary']}",
                "",
                f"Mejor para: {guide['best_for']}",
                f"Cuidado: {guide['caution']}",
                "",
                f"Tipo de perfil: {profile_type}",
                f"Filtro protocolo: {guide.get('protocol') or 'all'}",
                f"Filtro anonimato: {anonymity}",
                f"Uso sugerido: {guide.get('use_case') or '-'}",
                "",
                f"Comando/pista: {guide['command_hint']}",
                "",
                "Botones:",
                "- Aplicar perfil: ajusta el perfil seleccionado o crea uno nuevo.",
                "- Aplicar busqueda: cambia filtros de fuente/protocolo/anonimato.",
                "- Aplicar uso: selecciona el modo de uso del panel principal.",
            ]
        )

    def apply_proxy_type_to_profile(self, key: str) -> None:
        guide = PROXY_TYPE_GUIDE[key]
        profile_type = guide.get("profile_type", "")
        profile = self.get_selected()
        if not profile and profile_type:
            self.new_profile()
            profile = self.get_selected()
        if not profile:
            messagebox.showinfo(APP_NAME, "Selecciona un perfil para aplicar esta clasificacion.")
            return

        if profile_type:
            profile.type = profile_type
            if profile.name in {"Perfil", "Nuevo proxy HTTP", ""} or profile.name.startswith(("HTTP ", "HTTPS ", "SOCKS")):
                profile.name = guide["title"]
            if profile_type == "tor":
                profile.host = "127.0.0.1"
                profile.port = 9050
            elif profile_type in {"http", "https"}:
                profile.port = profile.port or 8080
            elif profile_type in {"socks4", "socks5"}:
                profile.port = profile.port or 1080
            elif profile_type in {"wireguard", "openvpn"}:
                profile.host = ""
                profile.port = 0
        anonymity = guide.get("anonymity", "")
        if key == "Transparente":
            profile.anonymity = "transparent"
        elif anonymity and anonymity != "all":
            profile.anonymity = anonymity
        profile.notes = f"{guide['title']}: {guide['summary']} Cuidado: {guide['caution']}"
        self.refresh_tree()
        self.on_select()
        self.log(f"Guia aplicada a perfil: {key} -> {profile.name}")

    def apply_proxy_type_to_discovery(self, key: str) -> None:
        guide = PROXY_TYPE_GUIDE[key]
        protocol = guide.get("protocol") or "all"
        anonymity = guide.get("anonymity") or ""
        if protocol in DISCOVERY_PROTOCOLS:
            self.discovery_fields["protocol"].set(protocol)
        if anonymity in DISCOVERY_ANONYMITY:
            self.discovery_fields["anonymity"].set(anonymity)
        self.discovery_fields["source"].set("Todas")
        if key in {"HTTP", "HTTPS", "SOCKS4", "SOCKS5", "Tor", "WireGuard VPN", "OpenVPN"}:
            self.discovery_fields["min_uptime"].set("80")
            self.discovery_fields["max_latency"].set("800")
        self.log(f"Filtro de busqueda aplicado desde guia: {key}")

    def apply_proxy_type_use(self, key: str) -> None:
        guide = PROXY_TYPE_GUIDE[key]
        use_case = guide.get("use_case")
        if use_case in PROXY_USE_CASES:
            self.ip_vars["proxy_use"].set(use_case)
            self.log(f"Uso seleccionado desde guia: {use_case}")

    def apply_all_proxy_types(self) -> None:
        self.discovery_fields["source"].set("Todas")
        self.discovery_fields["protocol"].set("all")
        self.discovery_fields["anonymity"].set("all")
        self.discovery_fields["min_uptime"].set("60")
        self.discovery_fields["max_latency"].set("1500")
        self.discovery_fields["limit"].set("200")
        self.log("Todos los tipos activados para busqueda: HTTP/HTTPS/SOCKS4/SOCKS5 y anon=all, incluidos transparentes.")

    def show_proxy_guide(self) -> None:
        keys = list(PROXY_TYPE_GUIDE)
        win = tk.Toplevel(self)
        win.title(f"{BRAND_NAME} guia dinamica de proxies")
        win.geometry("980x560")
        win.configure(bg="#050814")
        win.columnconfigure(1, weight=1)
        win.rowconfigure(1, weight=1)

        title = tk.Label(
            win,
            text="v3ctorlabs // selector de proxies",
            bg="#050814",
            fg="#42ffbf",
            font=("Inter", 16, "bold"),
            anchor="w",
        )
        title.grid(row=0, column=0, columnspan=2, sticky="ew", padx=14, pady=(12, 8))

        listbox = tk.Listbox(
            win,
            exportselection=False,
            bg="#07111f",
            fg="#dffcff",
            selectbackground="#33205f",
            selectforeground="#ffffff",
            highlightbackground="#1df2ff",
            highlightcolor="#ff4fd8",
            relief="flat",
            font=("Inter", 11, "bold"),
        )
        listbox.grid(row=1, column=0, sticky="ns", padx=(14, 8), pady=(0, 12))
        for key in keys:
            listbox.insert("end", key)

        detail = tk.Text(
            win,
            wrap="word",
            relief="flat",
            bg="#0b1020",
            fg="#ecfeff",
            insertbackground="#ff4fd8",
            font=("DejaVu Sans Mono", 10),
            padx=14,
            pady=12,
        )
        detail.grid(row=1, column=1, sticky="nsew", padx=(0, 14), pady=(0, 12))

        action_bar = ttk.Frame(win, padding=(14, 0, 14, 14))
        action_bar.grid(row=2, column=0, columnspan=2, sticky="ew")

        def selected_key() -> str:
            selection = listbox.curselection()
            if not selection:
                return keys[0]
            return keys[int(selection[0])]

        def render(_event: tk.Event | None = None) -> None:
            detail.configure(state="normal")
            detail.delete("1.0", "end")
            detail.insert("1.0", self.proxy_guide_text(selected_key()))
            detail.configure(state="disabled")

        ttk.Button(action_bar, text="Aplicar perfil", command=lambda: self.apply_proxy_type_to_profile(selected_key())).pack(
            side="left", padx=(0, 8)
        )
        ttk.Button(
            action_bar,
            text="Aplicar busqueda",
            command=lambda: self.apply_proxy_type_to_discovery(selected_key()),
        ).pack(side="left", padx=8)
        ttk.Button(action_bar, text="Aplicar uso", command=lambda: self.apply_proxy_type_use(selected_key())).pack(
            side="left", padx=8
        )
        ttk.Button(action_bar, text="Todos los tipos", command=self.apply_all_proxy_types).pack(side="left", padx=8)
        ttk.Button(action_bar, text="Buscar ahora", command=self.fetch_free_proxies).pack(side="right")

        listbox.bind("<<ListboxSelect>>", render)
        listbox.selection_set(0)
        render()

    def show_text_window(self, title: str, text: str) -> None:
        win = tk.Toplevel(self)
        win.title(title)
        win.geometry("860x520")
        win.configure(bg="#050814")
        win.columnconfigure(0, weight=1)
        win.rowconfigure(0, weight=1)
        widget = tk.Text(
            win,
            wrap="word",
            font=("DejaVu Sans Mono", 10),
            relief="flat",
            bg="#0b1020",
            fg="#ecfeff",
            insertbackground="#ff4fd8",
            padx=14,
            pady=12,
        )
        widget.grid(row=0, column=0, sticky="nsew")
        widget.insert("1.0", text)
        widget.configure(state="disabled")

    def show_ip_history(self) -> None:
        history = self.ip_history_store.load()
        win = tk.Toplevel(self)
        win.title(f"Historial de IP publica · max {DEFAULT_IP_HISTORY_LIMIT}")
        win.geometry("1500x520")
        win.columnconfigure(0, weight=1)
        win.rowconfigure(0, weight=1)
        columns = (
            "ip", "provider", "city", "region", "neighborhood", "road", "isp", "first_seen", "last_seen", "duration", "observations"
        )
        tree = ttk.Treeview(win, columns=columns, show="headings")
        headings = {
            "ip": "IP",
            "provider": "Proveedor",
            "city": "Ciudad",
            "region": "Region",
            "neighborhood": "Barrio/distrito",
            "road": "Calle/carretera",
            "isp": "ISP",
            "first_seen": "Primer visto",
            "last_seen": "Ultimo visto",
            "duration": "Tiempo desde cambio",
            "observations": "Obs.",
        }
        widths = {
            "ip": 140, "provider": 100, "city": 150, "region": 150, "neighborhood": 180,
            "road": 190, "isp": 190, "first_seen": 190, "last_seen": 190, "duration": 140, "observations": 60,
        }
        for col in columns:
            tree.heading(col, text=headings[col])
            tree.column(col, width=widths[col], stretch=col in {"city", "neighborhood", "road", "isp"})
        tree.grid(row=0, column=0, sticky="nsew")
        scrollbar = ttk.Scrollbar(win, orient="vertical", command=tree.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        tree.configure(yscrollcommand=scrollbar.set)
        xscroll = ttk.Scrollbar(win, orient="horizontal", command=tree.xview)
        xscroll.grid(row=1, column=0, sticky="ew")
        tree.configure(xscrollcommand=xscroll.set)
        now = datetime.now().astimezone()
        for item in reversed(history):
            snap = item.get("snapshot") or {}
            first_seen = str(item.get("first_seen") or "")
            first_dt = parse_iso(first_seen)
            duration = human_duration((now - first_dt).total_seconds()) if first_dt else ""
            tree.insert(
                "",
                "end",
                values=(
                    item.get("ip", ""),
                    snap.get("provider", ""),
                    snap.get("city", ""),
                    snap.get("region", ""),
                    snap.get("neighborhood", "") or snap.get("district", ""),
                    snap.get("road", "") or snap.get("street", ""),
                    snap.get("isp", "") or snap.get("org", ""),
                    first_seen,
                    item.get("last_seen", ""),
                    duration,
                    item.get("observations", ""),
                ),
            )

    def rotate_tor_once(self) -> None:
        try:
            port = int(self.ip_vars["tor_control_port"].get() or "9051")
        except ValueError:
            messagebox.showerror(APP_NAME, "ControlPort debe ser numerico.")
            return
        self.log(f"Solicitando nueva identidad Tor en 127.0.0.1:{port}...")

        def worker() -> None:
            ok, detail = TorController.signal_newnym(port=port)
            self.task_queue.put(("tor_newnym_result", (ok, detail)))

        threading.Thread(target=worker, daemon=True).start()

    def toggle_tor_rotation(self) -> None:
        self.tor_rotation_active = not self.tor_rotation_active
        if self.tor_rotation_active:
            self.log("Rotacion Tor automatica activada.")
            self.rotate_tor_once()
            self.schedule_tor_rotation()
        else:
            self.log("Rotacion Tor automatica desactivada.")

    def schedule_tor_rotation(self) -> None:
        if not self.tor_rotation_active:
            return
        try:
            minutes = max(1, int(self.ip_vars["tor_interval"].get() or "10"))
        except ValueError:
            minutes = 10
        self.after(minutes * 60 * 1000, self._tor_rotation_tick)

    def _tor_rotation_tick(self) -> None:
        if not self.tor_rotation_active:
            return
        self.rotate_tor_once()
        self.schedule_tor_rotation()

    def refresh_tree(self) -> None:
        selected = self.selected_id
        for item in self.tree.get_children():
            self.tree.delete(item)
        for profile in self.profiles:
            latency = "" if profile.latency_ms is None else str(profile.latency_ms)
            uptime = "" if profile.uptime_pct is None else f"{profile.uptime_pct:g}%"
            source_latency = "" if profile.source_latency_ms is None else str(profile.source_latency_ms)
            self.tree.insert(
                "",
                "end",
                iid=profile.id,
                values=(
                    "si" if profile.active else "",
                    profile.name,
                    profile.type,
                    profile.endpoint,
                    profile.country,
                    "laxa" if profile.country.upper() in LAX_DATA_PROTECTION_COUNTRIES else "",
                    profile.anonymity,
                    uptime,
                    source_latency,
                    profile.provider,
                    profile.status,
                    latency,
                ),
            )
        if selected and selected in {profile.id for profile in self.profiles}:
            self.tree.selection_set(selected)
            self.tree.focus(selected)

    def get_selected(self) -> ConnectionProfile | None:
        selection = self.tree.selection()
        if selection:
            self.selected_id = selection[0]
        if not self.selected_id:
            return None
        return next((profile for profile in self.profiles if profile.id == self.selected_id), None)

    def on_select(self, _event: tk.Event | None = None) -> None:
        profile = self.get_selected()
        if not profile:
            return
        self.fields["name"].set(profile.name)
        self.fields["type"].set(profile.type)
        self.fields["host"].set(profile.host)
        self.fields["port"].set(str(profile.port or ""))
        self.fields["country"].set(profile.country)
        self.fields["anonymity"].set(profile.anonymity)
        self.fields["uptime_pct"].set("" if profile.uptime_pct is None else str(profile.uptime_pct))
        self.fields["source_latency_ms"].set(
            "" if profile.source_latency_ms is None else str(profile.source_latency_ms)
        )
        self.fields["provider"].set(profile.provider)
        self.fields["config_path"].set(profile.config_path)
        self.fields["source"].set(profile.source)
        self.fields["notes"].set(profile.notes)

    def new_profile(self) -> None:
        profile = ConnectionProfile(
            id=safe_id(),
            name="Nuevo proxy HTTP",
            type="http",
            host="",
            port=8080,
        )
        self.profiles.append(profile)
        self.selected_id = profile.id
        self.refresh_tree()
        self.on_select()
        self.log("Perfil nuevo creado.")

    def add_tor_profile(self, log: bool = True) -> None:
        profile = ConnectionProfile(
            id=safe_id("tor"),
            name="Tor local",
            type="tor",
            host="127.0.0.1",
            port=9050,
            notes="Usa el servicio Tor local en 9050 o Tor Browser en 9150.",
        )
        self.profiles.append(profile)
        self.selected_id = profile.id
        self.refresh_tree()
        if log:
            self.log("Perfil Tor local anadido.")

    def apply_editor(self) -> None:
        profile = self.get_selected()
        if not profile:
            self.new_profile()
            profile = self.get_selected()
        if not profile:
            return
        profile.name = self.fields["name"].get().strip() or "Perfil"
        profile.type = self.fields["type"].get()
        profile.host = self.fields["host"].get().strip()
        try:
            profile.port = int(self.fields["port"].get() or "0")
        except ValueError:
            messagebox.showerror(APP_NAME, "El puerto debe ser numerico.")
            return
        profile.country = self.fields["country"].get().strip()
        profile.anonymity = self.fields["anonymity"].get().strip().lower()
        profile.uptime_pct = to_float(self.fields["uptime_pct"].get())
        profile.source_latency_ms = to_int(self.fields["source_latency_ms"].get())
        profile.speed_label = speed_from_latency(profile.source_latency_ms)
        profile.provider = self.fields["provider"].get().strip()
        profile.config_path = self.fields["config_path"].get().strip()
        profile.source = self.fields["source"].get().strip()
        profile.notes = self.fields["notes"].get().strip()
        self.refresh_tree()
        self.log(f"Perfil actualizado: {profile.name}")

    def add_profiles(self, imported: list[ConnectionProfile]) -> int:
        existing = {(p.type, p.host, p.port) for p in self.profiles}
        added = []
        for profile in imported:
            key = (profile.type, profile.host, profile.port)
            if key not in existing:
                added.append(profile)
                existing.add(key)
        self.profiles.extend(added)
        self.refresh_tree()
        return len(added)

    def delete_selected(self) -> None:
        profile = self.get_selected()
        if not profile:
            return
        if not messagebox.askyesno(APP_NAME, f"Eliminar {profile.name}?"):
            return
        self.profiles = [item for item in self.profiles if item.id != profile.id]
        self.selected_id = None
        self.refresh_tree()
        self.log(f"Perfil eliminado: {profile.name}")

    def import_proxies(self) -> None:
        path_text = filedialog.askopenfilename(
            title="Importar proxies",
            filetypes=(("Texto/CSV/JSON", "*.txt *.csv *.json"), ("Todos", "*.*")),
        )
        if not path_text:
            return
        path = Path(path_text)
        try:
            imported = import_proxy_file(path)
        except OSError as exc:
            messagebox.showerror(APP_NAME, str(exc))
            return

        added_count = self.add_profiles(imported)
        self.log(f"Importados {added_count} proxies validos desde {path}.")

    def read_discovery_options(self) -> DiscoveryOptions | None:
        try:
            min_uptime = int(self.discovery_fields["min_uptime"].get() or "0")
            max_latency = int(self.discovery_fields["max_latency"].get() or "1500")
            limit = int(self.discovery_fields["limit"].get() or "200")
        except ValueError:
            messagebox.showerror(APP_NAME, "Uptime, max ms y limite deben ser numericos.")
            return None
        if not (0 <= min_uptime <= 100):
            messagebox.showerror(APP_NAME, "Uptime debe estar entre 0 y 100.")
            return None
        if not (1 <= max_latency <= 120_000):
            messagebox.showerror(APP_NAME, "Max ms debe estar entre 1 y 120000.")
            return None
        if not (1 <= limit <= 2000):
            messagebox.showerror(APP_NAME, "Limite debe estar entre 1 y 2000.")
            return None
        return DiscoveryOptions(
            source=self.discovery_fields["source"].get(),
            protocol=self.discovery_fields["protocol"].get(),
            country=country_code(self.discovery_fields["country"].get()),
            anonymity=self.discovery_fields["anonymity"].get(),
            min_uptime=min_uptime,
            max_latency_ms=max_latency,
            limit=limit,
            lax_data_law_only=bool(self.discovery_fields["lax_data_law_only"].get()),
        )

    def set_fast_defaults(self) -> None:
        self.discovery_fields["source"].set("Todas")
        self.discovery_fields["protocol"].set("all")
        self.discovery_fields["country"].set("")
        self.discovery_fields["anonymity"].set("elite,anonymous")
        self.discovery_fields["min_uptime"].set("80")
        self.discovery_fields["max_latency"].set("800")
        self.discovery_fields["limit"].set("100")
        self.discovery_fields["lax_data_law_only"].set(False)
        self.log("Defaults rapidos aplicados: todas las fuentes, elite/anonymous, uptime 80%, max 800 ms, limite 100.")

    def fetch_free_proxies(self) -> None:
        options = self.read_discovery_options()
        if not options:
            return
        if options.anonymity == "all":
            if not messagebox.askyesno(
                APP_NAME,
                "Incluir transparentes reduce la privacidad. Continuar?",
            ):
                return
        self.log(
            "Buscando proxies gratis "
            f"fuente={options.source}, protocolo={options.protocol}, anon={options.anonymity}, "
            f"uptime>={options.min_uptime}%, max={options.max_latency_ms}ms, "
            f"laxo={options.lax_data_law_only}..."
        )

        def worker() -> None:
            profiles, errors = FreeProxyDiscovery.fetch(options)
            self.task_queue.put(("discovery_result", (profiles, errors, options)))

        threading.Thread(target=worker, daemon=True).start()

    def import_proxy_url(self) -> None:
        url = simpledialog.askstring("Importar URL", "URL de lista TXT/CSV/JSON:")
        if not url:
            return
        if not url.startswith(("https://", "http://")):
            messagebox.showerror(APP_NAME, "Usa una URL http:// o https://")
            return
        self.log(f"Descargando lista desde {url}...")

        def worker() -> None:
            try:
                req = request.Request(url, headers={"User-Agent": f"{APP_NAME}/1.0"})
                with request.urlopen(req, timeout=12) as response:
                    text = response.read(1_000_000).decode("utf-8", errors="replace")
                imported = import_proxy_text(text, source=url, is_json=url.lower().endswith(".json"))
                self.task_queue.put(("import_result", (url, imported, "")))
            except Exception as exc:
                self.task_queue.put(("import_result", (url, [], str(exc))))

        threading.Thread(target=worker, daemon=True).start()

    def choose_vpn_file(self) -> None:
        path_text = filedialog.askopenfilename(
            title="Elegir perfil VPN",
            filetypes=(("VPN config", "*.conf *.ovpn"), ("Todos", "*.*")),
        )
        if path_text:
            self.fields["config_path"].set(path_text)

    def test_selected(self) -> None:
        self.apply_editor()
        profile = self.get_selected()
        if not profile:
            return
        profile.status = "probando"
        profile.latency_ms = None
        self.refresh_tree()
        self.log(f"Probando {profile.name}...")

        def worker() -> None:
            ok, latency, detail = ConnectionTester.test_profile(profile)
            self.task_queue.put(("test_result", (profile.id, ok, latency, detail)))

        threading.Thread(target=worker, daemon=True).start()

    def _drain_queue(self) -> None:
        try:
            while True:
                event, payload = self.task_queue.get_nowait()
                if event == "test_result":
                    profile_id, ok, latency, detail = payload
                    profile = next((item for item in self.profiles if item.id == profile_id), None)
                    if profile:
                        profile.status = "ok" if ok else "fallo"
                        profile.latency_ms = latency
                        profile.last_test = time.strftime("%Y-%m-%d %H:%M:%S")
                        self.refresh_tree()
                        self.log(f"{profile.name}: {profile.status}. {detail}")
                        if ok:
                            self.connection_live = True
                            self.connection_mode_var.set(
                                f"MODO {CONNECTION_MODE_CONFIGS[self.connection_mode]['label']} · LINK LIVE"
                            )
                            self.apply_connection_palette(self.connection_mode, live=True)
                            self.log(
                                f"LINK LIVE: {profile.name} conectado · IP publica se refrescara · paleta activa {self.connection_mode}."
                            )
                        else:
                            self.connection_live = False
                            self.connection_mode_var.set(
                                f"MODO {CONNECTION_MODE_CONFIGS[self.connection_mode]['label']} · LINK FAIL"
                            )
                            self.apply_connection_palette(self.connection_mode, live=False)
                elif event == "local_telemetry_result":
                    self.update_local_telemetry(payload)
                elif event == "import_result":
                    source, imported, error = payload
                    if error:
                        self.log(f"No se pudo importar {source}: {error}")
                    else:
                        added_count = self.add_profiles(imported)
                        self.log(f"Importados {added_count} proxies validos desde {source}.")
                elif event == "discovery_result":
                    profiles, errors, options = payload
                    added_count = self.add_profiles(profiles)
                    self.log(
                        f"Descubrimiento terminado: {len(profiles)} candidatos, {added_count} nuevos "
                        f"(anon={options.anonymity}, uptime>={options.min_uptime}%)."
                    )
                    if options.lax_data_law_only:
                        self.log("Filtro legal aplicado: paises sin ley integral aparente o proteccion fragmentaria.")
                    for error in errors:
                        self.log(f"Fuente con error: {error}")
                elif event == "ip_lookup_result":
                    purpose, snapshot, history, changed, error, *extra = payload
                    if error:
                        self.log(f"No se pudo geolocalizar IP ({purpose}): {error}")
                    elif purpose == "public":
                        self.update_ip_summary(snapshot, history, changed)
                        marker = "cambio detectado" if changed else "sin cambio"
                        self.log(f"IP publica actualizada: {snapshot.ip} ({marker}) · {snapshot.location_line}")
                    elif purpose == "selected":
                        profile_id = extra[0] if extra else None
                        profile = next((item for item in self.profiles if item.id == profile_id), None)
                        if profile:
                            profile.geo_city = snapshot.city
                            profile.geo_region = snapshot.region
                            profile.geo_country = snapshot.country_code or snapshot.country
                            profile.geo_latitude = snapshot.latitude
                            profile.geo_longitude = snapshot.longitude
                            profile.geo_isp = snapshot.isp
                            profile.geo_asn = snapshot.asn
                            profile.geo_flags = snapshot.flags_line
                            profile.geo_checked_at = snapshot.observed_at
                            self.refresh_tree()
                        self.log(
                            f"IP seleccionada: {snapshot.ip} · {snapshot.location_line} · "
                            f"ASN {snapshot.asn or '-'} · {snapshot.flags_line}"
                        )
                        try:
                            path = MapWriter.write(snapshot, [])
                            webbrowser.open(path.as_uri())
                        except ValueError:
                            pass
                elif event == "tor_newnym_result":
                    ok, detail = payload
                    self.log(("Tor OK: " if ok else "Tor fallo: ") + detail)
                    if ok:
                        self.after(5000, self.refresh_public_ip)
                elif event == "command_result":
                    label, returncode, output = payload
                    status = "OK" if returncode == 0 else f"fallo {returncode}"
                    self.log(f"{label}: {status}")
                    if output:
                        self.log(output[-1200:])
                    if returncode == 0 and "VPN" in label:
                        self.connection_live = True
                        self.connection_mode_var.set(
                            f"MODO {CONNECTION_MODE_CONFIGS[self.connection_mode]['label']} · LINK LIVE"
                        )
                        self.apply_connection_palette(self.connection_mode, live=True)
                        self.log(f"LINK LIVE: {label} · paleta activa {self.connection_mode}.")
                        self.after(4000, self.refresh_public_ip)
        except queue.Empty:
            pass
        self.after(150, self._drain_queue)

    def activate_selected(self) -> None:
        profile = self.get_selected()
        if not profile:
            return
        for item in self.profiles:
            item.active = item.id == profile.id
        self.refresh_tree()
        self.log(f"Perfil activo: {profile.name}")
        if profile.type in {"http", "https", "socks4", "socks5", "tor"}:
            self.log("Usa Comandos para lanzar apps con este proxy sin cambiar todo el sistema.")
            self.show_commands()

    def save_plain(self) -> None:
        self.apply_editor()
        try:
            self.store.save_plain(self.profiles)
        except OSError as exc:
            messagebox.showerror(APP_NAME, str(exc))
            return
        self.log(f"Guardado local en {CONFIG_FILE}")

    def save_encrypted(self) -> None:
        self.apply_editor()
        if not HAS_CRYPTOGRAPHY:
            messagebox.showwarning(
                APP_NAME,
                "Instala cryptography para cifrado fuerte:\npython3 -m pip install cryptography",
            )
            return
        password = simpledialog.askstring("Guardar cifrado", "Contrasena:", show="*")
        if not password:
            return
        confirm = simpledialog.askstring("Guardar cifrado", "Repite la contrasena:", show="*")
        if password != confirm:
            messagebox.showerror(APP_NAME, "Las contrasenas no coinciden.")
            return
        try:
            self.store.save_encrypted(self.profiles, password)
        except Exception as exc:
            messagebox.showerror(APP_NAME, str(exc))
            return
        self.log(f"Guardado cifrado en {ENCRYPTED_CONFIG_FILE}")

    def show_commands(self) -> None:
        profile = self.get_selected()
        if not profile:
            return
        self.log(f"Comandos para {profile.name}:")
        if profile.type in {"http", "https", "socks5", "tor"}:
            self.log(CommandBuilder.proxy_environment(profile))
            self.log(CommandBuilder.browser_command(profile))
            self.log(CommandBuilder.proxychains_snippet(profile))
            self.log(CommandBuilder.proxychains_command(profile))
            self.log(CommandBuilder.torsocks_command(profile))
        elif profile.type in {"wireguard", "openvpn"}:
            self.log(CommandBuilder.vpn_up(profile))
            self.log(CommandBuilder.vpn_down(profile))

    def write_proxychains_config(self) -> bool:
        self.apply_editor()
        profile = self.get_selected()
        if not profile or profile.type not in {"http", "https", "socks4", "socks5", "tor"}:
            messagebox.showinfo(APP_NAME, "Selecciona un perfil proxy o Tor.")
            return False
        config = CommandBuilder.proxychains_snippet(profile)
        try:
            PROXYCHAINS_CONFIG_FILE.write_text(config + "\n", encoding="utf-8")
            chmod_private(PROXYCHAINS_CONFIG_FILE)
        except OSError as exc:
            messagebox.showerror(APP_NAME, str(exc))
            return False
        self.log(f"ProxyChains local escrito: {PROXYCHAINS_CONFIG_FILE}")
        return True

    def launch_proxychains_chromium(self) -> None:
        profile = self.get_selected()
        if not profile:
            return
        if not self.write_proxychains_config():
            return
        if not shutil.which("proxychains4"):
            messagebox.showerror(APP_NAME, "proxychains4 no esta instalado.")
            return
        command = ["proxychains4", "-f", str(PROXYCHAINS_CONFIG_FILE), "chromium"]
        self.launch_background(command, "Chromium via ProxyChains")

    def launch_torsocks_chromium(self) -> None:
        profile = self.get_selected()
        if not profile or profile.type != "tor":
            messagebox.showinfo(APP_NAME, "torsocks solo se lanza con perfil Tor.")
            return
        if not shutil.which("torsocks"):
            messagebox.showerror(APP_NAME, "torsocks no esta instalado.")
            return
        command = ["torsocks", "chromium"]
        self.launch_background(command, "Chromium via torsocks")

    def launch_background(self, command: list[str], label: str) -> None:
        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
            self.log(f"{label} lanzado: pid {process.pid}")
        except OSError as exc:
            messagebox.showerror(APP_NAME, str(exc))

    def command_output(self, command: list[str], timeout: int = 20) -> tuple[int, str]:
        try:
            completed = subprocess.run(command, check=False, capture_output=True, text=True, timeout=timeout)
            return completed.returncode, (completed.stdout or completed.stderr or "").strip()
        except Exception as exc:
            return 1, str(exc)

    def run_background_command(self, command: list[str], label: str, timeout: int = 60) -> None:
        self.log(f"Ejecutando {label}: {shell_join(command)}")

        def worker() -> None:
            try:
                completed = subprocess.run(
                    command,
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                )
                output = (completed.stdout or completed.stderr or "").strip()
                self.task_queue.put(("command_result", (label, completed.returncode, output)))
            except Exception as exc:
                self.task_queue.put(("command_result", (label, 1, str(exc))))

        threading.Thread(target=worker, daemon=True).start()

    def apply_proxy_use(self) -> None:
        profile = self.get_selected()
        use_case = self.ip_vars["proxy_use"].get()
        if not profile:
            messagebox.showinfo(APP_NAME, "Selecciona un perfil primero.")
            return
        if use_case == "Navegador rapido":
            self.log(CommandBuilder.browser_command(profile))
            if profile.browser_proxy_url and messagebox.askyesno(APP_NAME, "Lanzar Chromium con este proxy?"):
                self.launch_background(["chromium", f"--proxy-server={profile.browser_proxy_url}"], "Chromium con proxy")
        elif use_case == "Terminal con env":
            self.log(CommandBuilder.proxy_environment(profile))
        elif use_case == "ProxyChains app":
            self.write_proxychains_config()
            self.log(CommandBuilder.proxychains_command(profile))
        elif use_case == "Tor/torsocks":
            self.connect_tor_fast()
            self.log(CommandBuilder.torsocks_command(profile))
        elif use_case == "VPN completa":
            self.vpn_easy_connect()
        elif use_case == "OSINT ligero":
            self.write_proxychains_config()
            self.log("Perfil recomendado para OSINT: Tor o SOCKS5 elite, navegador limpio, sin cuentas personales.")
            self.log(CommandBuilder.proxychains_command(profile))
        elif use_case == "Descargas aisladas":
            self.write_proxychains_config()
            self.log(shell_join(["proxychains4", "-f", str(PROXYCHAINS_CONFIG_FILE), "curl", "-L", "URL"]))

    def proton_command_for_mode(self) -> list[str]:
        mode = self.ip_vars["proton_mode"].get()
        country = country_code(self.ip_vars["vpn_country"].get())
        if mode == "country" and country:
            return ["protonvpn", "connect", "--cc", country]
        if mode == "secure-core":
            return ["protonvpn", "connect", "--sc"]
        if mode == "tor":
            return ["protonvpn", "connect", "--tor"]
        if mode == "p2p":
            return ["protonvpn", "connect", "--p2p"]
        if mode == "random":
            return ["protonvpn", "connect", "--random"]
        return ["protonvpn", "connect", "--fastest"]

    def toggle_proton(self) -> None:
        if not shutil.which("protonvpn"):
            messagebox.showerror(APP_NAME, "protonvpn no esta instalado.")
            return
        connect_command = self.proton_command_for_mode()

        def worker() -> None:
            _, status = self.command_output(["protonvpn", "status"], timeout=20)
            if "Connected" in status or "connected" in status:
                command = ["protonvpn", "disconnect"]
                label = "Proton VPN OFF"
            else:
                command = connect_command
                label = "Proton VPN ON"
            code, output = self.command_output(command, timeout=120)
            self.task_queue.put(("command_result", (label, code, output)))

        threading.Thread(target=worker, daemon=True).start()

    def surfshark_binary(self) -> str:
        return shutil.which("surfshark-vpn") or shutil.which("surfshark") or ""

    def toggle_surfshark(self) -> None:
        binary = self.surfshark_binary()
        if not binary:
            messagebox.showerror(APP_NAME, "Surfshark no esta instalado. Usa VPN facil con .conf/.ovpn.")
            return
        location = self.ip_vars["surfshark_location"].get().strip()

        def worker() -> None:
            _, status = self.command_output([binary, "status"], timeout=20)
            if "Connected" in status or "connected" in status:
                command = [binary, "disconnect"]
                label = "Surfshark VPN OFF"
            else:
                command = [binary, "connect"]
                if location:
                    command.append(location)
                label = "Surfshark VPN ON"
            code, output = self.command_output(command, timeout=120)
            self.task_queue.put(("command_result", (label, code, output)))

        threading.Thread(target=worker, daemon=True).start()

    def disconnect_anonymous(self) -> None:
        self.connection_live = False
        self.connection_mode = "default"
        self.connection_mode_var.set("MODO DEFAULT · desconectado")
        self.apply_connection_palette("default", live=False)
        for item in self.profiles:
            item.active = False
        self.refresh_tree()
        if shutil.which("protonvpn"):
            self.run_background_command(["protonvpn", "disconnect"], "Proton VPN OFF", timeout=60)
        surfshark = self.surfshark_binary()
        if surfshark:
            self.run_background_command([surfshark, "disconnect"], "Surfshark VPN OFF", timeout=60)
        self.log("Perfiles proxy desactivados en el dashboard. Tor queda instalado, pero no se fuerza como ruta de apps.")
        self.after(4000, self.refresh_public_ip)

    def connect_tor_fast(self) -> None:
        tor_profile = next((item for item in self.profiles if item.type == "tor"), None)
        if not tor_profile:
            self.add_tor_profile(log=False)
            tor_profile = self.get_selected()
        if not tor_profile:
            return
        self.selected_id = tor_profile.id
        for item in self.profiles:
            item.active = item.id == tor_profile.id
        self.refresh_tree()
        self.write_proxychains_config()
        self.test_selected()
        self.rotate_tor_once()
        self.log("Tor rapido activo: perfil Tor seleccionado, ProxyChains escrito y NEWNYM solicitado.")

    def vpn_easy_connect(self) -> None:
        self.apply_editor()
        profile = self.get_selected()
        if not profile or profile.type not in {"wireguard", "openvpn"} or not profile.config_path:
            path_text = filedialog.askopenfilename(
                title="Elegir perfil VPN",
                filetypes=(("VPN config", "*.conf *.ovpn"), ("Todos", "*.*")),
            )
            if not path_text:
                return
            suffix = Path(path_text).suffix.lower()
            vpn_type = "openvpn" if suffix == ".ovpn" else "wireguard"
            profile = ConnectionProfile(
                id=safe_id("vpn"),
                name=Path(path_text).stem,
                type=vpn_type,
                config_path=path_text,
            )
            self.profiles.append(profile)
            self.selected_id = profile.id
            self.refresh_tree()
            self.on_select()

        path = Path(profile.config_path).expanduser()
        if not path.exists():
            messagebox.showerror(APP_NAME, "No existe el archivo VPN seleccionado.")
            return
        if shutil.which("nmcli"):
            import_type = "openvpn" if profile.type == "openvpn" else "wireguard"
            self.run_background_command(["nmcli", "connection", "import", "type", import_type, "file", str(path)], "importar VPN")
            connection_name = profile.name or path.stem
            self.after(2500, lambda: self.run_background_command(["nmcli", "connection", "up", connection_name], "conectar VPN"))
        else:
            self.log("NetworkManager/nmcli no disponible; uso metodo pkexec clasico.")
            self.connect_vpn()

    def connect_vpn(self) -> None:
        self.apply_editor()
        profile = self.get_selected()
        if not profile or profile.type not in {"wireguard", "openvpn"}:
            messagebox.showinfo(APP_NAME, "Selecciona un perfil WireGuard u OpenVPN.")
            return
        command = CommandBuilder.vpn_up(profile)
        if not messagebox.askyesno(APP_NAME, f"Ejecutar?\n\n{command}"):
            return
        try:
            self.active_process = subprocess.Popen(
                shlex.split(command),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            self.log(f"Proceso VPN lanzado: pid {self.active_process.pid}")
        except OSError as exc:
            messagebox.showerror(APP_NAME, str(exc))

    def disconnect_vpn(self) -> None:
        profile = self.get_selected()
        if not profile:
            return
        if profile.type == "openvpn" and self.active_process and self.active_process.poll() is None:
            self.active_process.terminate()
            self.log("OpenVPN detenido con terminate().")
            return
        command = CommandBuilder.vpn_down(profile)
        if command.startswith("#"):
            self.log(command)
            return
        if not messagebox.askyesno(APP_NAME, f"Ejecutar?\n\n{command}"):
            return
        try:
            completed = subprocess.run(
                shlex.split(command),
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.log(completed.stdout or completed.stderr or f"Salida codigo {completed.returncode}")
        except OSError as exc:
            messagebox.showerror(APP_NAME, str(exc))


def self_test() -> int:
    parsed = parse_proxy_line("http://127.0.0.1:8080")
    assert parsed is not None
    assert parsed.host == "127.0.0.1"
    assert parsed.port == 8080
    assert parsed.type == "http"
    parsed = parse_proxy_line("ES,socks5,10.0.0.5,9050")
    assert parsed is not None
    assert parsed.country == "ES"
    assert parsed.type == "socks5"
    tor = ConnectionProfile(id="tor", name="Tor", type="tor")
    assert "127.0.0.1" in CommandBuilder.proxy_environment(tor)
    profile = profile_from_proxy_record(
        {
            "protocol": "http",
            "host": "192.0.2.10",
            "port": 8080,
            "geoCountry": "ES",
            "anonymityLevel": "elite",
            "responseTimeMs": 321,
            "uptimeRating": 98,
            "pingAt": "2026-09-15T10:00:00Z",
        },
        source="test",
        provider="Litport",
    )
    assert profile is not None
    assert profile.provider == "Litport"
    assert profile.anonymity == "elite"
    assert profile.uptime_pct == 98
    assert profile.source_latency_ms == 321
    opts = DiscoveryOptions(lax_data_law_only=True)
    lax = ConnectionProfile(id="1", name="us", type="http", host="1.1.1.1", port=80, country="US")
    strict = ConnectionProfile(id="2", name="es", type="http", host="2.2.2.2", port=80, country="ES")
    assert FreeProxyDiscovery.filter_profiles([lax, strict], opts) == [lax]
    print("self-test ok")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=APP_NAME)
    parser.add_argument("--self-test", action="store_true", help="Run non-GUI checks")
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    app = Dashboard()
    app.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

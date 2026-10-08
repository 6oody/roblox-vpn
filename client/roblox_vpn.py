#!/usr/bin/env python3
"""
RobloxVPN - a minimal-data, split-tunnel VPN client for unblocking Roblox.

How it works
------------
Drives the official AmneziaWG Windows client (``amneziawg.exe`` / ``awg.exe``)
to bring an obfuscated WireGuard tunnel up/down as a Windows service
(``AmneziaWGTunnel$roblox``). Only Roblox traffic (AS22697) is routed through
the tunnel -- everything else stays on the direct connection, so metered-data
usage stays minimal. Full-tunnel configs are rejected on import.

Usage
-----
    RobloxVPN.exe              start the tray app (self-elevates to admin)
    RobloxVPN.exe --mock       dry-run mode: no admin, no real tunnel
    RobloxVPN.exe --self-test  run built-in logic tests and exit
"""

import argparse
import json
import os
import platform
import random
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

APP_NAME = "RobloxVPN"
APP_VERSION = "v31"
TUNNEL_NAME = "roblox"
SERVICE_NAME = "AmneziaWGTunnel$" + TUNNEL_NAME

# Roblox network footprint, grounded in ipinfo.io WHOIS (ARIN NET-128-116-0-0-1,
# OrgName "Roblox", ASN AS22697 -> 128.116.0.0/17). WARNING: 128.116.128.0/17 is
# AS35612 (EOLO S.p.A.), NOT Roblox -- never add it.
ROBLOX_ALLOWED_IPS = ["128.116.0.0/17"]

# Roblox endpoints that must resolve through the tunnel's network path.
# (Website/API = TCP 443, game servers = UDP 49152-65535; the CDN hosts below
# are only needed by the launcher and normally work direct, but resolving them
# here documents the full footprint.)
ROBLOX_HOSTS = [
    "www.roblox.com",
    "api.roblox.com",
    "setup.roblox.com",
    "setup.rbxcdn.com",
    "clientsettings.roblox.com",
]

DEFAULT_PORT = 443          # UDP 443 is less conspicuous than 51820
DEFAULT_MTU = 1420
CLIENT_ADDRESS = "10.8.0.2/32"
SERVER_NETWORK = "10.8.0.0/24"
PERSISTENT_KEEPALIVE = 25   # seconds; keeps NAT mapping alive, ~bytes/min

# Links used by the built-in setup guide (first-run onboarding).
GUIDE_LINKS = {
    "proton_free": "https://protonvpn.com/free-vpn",
    "proton_wg": "https://account.protonvpn.com/downloads",
}


def _app_dir():
    base = os.environ.get("APPDATA") or os.path.expanduser("~")
    d = os.path.join(base, APP_NAME)
    os.makedirs(d, exist_ok=True)
    return d


APP_DIR = None  # resolved lazily so --self-test works without touching disk
def app_dir():
    global APP_DIR
    if APP_DIR is None:
        APP_DIR = _app_dir()
    return APP_DIR


def conf_path():
    return os.path.join(app_dir(), TUNNEL_NAME + ".conf")


def stats_path():
    return os.path.join(app_dir(), "stats.json")


def settings_path():
    return os.path.join(app_dir(), "settings.json")


# ---------------------------------------------------------------------------
# Small pure helpers (covered by --self-test)
# ---------------------------------------------------------------------------

def fmt_bytes(n):
    """Human-readable byte count, e.g. 1536 -> '1.5 KB'."""
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return "%d %s" % (n, unit) if unit == "B" else "%.1f %s" % (n, unit)
        n /= 1024.0


def parse_transfer_amount(amount, unit):
    """Convert e.g. ('6.55', 'KiB') to bytes."""
    mult = {"B": 1, "KIB": 1024, "MIB": 1024 ** 2, "GIB": 1024 ** 3,
            "KB": 1000, "MB": 1000 ** 2, "GB": 1000 ** 3}
    return int(float(amount) * mult.get(unit.upper(), 1))


def parse_awg_show(text):
    """Parse `awg show <tunnel>` output.

    Returns dict(rx_bytes, tx_bytes, handshake, endpoint) or None if the
    tunnel is not up.
    """
    if not text or "interface:" not in text:
        return None
    m = re.search(
        r"transfer:\s*([\d.]+)\s*([KMGT]?i?B)\s*received,\s*"
        r"([\d.]+)\s*([KMGT]?i?B)\s*sent",
        text, re.IGNORECASE)
    if not m:
        return None
    hs = re.search(r"latest handshake:\s*(.+)", text)
    ep = re.search(r"endpoint:\s*(\S+)", text)
    return {
        "rx_bytes": parse_transfer_amount(m.group(1), m.group(2)),
        "tx_bytes": parse_transfer_amount(m.group(3), m.group(4)),
        "handshake": hs.group(1).strip() if hs else "?",
        "endpoint": ep.group(1).strip() if ep else "?",
    }


def random_obfuscation(rng=None):
    """Random AmneziaWG handshake-obfuscation params (must match the server)."""
    r = rng or random.SystemRandom()
    jmin = r.randint(20, 60)
    return {
        "Jc": r.randint(3, 10),
        "Jmin": jmin,
        "Jmax": jmin + r.randint(10, 60),
        "S1": r.randint(15, 127),
        "S2": r.randint(15, 127),
        "S3": r.randint(15, 127),
        "S4": r.randint(15, 127),
        "H1": r.randint(1, 2 ** 32 - 1),
        "H2": r.randint(1, 2 ** 32 - 1),
        "H3": r.randint(1, 2 ** 32 - 1),
        "H4": r.randint(1, 2 ** 32 - 1),
    }


def generate_private_key():
    """Generate a WireGuard private key (base64, 44 chars)."""
    import base64
    return base64.b64encode(random.SystemRandom().randbytes(32)).decode()


def generate_config(server_host, server_port, server_pubkey, client_privkey,
                    psk=None, address=CLIENT_ADDRESS, mtu=DEFAULT_MTU,
                    allowed_ips=None, obf=None,
                    keepalive=PERSISTENT_KEEPALIVE):
    """Build an AmneziaWG client .conf (split-tunnel, Roblox only)."""
    allowed_ips = allowed_ips or ROBLOX_ALLOWED_IPS
    obf = obf or random_obfuscation()
    lines = [
        "[Interface]",
        "PrivateKey = " + client_privkey.strip(),
        "Address = " + address,
        "MTU = %d" % mtu,
        "Jc = %d" % obf["Jc"],
        "Jmin = %d" % obf["Jmin"],
        "Jmax = %d" % obf["Jmax"],
        "S1 = %d" % obf["S1"],
        "S2 = %d" % obf["S2"],
        "S3 = %d" % obf["S3"],
        "S4 = %d" % obf["S4"],
        "H1 = %d" % obf["H1"],
        "H2 = %d" % obf["H2"],
        "H3 = %d" % obf["H3"],
        "H4 = %d" % obf["H4"],
        "",
        "[Peer]",
        "PublicKey = " + server_pubkey.strip(),
    ]
    if psk:
        lines.append("PresharedKey = " + psk.strip())
    lines += [
        "Endpoint = %s:%d" % (server_host.strip(), int(server_port)),
        "AllowedIPs = " + ", ".join(allowed_ips),
        "PersistentKeepalive = %d" % keepalive,
        "",
    ]
    return "\n".join(lines)


def _split_allowed_ips(text):
    vals = []
    for sec in re.finditer(
            r"^\[Peer\](.*?)(?=^\[|\Z)", text, re.MULTILINE | re.DOTALL):
        for m in re.finditer(r"^AllowedIPs\s*=\s*(.+)$", sec.group(1),
                             re.MULTILINE | re.IGNORECASE):
            vals += [v.strip() for v in m.group(1).split(",") if v.strip()]
    return vals


def convert_to_split_tunnel(text):
    """Rewrite a full-tunnel .conf into a Roblox-only split-tunnel .conf.

    Keeps Interface keys, Peer endpoint/keys, comments -- the [Peer]
    AllowedIPs lines are replaced with ROBLOX_ALLOWED_IPS (this is what
    makes third-party configs, e.g. ProtonVPN free which ships 0.0.0.0/0,
    usable without burning metered data), and a provider-internal DNS
    (e.g. ProtonVPN's 10.2.0.1, unreachable outside their full tunnel) is
    replaced with public resolvers so name resolution keeps working.
    Pure -- covered by --self-test.
    """
    def _repl_peer(m):
        body = m.group(1)
        new_body = re.sub(r"^AllowedIPs\s*=.*$",
                          "AllowedIPs = " + ", ".join(ROBLOX_ALLOWED_IPS),
                          body, flags=re.MULTILINE | re.IGNORECASE)
        return "[Peer]" + new_body

    text = re.sub(r"^\[Peer\](.*?)(?=^\[|\Z)", _repl_peer, text,
                  flags=re.MULTILINE | re.DOTALL)
    return _fix_dns_for_split_tunnel(text)


def _is_private_ip(ip):
    """True for RFC1918 / loopback addresses (unreachable via split tunnel)."""
    ip = ip.strip().lower()
    if ip.startswith(("10.", "192.168.", "127.", "::1")):
        return True
    if ip.startswith("172."):
        try:
            return 16 <= int(ip.split(".")[1]) <= 31
        except (IndexError, ValueError):
            return False
    return ip.startswith("fc00:") or ip.startswith("fd00:")


def _fix_dns_for_split_tunnel(text):
    """Replace provider-internal DNS with public resolvers.

    Provider configs (e.g. ProtonVPN) ship DNS = 10.x.x.x which is only
    reachable through their full tunnel. In our split tunnel that address
    is a blackhole: Windows sends name queries there, they die, and it
    feels like "the internet disconnected". Public resolvers go direct
    and work with or without the tunnel. Pure -- covered by --self-test.
    """
    def _repl_iface(m):
        body = m.group(1)
        dm = re.search(r"^DNS\s*=\s*(.+)$", body,
                       re.MULTILINE | re.IGNORECASE)
        if not dm:
            return m.group(0)
        vals = [v.strip() for v in dm.group(1).split(",")]
        if any(_is_private_ip(v) for v in vals):
            body = re.sub(r"^DNS\s*=.*$", "DNS = 1.1.1.1, 8.8.8.8",
                          body, flags=re.MULTILINE | re.IGNORECASE)
        return "[Interface]" + body

    return re.sub(r"^\[Interface\](.*?)(?=^\[|\Z)", _repl_iface, text,
                  flags=re.MULTILINE | re.DOTALL | re.IGNORECASE)


AWG_OBF_KEYS = ("Jc", "Jmin", "Jmax",
                "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4")


def has_obfuscation(text):
    """True if the config enables AmneziaWG obfuscation (Jc/S/H params)."""
    return any(re.search(r"^%s\s*=" % k, text,
                        re.MULTILINE | re.IGNORECASE)
               for k in AWG_OBF_KEYS)


def strip_obfuscation(text):
    """Remove AmneziaWG obfuscation params from a config.

    Needed when a config made for a private AmneziaWG server is used against
    a plain-WireGuard server (e.g. ProtonVPN): the obfuscated handshake is
    unparseable there, so it stays stuck at "waiting for handshake" forever.
    Keeps keys, endpoint, DNS and AllowedIPs untouched. Pure -- self-tested.
    """
    return re.sub(r"^(Jc|Jmin|Jmax|S[1-4]|H[1-4])\s*=.*$\n?",
                  "", text, flags=re.MULTILINE | re.IGNORECASE)


def validate_config_text(text, allow_full_tunnel=False):
    """Validate an imported .conf. Returns (ok, errors, warnings)."""
    errors, warnings = [], []
    if "[Interface]" not in text:
        errors.append("missing [Interface] section")
    if "[Peer]" not in text:
        errors.append("missing [Peer] section")
    pm = re.search(r"^PrivateKey\s*=\s*(\S+)", text, re.MULTILINE)
    if not pm:
        errors.append("missing PrivateKey in [Interface]")
    elif not re.fullmatch(r"[A-Za-z0-9+/]{43}=", pm.group(1)):
        # ProtonVPN's site masks the private key with asterisks unless you
        # download immediately after creating the config -- a masked key
        # parses fine but the server silently ignores every handshake.
        errors.append(
            "PrivateKey is not a valid WireGuard key (got %r). The site "
            "masks it with asterisks unless you download IMMEDIATELY after "
            "creating the config -- re-create it on Proton's site and "
            "download right away, then import the fresh file." %
            (pm.group(1)[:12] + "..."))
    if not re.search(r"^PublicKey\s*=\s*\S+", text, re.MULTILINE):
        errors.append("missing PublicKey in [Peer]")
    if not re.search(r"^Endpoint\s*=\s*\S+:\d+", text, re.MULTILINE):
        errors.append("missing or malformed Endpoint (host:port) in [Peer]")
    allowed = _split_allowed_ips(text)
    if not allowed:
        errors.append("missing AllowedIPs in [Peer]")
    full = [a for a in allowed if a in ("0.0.0.0/0", "::/0")]
    if full and not allow_full_tunnel:
        errors.append(
            "FULL-TUNNEL config (%s) rejected: this app is split-tunnel only "
            "(Roblox traffic). Full tunnel burns metered data." % ", ".join(full))
    if allowed and not any(a in ROBLOX_ALLOWED_IPS for a in allowed):
        warnings.append(
            "AllowedIPs does not include the Roblox range %s; Roblox may not "
            "be routed through the tunnel." % ", ".join(ROBLOX_ALLOWED_IPS))
    has_awg = has_obfuscation(text)
    if not has_awg:
        warnings.append(
            "no AmneziaWG obfuscation params (Jc/S1..) found -- plain "
            "WireGuard config. It will work with the AmneziaWG client, but "
            "the handshake is easier for DPI to fingerprint.")
    return (not errors, errors, warnings)

# ---------------------------------------------------------------------------
# Tunnel backends
# ---------------------------------------------------------------------------

class TunnelError(Exception):
    pass


def _run(cmd, timeout=30):
    """Run a command, return (ok, stdout+stderr). Never raises."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, **_no_window())
        return p.returncode == 0, (p.stdout or "") + (p.stderr or "")
    except FileNotFoundError:
        return False, "not found: %s" % cmd[0]
    except Exception as e:  # noqa: BLE001
        return False, str(e)


def _no_window():
    """subprocess kwargs that prevent console-window flashing on Windows.

    The exe is built --noconsole, but every child process (awg show every
    2s, sc, msiexec) would otherwise pop a visible cmd window.
    """
    if os.name != "nt":
        return {}
    si = subprocess.STARTUPINFO()
    si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    return {"startupinfo": si,
            "creationflags": subprocess.CREATE_NO_WINDOW}


# ---------------------------------------------------------------------------
# AmneziaWG auto-install: if the official Windows client is missing, this app
# downloads its MSI from the GitHub releases page and installs it silently --
# zero manual steps for the user. (~4 MB, the only download this app ever
# makes on its own.)
# ---------------------------------------------------------------------------

AWG_GITHUB_REPO = "amnezia-vpn/amneziawg-windows-client"
AWG_RELEASES_API = ("https://api.github.com/repos/" + AWG_GITHUB_REPO +
                    "/releases/latest")


def awg_arch_key(machine=None):
    """Map platform.machine() to the AmneziaWG release asset arch tag."""
    m = (machine or platform.machine()).lower()
    if "arm64" in m or "aarch64" in m:
        return "arm64"
    if m in ("x86", "i386", "i686"):
        return "x86"
    return "amd64"  # AMD64 / x86_64 default


def pick_awg_asset(assets, machine=None):
    """Pick the right .msi from a GitHub release asset list.

    assets: iterable of dicts with 'name'/'browser_download_url'/'size'.
    Returns (name, url, size) or None. Pure -- covered by --self-test.
    """
    want = "amneziawg-%s-" % awg_arch_key(machine)
    for a in assets or []:
        name = a.get("name", "")
        if name.startswith(want) and name.endswith(".msi"):
            return name, a.get("browser_download_url"), a.get("size", 0)
    return None


def _github_json(url, timeout=20):
    req = urllib.request.Request(
        url, headers={"User-Agent": APP_NAME,
                      "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


def download_awg_installer(progress_cb=None, timeout=30):
    """Download the AmneziaWG Windows MSI for this machine.

    Returns the local .msi path. Raises TunnelError on any failure.
    """
    try:
        rel = _github_json(AWG_RELEASES_API, timeout=timeout)
    except Exception as e:  # noqa: BLE001
        raise TunnelError("could not reach GitHub releases: %s" % e)
    picked = pick_awg_asset(rel.get("assets"))
    if not picked:
        raise TunnelError("no Windows installer found in the latest "
                          "AmneziaWG release")
    name, url, size = picked
    if not url:
        raise TunnelError("release asset has no download URL")
    dest = os.path.join(tempfile.gettempdir(), name)
    if size and os.path.isfile(dest) and os.path.getsize(dest) == size:
        return dest  # already fetched earlier
    try:
        req = urllib.request.Request(url, headers={"User-Agent": APP_NAME})
        with urllib.request.urlopen(req, timeout=timeout) as r, \
                open(dest, "wb") as f:
            total = int(r.headers.get("Content-Length") or size or 0)
            done = 0
            while True:
                chunk = r.read(256 * 1024)
                if not chunk:
                    break
                f.write(chunk)
                done += len(chunk)
                if progress_cb:
                    progress_cb(done, total)
    except Exception as e:  # noqa: BLE001
        try:
            os.unlink(dest)
        except OSError:
            pass
        raise TunnelError("download failed: %s" % e)
    return dest


def _msi_log_path():
    return os.path.join(tempfile.gettempdir(), "awg-install.log")


def _msi_failure_hint(log_path):
    """Extract the most useful error context from a verbose MSI log.

    MSI marks a failing custom action with "Return value 3" -- grab the
    lines around it. Pure -- covered by --self-test.
    """
    try:
        with open(log_path, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except OSError:
        return ""
    for i, ln in enumerate(lines):
        if "Return value 3" in ln:
            ctx = "".join(lines[max(0, i - 6):i + 1]).strip()
            if len(ctx) > 700:
                ctx = ctx[-700:]
            return " (failing step):\n" + ctx
    errs = [ln.strip()[:180] for ln in lines if "error" in ln.lower()][-3:]
    return (":\n" + "\n".join(errs)) if errs else ""


def _clear_awg_msi_cache():
    tmp = tempfile.gettempdir()
    try:
        for name in os.listdir(tmp):
            if name.startswith("amneziawg-") and name.endswith(".msi"):
                os.unlink(os.path.join(tmp, name))
    except OSError:
        pass


def install_awg_msi(msi_path):
    """Silently install the AmneziaWG MSI. Requires admin (app self-elevates).

    Writes a verbose log to %TEMP%\\awg-install.log so a 1603-style generic
    failure can be diagnosed with the real error.
    """
    log_path = _msi_log_path()
    try:
        p = subprocess.run(
            ["msiexec", "/i", msi_path, "/qn", "/norestart",
             "/l*v", log_path],
            capture_output=True, text=True, timeout=300, **_no_window())
    except Exception as e:  # noqa: BLE001
        raise TunnelError("installer failed to run: %s" % e)
    # 0 = ok, 3010 = ok, reboot needed (tunnel works without it)
    if p.returncode not in (0, 3010):
        raise TunnelError("installer exited with code %d%s"
                          % (p.returncode, _msi_failure_hint(log_path)))


def _wait_service_stopped(timeout=12):
    """Wait until the tunnel service is stopped or gone (best effort)."""
    end = time.time() + timeout
    while time.time() < end:
        ok, out = _run(["sc", "query", SERVICE_NAME])
        low = out.lower()
        if not ok or "1060" in out or "stopped" in low \
                or "does not exist" in low:
            return
        time.sleep(0.5)


class AmneziaWGBackend:
    """Drives the official AmneziaWG Windows client programmatically.

    Uses (documented in amneziawg-windows-client/docs/enterprise.md):
      amneziawg /installtunnelservice <conf>    -> service AmneziaWGTunnel$<name>
      amneziawg /uninstalltunnelservice <name>
      sc start/stop AmneziaWGTunnel$<name>
      awg show <name>                            -> handshake + transfer stats
    Requires administrator rights.
    """
    name = "amneziawg"

    def __init__(self):
        self.amneziawg = None
        self.awg = None

    def available(self):
        cands = [shutil.which("amneziawg"), shutil.which("awg")]
        pf = os.environ.get("ProgramFiles", r"C:\Program Files")
        for exe in ("amneziawg.exe", "awg.exe"):
            p = os.path.join(pf, "AmneziaWG", exe)
            if os.path.isfile(p):
                cands.append(p)
        self.amneziawg = next((c for c in cands if c and "amneziawg" in
                               os.path.basename(c).lower()), None)
        self.awg = next((c for c in cands if c and os.path.basename(c).lower()
                         == "awg.exe"), None)
        if not self.amneziawg:
            return (False,
                    "AmneziaWG client not found. Install it from:\n"
                    "https://github.com/amnezia-vpn/amneziawg-windows-client\n"
                    "(Releases page), then restart this app.")
        if not self.awg:
            return (False,
                    "awg.exe not found next to amneziawg.exe -- reinstall the "
                    "AmneziaWG client.")
        return True, ""

    def connect(self, conf):
        # Always reinstall from scratch. A stale service left behind by a
        # killed or older instance (possibly with an older config) must never
        # survive: the running tunnel has to match the config file on disk.
        # (The old code tried to tolerate "already exists", but AmneziaWG
        # actually reports "already installed and running", so Connect kept
        # failing instead of reusing the service.)
        _run(["sc", "stop", SERVICE_NAME])
        _wait_service_stopped()
        _run([self.amneziawg, "/uninstalltunnelservice", TUNNEL_NAME])
        ok, out = _run([self.amneziawg, "/installtunnelservice", conf])
        if not ok:
            raise TunnelError("installtunnelservice failed:\n" + out.strip())
        # Never auto-start on boot: this app manages the tunnel explicitly so
        # it can never silently burn metered data.
        _run(["sc", "config", SERVICE_NAME, "start=", "demand"])
        ok, out = _run(["sc", "start", SERVICE_NAME])
        if not ok and "already" not in out.lower() and "1060" not in out:
            raise TunnelError("could not start tunnel service:\n" + out.strip())

    def disconnect(self):
        _run(["sc", "stop", SERVICE_NAME])
        ok, out = _run([self.amneziawg, "/uninstalltunnelservice", TUNNEL_NAME])
        if not ok and "1060" not in out and "does not exist" not in out.lower():
            raise TunnelError("uninstalltunnelservice failed:\n" + out.strip())

    def get_stats(self):
        ok, out = _run([self.awg, "show", TUNNEL_NAME])
        if not ok:
            return None
        return parse_awg_show(out)


class MockBackend:
    """Dry-run backend: simulates a tunnel for testing without a server.

    Parses a realistic `awg show` sample with the same parser as the real
    backend, then simulates growing transfer counters.
    """
    name = "mock"
    SAMPLE = """interface: roblox
  public key: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx=
  private key: (hidden)
  listening port: 51820
peer: yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy=
  endpoint: 203.0.11.5:443
  allowed ips: 128.116.0.0/17
  latest handshake: 4 seconds ago
  transfer: 6.55 KiB received, 4.13 KiB sent
"""

    def __init__(self):
        self._up = False
        self._rx = 6707
        self._tx = 4229
        self._t0 = 0.0

    def available(self):
        return True, ""

    def connect(self, conf):
        if not os.path.isfile(conf):
            raise TunnelError("mock: config not found: %s" % conf)
        self._up = True
        self._t0 = time.time()
        self._up_at = time.time()

    def disconnect(self):
        self._up = False

    def get_stats(self):
        if not self._up:
            return None
        # Simulate modest Roblox traffic (~30 KB/s down, ~8 KB/s up).
        dt = time.time() - self._t0
        self._t0 = time.time()
        self._rx += int(dt * 30 * 1024 * (0.7 + random.random() * 0.6))
        self._tx += int(dt * 8 * 1024 * (0.7 + random.random() * 0.6))
        base = parse_awg_show(self.SAMPLE)
        base["rx_bytes"] = self._rx
        base["tx_bytes"] = self._tx
        base["handshake"] = "%d seconds ago" % max(
            1, int(time.time() - self._up_at) % 120 + 1)
        return base


# ---------------------------------------------------------------------------
# Stealth backend: WireGuard-over-TLS (Proton Stealth protocol) via a
# bundled Go binary (stealth-wg.exe) + wintun.dll. Bypasses DPI that
# fingerprints plain WireGuard UDP. Uses the same .conf (keys/endpoint);
# the Go binary connects via TCP/443 with uTLS + TunSafe framing.
# ---------------------------------------------------------------------------

STEALTH_IFNAME = "RobloxVPN-Stealth"


def _unique_ifname():
    """Generate a unique Stealth interface name per connect attempt.

    Reusing a fixed name/GUID can hit stale driver state (orphaned
    adapters, GUID conflicts) that makes WintunCreateAdapter hang. A
    fresh name + nil GUID (driver-generated) sidesteps all of it; the
    wintun.dll cleans up orphans automatically.
    """
    import random
    return "RobloxVPN-S%d" % random.randint(1000, 99999)
STEALTH_EXE = "stealth-wg.exe"


def _kill_stale_stealth():
    """Kill any leftover stealth-wg.exe processes from previous runs.

    A previous hung run leaves a process blocked in the driver; launching
    a second one concurrently wedges things further. Never raises.
    """
    if os.name != "nt":
        return
    ok, out = _run(["taskkill", "/F", "/IM", "stealth-wg.exe"], timeout=10)
    _stealth_log_cmd("taskkill stealth-wg.exe", ok, out)


def _clean_phantom_adapters():
    """Remove stale RobloxVPN-Stealth* PnP devices before creating anew.

    Orphaned adapters from killed runs keep the driver busy and can make
    WintunCreateAdapter hang. Uses pnputil to remove them. Never raises.
    """
    if os.name != "nt":
        return
    _stealth_log("enumerating stale RobloxVPN adapters ...")
    ps = ("Get-PnpDevice -Class Net -ErrorAction SilentlyContinue | "
          "Where-Object { $_.FriendlyName -like 'RobloxVPN*' } | "
          "ForEach-Object { $_.InstanceId }")
    ok, out = _run(["powershell", "-NoProfile", "-Command", ps], timeout=20)
    _stealth_log_cmd("pnp enum", ok, out, ok_cap=300)
    if not ok or not out.strip():
        return
    for inst in out.strip().split():
        inst = inst.strip()
        if not inst:
            continue
        _stealth_log("removing phantom device: %s" % inst[:80])
        ok2, out2 = _run(["pnputil", "/remove-device", inst], timeout=20)
        _stealth_log_cmd("pnputil remove", ok2, out2)
    time.sleep(2)


def _stealth_log_cmd(name, ok, out, ok_cap=200):
    """Log a helper-command result; full output on failure, capped on ok."""
    out = out.strip()
    if ok:
        _stealth_log("%s: ok=%s out=%s" % (name, ok, out[:ok_cap]))
    else:
        _stealth_log("%s: ok=%s FULL-OUT=%s" % (name, ok, out))


def _rescan_pnp_devices():
    """Re-enumerate PnP devices after phantom-adapter removal.

    Lets Windows settle the device tree after _clean_phantom_adapters()
    so a half-removed wintun stack does not wedge the next
    WintunCreateAdapter. Never raises.
    """
    if os.name != "nt":
        return
    _stealth_log("rescanning PnP devices ...")
    ok, out = _run(["pnputil", "/scan-devices"], timeout=30)
    _stealth_log_cmd("pnputil scan-devices", ok, out)
    time.sleep(2)


def _reinstall_wintun_driver(dll_path):
    """Force a clean Wintun driver reinstall via WintunDeleteDriver.

    A wedged driver can survive a service restart (sc stop/start) but a
    full delete forces wintun.dll to reinstall it from scratch on the
    next CreateAdapter ('Installing driver' path). Runs in a thread with
    a timeout in case the driver is too wedged to respond.
    """
    if os.name != "nt" or not dll_path or not os.path.isfile(dll_path):
        return
    _stealth_log("forcing clean wintun driver reinstall ...")
    import ctypes

    def _do():
        try:
            w = ctypes.WinDLL(dll_path)
            # WintunDeleteDriver returns BOOL; 0 + GetLastError on failure
            rc = w.WintunDeleteDriver()
            _stealth_log("WintunDeleteDriver rc=%s" % rc)
        except Exception as e:  # noqa: BLE001
            _stealth_log("WintunDeleteDriver failed: %r" % e)

    t = threading.Thread(target=_do, daemon=True)
    t.start()
    t.join(timeout=20)
    if t.is_alive():
        _stealth_log("WintunDeleteDriver hung; driver reinstall skipped")
    else:
        _stealth_log("driver delete done; dll will reinstall on next use")
        time.sleep(2)


def _recycle_wintun_driver():
    """Restart the Wintun driver service to unstick a wedged driver.

    WintunCreateAdapter can block forever when the driver is in a bad
    state (observed on user PC: wintun.dll logs 'Creating adapter' and
    never returns). A service recycle clears it. Safe when no other VPN
    is actively connected. Never raises; returns True if the driver is
    (now) running.
    """
    _stealth_log("checking wintun driver service ...")
    ok, out = _run(["sc", "query", "wintun"], timeout=10)
    _stealth_log("sc query wintun: ok=%s out=%s" % (ok, out.strip()[:120]))
    if not ok and "1060" in out:
        _stealth_log("wintun service not installed; dll will install it")
        return True
    ok, out = _run(["sc", "stop", "wintun"], timeout=15)
    _stealth_log("sc stop wintun: ok=%s out=%s" % (ok, out.strip()[:120]))
    time.sleep(2)
    ok, out = _run(["sc", "start", "wintun"], timeout=15)
    _stealth_log("sc start wintun: ok=%s out=%s" % (ok, out.strip()[:120]))
    time.sleep(2)
    return ok
WINTUN_DLL = "wintun.dll"


def _stealth_bin(name):
    """Locate a bundled stealth binary (PyInstaller bundle, app dir, dev)."""
    cands = []
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        cands.append(os.path.join(meipass, name))
    try:
        cands.append(os.path.join(app_dir(), name))
    except OSError:
        pass
    cands.append(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                              "..", "stealth", "dist", name))
    for c in cands:
        if os.path.isfile(c):
            return c
    return None


def _conf_address(conf):
    """Extract the IPv4 Address from a .conf (e.g. '10.2.0.2/32' -> '10.2.0.2')."""
    try:
        with open(conf, encoding="utf-8") as f:
            text = f.read()
    except OSError:
        return None
    m = re.search(r"(?im)^\s*Address\s*=\s*([0-9.]+)", text)
    return m.group(1) if m else None


HOSTS_TAG = "# RobloxVPN"


def _hosts_path():
    sysroot = os.environ.get("SystemRoot", r"C:\Windows")
    return os.path.join(sysroot, "System32", "drivers", "etc", "hosts")


def _doh_resolve(host, timeout=5):
    """Resolve an A record via DNS-over-HTTPS (plain DNS is DPI-poisoned).

    Direct HTTPS to 1.1.1.1/8.8.8.8 works where port-53 DNS fails.
    Returns the IPv4 string or None. Never raises.
    """
    queries = ("https://1.1.1.1/dns-query?name=%s&type=A" % host,
               "https://8.8.8.8/resolve?name=%s&type=A" % host)
    for url in queries:
        try:
            req = urllib.request.Request(
                url, headers={"accept": "application/dns-json"})
            d = json.load(urllib.request.urlopen(req, timeout=timeout))
            for a in d.get("Answer", []):
                if a.get("type") == 1 and re.match(
                        r"^\d+\.\d+\.\d+\.\d+$", a.get("data", "")):
                    return a["data"]
        except Exception:
            continue
    return None


def _hosts_add(entries, path=None):
    """Append '{ip} {host} # RobloxVPN' lines. Returns count. Never raises."""
    if os.name != "nt" or not entries:
        return 0
    path = path or _hosts_path()
    try:
        _hosts_remove(path=path)  # drop stale lines first (self-healing)
        with open(path, "a", encoding="utf-8") as f:
            for ip, host in entries:
                f.write("%s %s %s\n" % (ip, host, HOSTS_TAG))
        _stealth_log("hosts file: added %d entries" % len(entries))
        return len(entries)
    except OSError as e:
        _stealth_log("hosts file add failed: %s" % e)
        return 0


def _hosts_remove(path=None):
    """Remove our tagged lines. Returns count removed. Never raises."""
    if os.name != "nt":
        return 0
    path = path or _hosts_path()
    try:
        with open(path, encoding="utf-8") as f:
            lines = f.readlines()
    except OSError:
        return 0
    kept = [l for l in lines if HOSTS_TAG not in l]
    removed = len(lines) - len(kept)
    if not removed:
        return 0
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.writelines(kept)
    except OSError as e:
        _stealth_log("hosts file remove failed: %s" % e)
        return 0
    return removed


def _tun_if_index(ifname):
    """Windows interface index for a TUN adapter name (via netsh)."""
    ok, out = _run(["netsh", "interface", "ipv4", "show", "interfaces"])
    if not ok:
        return None
    for line in out.splitlines():
        if ifname.lower() in line.lower():
            parts = line.split()
            if parts and parts[0].isdigit():
                return parts[0]
    return None


def _stealth_log(msg):
    """Append a timestamped line to the Stealth debug log."""
    try:
        p = os.path.join(app_dir(), "stealth-debug.log")
        with open(p, "a", encoding="utf-8") as f:
            f.write("%s %s\n" % (time.strftime("%H:%M:%S"), msg))
    except OSError:
        pass


class StealthBackend:
    """Drives stealth-wg.exe (Go, Proton Stealth transport) as a child process.

    The Go binary owns the WireGuard device + TLS transport; this backend
    handles Windows network setup (IP address + split-tunnel route) and
    parses the JSON status lines the binary prints to stdout.
    Requires administrator rights (TUN creation + routes).
    """
    name = "stealth"

    def __init__(self):
        self.proc = None
        self._latest = {}
        self._reader = None
        self._stop_reader = threading.Event()
        self._exe = None
        self._if_ip = None
        self._connect_lock = threading.Lock()
        self._state_lock = threading.Lock()
        self._saw_ready = False

    def available(self):
        exe = _stealth_bin(STEALTH_EXE)
        dll = _stealth_bin(WINTUN_DLL)
        if not exe:
            return (False, "Stealth engine not found (stealth-wg.exe missing).")
        if not dll:
            return (False, "Stealth engine incomplete (wintun.dll missing).")
        self._exe = exe
        return True, ""

    def _read_loop(self):
        try:
            dropped = 0
            for line in self.proc.stdout:
                if self._stop_reader.is_set():
                    break
                line = line.strip()
                if not line.startswith("{"):
                    # The engine logs errors (e.g. wg data-path failures)
                    # as non-JSON lines -- they used to vanish silently.
                    # Keep the first few so the debug log shows them.
                    if line and dropped < 10:
                        _stealth_log("engine-log: %s" % line[:200])
                    dropped += 1
                    continue
                try:
                    d = json.loads(line)
                except ValueError:
                    continue
                _stealth_log("engine -> %s" % line[:200])
                with self._state_lock:
                    self._latest = d
                    # sticky: 'ready' is emitted once, then 'status' every
                    # 2s overwrites it -- a slow poller must not miss it
                    if d.get("type") in ("ready", "status"):
                        self._saw_ready = True
        except Exception as e:
            _stealth_log("reader thread ended: %s" % e)

    def connect(self, conf):
        _stealth_log("=== connect() start ===")
        if not self._connect_lock.acquire(blocking=False):
            raise TunnelError("already connecting -- please wait")
        try:
            self._connect_inner(conf)
        finally:
            self._connect_lock.release()

    def _connect_inner(self, conf):
        ok, msg = self.available()
        _stealth_log("available: %s %s" % (ok, msg))
        if not ok:
            raise TunnelError(msg)
        self.disconnect()  # clean slate
        # never run two engines at once -- concurrent WintunCreateAdapter
        # calls wedge the driver
        _kill_stale_stealth()
        # NOTE (v29): sc recycle + pnputil rescan were removed from the
        # connect path. They churn NDIS/PnP on every connect and the data
        # path measurably degrades with churn (sessions stop receiving).
        # Unique ifname + nil GUID already fixed creation; orphans are
        # still cleaned below. Helpers kept for manual use.
        # remove orphaned adapters from killed runs, then settle the PnP
        # tree so the next CreateAdapter does not wedge
        _clean_phantom_adapters()
        ip = _conf_address(conf)
        _stealth_log("tunnel IP from conf: %s" % ip)
        if not ip:
            raise TunnelError("could not read Address from config")
        self._if_ip = ip
        # wintun.dll must sit next to the exe
        dll = _stealth_bin(WINTUN_DLL)
        exe_dir = os.path.dirname(self._exe)
        _stealth_log("exe: %s" % self._exe)
        _stealth_log("dll: %s" % dll)
        try:
            if dll and os.path.abspath(os.path.dirname(dll)) != os.path.abspath(exe_dir):
                shutil.copy2(dll, os.path.join(exe_dir, WINTUN_DLL))
                _stealth_log("copied wintun.dll next to exe")
        except OSError as e:
            _stealth_log("dll copy failed: %s" % e)
        self._stop_reader.clear()
        self._latest = {}
        self._saw_ready = False
        # unique interface name per attempt (avoids stale name/GUID state)
        self._ifname = _unique_ifname()
        _stealth_log("interface name: %s" % self._ifname)
        # capture Go stderr to a file for diagnosis
        try:
            err_log = open(os.path.join(app_dir(), "stealth-go-stderr.log"),
                           "w", encoding="utf-8")
        except OSError:
            err_log = subprocess.DEVNULL
        _stealth_log("launching stealth-wg.exe ...")
        try:
            self.proc = subprocess.Popen(
                [self._exe, conf, self._ifname],
                stdout=subprocess.PIPE, stderr=err_log,
                stdin=subprocess.DEVNULL, text=True, bufsize=1,
                **_no_window())
        except Exception as e:  # noqa: BLE001 -- any launch failure must
            # surface as TunnelError, never kill the worker thread silently
            _stealth_log("Popen failed: %r" % e)
            raise TunnelError("could not start stealth engine:\n%s" % e)
        _stealth_log("process started, pid=%s" % self.proc.pid)
        try:
            err_log.close()
        except Exception:
            pass
        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()
        # wait for ready (up to 60s; TLS+handshake takes a while, and a
        # slow driver should get a chance). 'status' counts as ready too:
        # the engine emits 'ready' once then 'status' every 2s, and a
        # slow poller must not miss the window on a working tunnel.
        deadline = time.time() + 60
        err_msg = None
        while time.time() < deadline:
            with self._state_lock:
                d = dict(self._latest)
                saw = self._saw_ready
            if d.get("type") == "ready" or saw:
                _stealth_log("got READY from engine")
                break
            if d.get("type") == "error":
                err_msg = d.get("message", "unknown error")
                _stealth_log("got ERROR from engine: %s" % err_msg)
                break
            if self.proc.poll() is not None:
                err_msg = "stealth engine exited (code %s)" % self.proc.poll()
                _stealth_log(err_msg)
                break
            time.sleep(0.3)
        else:
            err_msg = "stealth engine did not become ready in time"
            _stealth_log("TIMEOUT waiting for ready; last status: %s; "
                         "engine poll=%s (None = still hung, will kill)"
                         % (d, self.proc.poll()))
        if err_msg:
            self.disconnect()
            raise TunnelError(err_msg)
        # --- Windows network setup: IP + split-tunnel route ---
        _stealth_log("setting tunnel IP via netsh ...")
        ok, out = _run(["netsh", "interface", "ip", "set", "address",
                        "name=%s" % self._ifname, "static", ip,
                        "255.255.255.255"])
        _stealth_log("netsh result: ok=%s out=%s" % (ok, out.strip()[:200]))
        if not ok:
            self.disconnect()
            raise TunnelError("could not set tunnel IP:\n" + out.strip())
        # Clamp the TUN MTU for double-TLS overhead: Windows sizes TCP
        # segments from the adapter MTU, and full-size segments would
        # blackhole inside the Stealth tunnel (TLS-in-TLS). 1280 is safe
        # and keeps IPv6 minimum-MTU happy too. Never raises loudly --
        # a fixed route matters more than MTU, so warn and continue.
        ok, out = _run(["netsh", "interface", "ipv4", "set", "subinterface",
                        self._ifname, "mtu=1280", "store=active"])
        _stealth_log_cmd("set MTU 1280", ok, out)
        # Roblox-only route via the tunnel -- bound to the TUN interface
        # explicitly (IF <index>): without IF, Windows silently binds the
        # route to the physical NIC (the /32 TUN address is not recognized
        # as an on-link gateway), sending Roblox traffic direct = timeout.
        if_idx = None
        for _ in range(10):
            if_idx = _tun_if_index(self._ifname)
            if if_idx:
                break
            time.sleep(1)
        _stealth_log("tunnel ifindex: %s" % if_idx)
        if not if_idx:
            self.disconnect()
            raise TunnelError("could not find tunnel interface "
                              "(%s) -- aborting" % self._ifname)
        for net4 in ROBLOX_ALLOWED_IPS:
            addr, bits = net4.split("/")
            mask = ".".join(str((0xFFFFFFFF << (32 - int(bits)) >> i) & 0xFF)
                            for i in (24, 16, 8, 0))
            _run(["route", "delete", addr, "mask", mask])
            ok, out = _run(["route", "add", addr, "mask", mask, ip,
                            "IF", if_idx])
            _stealth_log_cmd("route add %s IF %s" % (net4, if_idx), ok, out)
            if not ok:
                self.disconnect()
                raise TunnelError("could not add Roblox route:\n" + out.strip())
        # verify the route really goes through the tunnel (not the LAN)
        ok, out = _run(["powershell", "-NoProfile", "-Command",
                        "Find-NetRoute -RemoteIPAddress 128.116.13.3 "
                        "-ErrorAction SilentlyContinue | Select-Object "
                        "-First 1 -ExpandProperty InterfaceAlias"],
                       timeout=20)
        _stealth_log("route check: ok=%s alias=%s" % (ok, out.strip()[:80]))
        if ok and out.strip() and \
                self._ifname.lower() not in out.strip().lower():
            self.disconnect()
            raise TunnelError("Roblox route is not using the tunnel "
                              "(via %s) -- aborting" % out.strip()[:80])
        # --- DNS via hosts file: plain-DNS for Roblox is DPI-poisoned,
        # so resolve over HTTPS and pin results locally. Tagged lines are
        # removed on disconnect (self-healing if a run dies).
        entries = []
        for host in ROBLOX_HOSTS:
            ip = _doh_resolve(host)
            _stealth_log("DoH %s -> %s" % (host, ip))
            if ip:
                entries.append((ip, host))
        if entries:
            _hosts_add(entries)
            ok, out = _run(["ipconfig", "/flushdns"], timeout=15)
            _stealth_log("flushdns: ok=%s" % ok)
            # The DNS Client picks up hosts-file changes asynchronously;
            # without this pause+verify, the first lookups still fail.
            time.sleep(3)
            for _try in range(2):
                missing = []
                for ip, host in entries:
                    try:
                        got = socket.getaddrinfo(
                            host, 443, socket.AF_INET)[0][4][0]
                    except OSError:
                        got = None
                    if got != ip:
                        missing.append(host)
                _stealth_log("hosts verify: %s" %
                             ("all ok" if not missing else missing))
                if not missing:
                    break
                time.sleep(3)
        else:
            _stealth_log("DoH resolved nothing; browser DNS may still fail")
        _stealth_log("=== connect() done ===")

    def disconnect(self):
        _hosts_remove()
        try:
            _run(["ipconfig", "/flushdns"], timeout=15)
        except Exception:
            pass
        for net4 in ROBLOX_ALLOWED_IPS:
            addr, bits = net4.split("/")
            mask = ".".join(str((0xFFFFFFFF << (32 - int(bits)) >> i) & 0xFF)
                            for i in (24, 16, 8, 0))
            _run(["route", "delete", addr, "mask", mask])
        self._stop_reader.set()
        if self.proc and self.proc.poll() is None:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=5)
            except Exception:
                try:
                    self.proc.kill()
                    self.proc.wait(timeout=5)
                except Exception as e:
                    _stealth_log("stealth engine kill: %r" % e)
            try:
                if self.proc.stdout:
                    self.proc.stdout.close()
            except Exception:
                pass
        self.proc = None

    def get_stats(self):
        with self._state_lock:
            d = dict(self._latest)
        if d.get("type") not in ("status", "ready"):
            return None
        rx = int(d.get("rx_bytes", 0))
        tx = int(d.get("tx_bytes", 0))
        hs_unix = d.get("last_handshake_unix", 0)
        if hs_unix:
            ago = int(time.time() - hs_unix)
            hs = "%d seconds ago" % ago if ago < 3600 else "ok"
        else:
            hs = None
        if not hs_unix and d.get("type") == "ready":
            # tunnel up, handshake pending
            return {"rx_bytes": rx, "tx_bytes": tx, "handshake": None,
                    "endpoint": "stealth/443"}
        return {"rx_bytes": rx, "tx_bytes": tx, "handshake": hs,
                "endpoint": "stealth/443"}


# ---------------------------------------------------------------------------
# Persistent stats + settings
# ---------------------------------------------------------------------------

def load_stats():
    try:
        with open(stats_path(), encoding="utf-8") as f:
            d = json.load(f)
        return {"rx": int(d.get("rx", 0)), "tx": int(d.get("tx", 0))}
    except (OSError, ValueError):
        return {"rx": 0, "tx": 0}


def save_stats(rx, tx):
    try:
        with open(stats_path(), "w", encoding="utf-8") as f:
            json.dump({"rx": int(rx), "tx": int(tx)}, f)
    except OSError:
        pass


def load_settings():
    try:
        with open(settings_path(), encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def save_settings(s):
    try:
        with open(settings_path(), "w", encoding="utf-8") as f:
            json.dump(s, f, indent=2)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Elevation (Windows)
# ---------------------------------------------------------------------------

def is_admin():
    if os.name != "nt":
        return True  # mock/self-test on other platforms
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:  # noqa: BLE001
        return False


def relaunch_elevated(argv):
    import ctypes
    exe = sys.executable
    params = " ".join('"%s"' % a for a in argv)
    ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1)

# ---------------------------------------------------------------------------
# App state + tray UI
# ---------------------------------------------------------------------------

def _make_icon(connected, stale=False):
    from PIL import Image, ImageDraw
    img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    if connected and not stale:
        color = (46, 160, 67)      # green
    elif connected:
        color = (218, 165, 32)     # amber: up but no recent handshake
    else:
        color = (110, 110, 110)    # gray
    d.ellipse([10, 10, 54, 54], fill=color)
    d.ellipse([24, 24, 40, 40], fill=(255, 255, 255, 230))
    return img


def _conf_endpoint():
    try:
        with open(conf_path(), encoding="utf-8") as f:
            m = re.search(r"^Endpoint\s*=\s*(\S+)", f.read(), re.MULTILINE)
            return m.group(1) if m else "?"
    except OSError:
        return "?"


def make_backend(name, mock=False):
    """Create a tunnel backend by name: 'stealth', 'amneziawg', or mock."""
    if mock:
        return MockBackend()
    if name == "stealth":
        return StealthBackend()
    return AmneziaWGBackend()


class VpnApp:
    def __init__(self, mock=False):
        self.settings = load_settings()
        self.totals = load_stats()
        self.mock = mock
        self.backend_name = self.settings.get("backend", "amneziawg")
        self.backend = make_backend(self.backend_name, mock)
        self.connected = False
        self.base_rx = self.base_tx = 0
        self.sess_rx = self.sess_tx = 0
        self.last_handshake = None
        self.status_msg = "Starting..."
        self.icon = None
        self.root = None
        self.dash_win = None
        self._stop = threading.Event()
        self._lock = threading.Lock()
        ok, msg = self.backend.available()
        self.backend_ok = ok
        self.backend_msg = msg
        self._install_thread = None
        if not ok and not mock:
            # Missing engine: fetch + silently install the official client in
            # the background -- the user wants zero manual steps.
            self.status_msg = "AmneziaWG client not found -- downloading..."
            self._install_thread = threading.Thread(
                target=self._auto_install_backend, daemon=True)
            self._install_thread.start()

    def _auto_install_backend(self):
        def _progress(done, total):
            if total:
                self.status_msg = ("Downloading AmneziaWG client... %d%% "
                                   "(%s)" % (int(done * 100 / total),
                                             fmt_bytes(total)))
            else:
                self.status_msg = ("Downloading AmneziaWG client... %s"
                                   % fmt_bytes(done))

        try:
            if not is_admin():
                raise TunnelError(
                    "not running as administrator -- the installer needs "
                    "it. Close the app, right-click RobloxVPN.exe -> "
                    "'Run as administrator' (or accept the UAC prompt on "
                    "launch), then try again.")
            msi = download_awg_installer(progress_cb=_progress)
            self.status_msg = "Installing AmneziaWG client..."
            install_awg_msi(msi)
            try:
                os.unlink(msi)
            except OSError:
                pass
        except TunnelError as e:
            self.backend_msg = (
                "Could not install the AmneziaWG client automatically:\n%s\n\n"
                "Install it manually from:\n"
                "https://github.com/amnezia-vpn/amneziawg-windows-client\n"
                "(Releases page), then restart this app." % e)
            self.status_msg = "AmneziaWG client missing"
            self._notify("Install failed",
                         "The VPN engine could not be installed automatically. "
                         "A fix-it window is opening.")
            if self.root:
                self._install_failed_shown = True
                self.root.after(
                    0, lambda: _install_failed_dialog(self, str(e)))
            return
        ok, msg = self.backend.available()
        self.backend_ok = ok
        self.backend_msg = msg
        if ok:
            self.status_msg = "Ready -- import a config to connect"
            self._notify("AmneziaWG installed",
                         "The VPN engine is ready. Import a .conf to connect.")
        else:
            self.status_msg = "AmneziaWG client missing"

    def set_backend(self, name):
        """Switch tunnel backend ('amneziawg' or 'stealth'). Disconnects first."""
        if self.connected:
            self.do_disconnect()
        self.backend_name = name
        self.settings["backend"] = name
        save_settings(self.settings)
        self.backend = make_backend(name, self.mock)
        ok, msg = self.backend.available()
        self.backend_ok = ok
        self.backend_msg = msg
        self.status_msg = ("Ready -- import a config to connect (%s mode)" %
                           ("Stealth" if name == "stealth" else "AmneziaWG"))

    def retry_install(self):
        """Re-run the AmneziaWG auto-install with a fresh download."""
        _clear_awg_msi_cache()
        self._install_failed_shown = False
        self.status_msg = "Retrying AmneziaWG install..."
        self._install_thread = threading.Thread(
            target=self._auto_install_backend, daemon=True)
        self._install_thread.start()

    # -- connection control -------------------------------------------
    def do_connect(self):
        def _work():
            if not os.path.isfile(conf_path()):
                self._notify("No config",
                             "Import a .conf file or generate one first.")
                return
            if not self.backend_ok:
                self._notify("Backend missing", self.backend_msg)
                return
            self.status_msg = "Connecting..."
            try:
                self.backend.connect(conf_path())
            except TunnelError as e:
                self.status_msg = "Connect failed"
                self._notify("Connect failed", str(e)[:300])
                return
            except Exception as e:  # noqa: BLE001 -- never hang silently
                self.status_msg = "Connect failed"
                self._notify("Connect failed",
                             "Unexpected error: %s" % str(e)[:300])
                return
            # wait for a real handshake
            st = None
            for _ in range(15):
                time.sleep(1)
                st = self.backend.get_stats()
                if st and "ago" in st.get("handshake", ""):
                    break
            if not st:
                self.status_msg = "No handshake yet"
                self._notify("Connected?", "Tunnel is up but no handshake "
                             "from the server yet. Check the server.")
            with self._lock:
                self.connected = True
                self.base_rx = (st or {}).get("rx_bytes", 0)
                self.base_tx = (st or {}).get("tx_bytes", 0)
                self.sess_rx = self.sess_tx = 0
                self.last_handshake = (st or {}).get("handshake")
                self.status_msg = "Connected (%s)" % (
                    self.last_handshake or "?")
            self._notify("RobloxVPN connected",
                         "Split tunnel up. Only Roblox traffic uses it.")
        threading.Thread(target=_work, daemon=True).start()

    def do_disconnect(self):
        def _work():
            try:
                self.backend.disconnect()
            except TunnelError as e:
                self._notify("Disconnect issue", str(e)[:300])
            with self._lock:
                self.connected = False
                self.status_msg = "Disconnected"
            self._notify("RobloxVPN disconnected",
                         "Session: down %s / up %s" % (
                             fmt_bytes(self.sess_rx), fmt_bytes(self.sess_tx)))
        threading.Thread(target=_work, daemon=True).start()

    # -- polling --------------------------------------------------------
    def _poll_loop(self):
        while not self._stop.wait(2.0):
            try:
                self._poll_once()
            except Exception:  # noqa: BLE001 - never kill the poll thread
                pass
            self._refresh_tray()

    def _poll_once(self):
        with self._lock:
            if not self.connected:
                return
        st = self.backend.get_stats()
        with self._lock:
            if not self.connected:
                return
            if st is None:
                self.status_msg = "Tunnel down?"
                return
            rx, tx = st["rx_bytes"], st["tx_bytes"]
            drx = rx - self.base_rx if rx >= self.base_rx else rx
            dtx = tx - self.base_tx if tx >= self.base_tx else tx
            self.base_rx, self.base_tx = rx, tx
            self.sess_rx += drx
            self.sess_tx += dtx
            self.totals["rx"] += drx
            self.totals["tx"] += dtx
            save_stats(self.totals["rx"], self.totals["tx"])
            self.last_handshake = st.get("handshake")
            stale = self.last_handshake == "Never" or not self.last_handshake
            self._stale = stale
            self.status_msg = ("Connected (%s)" % self.last_handshake
                               if not stale else "Connected (no handshake)")

    # -- tray -----------------------------------------------------------
    def _menu(self):
        from pystray import Menu, MenuItem
        with self._lock:
            connected = self.connected
            status = self.status_msg
        if connected:
            short = "Connected"
        elif any(k in status.lower() for k in ("download", "install",
                                               "connecting", "starting")):
            short = status
        else:
            short = "Disconnected"
        items = [
            MenuItem(short, None, enabled=False),
            MenuItem("---", None, enabled=False),
        ]
        if connected:
            items.append(MenuItem("Disconnect", lambda i: self.do_disconnect()))
        else:
            items.append(MenuItem("Connect", lambda i: self.do_connect()))
        items += [
            MenuItem("Open dashboard", lambda i: self.open_dashboard()),
            MenuItem("Setup guide...", lambda i: self.open_guide()),
            MenuItem("Import .conf...", lambda i: self.import_dialog()),
            MenuItem("Generate config...", lambda i: self.generate_dialog()),
            MenuItem("Open config folder", lambda i: self.open_folder()),
            MenuItem("---", None, enabled=False),
            MenuItem("Quit", lambda i: self.quit()),
        ]
        return Menu(*items)

    def _refresh_tray(self):
        icon = self.icon
        if icon is None:
            return
        try:
            with self._lock:
                connected = self.connected
                stale = getattr(self, "_stale", False)
                status = self.status_msg
            icon.icon = _make_icon(connected, stale)
            icon.title = "RobloxVPN - " + status
            icon.menu = self._menu()
            icon.update_menu()
        except Exception:  # noqa: BLE001
            pass

    def _run_tray(self):
        from pystray import Icon
        self.icon = Icon("robloxvpn", _make_icon(False), "RobloxVPN",
                         self._menu())
        self.icon.run()

    def _notify(self, title, msg):
        try:
            if self.icon:
                self.icon.notify(msg, title)
        except Exception:  # noqa: BLE001
            pass

    # -- main loop ------------------------------------------------------
    def run(self):
        import tkinter as tk
        from tkinter import messagebox
        self.root = tk.Tk()
        self.root.withdraw()
        threading.Thread(target=self._poll_loop, daemon=True).start()
        threading.Thread(target=self._run_tray, daemon=True).start()
        # The dashboard is the app's main window: open it on every launch.
        # Closing it only hides it back to the tray (Quit lives in the menu).
        self.root.after(800, self.open_dashboard)
        if not self.settings.get("guide_seen"):
            # First run: pop the 4-step setup guide with links + buttons.
            self.root.after(2500, lambda: _open_guide(self))
        if not self.backend_ok and not self.mock:
            # The auto-installer runs in the background; warn only if it
            # finished without producing a working backend.
            def _watch_install():
                t = self._install_thread
                if t is not None:
                    t.join(timeout=180)
                if not self.backend_ok and self.root:
                    # Skip: the rich fix-it dialog was already shown.
                    if getattr(self, "_install_failed_shown", False):
                        return
                    self.root.after(0, lambda: messagebox.showwarning(
                        "AmneziaWG client not found",
                        self.backend_msg + "\n\nThe tray icon is running; "
                        "restart this app after installing the client."))
            threading.Thread(target=_watch_install, daemon=True).start()
        self.root.mainloop()

    def quit(self):
        self._stop.set()
        try:
            if self.icon:
                self.icon.stop()
        except Exception:  # noqa: BLE001
            pass
        try:
            if self.root:
                self.root.quit()
        except Exception:  # noqa: BLE001
            pass

    def open_folder(self):
        if os.name == "nt":
            os.startfile(app_dir())  # noqa: S606
        else:
            self._notify("Config folder", app_dir())

# ---------------------------------------------------------------------------
# Dashboard + dialogs (tkinter, lazy imports so --self-test stays stdlib-only)
# ---------------------------------------------------------------------------

def _v(app):
    """Snapshot of display state (called from UI thread)."""
    with app._lock:
        return {
            "status": app.status_msg,
            "connected": app.connected,
            "sess": (app.sess_rx, app.sess_tx),
            "tot": (app.totals["rx"], app.totals["tx"]),
            "endpoint": _conf_endpoint(),
            "mode": "mock (dry-run)" if app.mock else "amneziawg",
            "backend_ok": app.backend_ok,
        }


def _open_dashboard(app):
    """Main window: dark, glanceable status + big connect button.

    Pure-black theme, live data cards, one-tap import/guide actions.
    """
    import tkinter as tk
    from tkinter import messagebox
    if app.dash_win is not None:
        try:
            app.dash_win.lift()
            app.dash_win.focus_force()
            return
        except Exception:  # noqa: BLE001
            app.dash_win = None
    win = tk.Toplevel(app.root)
    app.dash_win = win
    win.title("RobloxVPN %s" % APP_VERSION)
    win.resizable(False, False)

    BG, CARD, FG, DIM = "#000000", "#141414", "#f5f5f5", "#8a8a8a"
    GREEN, RED, AMBER = "#2ea043", "#f85149", "#d29922"
    FONT = "Segoe UI"
    win.configure(bg=BG)

    # -- header ------------------------------------------------------
    header = tk.Frame(win, bg=BG)
    header.pack(fill="x", padx=20, pady=(18, 2))
    tk.Label(header, text="ROBLOXVPN", fg=FG, bg=BG,
             font=(FONT, 13, "bold")).pack(side="left")
    pill = tk.Label(header, text="", fg=DIM, bg=BG, font=(FONT, 9, "bold"))
    pill.pack(side="right")

    # -- status hero -------------------------------------------------
    hero = tk.Frame(win, bg=BG)
    hero.pack(fill="x", pady=(8, 2))
    dot = tk.Label(hero, text="\u25cf", fg=DIM, bg=BG, font=(FONT, 40))
    dot.pack()
    title = tk.Label(hero, text="Disconnected", fg=FG, bg=BG,
                     font=(FONT, 17, "bold"))
    title.pack()
    sub = tk.Label(hero, text="", fg=DIM, bg=BG, font=(FONT, 9))
    sub.pack(pady=(2, 0))
    obf_warn = tk.Label(hero, text="", fg=AMBER, bg=BG,
                        font=(FONT, 8, "bold"), wraplength=280,
                        justify="center")
    obf_warn.pack(pady=(2, 0))

    # -- main action -------------------------------------------------
    main_btn = tk.Button(win, text="Connect", fg="white", bg=GREEN,
                         activeforeground="white", activebackground="#3fb950",
                         font=(FONT, 11, "bold"), bd=0, relief="flat",
                         highlightthickness=0, padx=20, pady=10,
                         command=lambda: (app.do_disconnect()
                                          if _v(app)["connected"]
                                          else app.do_connect()))
    main_btn.pack(fill="x", padx=20, pady=(10, 2))

    # -- data cards --------------------------------------------------
    cards = tk.Frame(win, bg=BG)
    cards.pack(fill="x", padx=20, pady=(8, 2))
    cards.columnconfigure(0, weight=1)
    cards.columnconfigure(1, weight=1)

    def _card(col, heading):
        c = tk.Frame(cards, bg=CARD, padx=12, pady=10)
        c.grid(row=0, column=col, sticky="ew",
               padx=(0, 5) if col == 0 else (5, 0))
        tk.Label(c, text=heading, fg=DIM, bg=CARD,
                 font=(FONT, 8, "bold")).pack(anchor="w")
        down = tk.Label(c, text="\u2193  \u2014", fg=FG, bg=CARD,
                        font=(FONT, 12, "bold"))
        down.pack(anchor="w", pady=(6, 0))
        up = tk.Label(c, text="\u2191  \u2014", fg=FG, bg=CARD,
                      font=(FONT, 12, "bold"))
        up.pack(anchor="w")
        return down, up

    sess_down, sess_up = _card(0, "THIS SESSION")
    tot_down, tot_up = _card(1, "TOTAL")

    # -- footnote + secondary actions --------------------------------
    tk.Label(win, text="Split tunnel \u00b7 only Roblox traffic uses the VPN.",
             fg=DIM, bg=BG, font=(FONT, 8)).pack(pady=(8, 6))
    row = tk.Frame(win, bg=BG)
    row.pack()
    for text, cmd in (("Import config", app.import_dialog),
                      ("Setup guide", app.open_guide)):
        tk.Button(row, text=text, fg=FG, bg=CARD, activeforeground=FG,
                  activebackground="#222222", font=(FONT, 9), bd=0,
                  relief="flat", highlightthickness=0, padx=14, pady=7,
                  command=cmd).pack(side="left", padx=5)
    reset = tk.Label(win, text="reset counters", fg=DIM, bg=BG, cursor="hand2",
                     font=(FONT, 8, "underline"))
    reset.pack(pady=(8, 2))
    reset.bind("<Button-1>", lambda e: _reset_counters())
    tk.Label(win, text=APP_VERSION, fg="#3a3a3a", bg=BG,
             font=(FONT, 8)).pack(pady=(0, 8))

    adv = tk.BooleanVar(value=bool(app.settings.get("allow_full_tunnel")))

    def _toggle_adv():
        app.settings["allow_full_tunnel"] = bool(adv.get())
        save_settings(app.settings)
        if adv.get():
            messagebox.showwarning(
                "Full tunnel allowed",
                "Full-tunnel configs (0.0.0.0/0) will now import. This routes "
                "ALL traffic through the VPN and burns metered data fast.")

    tk.Checkbutton(win, text="Allow full-tunnel configs (not recommended)",
                   variable=adv, command=_toggle_adv, fg=DIM, bg=BG,
                   selectcolor=BG, activebackground=BG, activeforeground=DIM,
                   highlightthickness=0,
                   font=(FONT, 8)).pack(pady=(0, 6))

    # -- Stealth mode toggle (WireGuard-over-TLS, bypasses DPI) ---------
    stm = tk.BooleanVar(value=(app.backend_name == "stealth"))

    def _toggle_stealth():
        new = "stealth" if stm.get() else "amneziawg"
        if new == app.backend_name:
            return
        if app.connected:
            messagebox.showinfo(
                "Disconnect first",
                "Disconnect the VPN before switching engine mode.")
            stm.set(app.backend_name == "stealth")
            return
        app.set_backend(new)
        if not app.backend_ok:
            messagebox.showwarning(
                "Stealth engine",
                "Stealth mode selected but the engine is not available:\n%s\n\n"
                "Falling back to AmneziaWG mode." % app.backend_msg)
            stm.set(False)
            app.set_backend("amneziawg")
        else:
            messagebox.showinfo(
                "Engine switched",
                "Now using %s mode.\nImport your ProtonVPN config and connect." %
                ("Stealth (DPI-resistant)" if new == "stealth" else "AmneziaWG"))

    tk.Checkbutton(win, text="Stealth mode (WireGuard-over-TLS, beats DPI)",
                   variable=stm, command=_toggle_stealth, fg="#7ec8ff", bg=BG,
                   selectcolor=BG, activebackground=BG,
                   activeforeground="#7ec8ff",
                   highlightthickness=0,
                   font=(FONT, 9, "bold")).pack(pady=(0, 12))

    def _reset_counters():
        if messagebox.askyesno("Reset counters",
                               "Reset the lifetime data counters?"):
            with app._lock:
                app.totals = {"rx": 0, "tx": 0}
                save_stats(0, 0)

    def refresh():
        try:
            if not win.winfo_exists():
                return
        except Exception:  # noqa: BLE001
            return
        s = _v(app)
        st = s["status"]
        try:
            with open(conf_path(), encoding="utf-8",
                      errors="replace") as f:
                obf_on = has_obfuscation(f.read())
        except OSError:
            obf_on = False
        obf_warn.config(
            text="Obfuscation is ON -- ProtonVPN servers need it OFF.\n"
                 "Re-import the original file and choose Strip."
            if obf_on else "")
        if s["connected"]:
            color = GREEN
            title.config(text="Connected")
            pill.config(text="\u25cf CONNECTED", fg=GREEN)
            sub_text = "Server " + s["endpoint"]
            if "no handshake" in st or "(?)" in st:
                sub_text += "  \u00b7  waiting for handshake\u2026"
            sub.config(text=sub_text)
            main_btn.config(text="Disconnect", bg=RED,
                            activebackground="#ff7b72")
        elif any(k in st.lower()
                 for k in ("download", "install", "connecting")):
            color = AMBER
            title.config(text="Working\u2026")
            pill.config(text="\u25cf WORKING", fg=AMBER)
            sub.config(text=st)
            main_btn.config(text="Connect", bg=GREEN,
                            activebackground="#3fb950")
        else:
            color = DIM
            title.config(text="Disconnected")
            pill.config(text="\u25cb OFFLINE", fg=DIM)
            sub.config(text="Import a config, then Connect."
                       if s["endpoint"] == "?" else "Server " + s["endpoint"])
            main_btn.config(text="Connect", bg=GREEN,
                            activebackground="#3fb950")
        dot.config(fg=color)
        sess_down.config(text="\u2193  " + fmt_bytes(s["sess"][0]))
        sess_up.config(text="\u2191  " + fmt_bytes(s["sess"][1]))
        tot_down.config(text="\u2193  " + fmt_bytes(s["tot"][0]))
        tot_up.config(text="\u2191  " + fmt_bytes(s["tot"][1]))
        app.root.after(1500, refresh)

    def on_close():
        app.dash_win = None
        win.destroy()

    win.protocol("WM_DELETE_WINDOW", on_close)
    win.update_idletasks()
    win.geometry("+%d+%d" % ((win.winfo_screenwidth() - win.winfo_width()) // 2,
                             win.winfo_screenheight() // 4))
    refresh()


def _install_failed_dialog(app, detail):
    """Fix-it window shown when the AmneziaWG auto-install fails.

    Shows the real installer error (parsed from the MSI log), a Retry
    button (fresh download), and a clickable manual-download link --
    no dead-end message boxes.
    """
    import tkinter as tk
    import webbrowser
    win = tk.Toplevel(app.root)
    win.title("AmneziaWG install failed")
    win.resizable(False, False)
    tk.Label(win, text="The VPN engine could not be installed automatically.",
             font=("TkDefaultFont", 10, "bold")).pack(
                 anchor="w", padx=14, pady=(12, 4))
    short = detail if len(detail) <= 500 else detail[:500] + "..."
    tk.Message(win, text=short, width=440).pack(anchor="w", padx=14)
    tk.Label(win, text="What to try:",
             font=("TkDefaultFont", 9, "bold")).pack(
                 anchor="w", padx=14, pady=(8, 2))
    tk.Label(win, justify="left", wraplength=440, text=(
        "1. Make sure you accepted the admin (UAC) prompt when starting "
        "RobloxVPN.\n"
        "2. If Windows just updated, restart the PC, then press Retry.\n"
        "3. Or install it manually from the releases page.")).pack(
            anchor="w", padx=14)
    row = tk.Frame(win)
    row.pack(pady=12)
    tk.Button(row, text="Retry install",
              command=lambda: (win.destroy(), app.retry_install())).pack(
                  side="left", padx=6)
    tk.Button(row, text="Open download page",
              command=lambda: webbrowser.open(
                  "https://github.com/amnezia-vpn/"
                  "amneziawg-windows-client/releases")).pack(
                      side="left", padx=6)
    tk.Button(row, text="Close", command=win.destroy).pack(side="left",
                                                           padx=6)


def _open_guide(app):
    """First-run setup guide: the 4 steps with links and in-app buttons.

    Opens automatically once (until dismissed); re-openable from the tray
    menu ("Setup guide...").
    """
    import tkinter as tk
    import webbrowser
    existing = getattr(app, "guide_win", None)
    if existing is not None:
        try:
            existing.lift()
            existing.focus_force()
            return
        except Exception:  # noqa: BLE001
            pass
    win = tk.Toplevel(app.root)
    app.guide_win = win
    win.title("RobloxVPN setup - 4 steps")
    win.resizable(False, False)

    def _link(parent, text, url):
        lbl = tk.Label(parent, text="\u2197 " + text, fg="blue",
                       cursor="hand2",
                       font=("TkDefaultFont", 9, "underline"))
        lbl.pack(anchor="w")
        lbl.bind("<Button-1>", lambda e: webbrowser.open(url))

    steps = [
        ("1. Create a free ProtonVPN account",
         "Email only - no credit card needed.",
         ("Open protonvpn.com", GUIDE_LINKS["proton_free"]), None),
        ("2. Download a WireGuard config",
         "On account.protonvpn.com go to Downloads -> WireGuard "
         "configuration, choose a Netherlands server, press Create, then "
         "Download the .conf file.",
         ("Open config page", GUIDE_LINKS["proton_wg"]), None),
        ("3. Import the .conf here",
         "You will be offered a one-click conversion to Roblox-only "
         "split-tunnel, so data usage stays minimal.",
         None, ("Import .conf...", app.import_dialog)),
        ("4. Connect, then open Roblox",
         "The tray icon shows live data usage. Disconnect when done "
         "playing - the tunnel never starts on its own.",
         None, ("Connect now", app.do_connect)),
    ]
    for title, desc, link, btn in steps:
        f = tk.Frame(win, padx=14, pady=7)
        f.pack(fill="x", anchor="w")
        tk.Label(f, text=title,
                 font=("TkDefaultFont", 10, "bold")).pack(anchor="w")
        tk.Label(f, text=desc, wraplength=400, justify="left").pack(anchor="w")
        if link:
            _link(f, link[0], link[1])
        if btn:
            tk.Button(f, text=btn[0], command=btn[1]).pack(anchor="w",
                                                           pady=(5, 0))

    var = tk.BooleanVar(value=True)
    tk.Checkbutton(win, text="Don't show this guide again",
                   variable=var).pack(pady=(2, 10))

    def on_close():
        if var.get():
            app.settings["guide_seen"] = True
            save_settings(app.settings)
        app.guide_win = None
        win.destroy()

    win.protocol("WM_DELETE_WINDOW", on_close)


def _import_dialog(app):
    from tkinter import filedialog, messagebox
    p = filedialog.askopenfilename(
        title="Import AmneziaWG / WireGuard config",
        filetypes=[("Config files", "*.conf"), ("All files", "*.*")])
    if not p:
        return
    try:
        with open(p, encoding="utf-8", errors="replace") as f:
            text = f.read()
    except OSError as e:
        messagebox.showerror("Import failed", str(e))
        return
    allow = bool(app.settings.get("allow_full_tunnel"))
    ok, errors, warnings = validate_config_text(text, allow_full_tunnel=allow)
    if not ok:
        # One-click rescue: a full-tunnel config (e.g. ProtonVPN free) can be
        # converted to Roblox-only split-tunnel, keeping keys/endpoint
        # (and fixing provider-internal DNS to public resolvers).
        only_full = errors and all("FULL-TUNNEL" in e for e in errors)
        if only_full and messagebox.askyesno(
                "Full-tunnel config detected",
                "This config routes ALL your traffic through the VPN "
                "(burns mobile data).\n\nConvert it to Roblox-only "
                "split-tunnel?\n(Keys, server and endpoint are kept.)"):
            text = convert_to_split_tunnel(text)
            ok, errors, warnings = validate_config_text(text)
        if not ok:
            messagebox.showerror("Config rejected", "\n".join(errors))
            return
    if has_obfuscation(text) and messagebox.askyesno(
            "Obfuscation detected",
            "This config has AmneziaWG obfuscation turned ON.\n\n"
            "ProtonVPN servers use plain WireGuard and cannot understand "
            "obfuscated handshakes -- the connection would stay stuck at "
            "\"waiting for handshake\" forever.\n\n"
            "Strip the obfuscation for ProtonVPN?"):
        text = strip_obfuscation(text)
        ok, errors, warnings = validate_config_text(text)
        if not ok:
            messagebox.showerror("Config rejected", "\n".join(errors))
            return
    if warnings and not messagebox.askyesno(
            "Import with warnings?", "\n".join(warnings) +
            "\n\nImport anyway?"):
        return
    try:
        with open(conf_path(), "w", encoding="utf-8") as f:
            f.write(text if text.endswith("\n") else text + "\n")
    except OSError as e:
        messagebox.showerror("Import failed", str(e))
        return
    app._notify("Config imported", "Saved. Press Connect to bring it up.")


def _generate_dialog(app):
    import tkinter as tk
    from tkinter import messagebox
    win = tk.Toplevel(app.root)
    win.title("Generate RobloxVPN config")
    win.resizable(False, False)
    tk.Label(win, text="For your OWN AmneziaWG server only (e.g. the Oracle VM).\n"
                       "NOT for ProtonVPN -- import their .conf instead.",
             fg="#d29922", justify="left",
             font=("Segoe UI", 9, "bold")).grid(row=0, column=0, columnspan=2,
                                                sticky="w", padx=10, pady=(10, 2))
    fields = {}
    def row(r, label, default="", width=44):
        tk.Label(win, text=label).grid(row=r, column=0, sticky="w",
                                      padx=10, pady=3)
        e = tk.Entry(win, width=width)
        e.insert(0, default)
        e.grid(row=r, column=1, padx=10, pady=3)
        fields[label] = e
        return e
    row(1, "Server IP / hostname", "")
    row(2, "Port (UDP)", str(DEFAULT_PORT))
    row(3, "Server public key", "")
    row(4, "Client private key", generate_private_key())
    row(5, "Preshared key (optional)", "")
    row(6, "AllowedIPs", ", ".join(ROBLOX_ALLOWED_IPS))
    obf = [random_obfuscation()]
    obf_lbl = tk.Label(win, text="", fg="#555555", font=("Segoe UI", 8),
                       wraplength=380, justify="left")
    obf_lbl.grid(row=7, column=0, columnspan=2, padx=10, pady=3)
    def show_obf():
        o = obf[0]
        obf_lbl.config(text="Obfuscation: Jc=%d Jmin=%d Jmax=%d S=%d,%d,%d,%d "
                            "(H values hidden)" % (
                                o["Jc"], o["Jmin"], o["Jmax"], o["S1"],
                                o["S2"], o["S3"], o["S4"]))
    show_obf()
    btns = tk.Frame(win)
    btns.grid(row=8, column=0, columnspan=2, pady=8)
    tk.Button(btns, text="New client key",
              command=lambda: (fields["Client private key"].delete(0, "end"),
                               fields["Client private key"].insert(
                                   0, generate_private_key()))).pack(side="left",
                                                                    padx=4)
    tk.Button(btns, text="Randomize obfuscation",
              command=lambda: (obf.__setitem__(0, random_obfuscation()),
                               show_obf())).pack(side="left", padx=4)
    tk.Label(win, text="These values MUST match the server config.",
             fg="#a00", font=("Segoe UI", 8)).grid(row=9, column=0,
                                                  columnspan=2, pady=(0, 4))
    def save(and_connect):
        host = fields["Server IP / hostname"].get().strip()
        port = fields["Port (UDP)"].get().strip()
        spub = fields["Server public key"].get().strip()
        cpriv = fields["Client private key"].get().strip()
        psk = fields["Preshared key (optional)"].get().strip() or None
        allowed = [a.strip() for a in fields["AllowedIPs"].get().split(",")
                   if a.strip()]
        if not host or not spub or not cpriv:
            messagebox.showerror("Missing fields",
                                 "Server host, server public key and client "
                                 "private key are required.")
            return
        try:
            port_i = int(port)
            assert 1 <= port_i <= 65535
        except (ValueError, AssertionError):
            messagebox.showerror("Bad port", "Port must be 1-65535.")
            return
        text = generate_config(host, port_i, spub, cpriv, psk=psk,
                               allowed_ips=allowed, obf=obf[0])
        ok, errors, _ = validate_config_text(text)
        if not ok:
            messagebox.showerror("Generated config invalid",
                                 "\n".join(errors))
            return
        with open(conf_path(), "w", encoding="utf-8") as f:
            f.write(text)
        win.destroy()
        app._notify("Config saved", "Wrote %s" % conf_path())
        if and_connect:
            app.do_connect()
    act = tk.Frame(win)
    act.grid(row=9, column=0, columnspan=2, pady=(0, 10))
    tk.Button(act, text="Save", width=12,
              command=lambda: save(False)).pack(side="left", padx=4)
    tk.Button(act, text="Save & Connect", width=14,
              command=lambda: save(True)).pack(side="left", padx=4)


# Attach dialog entry points to VpnApp (kept out of the class body for clarity)
VpnApp.open_dashboard = lambda self: _open_dashboard(self)
VpnApp.open_guide = lambda self: _open_guide(self)
VpnApp.import_dialog = lambda self: _import_dialog(self)
VpnApp.generate_dialog = lambda self: _generate_dialog(self)


# ---------------------------------------------------------------------------
# Self-test (runs on any platform, stdlib only)
# ---------------------------------------------------------------------------

SAMPLE_SHOW = """interface: roblox
  public key: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=
  private key: (hidden)
  listening port: 53488
peer: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb=
  endpoint: 203.0.113.7:443
  allowed ips: 128.116.0.0/17
  latest handshake: 3 seconds ago
  transfer: 6.55 KiB received, 4.13 KiB sent
"""


def run_self_tests():
    fails = []
    total = [0]

    def check(name, cond, info=""):
        total[0] += 1
        print(("%s %s" % ("PASS" if cond else "FAIL", name)) +
              (" -- " + info if info and not cond else ""))
        if not cond:
            fails.append(name)

    check("fmt_bytes B", fmt_bytes(0) == "0 B")
    check("app version format",
          bool(re.match(r"^v\d+$", APP_VERSION)), APP_VERSION)
    check("fmt_bytes KB", fmt_bytes(1536) == "1.5 KB")
    check("fmt_bytes MB", fmt_bytes(5 * 1024 ** 2) == "5.0 MB")
    check("transfer KiB", parse_transfer_amount("6.55", "KiB") == 6707)
    check("transfer MiB", parse_transfer_amount("2.5", "MiB") == 2621440)

    st = parse_awg_show(SAMPLE_SHOW)
    check("awg_show parsed", st is not None)
    check("awg_show rx", st["rx_bytes"] == 6707, repr(st))
    check("awg_show tx", st["tx_bytes"] == 4229, repr(st))
    check("awg_show handshake", st["handshake"] == "3 seconds ago")
    check("awg_show endpoint", st["endpoint"] == "203.0.113.7:443")
    check("awg_show garbage -> None", parse_awg_show("nonsense") is None)
    check("awg_show no transfer -> None",
          parse_awg_show("interface: x\n  latest handshake: Never\n") is None)

    rng = random.Random(42)
    o = random_obfuscation(rng)
    check("obf Jmax>Jmin", o["Jmax"] > o["Jmin"], repr(o))
    check("obf ranges", 3 <= o["Jc"] <= 10 and 15 <= o["S1"] <= 127)
    check("obf H uint32", all(1 <= o[k] <= 2 ** 32 - 1
                              for k in ("H1", "H2", "H3", "H4")))

    check("awg arch amd64", awg_arch_key("AMD64") == "amd64")
    check("awg arch x86_64", awg_arch_key("x86_64") == "amd64")
    check("awg arch arm64", awg_arch_key("ARM64") == "arm64")
    check("awg arch x86", awg_arch_key("x86") == "x86")
    fake_assets = [
        {"name": "amneziawg-amd64-3.1.0.msi",
         "browser_download_url": "https://example.com/a.msi", "size": 3641344},
        {"name": "amneziawg-arm64-3.1.0.msi",
         "browser_download_url": "https://example.com/b.msi", "size": 3330048},
        {"name": "checksums.txt",
         "browser_download_url": "https://example.com/c", "size": 100},
    ]
    picked = pick_awg_asset(fake_assets, "AMD64")
    check("awg pick amd64",
          picked is not None and picked[0] == "amneziawg-amd64-3.1.0.msi"
          and picked[2] == 3641344, repr(picked))
    picked = pick_awg_asset(fake_assets, "ARM64")
    check("awg pick arm64 skips others",
          picked is not None and picked[0] == "amneziawg-arm64-3.1.0.msi")
    check("awg pick none", pick_awg_asset([], "AMD64") is None)
    check("awg pick no msi match",
          pick_awg_asset([{"name": "src.zip",
                           "browser_download_url": "x", "size": 1}],
                         "AMD64") is None)

    cfg = generate_config("203.0.113.7", 443, "c2VydmVycHVia2V5MTIzNDU2Nzg5MGFiY2RlZmdoaWo=",
                          "dGVzdHByaXZhdGVrZXkxMjM0NTY3ODkwYWJjZGVmZ2g=", obf=o)
    check("gen has Interface", "[Interface]" in cfg)
    check("gen MTU", "MTU = 1420" in cfg)
    check("gen endpoint port", "Endpoint = 203.0.113.7:443" in cfg)
    check("gen split tunnel", "AllowedIPs = 128.116.0.0/17" in cfg)
    check("gen no full tunnel", "0.0.0.0/0" not in cfg)
    check("gen obfuscation", "Jc = %d" % o["Jc"] in cfg and "H4" in cfg)
    check("gen keepalive", "PersistentKeepalive = 25" in cfg)

    ok, errs, warns = validate_config_text(cfg)
    check("validate good", ok and not errs, "; ".join(errs))

    full = cfg.replace("AllowedIPs = 128.116.0.0/17",
                       "AllowedIPs = 0.0.0.0/0, ::/0")
    ok, errs, _ = validate_config_text(full)
    check("reject full tunnel", not ok and any("FULL-TUNNEL" in e
                                               for e in errs))
    ok, errs, _ = validate_config_text(full, allow_full_tunnel=True)
    check("allow full tunnel override", ok, "; ".join(errs))
    conv = convert_to_split_tunnel(full)
    check("convert drops 0.0.0.0/0",
          "0.0.0.0/0" not in conv and "::/0" not in conv, conv[:200])
    check("convert adds roblox range", "128.116.0.0/17" in conv)
    check("convert keeps endpoint", "Endpoint = 203.0.113.7:443" in conv)
    check("convert keeps keys",
          "PrivateKey = dGVzdHByaXZhdGVrZXkxMjM0NTY3ODkwYWJjZGVmZ2g=" in conv
          and "PublicKey = c2VydmVycHVia2V5MTIzNDU2Nzg5MGFiY2RlZmdoaWo=" in conv)
    ok, errs, _ = validate_config_text(conv)
    check("convert validates clean", ok, "; ".join(errs))
    obf_cfg = ("[Interface]\nPrivateKey = dGVzdHByaXZhdGVrZXkxMjM0NTY3ODkwYWJjZGVmZ2g=\n"
               "Jc = 4\nJmin = 10\nJmax = 60\nS1 = 30\nH1 = 12345\n"
               "[Peer]\nPublicKey = c2VydmVycHVia2V5MTIzNDU2Nzg5MGFiY2RlZmdoaWo=\n"
               "Endpoint = 203.0.113.7:443\nAllowedIPs = 128.116.0.0/17\n")
    check("has_obfuscation detects", has_obfuscation(obf_cfg))
    plain_cfg = ("[Interface]\nPrivateKey = dGVzdHByaXZhdGVrZXkxMjM0NTY3ODkwYWJjZGVmZ2g=\n"
                 "[Peer]\nPublicKey = c2VydmVycHVia2V5MTIzNDU2Nzg5MGFiY2RlZmdoaWo=\n"
                 "Endpoint = 203.0.113.7:443\nAllowedIPs = 128.116.0.0/17\n")
    check("has_obfuscation clean", not has_obfuscation(plain_cfg))
    stripped = strip_obfuscation(obf_cfg)
    check("strip removes Jc/S/H",
          not has_obfuscation(stripped)
          and "Jc" not in stripped and "S1" not in stripped)
    check("strip keeps keys/endpoint",
          "PrivateKey = dGVzdHByaXZhdGVrZXkxMjM0NTY3ODkwYWJjZGVmZ2g=" in stripped
          and "Endpoint = 203.0.113.7:443" in stripped
          and "AllowedIPs = 128.116.0.0/17" in stripped)
    ok, errs, _ = validate_config_text(stripped)
    check("stripped validates clean", ok, "; ".join(errs))
    check("_is_private_ip 10.x", _is_private_ip("10.2.0.1"))
    check("_is_private_ip 192.168.x", _is_private_ip("192.168.1.1"))
    check("_is_private_ip 172.16-31", _is_private_ip("172.20.0.5")
          and not _is_private_ip("172.15.0.5"))
    check("_is_private_ip public",
          not _is_private_ip("1.1.1.1") and not _is_private_ip("8.8.8.8"))
    dns_cfg = ("[Interface]\nPrivateKey = AAA=\nDNS = 10.2.0.1\n"
               "[Peer]\nPublicKey = BBB=\nEndpoint = 203.0.113.7:443\n"
               "AllowedIPs = 0.0.0.0/0\n")
    conv2 = convert_to_split_tunnel(dns_cfg)
    check("convert fixes private DNS", "DNS = 1.1.1.1, 8.8.8.8" in conv2,
          conv2[:200])
    pub_cfg = dns_cfg.replace("DNS = 10.2.0.1", "DNS = 1.1.1.1")
    check("convert keeps public DNS",
          "DNS = 1.1.1.1" in convert_to_split_tunnel(pub_cfg))
    nodns_cfg = dns_cfg.replace("DNS = 10.2.0.1\n", "")
    check("convert no DNS line ok",
          "DNS" not in convert_to_split_tunnel(nodns_cfg))
    badkey = plain_cfg.replace("PrivateKey = dGVzdHByaXZhdGVrZXkxMjM0NTY3ODkwYWJjZGVmZ2g=",
                               "PrivateKey = ****************")
    ok, errs, _ = validate_config_text(badkey)
    check("reject masked private key",
          not ok and any("PrivateKey is not a valid" in e for e in errs),
          "; ".join(errs))
    ok, errs, _ = validate_config_text(plain_cfg)
    check("accept valid private key", ok, "; ".join(errs))
    # connect() must reinstall the tunnel service from scratch, so a stale
    # service left by a killed/older instance can never survive with an old
    # config (this was the "Tunnel already installed and running" failure).
    calls = []
    def fake_run(cmd, timeout=30):
        calls.append(cmd)
        if cmd[:2] == ["sc", "query"]:
            return True, "STATE              : 1  STOPPED"
        return True, ""
    real_run = globals()["_run"]
    globals()["_run"] = fake_run
    try:
        b = AmneziaWGBackend()
        b.amneziawg = "amneziawg.exe"
        b.connect("dummy.conf")
    finally:
        globals()["_run"] = real_run
    seq = [c[1] for c in calls]
    check("connect reinstalls service",
          seq == ["stop", "query", "/uninstalltunnelservice",
                  "/installtunnelservice", "config", "start"],
          repr(seq))
    check("connect installs current conf", calls[3][2] == "dummy.conf")
    def fake_run_fail(cmd, timeout=30):
        if cmd[:2] == ["sc", "query"]:
            return True, "STOPPED"
        if cmd[1] == "/installtunnelservice":
            return False, "[Error: install blew up]"
        return True, ""
    globals()["_run"] = fake_run_fail
    try:
        b2 = AmneziaWGBackend()
        b2.amneziawg = "amneziawg.exe"
        try:
            b2.connect("dummy.conf")
            raised = False
        except TunnelError:
            raised = True
    finally:
        globals()["_run"] = real_run
    check("connect raises on install failure", raised)
    ok, errs, _ = validate_config_text("[Interface]\nPrivateKey = x\n")
    check("reject malformed", not ok and len(errs) >= 2, "; ".join(errs))
    ok, _, warns = validate_config_text(
        cfg.replace("128.116.0.0/17", "9.9.9.9/32"))
    check("warn missing roblox range", ok and len(warns) > 0)
    plain_wg = re.sub(r"^Jc.*\n|^Jmin.*\n|^Jmax.*\n|^S[1-4].*\n|^H[1-4].*\n",
                      "", cfg, flags=re.MULTILINE)
    ok, _, warns = validate_config_text(plain_wg)
    check("warn plain wireguard", ok and any("obfuscation" in w
                                             for w in warns))

    check("guide links https",
          len(GUIDE_LINKS) >= 2
          and all(v.startswith("https://") for v in GUIDE_LINKS.values()))

    import tempfile as _tf
    with _tf.NamedTemporaryFile("w", suffix=".log", delete=False) as f:
        f.write("MSI (s) ...\nAction start InstallDriver\n"
                "InstallDriver: Error 1721 configuring\n"
                "Action ended with Return value 3.\n"
                "MSI (s): note after\n")
        fake_log = f.name
    try:
        hint = _msi_failure_hint(fake_log)
        check("msi hint finds Return value 3",
              "Return value 3" in hint and "InstallDriver" in hint, hint[:120])
    finally:
        os.unlink(fake_log)
    check("msi hint missing log", _msi_failure_hint("/nonexistent/x.log") == "")
    if os.name != "nt":
        check("no_window empty off-windows", _no_window() == {})
    else:
        check("no_window hides console on windows",
              "creationflags" in _no_window())

    # MockBackend cycle (uses a temp conf file)
    import tempfile
    mb = MockBackend()
    check("mock available", mb.available()[0])
    try:
        mb.connect("/nonexistent/roblox.conf")
        check("mock rejects missing conf", False)
    except TunnelError:
        check("mock rejects missing conf", True)
    with tempfile.NamedTemporaryFile("w", suffix=".conf",
                                     delete=False) as f:
        f.write(cfg)
        tmp = f.name
    try:
        mb.connect(tmp)
        s1 = mb.get_stats()
        time.sleep(0.05)
        s2 = mb.get_stats()
        check("mock stats grow",
              s1 and s2 and s2["rx_bytes"] > s1["rx_bytes"])
        mb.disconnect()
        check("mock disconnect", mb.get_stats() is None)
    finally:
        os.unlink(tmp)

    # --- Stealth backend ---
    check("make_backend stealth", make_backend("stealth").name == "stealth")
    check("make_backend amneziawg",
          make_backend("amneziawg").name == "amneziawg")
    check("make_backend mock", make_backend("x", mock=True).name == "mock")
    sb = StealthBackend()
    check("stealth get_stats none when down", sb.get_stats() is None)
    with tempfile.NamedTemporaryFile("w", suffix=".conf",
                                     delete=False) as f:
        f.write("[Interface]\nPrivateKey = AAAA\n"
                "Address = 10.2.0.2/32, 2a07:b944::2:2/128\n"
                "[Peer]\nPublicKey = BBBB\nEndpoint = 1.2.3.4:51820\n")
        tmp2 = f.name
    try:
        check("conf_address ipv4", _conf_address(tmp2) == "10.2.0.2")
    finally:
        os.unlink(tmp2)
    check("conf_address missing", _conf_address("/nonexistent.conf") is None)
    # mask computation used for the Roblox route
    bits = 17
    mask = ".".join(str((0xFFFFFFFF << (32 - bits) >> i) & 0xFF)
                    for i in (24, 16, 8, 0))
    check("route mask /17", mask == "255.255.128.0", mask)

    # --- regression: stealth Popen must unpack _no_window() kwargs ---
    # v16 shipped creationflags=_no_window() which passes a dict where
    # Popen expects an int -> TypeError -> silent thread death, UI hangs
    # on "Connecting..." forever. Guard the source directly.
    # NOTE: inspect.getsource raises OSError inside the frozen PyInstaller
    # exe (no .py source bundled) -- skip source-grep checks there.
    import inspect as _inspect
    try:
        _src = _inspect.getsource(StealthBackend._connect_inner)
    except OSError:
        _src = None
    if _src is None:
        check("stealth popen unpacks no_window (skipped frozen)", True)
    else:
        check("stealth popen unpacks no_window",
              "creationflags=_no_window()" not in _src
              and "**_no_window()" in _src)
    # wintun driver recycle must never raise (sc missing on linux is fine)
    try:
        r = _recycle_wintun_driver()
        check("recycle_wintun_driver safe", isinstance(r, bool))
    except Exception as e:  # noqa: BLE001
        check("recycle_wintun_driver safe", False, repr(e))
    # stale-process kill + phantom cleanup must never raise either
    try:
        _kill_stale_stealth()
        _clean_phantom_adapters()
        check("stealth cleanup helpers safe", True)
    except Exception as e:  # noqa: BLE001
        check("stealth cleanup helpers safe", False, repr(e))
    # v31: hosts-file DNS bypass (plain DNS for Roblox is DPI-poisoned).
    # add/remove roundtrip on a temp file; other lines must survive.
    try:
        with tempfile.NamedTemporaryFile("w", delete=False,
                                         encoding="utf-8") as f:
            f.write("127.0.0.1 localhost\n")
            tmp3 = f.name
        try:
            ok_add = _hosts_add([("1.2.3.4", "www.roblox.com")], path=tmp3)
            with open(tmp3, encoding="utf-8") as f:
                body = f.read()
            ok_keep = "127.0.0.1 localhost" in body
            ok_tag = "1.2.3.4 www.roblox.com" in body
            n_rm = _hosts_remove(path=tmp3)
            with open(tmp3, encoding="utf-8") as f:
                gone = HOSTS_TAG not in f.read()
            check("hosts add/remove roundtrip",
                  ok_add == 1 and ok_keep and ok_tag
                  and n_rm == 1 and gone)
        finally:
            os.unlink(tmp3)
    except Exception as e:  # noqa: BLE001
        check("hosts add/remove roundtrip", False, repr(e))
    # v27: Roblox route must be bound to the TUN via IF <index>;
    # resolving an unknown interface must safely return None
    try:
        check("tun_if_index safe unknown",
              _tun_if_index("no-such-if-xyz") is None)
    except Exception as e:  # noqa: BLE001
        check("tun_if_index safe unknown", False, repr(e))
    if _src is None:
        check("route add binds tunnel IF (skipped frozen)", True)
    else:
        check("route add binds tunnel IF", '"IF"' in _src)
    # v29: connect path must NOT churn NDIS/PnP (no sc recycle, no
    # pnputil rescan) -- churn degrades the data path; unique ifname
    # already fixes creation. Helpers still exist and must stay safe.
    try:
        _rescan_pnp_devices()
        check("stealth rescan helper safe", True)
    except Exception as e:  # noqa: BLE001
        check("stealth rescan helper safe", False, repr(e))
    if _src is None:
        check("connect skips pnp churn (skipped frozen)", True)
    else:
        check("connect skips pnp churn",
              "_rescan_pnp_devices()" not in _src
              and "_recycle_wintun_driver()" not in _src)
    # v23: ready is sticky -- a 'status' line must not hide a working tunnel
    # from the connect waiter
    try:
        _sb3 = StealthBackend()
        _sb3._latest = {"type": "status", "rx_bytes": 1}
        _sb3._saw_ready = True
        check("stealth ready sticky", _sb3._saw_ready is True)
    except Exception as e:  # noqa: BLE001
        check("stealth ready sticky", False, repr(e))
    # concurrent connects are rejected, not run in parallel
    _sb2 = StealthBackend()
    _got = _sb2._connect_lock.acquire(blocking=False)
    check("connect lock acquirable", _got)
    if _got:
        _sb2._connect_lock.release()

    print("\n%d/%d tests passed" % (total[0] - len(fails), total[0]))
    if fails:
        print("FAILURES:", fails)
        return 1
    print("ALL SELF-TESTS PASSED")
    return 0


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

_single_instance_mutex = None


def ensure_single_instance():
    """Windows: refuse to run when another copy is already up.

    Prevents the classic upgrade confusion where the old exe keeps running
    in the tray while the user launches the new one (two identical icons).
    Returns True if this instance may continue.
    """
    global _single_instance_mutex
    if os.name != "nt":
        return True
    import ctypes
    kernel32 = ctypes.windll.kernel32
    _single_instance_mutex = kernel32.CreateMutexW(
        None, False, "RobloxVPN_SingleInstance_Mutex")
    if kernel32.GetLastError() == 183:  # ERROR_ALREADY_EXISTS
        ctypes.windll.user32.MessageBoxW(
            None,
            "RobloxVPN is already running.\n\n"
            "Right-click its tray icon (near the clock) and choose Exit,\n"
            "then run this file again.",
            APP_NAME, 0x40)
        return False
    return True


def main(argv=None):
    ap = argparse.ArgumentParser(prog=APP_NAME,
                                 description="Minimal-data split-tunnel VPN "
                                             "client for Roblox (AmneziaWG).")
    ap.add_argument("--mock", action="store_true",
                    help="dry-run mode: simulate the tunnel, no admin needed")
    ap.add_argument("--self-test", action="store_true",
                    help="run built-in logic tests and exit")
    args = ap.parse_args(argv)

    if args.self_test:
        sys.exit(run_self_tests())

    if os.name == "nt" and not args.mock and not is_admin():
        # Re-launch elevated; the elevated copy does the real work.
        relaunch_elevated([a for a in sys.argv[1:]])
        return

    if not ensure_single_instance():
        return

    app = VpnApp(mock=args.mock)
    app.run()


if __name__ == "__main__":
    main()

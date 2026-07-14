import logging
import platform
import subprocess
import threading
from typing import Optional

logger = logging.getLogger(__name__)

_WATCHER_MODULES = ["aw-watcher-window", "aw-watcher-afk"]


def is_vpn_connected() -> bool:
    """Return True if any VPN is actively connected."""
    try:
        system = platform.system()
        if system == "Darwin":
            # Two-layer check needed on macOS:
            # 1. scutil --nc list: catches System Preferences / IKEv2 / L2TP VPNs
            # 2. ifconfig point-to-point utun: catches NetworkExtension VPNs
            #    (OpenVPN Connect, WireGuard app, Cisco AnyConnect) which bypass scutil.
            #    System utun interfaces always exist but never have a --> peer address;
            #    only an active VPN tunnel has "inet X.X.X.X --> Y.Y.Y.Y" on a utun.
            result = subprocess.run(
                ["scutil", "--nc", "list"], capture_output=True, text=True, timeout=5
            )
            if any("(Connected)" in line for line in result.stdout.splitlines()):
                return True
            ifc = subprocess.run(
                ["ifconfig"], capture_output=True, text=True, timeout=5
            )
            current_iface = ""
            for line in ifc.stdout.splitlines():
                if line and not line[0].isspace():
                    current_iface = line.split(":")[0]
                elif current_iface.startswith("utun") and "-->" in line:
                    return True
            return False
        elif system == "Linux":
            # Check for any active tun/tap/WireGuard interface
            result = subprocess.run(
                ["ip", "link", "show"],
                capture_output=True, text=True, timeout=5,
            )
            _vpn_prefixes = ("tun", "tap", "wg", "vpn")
            for line in result.stdout.splitlines():
                parts = line.split(":", 2)
                if len(parts) >= 2:
                    name = parts[1].strip().lower().split("@")[0]
                    if any(name.startswith(p) for p in _vpn_prefixes) and "UP" in line:
                        return True
            return False
        else:  # Windows
            result = subprocess.run(
                [
                    "powershell", "-NoProfile", "-Command",
                    "Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } "
                    "| Select-Object -ExpandProperty InterfaceDescription",
                ],
                capture_output=True, text=True, timeout=5,
            )
            out = result.stdout.lower()
            return any(kw in out for kw in ("wireguard", "vpn", "tap-windows", "openvpn"))
    except Exception as e:
        logger.debug(f"VPN check failed: {e}")
        return False


class VpnMonitor:
    """Polls VPN status and starts/stops activity watchers accordingly."""

    def __init__(self, manager, testing: bool, poll_interval: int = 30) -> None:
        self._manager = manager
        self._testing = testing
        self._poll_interval = poll_interval
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._last_state: Optional[bool] = None

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, daemon=True, name="vpn-monitor")
        self._thread.start()
        logger.info("VPN monitor started (interval=%ds)", self._poll_interval)

    def stop(self) -> None:
        self._stop_event.set()

    # ------------------------------------------------------------------
    def _run(self) -> None:
        # Immediate check so watchers are gated correctly from the very first second
        self._check()
        while not self._stop_event.wait(self._poll_interval):
            self._check()

    def _check(self) -> None:
        try:
            connected = is_vpn_connected()
            if connected != self._last_state:
                self._on_change(connected)
                self._last_state = connected
        except Exception:
            logger.exception("VPN monitor check error")

    def _on_change(self, connected: bool) -> None:
        if connected:
            logger.info("VPN connected — starting activity watchers")
            for name in _WATCHER_MODULES:
                alive = any(
                    m.name == name and m.is_alive() for m in self._manager.modules
                )
                if not alive:
                    self._manager.start(name)
        else:
            logger.info("VPN disconnected — stopping activity watchers")
            for name in _WATCHER_MODULES:
                alive = any(
                    m.name == name and m.is_alive() for m in self._manager.modules
                )
                if alive:
                    self._manager.stop(name)

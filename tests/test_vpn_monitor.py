"""Unit tests for the VPN monitor — is_vpn_connected() and VpnMonitor class."""

from subprocess import TimeoutExpired
from unittest.mock import MagicMock, patch

from aw_qt.vpn_monitor import VpnMonitor, is_vpn_connected
from aw_qt.manager import Module


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# macOS: scutil --nc list output samples
SCUTIL_MACOS_WG_CONNECTED = """\
Available network connection services in the current set (*=enabled):
* (Connected)    A1B2C3D4-0000-0000-0000-000000000001  vpn.example.com [wg_profile]  [VPN:WireGuard]
"""

SCUTIL_MACOS_WG_DISCONNECTED = """\
Available network connection services in the current set (*=enabled):
* (Disconnected) A1B2C3D4-0000-0000-0000-000000000001  vpn.example.com [wg_profile]  [VPN:WireGuard]
"""

SCUTIL_MACOS_NO_VPN = """\
Available network connection services in the current set (*=enabled):
"""

SCUTIL_MACOS_OPENVPN_CONNECTED = """\
Available network connection services in the current set (*=enabled):
* (Connected)    B2C3D4E5-0000-0000-0000-000000000002  office-vpn  [VPN:L2TP]
"""

# macOS ifconfig output — OpenVPN Connect (NetworkExtension) creates a utun with -->
IFCONFIG_OPENVPN_CONNECTED = """\
lo0: flags=8049<UP,LOOPBACK,RUNNING> mtu 16384
\tinet 127.0.0.1 netmask 0xff000000
utun0: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 2000
\tinet 192.168.1.116 netmask 0xffffff00 broadcast 192.168.1.255
utun6: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1500
\tinet 10.140.0.47 --> 10.140.0.1 netmask 0xffffff00
"""

IFCONFIG_NO_VPN = """\
lo0: flags=8049<UP,LOOPBACK,RUNNING> mtu 16384
\tinet 127.0.0.1 netmask 0xff000000
utun0: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 2000
\tinet 192.168.1.116 netmask 0xffffff00 broadcast 192.168.1.255
"""

# Linux: ip link show output
IP_LINK_WG_UP = "4: wg0: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1420 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000\n"
IP_LINK_TUN_UP = "5: tun0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UNKNOWN\n"
IP_LINK_NO_VPN = "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536\n2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n"

# Windows: Get-NetAdapter InterfaceDescription output
POWERSHELL_WG_UP = "WireGuard Tunnel\n"
POWERSHELL_NO_VPN = "Intel(R) Wi-Fi 6 AX201 160MHz\nRealtek PCIe GbE Family Controller\n"


def _make_proc_result(stdout: str, returncode: int = 0):
    r = MagicMock()
    r.stdout = stdout
    r.returncode = returncode
    return r


def _make_manager(*module_names_alive: str):
    """Return a mock Manager whose modules list reflects which watchers are alive."""
    mgr = MagicMock()
    modules = []
    for name in module_names_alive:
        m = MagicMock(spec=Module)
        m.name = name
        m.is_alive.return_value = True
        modules.append(m)
    mgr.modules = modules
    return mgr


# ---------------------------------------------------------------------------
# is_vpn_connected — macOS (scutil --nc list)
# ---------------------------------------------------------------------------

class TestIsVpnConnectedMacOS:

    def _run_side_effects(self, scutil_out, ifconfig_out=IFCONFIG_NO_VPN):
        """Return a side_effect list: first call=scutil, second call=ifconfig."""
        return [_make_proc_result(scutil_out), _make_proc_result(ifconfig_out)]

    def test_wireguard_connected_via_scutil(self):
        with (
            patch("aw_qt.vpn_monitor.platform.system", return_value="Darwin"),
            patch("subprocess.run", side_effect=self._run_side_effects(SCUTIL_MACOS_WG_CONNECTED)),
        ):
            assert is_vpn_connected() is True

    def test_wireguard_disconnected(self):
        """WireGuard profile exists but is not Connected — must return False."""
        with (
            patch("aw_qt.vpn_monitor.platform.system", return_value="Darwin"),
            patch("subprocess.run", side_effect=self._run_side_effects(SCUTIL_MACOS_WG_DISCONNECTED)),
        ):
            assert is_vpn_connected() is False

    def test_no_vpn_configured(self):
        with (
            patch("aw_qt.vpn_monitor.platform.system", return_value="Darwin"),
            patch("subprocess.run", side_effect=self._run_side_effects(SCUTIL_MACOS_NO_VPN)),
        ):
            assert is_vpn_connected() is False

    def test_l2tp_vpn_connected_via_scutil(self):
        """A connected L2TP VPN in System Preferences must be detected."""
        with (
            patch("aw_qt.vpn_monitor.platform.system", return_value="Darwin"),
            patch("subprocess.run", side_effect=self._run_side_effects(SCUTIL_MACOS_OPENVPN_CONNECTED)),
        ):
            assert is_vpn_connected() is True

    def test_networkextension_vpn_connected_via_ifconfig(self):
        """OpenVPN Connect (NetworkExtension) creates utun with --> — must be detected."""
        with (
            patch("aw_qt.vpn_monitor.platform.system", return_value="Darwin"),
            patch("subprocess.run", side_effect=self._run_side_effects(SCUTIL_MACOS_NO_VPN, IFCONFIG_OPENVPN_CONNECTED)),
        ):
            assert is_vpn_connected() is True

    def test_utun_without_peer_not_detected(self):
        """System utun interfaces with plain inet (no -->) must not trigger VPN."""
        with (
            patch("aw_qt.vpn_monitor.platform.system", return_value="Darwin"),
            patch("subprocess.run", side_effect=self._run_side_effects(SCUTIL_MACOS_NO_VPN, IFCONFIG_NO_VPN)),
        ):
            assert is_vpn_connected() is False

    def test_scutil_timeout_returns_false(self):
        with (
            patch("aw_qt.vpn_monitor.platform.system", return_value="Darwin"),
            patch("subprocess.run", side_effect=TimeoutExpired(cmd="scutil", timeout=5)),
        ):
            assert is_vpn_connected() is False

    def test_unexpected_exception_returns_false(self):
        with (
            patch("aw_qt.vpn_monitor.platform.system", return_value="Darwin"),
            patch("subprocess.run", side_effect=OSError("no such file")),
        ):
            assert is_vpn_connected() is False


# ---------------------------------------------------------------------------
# is_vpn_connected — Linux (ip link show type wireguard)
# ---------------------------------------------------------------------------

class TestIsVpnConnectedLinux:

    def test_wireguard_interface_present(self):
        with (
            patch("aw_qt.vpn_monitor.platform.system", return_value="Linux"),
            patch("subprocess.run", return_value=_make_proc_result(IP_LINK_WG_UP)),
        ):
            assert is_vpn_connected() is True

    def test_no_vpn_interface(self):
        with (
            patch("aw_qt.vpn_monitor.platform.system", return_value="Linux"),
            patch("subprocess.run", return_value=_make_proc_result(IP_LINK_NO_VPN)),
        ):
            assert is_vpn_connected() is False

    def test_ip_command_timeout_returns_false(self):
        with (
            patch("aw_qt.vpn_monitor.platform.system", return_value="Linux"),
            patch("subprocess.run", side_effect=TimeoutExpired(cmd="ip", timeout=5)),
        ):
            assert is_vpn_connected() is False


# ---------------------------------------------------------------------------
# is_vpn_connected — Windows (Get-NetAdapter)
# ---------------------------------------------------------------------------

class TestIsVpnConnectedWindows:

    def test_wireguard_adapter_up(self):
        with (
            patch("aw_qt.vpn_monitor.platform.system", return_value="Windows"),
            patch("subprocess.run", return_value=_make_proc_result(POWERSHELL_WG_UP)),
        ):
            assert is_vpn_connected() is True

    def test_no_vpn_adapter(self):
        with (
            patch("aw_qt.vpn_monitor.platform.system", return_value="Windows"),
            patch("subprocess.run", return_value=_make_proc_result(POWERSHELL_NO_VPN)),
        ):
            assert is_vpn_connected() is False

    def test_powershell_timeout_returns_false(self):
        with (
            patch("aw_qt.vpn_monitor.platform.system", return_value="Windows"),
            patch("subprocess.run", side_effect=TimeoutExpired(cmd="powershell", timeout=5)),
        ):
            assert is_vpn_connected() is False


# ---------------------------------------------------------------------------
# VpnMonitor — state transitions
# ---------------------------------------------------------------------------

class TestVpnMonitorOnChange:

    def _monitor(self, alive_modules=()) -> VpnMonitor:
        mgr = _make_manager(*alive_modules)
        return VpnMonitor(mgr, testing=False)

    def test_vpn_connects_starts_both_watchers(self):
        mon = self._monitor(alive_modules=())
        mon._on_change(connected=True)

        names_started = [c.args[0] for c in mon._manager.start.call_args_list]
        assert "aw-watcher-window" in names_started
        assert "aw-watcher-afk" in names_started

    def test_vpn_disconnects_stops_both_watchers(self):
        mon = self._monitor(alive_modules=("aw-watcher-window", "aw-watcher-afk"))
        mon._on_change(connected=False)

        names_stopped = [c.args[0] for c in mon._manager.stop.call_args_list]
        assert "aw-watcher-window" in names_stopped
        assert "aw-watcher-afk" in names_stopped

    def test_vpn_connect_skips_already_alive_watcher(self):
        """If a watcher is already running, start() should not be called again."""
        mon = self._monitor(alive_modules=("aw-watcher-window",))
        mon._on_change(connected=True)

        names_started = [c.args[0] for c in mon._manager.start.call_args_list]
        assert "aw-watcher-window" not in names_started
        assert "aw-watcher-afk" in names_started

    def test_vpn_disconnect_skips_already_stopped_watcher(self):
        """If a watcher is already stopped, stop() should not be called."""
        mon = self._monitor(alive_modules=("aw-watcher-window",))
        mon._on_change(connected=False)

        names_stopped = [c.args[0] for c in mon._manager.stop.call_args_list]
        assert "aw-watcher-window" in names_stopped
        assert "aw-watcher-afk" not in names_stopped


# ---------------------------------------------------------------------------
# VpnMonitor — _check() state machine
# ---------------------------------------------------------------------------

class TestVpnMonitorCheck:

    def test_first_check_with_vpn_on_triggers_on_change(self):
        mgr = _make_manager()
        mon = VpnMonitor(mgr, testing=False)

        with patch.object(mon, "_on_change") as mock_change:
            with patch("aw_qt.vpn_monitor.is_vpn_connected", return_value=True):
                mon._check()
            mock_change.assert_called_once_with(True)
            assert mon._last_state is True

    def test_first_check_with_vpn_off_triggers_on_change(self):
        mgr = _make_manager()
        mon = VpnMonitor(mgr, testing=False)

        with patch.object(mon, "_on_change") as mock_change:
            with patch("aw_qt.vpn_monitor.is_vpn_connected", return_value=False):
                mon._check()
            mock_change.assert_called_once_with(False)
            assert mon._last_state is False

    def test_repeated_same_state_does_not_trigger_on_change(self):
        """_on_change must only be called when state transitions, not on every poll."""
        mgr = _make_manager()
        mon = VpnMonitor(mgr, testing=False)
        mon._last_state = True  # already recorded as connected

        with patch.object(mon, "_on_change") as mock_change:
            with patch("aw_qt.vpn_monitor.is_vpn_connected", return_value=True):
                mon._check()
                mon._check()
            mock_change.assert_not_called()

    def test_vpn_disconnect_transition_triggers_on_change(self):
        """Going from connected=True to connected=False triggers _on_change(False)."""
        mgr = _make_manager()
        mon = VpnMonitor(mgr, testing=False)
        mon._last_state = True

        with patch.object(mon, "_on_change") as mock_change:
            with patch("aw_qt.vpn_monitor.is_vpn_connected", return_value=False):
                mon._check()
            mock_change.assert_called_once_with(False)

    def test_vpn_reconnect_transition_triggers_on_change(self):
        """Going from connected=False back to True triggers _on_change(True)."""
        mgr = _make_manager()
        mon = VpnMonitor(mgr, testing=False)
        mon._last_state = False

        with patch.object(mon, "_on_change") as mock_change:
            with patch("aw_qt.vpn_monitor.is_vpn_connected", return_value=True):
                mon._check()
            mock_change.assert_called_once_with(True)

    def test_check_exception_does_not_crash(self):
        """An error inside is_vpn_connected should be caught and not propagate."""
        mgr = _make_manager()
        mon = VpnMonitor(mgr, testing=False)

        with patch("aw_qt.vpn_monitor.is_vpn_connected", side_effect=RuntimeError("oops")):
            mon._check()  # should not raise


# ---------------------------------------------------------------------------
# VpnMonitor — thread lifecycle
# ---------------------------------------------------------------------------

class TestVpnMonitorThread:

    def test_start_spawns_daemon_thread(self):
        mgr = _make_manager()
        mon = VpnMonitor(mgr, testing=False)

        with patch.object(mon, "_run"):
            mon.start()
            assert mon._thread is not None
            assert mon._thread.daemon is True
            assert mon._thread.name == "vpn-monitor"
            mon.stop()

    def test_stop_signals_thread_to_exit(self):
        mgr = _make_manager()
        mon = VpnMonitor(mgr, testing=False)

        with patch.object(mon, "_run"):
            mon.start()
            assert not mon._stop_event.is_set()
            mon.stop()
            assert mon._stop_event.is_set()

    def test_immediate_check_on_thread_start(self):
        """_run must call _check() once before entering the wait loop."""
        mgr = _make_manager()
        mon = VpnMonitor(mgr, testing=False, poll_interval=9999)
        checks: list = []

        def fake_check():
            checks.append(1)
            mon._stop_event.set()  # exit after first check

        with patch.object(mon, "_check", side_effect=fake_check):
            mon._run()

        assert len(checks) == 1, "Expected exactly one immediate check before the loop"

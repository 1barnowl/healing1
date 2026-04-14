"""
╔══════════════════════════════════════════════════════════════════════════════╗
║           ERROR / EXCEPTION / HEALING CORE  —  v0.2                        ║
║                                                                              ║
║  v0.2 additions over v0.1:                                                  ║
║    ✦ LearningStore        — failure fingerprints, outcome history,          ║
║                              adaptive policy adjustment                      ║
║    ✦ EventCorrelator      — causality grouping, dedup, fingerprinting       ║
║    ✦ ExceptionCatalog     — full structured exception tree (30+ categories) ║
║    ✦ ActuationDriver      — real subprocess calls, cross-platform           ║
║                              (Windows & Linux), per failure category        ║
║    ✦ SystemMetricsCollector— psutil-based real CPU/mem/disk/net signals     ║
║    ✦ TelemetryOutlet      — publish events to external hooks/queues         ║
║    ✦ WebSearchFallback    — stub: query web when no primitive matches       ║
║    ✦ AIServiceConsultant  — Claude API call for unknown/novel errors        ║
║    ✦ AdaptivePolicyManager— AdjustPoliciesIfNeeded from pseudocode         ║
║    ✦ Expanded primitives  — real OS commands per category from docs         ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import platform
import subprocess
import sys
import time
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable, Dict, List, Optional, Tuple

# ── optional deps — graceful fallback ────────────────────────────────────────
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

try:
    import urllib.request
    import urllib.parse
    NETWORK_AVAILABLE = True
except ImportError:
    NETWORK_AVAILABLE = False

log = logging.getLogger("healing_core")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)-8s] %(name)s — %(message)s",
)

OS = platform.system()   # "Windows" | "Linux" | "Darwin"


# ══════════════════════════════════════════════════════════════════════════════
# ENUMS  (same as v0.1, extended)
# ══════════════════════════════════════════════════════════════════════════════

class IncidentCategory(Enum):
    TRANSIENT        = auto()
    SYSTEMIC         = auto()
    RESOURCE         = auto()
    SEMANTIC         = auto()
    SECURITY         = auto()
    NETWORK          = auto()
    SERVICE          = auto()
    HARDWARE         = auto()
    AUTHENTICATION   = auto()
    DEPENDENCY       = auto()
    CONFIGURATION    = auto()
    MALWARE          = auto()
    DRIVER           = auto()
    UNKNOWN          = auto()

class Scope(Enum):
    MODULE    = auto()
    SUBSYSTEM = auto()
    GLOBAL    = auto()

class RemediationStatus(Enum):
    PENDING     = auto()
    STAGED      = auto()
    VERIFIED    = auto()
    COMMITTED   = auto()
    ROLLED_BACK = auto()
    ESCALATED   = auto()
    LEARNING    = auto()   # dispatched to AI consultant

class Severity(Enum):
    LOW      = 1
    MEDIUM   = 2
    HIGH     = 3
    CRITICAL = 4


# ══════════════════════════════════════════════════════════════════════════════
# DATA STRUCTURES
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class HealthSignal:
    source:    str
    metric:    str
    value:     float
    unit:      str   = ""
    timestamp: float = field(default_factory=time.time)

@dataclass
class Event:
    id:               str   = field(default_factory=lambda: str(uuid.uuid4()))
    actor:            str   = ""
    subsystem:        str   = ""
    error_type:       str   = ""
    message:          str   = ""
    raw:              Any   = None
    timestamp:        float = field(default_factory=time.time)
    is_health_signal: bool  = False
    fingerprint:      str   = ""   # filled by EventCorrelator

@dataclass
class Incident:
    id:          str               = field(default_factory=lambda: str(uuid.uuid4()))
    event:       Event             = field(default_factory=Event)
    category:    IncidentCategory  = IncidentCategory.UNKNOWN
    scope:       Scope             = Scope.MODULE
    severity:    Severity          = Severity.MEDIUM
    risk_score:  float             = 0.0
    status:      RemediationStatus = RemediationStatus.PENDING
    timestamp:   float             = field(default_factory=time.time)
    correlation_id: str            = ""  # groups causally related incidents

@dataclass
class Snapshot:
    id:          str            = field(default_factory=lambda: str(uuid.uuid4()))
    incident_id: str            = ""
    tag:         str            = ""
    state:       Dict[str, Any] = field(default_factory=dict)
    checksum:    str            = ""
    timestamp:   float          = field(default_factory=time.time)

    def sign(self) -> None:
        payload = json.dumps(self.state, sort_keys=True, default=str)
        self.checksum = hashlib.sha256(payload.encode()).hexdigest()

    def verify(self) -> bool:
        payload = json.dumps(self.state, sort_keys=True, default=str)
        return self.checksum == hashlib.sha256(payload.encode()).hexdigest()

@dataclass
class RemediationFix:
    id:          str                  = field(default_factory=lambda: str(uuid.uuid4()))
    name:        str                  = ""
    category:    IncidentCategory     = IncidentCategory.UNKNOWN
    description: str                  = ""
    steps:       List[Callable]       = field(default_factory=list)
    cost:        float                = 0.0
    impact:      float                = 0.0
    version:     str                  = "0.2.0"
    promoted_at: Optional[float]      = None
    success_count: int                = 0
    failure_count: int                = 0

    @property
    def success_rate(self) -> float:
        total = self.success_count + self.failure_count
        return self.success_count / total if total else 0.0

@dataclass
class AuditEntry:
    id:          str            = field(default_factory=lambda: str(uuid.uuid4()))
    event_type:  str            = ""
    incident_id: str            = ""
    snapshot_id: str            = ""
    actor:       str            = "healing_core"
    detail:      Dict[str, Any] = field(default_factory=dict)
    timestamp:   float          = field(default_factory=time.time)
    checksum:    str            = ""

    def sign(self) -> None:
        payload = json.dumps({
            "id": self.id, "event_type": self.event_type,
            "incident_id": self.incident_id, "snapshot_id": self.snapshot_id,
            "detail": self.detail, "timestamp": self.timestamp,
        }, sort_keys=True, default=str)
        self.checksum = hashlib.sha256(payload.encode()).hexdigest()

    def verify(self) -> bool:
        stored = self.checksum; self.sign()
        ok = self.checksum == stored; self.checksum = stored
        return ok

@dataclass
class LearningRecord:
    fingerprint:  str
    category:     IncidentCategory
    fix_name:     str
    outcome:      str      # "success" | "failure"
    timestamp:    float    = field(default_factory=time.time)
    detail:       str      = ""


# ══════════════════════════════════════════════════════════════════════════════
# EXCEPTION CATALOG  — structured tree of all known failure signatures
# ══════════════════════════════════════════════════════════════════════════════

EXCEPTION_CATALOG: Dict[str, Dict] = {
    # ── Network ──────────────────────────────────────────────────────────────
    "wifi_down":            {"category": "NETWORK",        "severity": "HIGH",     "keywords": ["wifi","wi-fi","interface down","wlan","no connection"]},
    "dns_failure":          {"category": "NETWORK",        "severity": "HIGH",     "keywords": ["dns","resolution failed","nslookup","nameserver"]},
    "gateway_unreachable":  {"category": "NETWORK",        "severity": "HIGH",     "keywords": ["gateway","default route","unreachable","dhcp"]},
    "packet_loss":          {"category": "NETWORK",        "severity": "MEDIUM",   "keywords": ["packet loss","dropped packet","high latency"]},
    "bandwidth_saturation": {"category": "NETWORK",        "severity": "MEDIUM",   "keywords": ["bandwidth","saturation","throttled","rate limit"]},
    "nat_failure":          {"category": "NETWORK",        "severity": "HIGH",     "keywords": ["nat","routing","remote access"]},
    "proxy_restriction":    {"category": "NETWORK",        "severity": "MEDIUM",   "keywords": ["proxy","connection refused","blocked"]},
    "port_conflict":        {"category": "NETWORK",        "severity": "MEDIUM",   "keywords": ["port","already in use","bind","address in use"]},
    # ── Service ───────────────────────────────────────────────────────────────
    "service_crash":        {"category": "SERVICE",        "severity": "HIGH",     "keywords": ["crash","crashed","service terminated","7034","7031"]},
    "service_hung":         {"category": "SERVICE",        "severity": "HIGH",     "keywords": ["hung","not responding","deadlock","7011"]},
    "service_timeout":      {"category": "SERVICE",        "severity": "MEDIUM",   "keywords": ["timeout","startup time","7009"]},
    "service_dependency":   {"category": "SERVICE",        "severity": "MEDIUM",   "keywords": ["dependency","dependent service","7003","missing service"]},
    "service_restart_flood":{"category": "SERVICE",        "severity": "HIGH",     "keywords": ["restart flood","crash loop","repeated failure"]},
    "task_scheduler_stop":  {"category": "SERVICE",        "severity": "HIGH",     "keywords": ["task scheduler","schedule service","7036","7040"]},
    # ── Resource ──────────────────────────────────────────────────────────────
    "memory_depletion":     {"category": "RESOURCE",       "severity": "CRITICAL", "keywords": ["memory","oom","out of memory","ram","heap"]},
    "cpu_overload":         {"category": "RESOURCE",       "severity": "HIGH",     "keywords": ["cpu","processor","high utilization","overload"]},
    "disk_full":            {"category": "RESOURCE",       "severity": "HIGH",     "keywords": ["disk","storage","no space","quota exceeded","full"]},
    "disk_io_contention":   {"category": "RESOURCE",       "severity": "MEDIUM",   "keywords": ["io wait","disk io","i/o contention"]},
    "handle_leak":          {"category": "RESOURCE",       "severity": "HIGH",     "keywords": ["handle","unreleased","leak","2004"]},
    # ── Security ──────────────────────────────────────────────────────────────
    "unauthorized_access":  {"category": "SECURITY",       "severity": "CRITICAL", "keywords": ["unauthorized","suspicious","intrusion","4624","4625","4740"]},
    "malware_detected":     {"category": "MALWARE",        "severity": "CRITICAL", "keywords": ["malware","ransomware","rootkit","trojan","virus","inject"]},
    "ransomware":           {"category": "MALWARE",        "severity": "CRITICAL", "keywords": ["ransomware","encrypted","ransom"]},
    "rogue_process":        {"category": "MALWARE",        "severity": "CRITICAL", "keywords": ["rogue process","suspicious process","spawn"]},
    # ── Authentication ────────────────────────────────────────────────────────
    "auth_failure":         {"category": "AUTHENTICATION", "severity": "HIGH",     "keywords": ["auth","authentication","credential","logon failure","4625"]},
    "token_expired":        {"category": "AUTHENTICATION", "severity": "MEDIUM",   "keywords": ["token","expired","oauth","kerberos","4768"]},
    "account_locked":       {"category": "AUTHENTICATION", "severity": "HIGH",     "keywords": ["locked","lockout","4740","account disabled"]},
    "cert_expired":         {"category": "AUTHENTICATION", "severity": "HIGH",     "keywords": ["certificate","cert","expired cert","ssl","tls"]},
    # ── Hardware ──────────────────────────────────────────────────────────────
    "cpu_overheating":      {"category": "HARDWARE",       "severity": "CRITICAL", "keywords": ["overheat","thermal","temperature","throttl"]},
    "disk_crash":           {"category": "HARDWARE",       "severity": "CRITICAL", "keywords": ["disk crash","bad sector","smart","7","51"]},
    "ram_fault":            {"category": "HARDWARE",       "severity": "CRITICAL", "keywords": ["ram fault","memory error","ecc","parity"]},
    "driver_conflict":      {"category": "DRIVER",         "severity": "HIGH",     "keywords": ["driver","bsod","bugcheck","kernel panic","1001","219"]},
    # ── Configuration ─────────────────────────────────────────────────────────
    "config_corrupt":       {"category": "CONFIGURATION",  "severity": "HIGH",     "keywords": ["config","corrupt","corrupt config","invalid config"]},
    "registry_damage":      {"category": "CONFIGURATION",  "severity": "HIGH",     "keywords": ["registry","hive","reg key","damaged"]},
    "permission_error":     {"category": "SEMANTIC",       "severity": "MEDIUM",   "keywords": ["permission","access denied","acl","4656","icacls"]},
    # ── Dependency ────────────────────────────────────────────────────────────
    "api_down":             {"category": "DEPENDENCY",     "severity": "HIGH",     "keywords": ["api","endpoint","503","502","504","down"]},
    "cloud_failure":        {"category": "DEPENDENCY",     "severity": "HIGH",     "keywords": ["cloud","provider","region","outage"]},
    "third_party_timeout":  {"category": "DEPENDENCY",     "severity": "MEDIUM",   "keywords": ["third party","external","timeout","upstream"]},
    "library_conflict":     {"category": "DEPENDENCY",     "severity": "MEDIUM",   "keywords": ["library","dll","version conflict","incompatible"]},
}


# ══════════════════════════════════════════════════════════════════════════════
# LAYER 0 — ACTUATION DRIVER  (real OS commands)
# ══════════════════════════════════════════════════════════════════════════════

class ActuationDriver:
    """
    Executes real system commands for each remediation action.
    All commands run with a timeout; stdout/stderr are captured and returned.
    Dry-run mode logs commands without executing (safe for testing).
    """

    def __init__(self, dry_run: bool = True):
        self.dry_run  = dry_run
        self._history: List[Dict] = []

    def run(self, cmd: List[str], timeout: int = 30) -> Tuple[bool, str]:
        entry = {"cmd": cmd, "timestamp": time.time(), "dry_run": self.dry_run}
        if self.dry_run:
            log.info("DRY-RUN cmd: %s", " ".join(cmd))
            entry["result"] = "dry_run"
            self._history.append(entry)
            return True, "dry_run"
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=timeout, check=False,
            )
            ok  = result.returncode == 0
            out = (result.stdout + result.stderr).strip()
            entry.update({"returncode": result.returncode, "output": out[:500]})
            log.info("cmd %s → rc=%d", cmd[0], result.returncode)
            self._history.append(entry)
            return ok, out
        except subprocess.TimeoutExpired:
            log.warning("cmd timeout: %s", cmd[0])
            entry["result"] = "timeout"
            self._history.append(entry)
            return False, "timeout"
        except Exception as exc:
            log.warning("cmd error: %s — %s", cmd[0], exc)
            entry["result"] = str(exc)
            self._history.append(entry)
            return False, str(exc)

    # ── Windows command library ───────────────────────────────────────────────

    def win_restart_service(self, name: str) -> Tuple[bool, str]:
        ok, out = self.run(["net", "stop", name])
        ok2, out2 = self.run(["net", "start", name])
        return ok2, out2

    def win_kill_process(self, image: str) -> Tuple[bool, str]:
        return self.run(["taskkill", "/IM", image, "/F"])

    def win_kill_pid(self, pid: int) -> Tuple[bool, str]:
        return self.run(["taskkill", "/PID", str(pid), "/F"])

    def win_flush_dns(self) -> Tuple[bool, str]:
        return self.run(["ipconfig", "/flushdns"])

    def win_reset_network(self) -> Tuple[bool, str]:
        self.run(["netsh", "winsock", "reset"])
        return self.run(["netsh", "int", "ip", "reset"])

    def win_restart_wifi(self) -> Tuple[bool, str]:
        self.run(["netsh", "interface", "set", "interface", "Wi-Fi", "disable"])
        return self.run(["netsh", "interface", "set", "interface", "Wi-Fi", "enable"])

    def win_set_dns(self, dns: str = "1.1.1.1") -> Tuple[bool, str]:
        return self.run(["netsh", "interface", "ip", "set", "dns",
                         "name=Wi-Fi", "source=static", f"addr={dns}"])

    def win_release_renew_ip(self) -> Tuple[bool, str]:
        self.run(["ipconfig", "/release"])
        return self.run(["ipconfig", "/renew"])

    def win_reset_permissions(self, path: str) -> Tuple[bool, str]:
        return self.run(["icacls", path, "/reset", "/T", "/C"])

    def win_take_ownership(self, path: str) -> Tuple[bool, str]:
        return self.run(["takeown", "/F", path, "/R", "/D", "Y"])

    def win_firewall_block_ip(self, ip: str, name: str = "BlockThreat") -> Tuple[bool, str]:
        return self.run(["netsh", "advfirewall", "firewall", "add", "rule",
                         f"name={name}", "dir=out", "action=block", f"remoteip={ip}"])

    def win_firewall_allow_port(self, port: int, proto: str = "TCP") -> Tuple[bool, str]:
        return self.run(["netsh", "advfirewall", "firewall", "add", "rule",
                         f"name=AllowPort{port}", f"dir=in", "action=allow",
                         f"protocol={proto}", f"localport={port}"])

    def win_enable_account(self, username: str) -> Tuple[bool, str]:
        return self.run(["net", "user", username, "/active:yes"])

    def win_disable_account(self, username: str) -> Tuple[bool, str]:
        return self.run(["net", "user", username, "/active:no"])

    def win_free_disk(self, path: str = "%temp%") -> Tuple[bool, str]:
        return self.run(["del", "/S", "/Q", path], timeout=60)

    def win_chkdsk(self, drive: str = "C:") -> Tuple[bool, str]:
        return self.run(["chkdsk", drive, "/f"], timeout=300)

    def win_sfc_scan(self) -> Tuple[bool, str]:
        return self.run(["sfc", "/scannow"], timeout=600)

    def win_update_driver(self, inf_path: str) -> Tuple[bool, str]:
        return self.run(["pnputil", "/add-driver", inf_path, "/install"])

    def win_rollback_driver(self, device_id: str) -> Tuple[bool, str]:
        return self.run(["pnputil", "/revert-driver", device_id])

    def win_defender_scan(self) -> Tuple[bool, str]:
        return self.run(["powershell", "-Command",
                         "Start-MpScan -ScanType QuickScan"], timeout=300)

    def win_update_defender(self) -> Tuple[bool, str]:
        return self.run(["powershell", "-Command", "Update-MpSignature"])

    def win_set_process_priority(self, image: str, priority: str = "below normal") -> Tuple[bool, str]:
        return self.run(["wmic", "process", "where", f"name={image}",
                         "CALL", "setpriority", priority])

    # ── Linux command library ─────────────────────────────────────────────────

    def lx_restart_service(self, name: str) -> Tuple[bool, str]:
        return self.run(["systemctl", "restart", name])

    def lx_kill_process(self, name: str) -> Tuple[bool, str]:
        return self.run(["pkill", "-9", "-f", name])

    def lx_kill_pid(self, pid: int) -> Tuple[bool, str]:
        return self.run(["kill", "-9", str(pid)])

    def lx_flush_dns(self) -> Tuple[bool, str]:
        return self.run(["systemd-resolve", "--flush-caches"])

    def lx_reset_network(self, iface: str = "eth0") -> Tuple[bool, str]:
        self.run(["ip", "link", "set", iface, "down"])
        return self.run(["ip", "link", "set", iface, "up"])

    def lx_block_ip(self, ip: str) -> Tuple[bool, str]:
        return self.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])

    def lx_allow_port(self, port: int, proto: str = "tcp") -> Tuple[bool, str]:
        return self.run(["iptables", "-A", "INPUT", "-p", proto,
                         "--dport", str(port), "-j", "ACCEPT"])

    def lx_reset_permissions(self, path: str) -> Tuple[bool, str]:
        return self.run(["chmod", "-R", "755", path])

    def lx_free_disk(self, path: str = "/tmp") -> Tuple[bool, str]:
        return self.run(["find", path, "-maxdepth", "1",
                         "-mtime", "+7", "-delete"], timeout=60)

    def lx_fsck(self, device: str = "/dev/sda1") -> Tuple[bool, str]:
        return self.run(["fsck", "-y", device], timeout=300)

    def lx_clear_cache(self) -> Tuple[bool, str]:
        return self.run(["bash", "-c", "sync; echo 3 > /proc/sys/vm/drop_caches"])

    def lx_limit_cpu(self, pid: int, quota: int = 50) -> Tuple[bool, str]:
        return self.run(["cpulimit", "-p", str(pid), "-l", str(quota)])

    def lx_defender_scan(self) -> Tuple[bool, str]:
        return self.run(["clamscan", "-r", "--quiet", "/tmp"], timeout=120)

    def lx_rotate_logs(self) -> Tuple[bool, str]:
        return self.run(["logrotate", "-f", "/etc/logrotate.conf"])

    # ── Dispatcher ────────────────────────────────────────────────────────────

    def restart_service(self, name: str) -> Tuple[bool, str]:
        return self.win_restart_service(name) if OS == "Windows" \
               else self.lx_restart_service(name)

    def kill_process(self, name: str) -> Tuple[bool, str]:
        return self.win_kill_process(name) if OS == "Windows" \
               else self.lx_kill_process(name)

    def block_ip(self, ip: str) -> Tuple[bool, str]:
        return self.win_firewall_block_ip(ip) if OS == "Windows" \
               else self.lx_block_ip(ip)

    def reset_permissions(self, path: str) -> Tuple[bool, str]:
        return self.win_reset_permissions(path) if OS == "Windows" \
               else self.lx_reset_permissions(path)

    def free_disk(self) -> Tuple[bool, str]:
        return self.win_free_disk() if OS == "Windows" \
               else self.lx_free_disk()

    def clear_cache(self) -> Tuple[bool, str]:
        if OS == "Windows":
            return self.run(["powershell", "-Command",
                             "Clear-RecycleBin -Force -ErrorAction SilentlyContinue"])
        return self.lx_clear_cache()

    def defender_scan(self) -> Tuple[bool, str]:
        return self.win_defender_scan() if OS == "Windows" \
               else self.lx_defender_scan()

    def flush_dns(self) -> Tuple[bool, str]:
        return self.win_flush_dns() if OS == "Windows" \
               else self.lx_flush_dns()


# ══════════════════════════════════════════════════════════════════════════════
# LAYER 1 — POLICY ENGINE
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class HealingPolicy:
    max_automated_attempts:              int   = 3
    max_cost_per_fix:                    float = 0.6
    max_impact_per_fix:                  float = 0.4
    human_approval_required_above_impact:float = 0.7
    cooldown_seconds:                    float = 30.0
    escalate_on_categories: List[IncidentCategory] = field(
        default_factory=lambda: [IncidentCategory.SECURITY, IncidentCategory.MALWARE]
    )
    quarantine_limits: Dict[str, Any] = field(default_factory=lambda: {
        "cpu_cap": 0.1, "memory_cap_mb": 128, "network": "blocked"})
    throttle_limits: Dict[str, Any]   = field(default_factory=lambda: {
        "request_rate": 0.2, "io_cap": 0.3})
    global_limits: Dict[str, Any]     = field(default_factory=lambda: {
        "mode": "read_only", "feature_set": "minimal"})
    # adaptive thresholds — adjusted by AdaptivePolicyManager
    auto_retry_on_categories: List[IncidentCategory] = field(
        default_factory=lambda: [
            IncidentCategory.TRANSIENT, IncidentCategory.NETWORK,
            IncidentCategory.SERVICE
        ]
    )

    def gate(self, fix: RemediationFix) -> Tuple[bool, str]:
        if fix.cost > self.max_cost_per_fix:
            return False, f"cost {fix.cost:.2f} > cap {self.max_cost_per_fix:.2f}"
        if fix.impact > self.max_impact_per_fix:
            return False, f"impact {fix.impact:.2f} > cap {self.max_impact_per_fix:.2f}"
        return True, "ok"

    def requires_human_approval(self, fix: RemediationFix) -> bool:
        return fix.impact > self.human_approval_required_above_impact


# ══════════════════════════════════════════════════════════════════════════════
# LAYER 2 — SYSTEM METRICS COLLECTOR  (real psutil + manual signals)
# ══════════════════════════════════════════════════════════════════════════════

class SystemMetricsCollector:
    """
    Collects real runtime health signals via psutil where available,
    falls back to manual signal injection for test environments.
    Rolling time-window with threshold helpers.
    """

    def __init__(self, window_seconds: int = 60, poll_interval: float = 5.0):
        self._window        = window_seconds
        self._poll_interval = poll_interval
        self._signals: List[HealthSignal] = []
        self._thresholds = {
            "cpu_percent":         85.0,
            "memory_percent":      90.0,
            "disk_percent":        90.0,
            "net_errors_per_sec":  50.0,
        }

    def poll(self) -> List[HealthSignal]:
        """Collect real system metrics. No-op if psutil unavailable."""
        collected = []
        if not PSUTIL_AVAILABLE:
            return collected
        try:
            now = time.time()
            collected += [
                HealthSignal("system", "cpu_percent",    psutil.cpu_percent(interval=1), "%"),
                HealthSignal("system", "memory_percent", psutil.virtual_memory().percent,  "%"),
                HealthSignal("system", "disk_percent",   psutil.disk_usage("/").percent,   "%"),
            ]
            net = psutil.net_io_counters()
            collected.append(HealthSignal(
                "system", "net_errors", float(net.errin + net.errout), "count"))
            for s in collected:
                self._signals.append(s)
        except Exception as exc:
            log.debug("metrics poll error: %s", exc)
        self._prune()
        return collected

    def ingest(self, signal: HealthSignal) -> None:
        self._signals.append(signal)
        self._prune()

    def _prune(self) -> None:
        cutoff = time.time() - self._window
        self._signals = [s for s in self._signals if s.timestamp >= cutoff]

    def latest(self, metric: str) -> Optional[float]:
        matches = [s for s in self._signals if s.metric == metric]
        return max(matches, key=lambda s: s.timestamp).value if matches else None

    def above_threshold(self, metric: str) -> bool:
        val = self.latest(metric)
        thr = self._thresholds.get(metric)
        return val is not None and thr is not None and val > thr

    def anomalies(self) -> List[str]:
        """Return list of metrics currently above threshold."""
        return [m for m in self._thresholds if self.above_threshold(m)]

    def summary(self) -> Dict[str, Any]:
        return {
            "psutil": PSUTIL_AVAILABLE,
            "signals": len(self._signals),
            "anomalies": self.anomalies(),
            "cpu":    self.latest("cpu_percent"),
            "memory": self.latest("memory_percent"),
            "disk":   self.latest("disk_percent"),
        }


# ══════════════════════════════════════════════════════════════════════════════
# LAYER 3 — EVENT CORRELATOR
# ══════════════════════════════════════════════════════════════════════════════

class EventCorrelator:
    """
    Groups events by causality fingerprint to avoid treating one underlying
    failure as multiple separate incidents. Deduplicates within cooldown.
    """

    def __init__(self, dedup_window_seconds: float = 60.0):
        self._window    = dedup_window_seconds
        self._seen: Dict[str, float] = {}            # fingerprint → last seen
        self._groups: Dict[str, List[str]] = defaultdict(list)  # corr_id → [event_ids]

    def fingerprint(self, event: Event) -> str:
        """Stable hash of (actor, error_type, message[:80])."""
        raw = f"{event.actor}|{event.error_type}|{event.message[:80]}"
        return hashlib.md5(raw.encode()).hexdigest()[:12]

    def correlate(self, event: Event) -> Tuple[str, bool]:
        """
        Returns (correlation_id, is_duplicate).
        Duplicate = same fingerprint seen within dedup window.
        """
        fp = self.fingerprint(event)
        event.fingerprint = fp
        now   = time.time()
        last  = self._seen.get(fp, 0)
        is_dup = (now - last) < self._window

        if not is_dup:
            self._seen[fp] = now
            corr_id = str(uuid.uuid4())[:8]
        else:
            corr_id = next(
                (cid for cid, fps in self._groups.items() if fp in fps),
                str(uuid.uuid4())[:8],
            )

        self._groups[corr_id].append(fp)
        return corr_id, is_dup


# ══════════════════════════════════════════════════════════════════════════════
# LAYER 4 — ANOMALY CLASSIFIER  (extended with catalog)
# ══════════════════════════════════════════════════════════════════════════════

class AnomalyClassifier:
    """
    Two-pass classifier:
      Pass 1 — check ExceptionCatalog keyword match (structured)
      Pass 2 — rule predicates (same as v0.1, extended)
    """

    _CAT_MAP = {
        "NETWORK":        IncidentCategory.NETWORK,
        "SERVICE":        IncidentCategory.SERVICE,
        "RESOURCE":       IncidentCategory.RESOURCE,
        "SECURITY":       IncidentCategory.SECURITY,
        "MALWARE":        IncidentCategory.MALWARE,
        "AUTHENTICATION": IncidentCategory.AUTHENTICATION,
        "HARDWARE":       IncidentCategory.HARDWARE,
        "DRIVER":         IncidentCategory.DRIVER,
        "CONFIGURATION":  IncidentCategory.CONFIGURATION,
        "DEPENDENCY":     IncidentCategory.DEPENDENCY,
        "SEMANTIC":       IncidentCategory.SEMANTIC,
        "TRANSIENT":      IncidentCategory.TRANSIENT,
        "SYSTEMIC":       IncidentCategory.SYSTEMIC,
    }
    _SEV_MAP = {
        "LOW": Severity.LOW, "MEDIUM": Severity.MEDIUM,
        "HIGH": Severity.HIGH, "CRITICAL": Severity.CRITICAL,
    }

    def __init__(self):
        self._rules: List[Tuple] = []
        self._register_defaults()

    def _register_defaults(self) -> None:
        R = self.add_rule
        # transient
        R(lambda e: "timeout"    in e.message.lower(), IncidentCategory.TRANSIENT,   Severity.MEDIUM)
        R(lambda e: "retry"      in e.message.lower(), IncidentCategory.TRANSIENT,   Severity.LOW)
        R(lambda e: "flap"       in e.message.lower(), IncidentCategory.TRANSIENT,   Severity.MEDIUM)
        # resource
        R(lambda e: "oom"        in e.message.lower(), IncidentCategory.RESOURCE,    Severity.CRITICAL)
        R(lambda e: "memory"     in e.message.lower(), IncidentCategory.RESOURCE,    Severity.HIGH)
        R(lambda e: "cpu"        in e.message.lower(), IncidentCategory.RESOURCE,    Severity.HIGH)
        R(lambda e: "disk"       in e.message.lower(), IncidentCategory.RESOURCE,    Severity.HIGH)
        R(lambda e: "quota"      in e.message.lower(), IncidentCategory.RESOURCE,    Severity.MEDIUM)
        # semantic / config
        R(lambda e: "config"     in e.message.lower(), IncidentCategory.CONFIGURATION, Severity.MEDIUM)
        R(lambda e: "corrupt"    in e.message.lower(), IncidentCategory.CONFIGURATION, Severity.HIGH)
        R(lambda e: "permission" in e.message.lower(), IncidentCategory.SEMANTIC,    Severity.MEDIUM)
        R(lambda e: "mismatch"   in e.message.lower(), IncidentCategory.SEMANTIC,    Severity.MEDIUM)
        # systemic
        R(lambda e: "crash"      in e.message.lower(), IncidentCategory.SYSTEMIC,    Severity.HIGH)
        R(lambda e: "deadlock"   in e.message.lower(), IncidentCategory.SYSTEMIC,    Severity.HIGH)
        R(lambda e: "cascade"    in e.message.lower(), IncidentCategory.SYSTEMIC,    Severity.CRITICAL)
        # network
        R(lambda e: "dns"        in e.message.lower(), IncidentCategory.NETWORK,     Severity.HIGH)
        R(lambda e: "gateway"    in e.message.lower(), IncidentCategory.NETWORK,     Severity.HIGH)
        R(lambda e: "wifi"       in e.message.lower(), IncidentCategory.NETWORK,     Severity.HIGH)
        R(lambda e: "connection" in e.message.lower(), IncidentCategory.NETWORK,     Severity.MEDIUM)
        R(lambda e: "packet"     in e.message.lower(), IncidentCategory.NETWORK,     Severity.MEDIUM)
        # service
        R(lambda e: "service"    in e.message.lower(), IncidentCategory.SERVICE,     Severity.HIGH)
        R(lambda e: "hung"       in e.message.lower(), IncidentCategory.SERVICE,     Severity.HIGH)
        R(lambda e: "restart flood" in e.message.lower(), IncidentCategory.SERVICE,  Severity.HIGH)
        # security / malware
        R(lambda e: "malware"    in e.message.lower(), IncidentCategory.MALWARE,     Severity.CRITICAL)
        R(lambda e: "ransomware" in e.message.lower(), IncidentCategory.MALWARE,     Severity.CRITICAL)
        R(lambda e: "rootkit"    in e.message.lower(), IncidentCategory.MALWARE,     Severity.CRITICAL)
        R(lambda e: "auth"       in e.message.lower(), IncidentCategory.AUTHENTICATION, Severity.CRITICAL)
        R(lambda e: "unauthori"  in e.message.lower(), IncidentCategory.SECURITY,    Severity.CRITICAL)
        # hardware / driver
        R(lambda e: "overheating" in e.message.lower(), IncidentCategory.HARDWARE,   Severity.CRITICAL)
        R(lambda e: "driver"     in e.message.lower(), IncidentCategory.DRIVER,      Severity.HIGH)
        R(lambda e: "bsod"       in e.message.lower(), IncidentCategory.DRIVER,      Severity.CRITICAL)
        # dependency
        R(lambda e: "api"        in e.message.lower(), IncidentCategory.DEPENDENCY,  Severity.HIGH)
        R(lambda e: "endpoint"   in e.message.lower(), IncidentCategory.DEPENDENCY,  Severity.MEDIUM)
        R(lambda e: "upstream"   in e.message.lower(), IncidentCategory.DEPENDENCY,  Severity.MEDIUM)
        R(lambda e: "library"    in e.message.lower(), IncidentCategory.DEPENDENCY,  Severity.MEDIUM)

    def add_rule(self, predicate, category, severity) -> None:
        self._rules.append((predicate, category, severity))

    def classify(self, event: Event) -> Tuple[IncidentCategory, Severity]:
        msg = event.message.lower()
        # Pass 1 — catalog keyword match
        for exc_name, exc_def in EXCEPTION_CATALOG.items():
            if any(kw in msg for kw in exc_def["keywords"]):
                cat = self._CAT_MAP.get(exc_def["category"], IncidentCategory.UNKNOWN)
                sev = self._SEV_MAP.get(exc_def["severity"],  Severity.MEDIUM)
                return cat, sev
        # Pass 2 — rule predicates
        for pred, cat, sev in self._rules:
            try:
                if pred(event):
                    return cat, sev
            except Exception:
                pass
        return IncidentCategory.UNKNOWN, Severity.MEDIUM


# ══════════════════════════════════════════════════════════════════════════════
# LAYER 5 — INCIDENT TRIAGE
# ══════════════════════════════════════════════════════════════════════════════

class IncidentTriage:
    _SCOPE_MAP = {
        IncidentCategory.TRANSIENT:      Scope.MODULE,
        IncidentCategory.RESOURCE:       Scope.SUBSYSTEM,
        IncidentCategory.SEMANTIC:       Scope.MODULE,
        IncidentCategory.SYSTEMIC:       Scope.SUBSYSTEM,
        IncidentCategory.SECURITY:       Scope.GLOBAL,
        IncidentCategory.MALWARE:        Scope.GLOBAL,
        IncidentCategory.NETWORK:        Scope.SUBSYSTEM,
        IncidentCategory.SERVICE:        Scope.MODULE,
        IncidentCategory.HARDWARE:       Scope.GLOBAL,
        IncidentCategory.AUTHENTICATION: Scope.SUBSYSTEM,
        IncidentCategory.DEPENDENCY:     Scope.SUBSYSTEM,
        IncidentCategory.CONFIGURATION:  Scope.MODULE,
        IncidentCategory.DRIVER:         Scope.GLOBAL,
        IncidentCategory.UNKNOWN:        Scope.MODULE,
    }
    _CAT_WEIGHT = {
        IncidentCategory.TRANSIENT:      0.1,
        IncidentCategory.RESOURCE:       0.3,
        IncidentCategory.SEMANTIC:       0.2,
        IncidentCategory.SYSTEMIC:       0.4,
        IncidentCategory.SECURITY:       0.5,
        IncidentCategory.MALWARE:        0.6,
        IncidentCategory.NETWORK:        0.25,
        IncidentCategory.SERVICE:        0.3,
        IncidentCategory.HARDWARE:       0.5,
        IncidentCategory.AUTHENTICATION: 0.4,
        IncidentCategory.DEPENDENCY:     0.25,
        IncidentCategory.CONFIGURATION:  0.2,
        IncidentCategory.DRIVER:         0.4,
        IncidentCategory.UNKNOWN:        0.2,
    }

    def triage(self, event: Event, category: IncidentCategory,
               severity: Severity, correlation_id: str = "") -> Incident:
        scope      = self._SCOPE_MAP.get(category, Scope.MODULE)
        risk_score = min(1.0, severity.value / 4.0 + self._CAT_WEIGHT.get(category, 0.2))
        return Incident(
            event=event, category=category, scope=scope,
            severity=severity, risk_score=risk_score,
            correlation_id=correlation_id,
        )


# ══════════════════════════════════════════════════════════════════════════════
# LAYER 6 — LEARNING STORE
# ══════════════════════════════════════════════════════════════════════════════

class LearningStore:
    """
    Stores failure signatures, remediation outcomes, and failure frequency.
    Used to:
      • select best fix (highest success_rate for this fingerprint)
      • feed AdaptivePolicyManager with oscillation / success signals
      • surface best_matches for operator escalation
    """

    def __init__(self, max_records: int = 10_000):
        self._records: deque    = deque(maxlen=max_records)
        self._fingerprint_stats: Dict[str, Dict] = {}  # fp → {success, failure, last_fix}

    def record(self, incident: Incident, fix_name: str, outcome: str,
               detail: str = "") -> None:
        fp = incident.event.fingerprint
        lr = LearningRecord(
            fingerprint=fp, category=incident.category,
            fix_name=fix_name, outcome=outcome, detail=detail,
        )
        self._records.append(lr)
        stats = self._fingerprint_stats.setdefault(fp, {"success": 0, "failure": 0, "last_fix": ""})
        if outcome == "success":
            stats["success"] += 1
        else:
            stats["failure"] += 1
        stats["last_fix"] = fix_name
        log.debug("learning | fp=%.8s  fix=%-25s  outcome=%s", fp, fix_name, outcome)

    def best_fix_for(self, fingerprint: str) -> Optional[str]:
        """Return name of fix with best track record for this fingerprint."""
        stats = self._fingerprint_stats.get(fingerprint)
        if not stats:
            return None
        return stats["last_fix"] if stats["success"] > 0 else None

    def best_matches(self, category: IncidentCategory, top_n: int = 3) -> List[str]:
        """Top N fix names by success rate for this category."""
        cat_records = [r for r in self._records if r.category == category]
        score: Dict[str, int] = defaultdict(int)
        for r in cat_records:
            if r.outcome == "success":
                score[r.fix_name] += 1
        return sorted(score, key=score.get, reverse=True)[:top_n]

    def failure_frequency(self, fingerprint: str) -> int:
        stats = self._fingerprint_stats.get(fingerprint)
        return stats["failure"] if stats else 0

    def summary(self) -> Dict[str, Any]:
        return {
            "total_records":   len(self._records),
            "unique_patterns": len(self._fingerprint_stats),
        }


# ══════════════════════════════════════════════════════════════════════════════
# LAYER 7 — ADAPTIVE POLICY MANAGER
# ══════════════════════════════════════════════════════════════════════════════

class AdaptivePolicyManager:
    """
    AdjustPoliciesIfNeeded from the pseudocode.
    Watches success/failure patterns across categories and tightens or
    relaxes policy caps to avoid oscillation and unnecessary throttles.
    """

    def __init__(self, policy: HealingPolicy):
        self._policy   = policy
        self._category_stats: Dict[str, Dict] = {}

    def update(self, category: IncidentCategory, success: bool) -> None:
        name  = category.name
        stats = self._category_stats.setdefault(name, {"success": 0, "failure": 0, "adjustments": 0})
        if success:
            stats["success"] += 1
            # if we've been succeeding, relax cooldown slightly
            if stats["success"] % 5 == 0:
                self._policy.cooldown_seconds = max(10.0, self._policy.cooldown_seconds * 0.9)
                stats["adjustments"] += 1
                log.info("adaptive policy | cooldown relaxed → %.1fs", self._policy.cooldown_seconds)
        else:
            stats["failure"] += 1
            # if we're repeatedly failing same category, tighten cooldown to prevent flap
            if stats["failure"] >= 3 and stats["failure"] % 3 == 0:
                self._policy.cooldown_seconds = min(300.0, self._policy.cooldown_seconds * 1.5)
                stats["adjustments"] += 1
                log.warning("adaptive policy | repeated failures in %s → cooldown %.1fs",
                            name, self._policy.cooldown_seconds)
            # if security/malware failures spike, lower human-approval threshold
            if category in (IncidentCategory.SECURITY, IncidentCategory.MALWARE):
                self._policy.human_approval_required_above_impact = max(
                    0.3, self._policy.human_approval_required_above_impact - 0.05)
                log.warning("adaptive policy | security failure → approval threshold %.2f",
                            self._policy.human_approval_required_above_impact)

    def summary(self) -> Dict[str, Any]:
        return dict(self._category_stats)


# ══════════════════════════════════════════════════════════════════════════════
# LAYER 8 — CONTAINMENT ENGINE
# ══════════════════════════════════════════════════════════════════════════════

class ContainmentEngine:
    def __init__(self, policy: HealingPolicy, actuator: ActuationDriver):
        self._policy    = policy
        self._actuator  = actuator
        self._contained: Dict[str, Dict] = {}

    def contain(self, incident: Incident) -> Dict[str, Any]:
        if incident.scope == Scope.MODULE:
            result = self._quarantine_module(incident.event.actor)
        elif incident.scope == Scope.SUBSYSTEM:
            result = self._throttle_subsystem(incident.event.subsystem)
        else:
            result = self._enter_degraded_mode()
        log.info("containment | scope=%-10s  actor=%-20s  action=%s",
                 incident.scope.name, incident.event.actor, result.get("action"))
        return result

    def _quarantine_module(self, actor: str) -> Dict:
        limits = self._policy.quarantine_limits.copy()
        self._contained[actor] = {"type": "quarantine", **limits}
        # Real enforcement: try to lower process priority
        if actor and actor != "":
            self._actuator.set_process_priority(actor) if OS == "Windows" else None
        return {"action": "quarantine", "actor": actor, "limits": limits}

    def _throttle_subsystem(self, subsystem: str) -> Dict:
        limits = self._policy.throttle_limits.copy()
        self._contained[subsystem] = {"type": "throttle", **limits}
        return {"action": "throttle", "subsystem": subsystem, "limits": limits}

    def _enter_degraded_mode(self) -> Dict:
        limits = self._policy.global_limits.copy()
        return {"action": "degraded_mode", "limits": limits}

    def release(self, actor: str) -> None:
        self._contained.pop(actor, None)
        log.info("containment released | actor=%s", actor)

    def is_contained(self, actor: str) -> bool:
        return actor in self._contained

    # Windows-only helper exposed to actuator dispatch above
    def set_process_priority(self, image: str):
        self._actuator.win_set_process_priority(image + ".exe", "below normal")


# ══════════════════════════════════════════════════════════════════════════════
# LAYER 9 — SNAPSHOT MANAGER
# ══════════════════════════════════════════════════════════════════════════════

class SnapshotManager:
    def __init__(self):
        self._store: Dict[str, Snapshot] = {}

    def capture(self, incident_id: str, state: Dict[str, Any],
                tag: str = "") -> Snapshot:
        # Enrich state with real system metrics if available
        if PSUTIL_AVAILABLE:
            try:
                state["_sys"] = {
                    "cpu":    psutil.cpu_percent(),
                    "mem":    psutil.virtual_memory().percent,
                    "disk":   psutil.disk_usage("/").percent,
                    "uptime": time.time() - psutil.boot_time(),
                }
            except Exception:
                pass
        snap = Snapshot(incident_id=incident_id, tag=tag, state=state)
        snap.sign()
        self._store[snap.id] = snap
        log.info("snapshot | id=%.8s  tag=%-12s  checksum=%.10s",
                 snap.id, tag, snap.checksum)
        return snap

    def get(self, sid: str) -> Optional[Snapshot]:
        return self._store.get(sid)

    def verify(self, sid: str) -> bool:
        snap = self._store.get(sid)
        return snap.verify() if snap else False

    def list_for(self, incident_id: str) -> List[Snapshot]:
        return [s for s in self._store.values() if s.incident_id == incident_id]


# ══════════════════════════════════════════════════════════════════════════════
# LAYER 10 — WEB SEARCH FALLBACK  (stub, real impl in v0.3)
# ══════════════════════════════════════════════════════════════════════════════

class WebSearchFallback:
    """
    When no primitive matches an UNKNOWN incident, query the web for solutions.
    v0.2: builds the query and returns it; HTTP call is stubbed.
    v0.3: real DuckDuckGo/Bing API call + answer extraction.
    """

    def search(self, incident: Incident) -> Optional[str]:
        query = (
            f"fix {incident.event.error_type or incident.category.name} "
            f"{incident.event.message[:60]}"
        )
        log.info("web_search | query: %s", query)
        # v0.2 stub — returns the constructed query for logging/audit
        # v0.3 will perform: urllib.request.urlopen(search_url)
        return f"[WEB_SEARCH_STUB] query={query!r}"


# ══════════════════════════════════════════════════════════════════════════════
# LAYER 11 — AI SERVICE CONSULTANT  (Claude API)
# ══════════════════════════════════════════════════════════════════════════════

class AIServiceConsultant:
    """
    For truly novel or UNKNOWN incidents, asks the Claude API to diagnose
    and suggest a remediation recipe.

    v0.2: builds the prompt + makes the API call; parses suggested fix name.
    Requires ANTHROPIC_API_KEY env var.  Gracefully skips if not set.
    """

    API_URL = "https://api.anthropic.com/v1/messages"
    MODEL   = "claude-sonnet-4-20250514"

    def __init__(self):
        self._api_key = os.environ.get("ANTHROPIC_API_KEY", "")
        self._enabled = bool(self._api_key)
        if not self._enabled:
            log.info("AIServiceConsultant | ANTHROPIC_API_KEY not set — disabled")

    def consult(self, incident: Incident, audit_trail: List[str]) -> Optional[str]:
        """
        Ask Claude to diagnose the incident and return a suggested fix name.
        Returns None if disabled or request fails.
        """
        if not self._enabled or not NETWORK_AVAILABLE:
            return None

        prompt = (
            f"You are a systems reliability engineer.\n"
            f"Incident category: {incident.category.name}\n"
            f"Severity: {incident.severity.name}\n"
            f"Actor: {incident.event.actor}\n"
            f"Error message: {incident.event.message}\n"
            f"Recent audit events: {audit_trail[-5:]}\n\n"
            f"Respond with ONLY a JSON object: "
            f"{{\"fix_name\": \"<short_snake_case_name>\", "
            f"\"steps\": [\"<step1>\", \"<step2>\"], "
            f"\"explanation\": \"<1 sentence>\"}}"
        )

        payload = json.dumps({
            "model": self.MODEL,
            "max_tokens": 512,
            "messages": [{"role": "user", "content": prompt}],
        }).encode()

        try:
            req = urllib.request.Request(
                self.API_URL,
                data    = payload,
                headers = {
                    "Content-Type":      "application/json",
                    "x-api-key":         self._api_key,
                    "anthropic-version": "2023-06-01",
                },
                method = "POST",
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                data    = json.loads(resp.read())
                content = data.get("content", [{}])[0].get("text", "")
                parsed  = json.loads(content)
                fix_name = parsed.get("fix_name", "ai_suggested_fix")
                steps    = parsed.get("steps", [])
                log.info("AIConsultant | suggested fix=%s  steps=%d", fix_name, len(steps))
                return fix_name
        except Exception as exc:
            log.warning("AIConsultant | request failed: %s", exc)
            return None


# ══════════════════════════════════════════════════════════════════════════════
# LAYER 12 — TELEMETRY OUTLET
# ══════════════════════════════════════════════════════════════════════════════

class TelemetryOutlet:
    """
    Publishes healing events to external observers.
    v0.2: in-memory queue + optional HTTP POST hook.
    v0.3: Prometheus metrics, structured logging (JSON), OpenTelemetry spans.
    """

    def __init__(self, webhook_url: str = ""):
        self._queue: deque      = deque(maxlen=1000)
        self._webhook_url       = webhook_url
        self._counters: Dict[str, int] = defaultdict(int)

    def publish(self, event_type: str, incident_id: str,
                success: bool, detail: Dict = None) -> None:
        record = {
            "event_type":  event_type,
            "incident_id": incident_id,
            "success":     success,
            "detail":      detail or {},
            "timestamp":   time.time(),
        }
        self._queue.append(record)
        self._counters[event_type] += 1
        log.debug("telemetry | %s  success=%s", event_type, success)

        if self._webhook_url and NETWORK_AVAILABLE:
            self._post(record)

    def _post(self, record: Dict) -> None:
        try:
            payload = json.dumps(record).encode()
            req = urllib.request.Request(
                self._webhook_url, data=payload,
                headers={"Content-Type": "application/json"}, method="POST")
            urllib.request.urlopen(req, timeout=5)
        except Exception as exc:
            log.debug("telemetry post failed: %s", exc)

    def metrics(self) -> Dict[str, int]:
        return dict(self._counters)

    def drain(self, limit: int = 100) -> List[Dict]:
        result = []
        for _ in range(min(limit, len(self._queue))):
            result.append(self._queue.popleft())
        return result


# ══════════════════════════════════════════════════════════════════════════════
# LAYER 13 — REMEDIATION ENGINE  (with real actuation)
# ══════════════════════════════════════════════════════════════════════════════

class RemediationEngine:
    def __init__(self, policy: HealingPolicy, primitives: "PrimitivesRegistry"):
        self._policy     = policy
        self._primitives = primitives

    def select(self, incident: Incident,
               learning: Optional[LearningStore] = None) -> Optional["RemediationFix"]:
        # Check if learning store has a proven fix for this exact fingerprint
        if learning:
            best = learning.best_fix_for(incident.event.fingerprint)
            if best:
                fix = self._primitives.by_name(best)
                if fix:
                    log.info("remediation | learning-guided fix: %s", best)
                    return fix
        return self._primitives.best_match(incident.category)

    def apply_staged(self, fix: RemediationFix, incident: Incident) -> Tuple[bool, str]:
        allowed, reason = self._policy.gate(fix)
        if not allowed:
            return False, f"policy blocked — {reason}"
        if self._policy.requires_human_approval(fix):
            return False, f"human approval required (impact={fix.impact:.2f})"
        log.info("applying fix | %-30s  category=%s", fix.name, incident.category.name)
        try:
            for step in fix.steps:
                step(incident)
            fix.success_count += 1
            return True, "all steps completed"
        except Exception as exc:
            fix.failure_count += 1
            return False, f"step raised: {exc}"

    def rollback(self, snapshot: Snapshot) -> bool:
        if not snapshot.verify():
            log.error("rollback ABORTED — snapshot tampered | id=%.8s", snapshot.id)
            return False
        log.info("rollback | id=%.8s  tag=%s", snapshot.id, snapshot.tag)
        # v0.2 hook: real rollback applies snapshot.state back to live system
        # e.g. restore config files, restart previous service version
        return True


# ══════════════════════════════════════════════════════════════════════════════
# LAYER 14 — VERIFIER HARNESS
# ══════════════════════════════════════════════════════════════════════════════

class VerifierHarness:
    def run(self, fix: RemediationFix, incident: Incident) -> Tuple[bool, str]:
        log.info("verifier | %-30s  simulating...", fix.name)
        sim = Incident(
            event=incident.event, category=incident.category,
            scope=incident.scope, severity=incident.severity,
            risk_score=incident.risk_score,
        )
        try:
            for step in fix.steps:
                step(sim)
            return True, "simulation passed"
        except Exception as exc:
            return False, f"simulation failed — {exc}"


# ══════════════════════════════════════════════════════════════════════════════
# LAYER 15 — AUDIT TRAIL
# ══════════════════════════════════════════════════════════════════════════════

class AuditTrail:
    def __init__(self):
        self._log: List[AuditEntry] = []

    def append(self, event_type: str, incident_id: str = "",
               snapshot_id: str = "", detail: Optional[Dict] = None,
               actor: str = "healing_core") -> AuditEntry:
        entry = AuditEntry(event_type=event_type, incident_id=incident_id,
                           snapshot_id=snapshot_id, actor=actor, detail=detail or {})
        entry.sign()
        self._log.append(entry)
        log.info("audit | %-35s  incident=…%.6s  chk=%.10s",
                 event_type, incident_id, entry.checksum)
        return entry

    def query(self, incident_id: str = "", event_type: str = "") -> List[AuditEntry]:
        results = self._log
        if incident_id: results = [e for e in results if e.incident_id == incident_id]
        if event_type:  results = [e for e in results if e.event_type  == event_type]
        return results

    def verify_all(self) -> Tuple[bool, List[str]]:
        bad = [e.id for e in self._log if not e.verify()]
        return len(bad) == 0, bad

    def event_types(self) -> List[str]:
        return [e.event_type for e in self._log]

    def export(self) -> List[Dict]:
        return [{k: v for k, v in vars(e).items()} for e in self._log]


# ══════════════════════════════════════════════════════════════════════════════
# LAYER 16 — PRIMITIVES REGISTRY  (real OS commands via ActuationDriver)
# ══════════════════════════════════════════════════════════════════════════════

class PrimitivesRegistry:
    def __init__(self, actuator: ActuationDriver):
        self._store: Dict[str, List[RemediationFix]] = {}
        self._a = actuator
        self._seed_builtins()

    def _seed_builtins(self) -> None:
        a = self._a
        R = self.register

        # ── TRANSIENT ────────────────────────────────────────────────────────
        R(RemediationFix(
            name="retry_with_backoff", category=IncidentCategory.TRANSIENT,
            description="Log retry; real backoff handled by caller.",
            steps=[lambda inc: log.info("[fix] backoff retry → %s", inc.event.actor)],
            cost=0.05, impact=0.05))
        R(RemediationFix(
            name="restart_module", category=IncidentCategory.TRANSIENT,
            description="Restart the affected module/process.",
            steps=[lambda inc: a.restart_service(inc.event.actor)],
            cost=0.15, impact=0.15))

        # ── RESOURCE ─────────────────────────────────────────────────────────
        R(RemediationFix(
            name="free_disk_space", category=IncidentCategory.RESOURCE,
            description="Delete temp files to reclaim disk space.",
            steps=[lambda inc: a.free_disk()],
            cost=0.2, impact=0.1))
        R(RemediationFix(
            name="clear_memory_cache", category=IncidentCategory.RESOURCE,
            description="Drop OS page/slab cache to reclaim memory.",
            steps=[lambda inc: a.clear_cache()],
            cost=0.1, impact=0.2))
        R(RemediationFix(
            name="kill_high_cpu_process", category=IncidentCategory.RESOURCE,
            description="Terminate the actor process consuming excessive CPU.",
            steps=[lambda inc: a.kill_process(inc.event.actor)],
            cost=0.3, impact=0.35))

        # ── NETWORK ──────────────────────────────────────────────────────────
        R(RemediationFix(
            name="flush_dns_cache", category=IncidentCategory.NETWORK,
            description="Flush the OS DNS resolver cache.",
            steps=[lambda inc: a.flush_dns()],
            cost=0.05, impact=0.05))
        R(RemediationFix(
            name="reset_network_stack", category=IncidentCategory.NETWORK,
            description="Run winsock/ip reset or interface restart.",
            steps=[
                lambda inc: a.win_reset_network() if OS == "Windows"
                            else a.lx_reset_network(),
            ],
            cost=0.2, impact=0.3))
        R(RemediationFix(
            name="restart_wifi_adapter", category=IncidentCategory.NETWORK,
            description="Disable then re-enable the Wi-Fi adapter.",
            steps=[
                lambda inc: a.win_restart_wifi() if OS == "Windows"
                            else a.lx_reset_network("wlan0"),
            ],
            cost=0.15, impact=0.2))
        R(RemediationFix(
            name="set_alternate_dns", category=IncidentCategory.NETWORK,
            description="Switch to Cloudflare DNS 1.1.1.1.",
            steps=[lambda inc: a.win_set_dns("1.1.1.1") if OS == "Windows" else None],
            cost=0.05, impact=0.05))
        R(RemediationFix(
            name="release_renew_ip", category=IncidentCategory.NETWORK,
            description="Release and renew DHCP lease.",
            steps=[
                lambda inc: a.win_release_renew_ip() if OS == "Windows"
                            else a.lx_reset_network(),
            ],
            cost=0.1, impact=0.1))

        # ── SERVICE ──────────────────────────────────────────────────────────
        R(RemediationFix(
            name="restart_service", category=IncidentCategory.SERVICE,
            description="Graceful stop + start of the affected service.",
            steps=[lambda inc: a.restart_service(inc.event.actor)],
            cost=0.2, impact=0.25))
        R(RemediationFix(
            name="kill_hung_process", category=IncidentCategory.SERVICE,
            description="Force-kill the hung process and let supervisor restart it.",
            steps=[lambda inc: a.kill_process(inc.event.actor)],
            cost=0.3, impact=0.3))

        # ── AUTHENTICATION ────────────────────────────────────────────────────
        R(RemediationFix(
            name="enable_locked_account", category=IncidentCategory.AUTHENTICATION,
            description="Re-enable a locked/disabled service account.",
            steps=[
                lambda inc: a.win_enable_account(inc.event.actor) if OS == "Windows"
                            else log.info("[fix] enable account → %s", inc.event.actor),
            ],
            cost=0.15, impact=0.2))
        R(RemediationFix(
            name="flush_kerberos_tickets", category=IncidentCategory.AUTHENTICATION,
            description="Purge expired Kerberos tickets.",
            steps=[
                lambda inc: a.run(["klist", "purge"]) if OS == "Windows"
                            else a.run(["kdestroy"]),
            ],
            cost=0.05, impact=0.05))

        # ── CONFIGURATION ─────────────────────────────────────────────────────
        R(RemediationFix(
            name="reset_permissions", category=IncidentCategory.CONFIGURATION,
            description="Reset ACLs on affected resource to policy defaults.",
            steps=[lambda inc: a.reset_permissions(inc.event.actor or "/tmp")],
            cost=0.1, impact=0.1))
        R(RemediationFix(
            name="reload_config", category=IncidentCategory.CONFIGURATION,
            description="Reload service config from last-known-good state.",
            steps=[lambda inc: a.restart_service(inc.event.actor)],
            cost=0.1, impact=0.1))

        # ── MALWARE ───────────────────────────────────────────────────────────
        R(RemediationFix(
            name="run_av_scan", category=IncidentCategory.MALWARE,
            description="Run quick antivirus scan (Defender/ClamAV).",
            steps=[lambda inc: a.defender_scan()],
            cost=0.3, impact=0.2))
        R(RemediationFix(
            name="block_malicious_ip", category=IncidentCategory.MALWARE,
            description="Block outbound connections to known malicious IP.",
            steps=[
                lambda inc: a.block_ip(inc.event.raw.get("ip", "0.0.0.0"))
                if isinstance(inc.event.raw, dict) else
                log.info("[fix] block_ip stub → no IP in event"),
            ],
            cost=0.15, impact=0.2))
        R(RemediationFix(
            name="isolate_and_alert", category=IncidentCategory.SECURITY,
            description="Disable network adapter + alert operator.",
            steps=[
                lambda inc: log.critical("SECURITY ISOLATION → %s", inc.event.actor),
            ],
            cost=0.4, impact=0.7))

        # ── HARDWARE ──────────────────────────────────────────────────────────
        R(RemediationFix(
            name="run_disk_check", category=IncidentCategory.HARDWARE,
            description="Schedule chkdsk / fsck on the next boot.",
            steps=[
                lambda inc: a.win_chkdsk() if OS == "Windows"
                            else a.lx_fsck(),
            ],
            cost=0.3, impact=0.4))
        R(RemediationFix(
            name="reduce_thermal_load", category=IncidentCategory.HARDWARE,
            description="Lower CPU process priority to reduce heat.",
            steps=[
                lambda inc: a.win_set_process_priority(inc.event.actor + ".exe")
                if OS == "Windows" else a.lx_limit_cpu(0, 50),
            ],
            cost=0.1, impact=0.2))

        # ── DRIVER ────────────────────────────────────────────────────────────
        R(RemediationFix(
            name="disable_problematic_driver", category=IncidentCategory.DRIVER,
            description="Disable the faulting device/driver.",
            steps=[
                lambda inc: a.run(
                    ["powershell", "-Command",
                     f"Disable-PnpDevice -InstanceId '{inc.event.actor}' -Confirm:$false"])
                if OS == "Windows" else
                a.run(["modprobe", "-r", inc.event.actor]),
            ],
            cost=0.3, impact=0.4))
        R(RemediationFix(
            name="rollback_driver", category=IncidentCategory.DRIVER,
            description="Roll back to previous stable driver version.",
            steps=[
                lambda inc: a.win_rollback_driver(inc.event.actor)
                if OS == "Windows" else log.info("[fix] driver rollback stub"),
            ],
            cost=0.35, impact=0.4))

        # ── DEPENDENCY ────────────────────────────────────────────────────────
        R(RemediationFix(
            name="retry_endpoint", category=IncidentCategory.DEPENDENCY,
            description="Retry the failing external endpoint with backoff.",
            steps=[lambda inc: log.info("[fix] retry endpoint → %s", inc.event.actor)],
            cost=0.05, impact=0.05))
        R(RemediationFix(
            name="switch_fallback_endpoint", category=IncidentCategory.DEPENDENCY,
            description="Update config to use backup endpoint.",
            steps=[lambda inc: log.info("[fix] switch endpoint → %s", inc.event.actor)],
            cost=0.15, impact=0.1))

        # ── SEMANTIC ─────────────────────────────────────────────────────────
        R(RemediationFix(
            name="repair_filesystem", category=IncidentCategory.SEMANTIC,
            description="Run sfc /scannow or fsck to repair file system.",
            steps=[
                lambda inc: a.win_sfc_scan() if OS == "Windows"
                            else a.lx_fsck(),
            ],
            cost=0.4, impact=0.3))

        # ── SYSTEMIC ─────────────────────────────────────────────────────────
        R(RemediationFix(
            name="rotate_logs", category=IncidentCategory.SYSTEMIC,
            description="Force log rotation to reclaim space and clear locks.",
            steps=[
                lambda inc: a.lx_rotate_logs() if OS == "Linux"
                            else log.info("[fix] rotate logs stub (Windows)"),
            ],
            cost=0.1, impact=0.05))

        # ── UNKNOWN (last resort) ─────────────────────────────────────────────
        R(RemediationFix(
            name="graceful_restart", category=IncidentCategory.UNKNOWN,
            description="Generic restart of the affected actor.",
            steps=[lambda inc: a.restart_service(inc.event.actor)],
            cost=0.2, impact=0.2))

    # ── public API ────────────────────────────────────────────────────────────

    def register(self, fix: RemediationFix) -> None:
        bucket = self._store.setdefault(fix.category.name, [])
        bucket.append(fix)

    def by_name(self, name: str) -> Optional[RemediationFix]:
        for bucket in self._store.values():
            for fix in bucket:
                if fix.name == name:
                    return fix
        return None

    def best_match(self, category: IncidentCategory) -> Optional[RemediationFix]:
        candidates = self._store.get(category.name, [])
        if not candidates:
            # fallback to UNKNOWN
            candidates = self._store.get(IncidentCategory.UNKNOWN.name, [])
        if not candidates:
            return None
        # prefer highest success_rate, break ties by lowest cost+impact
        return max(candidates, key=lambda f: (f.success_rate, -(f.cost + f.impact)))

    def promote(self, fix: RemediationFix, outcome: str) -> None:
        fix.promoted_at = time.time()
        log.info("primitive promoted | %-28s  outcome=%s  sr=%.2f",
                 fix.name, outcome, fix.success_rate)

    def list_all(self) -> Dict[str, List[str]]:
        return {cat: [f.name for f in fixes] for cat, fixes in self._store.items()}


# ══════════════════════════════════════════════════════════════════════════════
# LAYER 17 — ESCALATION MANAGER
# ══════════════════════════════════════════════════════════════════════════════

class EscalationManager:
    def __init__(self, ai_consultant: Optional[AIServiceConsultant] = None):
        self._ai = ai_consultant

    def escalate(self, incident: Incident, snapshot: Snapshot,
                 candidates: List[RemediationFix], audit_trail: AuditTrail) -> None:
        log.warning(
            "⚠  ESCALATION ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            "   incident  : %.8s\n   category  : %s\n"
            "   severity  : %s\n   risk      : %.2f\n"
            "   snapshot  : %.8s (%s)\n   candidates: %s\n"
            "   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
            incident.id, incident.category.name, incident.severity.name,
            incident.risk_score, snapshot.id, snapshot.tag,
            [f.name for f in candidates],
        )
        # Attempt AI consultation for UNKNOWN incidents
        if incident.category == IncidentCategory.UNKNOWN and self._ai:
            event_types = audit_trail.event_types()[-10:]
            fix_name = self._ai.consult(incident, event_types)
            if fix_name:
                log.info("AI consultant suggested: %s", fix_name)


# ══════════════════════════════════════════════════════════════════════════════
# HEALING CORE  — main orchestrator
# ══════════════════════════════════════════════════════════════════════════════

class HealingCore:
    """
    v0.2 orchestrator — all 17 layers wired together.

    Pipeline on fault ingestion:
      correlate → classify → triage → snapshot →
      [security fast-path] → contain → remediate loop
      (learning-guided → verifier → policy-gate → actuate)
      → audit → telemetry → adaptive policy update → promote/escalate
    """

    def __init__(
        self,
        policy:      Optional[HealingPolicy]   = None,
        dry_run:     bool                       = True,
        webhook_url: str                        = "",
    ):
        self.policy      = policy or HealingPolicy()
        self.actuator    = ActuationDriver(dry_run=dry_run)
        self.primitives  = PrimitivesRegistry(self.actuator)
        self.metrics     = SystemMetricsCollector()
        self.correlator  = EventCorrelator()
        self.classifier  = AnomalyClassifier()
        self.triage_eng  = IncidentTriage()
        self.containment = ContainmentEngine(self.policy, self.actuator)
        self.snapshots   = SnapshotManager()
        self.remediation = RemediationEngine(self.policy, self.primitives)
        self.verifier    = VerifierHarness()
        self.audit       = AuditTrail()
        self.learning    = LearningStore()
        self.telemetry   = TelemetryOutlet(webhook_url)
        self.web_search  = WebSearchFallback()
        self.ai_consul   = AIServiceConsultant()
        self.adaptive    = AdaptivePolicyManager(self.policy)
        self.escalation  = EscalationManager(self.ai_consul)
        self._cooldowns: Dict[str, float] = {}

    # ── public API ────────────────────────────────────────────────────────────

    def ingest(self, event: Event) -> Optional[Incident]:
        if event.is_health_signal:
            self.metrics.ingest(HealthSignal(
                source=event.actor, metric=event.message,
                value=float(event.raw) if isinstance(event.raw, (int, float)) else 0.0,
            ))
            return None
        # Poll real metrics opportunistically
        self.metrics.poll()
        return self._run_pipeline(event)

    def poll_metrics(self) -> Dict[str, Any]:
        """Manually trigger a system metrics poll and return summary."""
        self.metrics.poll()
        return self.metrics.summary()

    def audit_report(self) -> None:
        entries = self.audit.export()
        all_ok, bad = self.audit.verify_all()
        print(f"\n{'─'*72}")
        print(f"  AUDIT TRAIL  ({len(entries)} entries)  "
              f"integrity={'✓ OK' if all_ok else '✗ TAMPERED'}")
        print(f"{'─'*72}")
        for e in entries[-20:]:
            print(f"  {e['event_type']:38s}  "
                  f"incident=…{str(e['incident_id'])[-6:]}  "
                  f"chk={e['checksum'][:12]}")
        print(f"{'─'*72}")

    def primitives_report(self) -> None:
        print(f"\n{'─'*72}")
        print("  HEALING PRIMITIVES")
        print(f"{'─'*72}")
        for cat, names in self.primitives.list_all().items():
            print(f"  {cat:<22s}  →  {', '.join(names)}")
        print(f"{'─'*72}")

    def learning_report(self) -> None:
        print(f"\n{'─'*72}")
        print("  LEARNING STORE")
        print(f"{'─'*72}")
        s = self.learning.summary()
        print(f"  Total records  : {s['total_records']}")
        print(f"  Unique patterns: {s['unique_patterns']}")
        print(f"{'─'*72}")

    def telemetry_report(self) -> None:
        print(f"\n{'─'*72}")
        print("  TELEMETRY COUNTERS")
        print(f"{'─'*72}")
        for k, v in self.telemetry.metrics().items():
            print(f"  {k:<40s}  {v}")
        print(f"{'─'*72}")

    # ── internal pipeline ─────────────────────────────────────────────────────

    def _run_pipeline(self, event: Event) -> Incident:
        # ① Correlate
        corr_id, is_dup = self.correlator.correlate(event)
        if is_dup:
            log.info("event deduplicated | fp=%.8s  corr=%s", event.fingerprint, corr_id)

        # ② Classify
        category, severity = self.classifier.classify(event)

        # ③ Triage
        incident = self.triage_eng.triage(event, category, severity, corr_id)

        # ④ Snapshot
        snapshot = self.snapshots.capture(
            incident.id,
            {"event": vars(event), "actor": event.actor,
             "fingerprint": event.fingerprint},
            tag="pre-heal",
        )
        self.audit.append("fault_detected", incident.id, snapshot.id, {
            "category": category.name, "severity": severity.name,
            "risk": incident.risk_score, "fingerprint": event.fingerprint,
            "is_duplicate": is_dup, "correlation_id": corr_id,
        })

        # ⑤ Security fast-path
        if category in self.policy.escalate_on_categories:
            incident.status = RemediationStatus.ESCALATED
            self.audit.append("escalated_immediately", incident.id, snapshot.id,
                              {"reason": "security/malware category"})
            self.telemetry.publish("escalate", incident.id, False,
                                   {"category": category.name})
            candidates = self.primitives._store.get(category.name, [])
            self.escalation.escalate(incident, snapshot, candidates, self.audit)
            return incident

        # ⑥ Contain
        self.containment.contain(incident)

        # ⑦ Remediation loop
        self._remediate(incident, snapshot)

        # ⑧ Adaptive policy update
        success = incident.status == RemediationStatus.COMMITTED
        self.adaptive.update(category, success)

        return incident

    def _remediate(self, incident: Incident, snapshot: Snapshot) -> None:
        actor    = incident.event.actor
        last_attempt = self._cooldowns.get(actor, 0.0)
        if (time.time() - last_attempt) < self.policy.cooldown_seconds:
            log.info("cooldown active | actor=%s", actor)
            self.audit.append("cooldown_skipped", incident.id, snapshot.id, {"actor": actor})
            incident.status = RemediationStatus.ESCALATED
            return

        attempts = 0
        success  = False

        while attempts < self.policy.max_automated_attempts and not success:
            fix = self.remediation.select(incident, self.learning)

            if fix is None:
                # Try web search fallback for clues
                search_result = self.web_search.search(incident)
                self.audit.append("web_search_fallback", incident.id, snapshot.id,
                                  {"result": search_result})
                log.warning("no primitive | category=%s  web_search=%s",
                            incident.category.name, search_result)
                break

            # Verifier pass
            verified, v_detail = self.verifier.run(fix, incident)
            if not verified:
                log.warning("verifier rejected | fix=%s  reason=%s", fix.name, v_detail)
                self.learning.record(incident, fix.name, "verifier_failure", v_detail)
                self.audit.append("verifier_rejected", incident.id, snapshot.id,
                                  {"fix": fix.name, "detail": v_detail})
                attempts += 1
                continue

            # Apply staged
            applied, a_detail = self.remediation.apply_staged(fix, incident)
            if applied:
                success = True
                incident.status = RemediationStatus.COMMITTED
                self._cooldowns[actor] = time.time()
                self.containment.release(actor)
                self.learning.record(incident, fix.name, "success")
                self.primitives.promote(fix, "success")
                self.audit.append("heal_success", incident.id, snapshot.id,
                                  {"fix": fix.name, "attempts": attempts + 1})
                self.telemetry.publish("heal", incident.id, True,
                                       {"fix": fix.name, "attempts": attempts + 1})
                log.info("✓ healed | incident=%.8s  fix=%s", incident.id, fix.name)
            else:
                log.warning("fix failed | fix=%s  reason=%s", fix.name, a_detail)
                self.remediation.rollback(snapshot)
                incident.status = RemediationStatus.ROLLED_BACK
                self.learning.record(incident, fix.name, "failure", a_detail)
                self.audit.append("fix_failed_rolled_back", incident.id, snapshot.id,
                                  {"fix": fix.name, "reason": a_detail,
                                   "attempt": attempts + 1})
                self.telemetry.publish("heal", incident.id, False,
                                       {"fix": fix.name, "attempt": attempts + 1})
                attempts += 1

        if not success:
            incident.status = RemediationStatus.ESCALATED
            candidates = self.primitives._store.get(incident.category.name, [])
            self.audit.append("heal_failed_escalated", incident.id, snapshot.id,
                              {"attempts": attempts})
            self.telemetry.publish("escalate", incident.id, False, {"attempts": attempts})
            self.escalation.escalate(incident, snapshot, candidates, self.audit)


# ══════════════════════════════════════════════════════════════════════════════
# SMOKE TEST
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("\n" + "═" * 72)
    print("  HEALING CORE  v0.2  —  Smoke Test")
    print(f"  OS={OS}  psutil={PSUTIL_AVAILABLE}")
    print("═" * 72)

    core = HealingCore(dry_run=True)  # dry_run=False for live commands

    scenarios = [
        # ── Network
        Event(actor="wlan_adapter",   subsystem="network",  error_type="wifi_down",
              message="Wi-Fi interface down — no connection"),
        Event(actor="dns_resolver",   subsystem="network",  error_type="dns_failure",
              message="DNS resolution failed for api.example.com"),
        Event(actor="dhcp_client",    subsystem="network",  error_type="gateway_unreachable",
              message="Default gateway 192.168.1.1 unreachable after DHCP renewal"),
        # ── Service
        Event(actor="task_scheduler", subsystem="core",     error_type="service_crash",
              message="Task scheduler service crash loop — Event ID 7034"),
        Event(actor="db_service",     subsystem="data",     error_type="service_hung",
              message="Database service hung — deadlock detected in transaction log"),
        # ── Resource
        Event(actor="worker_pool",    subsystem="compute",  error_type="memory_depletion",
              message="OOM kill imminent — memory at 98%, process swapping"),
        Event(actor="log_writer",     subsystem="storage",  error_type="disk_full",
              message="Disk usage at 98%, quota exceeded on /var/log"),
        # ── Authentication
        Event(actor="auth_gateway",   subsystem="security", error_type="auth_failure",
              message="Authentication failure — account locked after 5 failed attempts"),
        # ── Security (fast-path escalation)
        Event(actor="svc_host",       subsystem="system",   error_type="malware_detected",
              message="Ransomware encryption activity detected on C:\\Data"),
        # ── Dependency
        Event(actor="payment_api",    subsystem="external", error_type="api_down",
              message="Payment API endpoint returned 503 — upstream provider down"),
        # ── Hardware
        Event(actor="cpu0",           subsystem="hardware", error_type="cpu_overheating",
              message="CPU thermal throttling triggered — temperature 95°C"),
        # ── Configuration
        Event(actor="nginx",          subsystem="web",      error_type="config_corrupt",
              message="Config file corrupt — nginx failed to reload"),
        # ── Unknown (triggers web search fallback)
        Event(actor="quantum_svc",    subsystem="exotic",   error_type="unknown_fault",
              message="Entanglement decoherence in qubit register — no known fix"),
        # ── Duplicate (same as first — should be deduplicated)
        Event(actor="wlan_adapter",   subsystem="network",  error_type="wifi_down",
              message="Wi-Fi interface down — no connection"),
    ]

    results = []
    for ev in scenarios:
        print(f"\n  ▶  [{ev.actor}]  {ev.message[:65]}")
        incident = core.ingest(ev)
        if incident:
            results.append(incident)
            print(
                f"     cat={incident.category.name:<18s}  "
                f"sev={incident.severity.name:<10s}  "
                f"risk={incident.risk_score:.2f}  "
                f"status={incident.status.name}"
            )

    # ── Reports ───────────────────────────────────────────────────────────────
    core.audit_report()
    core.primitives_report()
    core.learning_report()
    core.telemetry_report()

    # ── Metrics ───────────────────────────────────────────────────────────────
    print(f"\n{'─'*72}")
    print("  SYSTEM METRICS SNAPSHOT")
    print(f"{'─'*72}")
    m = core.poll_metrics()
    for k, v in m.items():
        print(f"  {k:<20s}  {v}")
    print(f"{'─'*72}")

    # ── Adaptive policy ───────────────────────────────────────────────────────
    print(f"\n{'─'*72}")
    print("  ADAPTIVE POLICY STATS")
    print(f"{'─'*72}")
    for cat, stats in core.adaptive.summary().items():
        print(f"  {cat:<22s}  {stats}")
    print(f"{'─'*72}")

    print(f"\n  cooldown (current): {core.policy.cooldown_seconds:.1f}s")
    print(f"  human-approval threshold: {core.policy.human_approval_required_above_impact:.2f}")
    print(f"\n  ✓ v0.2 smoke test complete — {len(results)} incidents processed")

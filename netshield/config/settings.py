"""Configuration loading and validation.

Thresholds live in a TOML file (stdlib ``tomllib``) so the project has no
YAML dependency and cannot fail to install on a student machine because a
C-extension wheel is missing.

Environment variables override only deployment concerns (bind address,
database path, queue size). Detection thresholds stay in the file so they
are auditable and can be changed without touching code.
"""

from __future__ import annotations

import ipaddress
import os
import tomllib
from dataclasses import dataclass, field, replace
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "config" / "thresholds.toml"
DEFAULT_DB_PATH = PROJECT_ROOT / "data" / "netshield.db"


class ConfigError(ValueError):
    """Raised when configuration is missing, malformed or unsafe."""


@dataclass(frozen=True)
class CaptureConfig:
    default_mode: str = "pcap"
    flush_interval_seconds: float = 1.0
    queue_maxsize: int = 10000


@dataclass(frozen=True)
class PortScanConfig:
    window_seconds: int = 60
    distinct_port_threshold: int = 15
    distinct_host_threshold: int = 20
    min_packets_per_target: int = 10


@dataclass(frozen=True)
class SuspiciousConfig:
    window_seconds: int = 60
    repeat_attempt_threshold: int = 15
    repeat_min_source_ports: int = 2
    conn_rate_threshold: int = 60
    conn_rate_multiplier: float = 3.0
    half_open_threshold: int = 20
    sensitive_ports: tuple[int, ...] = (21, 22, 23, 445, 1433, 3306, 3389, 5432, 5900, 6379, 9200, 27017)


@dataclass(frozen=True)
class SpikeConfig:
    window_seconds: int = 10
    spike_absolute_pps: int = 500
    spike_baseline_ratio: float = 3.0
    spike_min_pps: int = 100
    baseline_alpha: float = 0.3
    baseline_min_samples: int = 3


@dataclass(frozen=True)
class DedupConfig:
    suppression_seconds: int = 300


@dataclass(frozen=True)
class ScoringConfig:
    low_max: int = 34
    medium_max: int = 67


@dataclass(frozen=True)
class RetentionConfig:
    packet_days: int = 7
    prune_interval_seconds: int = 300


@dataclass(frozen=True)
class SafeResponseConfig:
    enabled: bool = False
    allow_firewall_changes: bool = False
    allowed_cidrs: tuple[str, ...] = ("127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")

    def is_lab_target(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in ipaddress.ip_network(cidr, strict=False) for cidr in self.allowed_cidrs)


@dataclass(frozen=True)
class Settings:
    capture: CaptureConfig = field(default_factory=CaptureConfig)
    port_scan: PortScanConfig = field(default_factory=PortScanConfig)
    suspicious: SuspiciousConfig = field(default_factory=SuspiciousConfig)
    spike: SpikeConfig = field(default_factory=SpikeConfig)
    dedup: DedupConfig = field(default_factory=DedupConfig)
    scoring: ScoringConfig = field(default_factory=ScoringConfig)
    retention: RetentionConfig = field(default_factory=RetentionConfig)
    safe_response: SafeResponseConfig = field(default_factory=SafeResponseConfig)
    db_path: Path = DEFAULT_DB_PATH
    host: str = "127.0.0.1"
    port: int = 5000
    debug: bool = False
    demo_duration: int = 45

    def with_overrides(self, **changes) -> "Settings":
        return replace(self, **changes)

    def to_public_dict(self) -> dict:
        """JSON-safe view for the Settings screen. Paths are not secrets,
        but the DB path is returned only as a display string."""
        return {
            "capture": {
                "default_mode": self.capture.default_mode,
                "flush_interval_seconds": self.capture.flush_interval_seconds,
                "queue_maxsize": self.capture.queue_maxsize,
            },
            "port_scan": {
                "window_seconds": self.port_scan.window_seconds,
                "distinct_port_threshold": self.port_scan.distinct_port_threshold,
                "distinct_host_threshold": self.port_scan.distinct_host_threshold,
                "min_packets_per_target": self.port_scan.min_packets_per_target,
            },
            "suspicious": {
                "window_seconds": self.suspicious.window_seconds,
                "repeat_attempt_threshold": self.suspicious.repeat_attempt_threshold,
                "repeat_min_source_ports": self.suspicious.repeat_min_source_ports,
                "conn_rate_threshold": self.suspicious.conn_rate_threshold,
                "conn_rate_multiplier": self.suspicious.conn_rate_multiplier,
                "half_open_threshold": self.suspicious.half_open_threshold,
                "sensitive_ports": list(self.suspicious.sensitive_ports),
            },
            "spike": {
                "window_seconds": self.spike.window_seconds,
                "spike_absolute_pps": self.spike.spike_absolute_pps,
                "spike_baseline_ratio": self.spike.spike_baseline_ratio,
                "spike_min_pps": self.spike.spike_min_pps,
                "baseline_alpha": self.spike.baseline_alpha,
                "baseline_min_samples": self.spike.baseline_min_samples,
            },
            "dedup": {"suppression_seconds": self.dedup.suppression_seconds},
            "scoring": {"low_max": self.scoring.low_max, "medium_max": self.scoring.medium_max},
            "retention": {
                "packet_days": self.retention.packet_days,
                "prune_interval_seconds": self.retention.prune_interval_seconds,
            },
            "safe_response": {
                "enabled": self.safe_response.enabled,
                "allow_firewall_changes": self.safe_response.allow_firewall_changes,
                "allowed_cidrs": list(self.safe_response.allowed_cidrs),
            },
            "db_path": str(self.db_path),
            "demo_duration": self.demo_duration,
        }


def load_env_file(path: Path | None = None) -> None:
    """Minimal .env loader. Avoids adding python-dotenv as a dependency.

    Existing environment variables win, so a real deployment can override
    the file without editing it.
    """
    env_path = path or PROJECT_ROOT / ".env"
    if not env_path.is_file():
        return
    for raw in env_path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


def _require(mapping: dict, key: str, kind, section: str):
    if key not in mapping:
        raise ConfigError(f"missing required key '{section}.{key}'")
    value = mapping[key]
    if not isinstance(value, kind) or isinstance(value, bool) and kind is int:
        raise ConfigError(f"'{section}.{key}' must be {getattr(kind, '__name__', kind)}")
    return value


def _positive(value, label: str):
    if value <= 0:
        raise ConfigError(f"'{label}' must be greater than zero (got {value})")
    return value


def parse_settings(raw: dict) -> Settings:
    try:
        capture_raw = raw.get("capture", {})
        ps_raw = raw["detection"]["port_scan"]
        sus_raw = raw["detection"]["suspicious"]
        spike_raw = raw["detection"]["spike"]
        dedup_raw = raw["detection"]["dedup"]
        scoring_raw = raw["scoring"]
        retention_raw = raw["retention"]
        response_raw = raw["safe_response"]
    except (KeyError, TypeError) as exc:
        raise ConfigError(f"configuration is missing a required section: {exc}") from exc

    mode = capture_raw.get("default_mode", "pcap")
    if mode not in ("pcap", "live", "demo"):
        raise ConfigError(f"capture.default_mode must be pcap/live/demo (got {mode!r})")

    port_scan = PortScanConfig(
        window_seconds=_positive(_require(ps_raw, "window_seconds", int, "detection.port_scan"), "port_scan.window_seconds"),
        distinct_port_threshold=_positive(_require(ps_raw, "distinct_port_threshold", int, "detection.port_scan"), "port_scan.distinct_port_threshold"),
        distinct_host_threshold=_positive(_require(ps_raw, "distinct_host_threshold", int, "detection.port_scan"), "port_scan.distinct_host_threshold"),
        min_packets_per_target=_positive(_require(ps_raw, "min_packets_per_target", int, "detection.port_scan"), "port_scan.min_packets_per_target"),
    )

    ports = sus_raw.get("sensitive_ports", [])
    if not isinstance(ports, list) or not all(isinstance(p, int) and 0 < p < 65536 for p in ports):
        raise ConfigError("detection.suspicious.sensitive_ports must be a list of valid port numbers")

    suspicious = SuspiciousConfig(
        window_seconds=_positive(_require(sus_raw, "window_seconds", int, "detection.suspicious"), "suspicious.window_seconds"),
        repeat_attempt_threshold=_positive(_require(sus_raw, "repeat_attempt_threshold", int, "detection.suspicious"), "suspicious.repeat_attempt_threshold"),
        repeat_min_source_ports=_positive(_require(sus_raw, "repeat_min_source_ports", int, "detection.suspicious"), "suspicious.repeat_min_source_ports"),
        conn_rate_threshold=_positive(_require(sus_raw, "conn_rate_threshold", int, "detection.suspicious"), "suspicious.conn_rate_threshold"),
        conn_rate_multiplier=float(_require(sus_raw, "conn_rate_multiplier", (int, float), "detection.suspicious")),
        half_open_threshold=_positive(_require(sus_raw, "half_open_threshold", int, "detection.suspicious"), "suspicious.half_open_threshold"),
        sensitive_ports=tuple(sorted(set(ports))),
    )

    alpha = float(_require(spike_raw, "baseline_alpha", (int, float), "detection.spike"))
    if not 0 < alpha <= 1:
        raise ConfigError("detection.spike.baseline_alpha must be in (0, 1]")

    spike = SpikeConfig(
        window_seconds=_positive(_require(spike_raw, "window_seconds", int, "detection.spike"), "spike.window_seconds"),
        spike_absolute_pps=_positive(_require(spike_raw, "spike_absolute_pps", int, "detection.spike"), "spike.spike_absolute_pps"),
        spike_baseline_ratio=float(_require(spike_raw, "spike_baseline_ratio", (int, float), "detection.spike")),
        spike_min_pps=_positive(_require(spike_raw, "spike_min_pps", int, "detection.spike"), "spike.spike_min_pps"),
        baseline_alpha=alpha,
        baseline_min_samples=_positive(_require(spike_raw, "baseline_min_samples", int, "detection.spike"), "spike.baseline_min_samples"),
    )

    dedup = DedupConfig(
        suppression_seconds=_positive(_require(dedup_raw, "suppression_seconds", int, "detection.dedup"), "dedup.suppression_seconds")
    )

    scoring = ScoringConfig(
        low_max=_positive(_require(scoring_raw, "low_max", int, "scoring"), "scoring.low_max"),
        medium_max=_positive(_require(scoring_raw, "medium_max", int, "scoring"), "scoring.medium_max"),
    )
    if scoring.low_max >= scoring.medium_max:
        raise ConfigError("scoring.low_max must be less than scoring.medium_max")

    retention = RetentionConfig(
        packet_days=_positive(_require(retention_raw, "packet_days", int, "retention"), "retention.packet_days"),
        prune_interval_seconds=_positive(_require(retention_raw, "prune_interval_seconds", int, "retention"), "retention.prune_interval_seconds"),
    )

    cidrs = response_raw.get("allowed_cidrs", [])
    if not isinstance(cidrs, list) or not cidrs:
        raise ConfigError("safe_response.allowed_cidrs must be a non-empty list")
    for cidr in cidrs:
        try:
            net = ipaddress.ip_network(str(cidr), strict=False)
        except ValueError as exc:
            raise ConfigError(f"invalid CIDR in safe_response.allowed_cidrs: {cidr!r}") from exc
        if net.prefixlen == 0:
            raise ConfigError("safe_response.allowed_cidrs must not contain 0.0.0.0/0 or ::/0")

    response = SafeResponseConfig(
        enabled=bool(response_raw.get("enabled", False)),
        allow_firewall_changes=bool(response_raw.get("allow_firewall_changes", False)),
        allowed_cidrs=tuple(str(c) for c in cidrs),
    )

    capture = CaptureConfig(
        default_mode=mode,
        flush_interval_seconds=float(capture_raw.get("flush_interval_seconds", 1.0)),
        queue_maxsize=_positive(int(capture_raw.get("queue_maxsize", 10000)), "capture.queue_maxsize"),
    )
    if capture.flush_interval_seconds <= 0:
        raise ConfigError("capture.flush_interval_seconds must be greater than zero")

    return Settings(
        capture=capture,
        port_scan=port_scan,
        suspicious=suspicious,
        spike=spike,
        dedup=dedup,
        scoring=scoring,
        retention=retention,
        safe_response=response,
    )


def load_settings(config_path: Path | str | None = None, env_path: Path | None = None) -> Settings:
    """Load TOML thresholds, then apply deployment overrides from the environment."""
    load_env_file(env_path)

    path = Path(config_path or os.environ.get("NETSHIELD_CONFIG") or DEFAULT_CONFIG_PATH)
    if not path.is_file():
        raise ConfigError(f"config file not found: {path}")
    try:
        with path.open("rb") as handle:
            raw = tomllib.load(handle)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"could not parse {path}: {exc}") from exc

    settings = parse_settings(raw)

    db_path = Path(os.environ.get("NETSHIELD_DB_PATH") or DEFAULT_DB_PATH)
    host = os.environ.get("NETSHIELD_HOST", "127.0.0.1")
    port = int(os.environ.get("NETSHIELD_PORT", "5000"))
    debug = os.environ.get("NETSHIELD_DEBUG", "false").strip().lower() in ("1", "true", "yes", "on")
    queue_maxsize = int(os.environ.get("NETSHIELD_QUEUE_MAXSIZE", settings.capture.queue_maxsize))
    demo_duration = int(os.environ.get("NETSHIELD_DEMO_DURATION", "45"))

    if not 1 <= port <= 65535:
        raise ConfigError(f"NETSHIELD_PORT out of range: {port}")

    return settings.with_overrides(
        db_path=db_path,
        host=host,
        port=port,
        debug=debug,
        demo_duration=demo_duration,
        capture=replace(settings.capture, queue_maxsize=queue_maxsize),
    )

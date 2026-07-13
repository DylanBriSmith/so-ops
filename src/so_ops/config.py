"""TOML config loader with typed dataclasses."""

from __future__ import annotations

import os
import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ESIndicesConfig:
    suricata: str = "logs-suricata.alerts-so"
    zeek: str = "logs-zeek-so"
    detections: str = "logs-detections.alerts-so"
    syslog: str = "logs-syslog-so"
    data_streams: str = "*so*"


@dataclass
class ESConfig:
    host: str
    user: str
    password: str
    verify_ssl: bool = False
    indices: ESIndicesConfig = field(default_factory=ESIndicesConfig)


@dataclass
class OllamaConfig:
    url: str
    model: str
    timeout: int = 600


@dataclass
class OpenRouterConfig:
    model: str
    api_key: str = ""
    base_url: str = "https://openrouter.ai/api/v1"


@dataclass
class PathsConfig:
    data_dir: Path

    def __post_init__(self):
        self.data_dir = Path(os.path.expanduser(str(self.data_dir)))


@dataclass
class TriageEscalation:
    minimum_medium: list[str] = field(default_factory=list)
    minimum_high: list[str] = field(default_factory=list)


@dataclass
class TriageAutoNoise:
    signatures: list[str] = field(default_factory=list)


@dataclass
class TriageConfig:
    lookback_hours: int = 24
    max_alerts_per_run: int = 500
    max_alerts_per_query: int = 2000
    max_batch_size: int = 50
    llm_temperature: float = 0.1
    scrub_ips: bool = True
    scrub_zones: bool = True
    auto_noise: TriageAutoNoise = field(default_factory=TriageAutoNoise)
    escalation: TriageEscalation = field(default_factory=TriageEscalation)


@dataclass
class HealthConfig:
    llm_temperature: float = 0.3


@dataclass
class VulnscanConfig:
    targets: list[str] = field(default_factory=lambda: ["192.168.0.0/24"])
    nmap_bin: str = "/usr/bin/nmap"
    nmap_args: str = "-sV --script=vulners -T4 --open"
    nuclei_docker: str = "projectdiscovery/nuclei:latest"
    nuclei_severity: str = "medium,high,critical"


@dataclass
class NetworkZone:
    cidr: str
    name: str
    description: str


@dataclass
class NetworkConfig:
    internal_prefixes: list[str] = field(default_factory=lambda: ["192.168.", "10.", "172.16."])
    zones: list[NetworkZone] = field(default_factory=list)


@dataclass
class CorrelateConfig:
    notify_on_triage_llm: bool = False


@dataclass
class Config:
    elasticsearch: ESConfig
    paths: PathsConfig
    notifications: dict[str, dict]
    triage: TriageConfig
    health: HealthConfig
    vulnscan: VulnscanConfig
    network: NetworkConfig
    correlate: CorrelateConfig = field(default_factory=CorrelateConfig)
    ollama: OllamaConfig | None = None
    openrouter: OpenRouterConfig | None = None
    llm_provider: str = "ollama"


def _find_config_file() -> Path:
    """Search for config.toml in standard locations."""
    env = os.environ.get("SO_OPS_CONFIG")
    if env:
        p = Path(env)
        if p.is_file():
            return p
        print(f"so-ops: $SO_OPS_CONFIG points to {p} which does not exist", file=sys.stderr)
        sys.exit(1)

    candidates = [
        Path.cwd() / "config.toml",
        Path.home() / ".config" / "so-ops" / "config.toml",
    ]
    for c in candidates:
        if c.is_file():
            return c

    print(
        "so-ops: config.toml not found. Searched:\n"
        "  $SO_OPS_CONFIG\n"
        f"  {candidates[0]}\n"
        f"  {candidates[1]}\n"
        "Run 'so-ops init' to create one, or copy config.example.toml.",
        file=sys.stderr,
    )
    sys.exit(1)


def load_config(path: Path | None = None) -> Config:
    """Load and validate config from TOML file."""
    if path is None:
        path = _find_config_file()

    with open(path, "rb") as f:
        raw = tomllib.load(f)

    try:
        es_raw = dict(raw["elasticsearch"])
        indices_raw = es_raw.pop("indices", {})
        # Allow env var to override password (keeps secrets out of config file)
        env_password = os.environ.get("SO_OPS_ES_PASSWORD")
        if env_password:
            es_raw["password"] = env_password
        es = ESConfig(**es_raw, indices=ESIndicesConfig(**indices_raw))

        ollama = OllamaConfig(**raw["ollama"]) if "ollama" in raw else None

        openrouter: OpenRouterConfig | None = None
        if "openrouter" in raw:
            or_raw = dict(raw["openrouter"])
            env_key = os.environ.get("SO_OPS_OR_API_KEY")
            if env_key:
                or_raw["api_key"] = env_key
            openrouter = OpenRouterConfig(**or_raw)

        llm_provider = str(raw.get("llm_provider", "ollama"))
        if llm_provider not in ("ollama", "openrouter"):
            print(
                f"so-ops: unknown llm_provider '{llm_provider}' in {path}; must be 'ollama' or 'openrouter'",
                file=sys.stderr,
            )
            sys.exit(1)
        if llm_provider == "ollama" and ollama is None:
            print(
                f"so-ops: llm_provider = 'ollama' but no [ollama] section in {path}",
                file=sys.stderr,
            )
            sys.exit(1)
        if llm_provider == "openrouter" and openrouter is None:
            print(
                f"so-ops: llm_provider = 'openrouter' but no [openrouter] section in {path}",
                file=sys.stderr,
            )
            sys.exit(1)

        paths_raw = dict(raw.get("paths", {"data_dir": "~/so-ops-data"}))
        if os.environ.get("SO_OPS_DATA_DIR"):
            paths_raw["data_dir"] = os.environ["SO_OPS_DATA_DIR"]
        paths = PathsConfig(**paths_raw)

        # Notifications: collect all [notifications.*] sections
        notifications: dict[str, dict] = {}
        notif_raw = raw.get("notifications", {})
        for provider_name, provider_cfg in notif_raw.items():
            if isinstance(provider_cfg, dict):
                notifications[provider_name] = dict(provider_cfg)

        # Backwards compat: old [email] and [sms] top-level sections
        if "email" in raw and "email" not in notifications:
            email_raw = dict(raw["email"])
            email_raw.setdefault("enabled", True)
            notifications["email"] = email_raw
        if "sms" in raw and "sms" not in notifications:
            sms_raw = dict(raw["sms"])
            notifications["sms"] = sms_raw

        triage_raw = dict(raw.get("triage", {}))
        auto_noise_raw = triage_raw.pop("auto_noise", {})
        escalation_raw = triage_raw.pop("escalation", {})
        triage = TriageConfig(
            **triage_raw,
            auto_noise=TriageAutoNoise(**auto_noise_raw),
            escalation=TriageEscalation(**escalation_raw),
        )

        health = HealthConfig(**raw.get("health", {}))
        vulnscan = VulnscanConfig(**raw.get("vulnscan", {}))

        # Network config with zones
        net_raw = dict(raw.get("network", {}))
        zones_raw = net_raw.pop("zones", [])
        zones = [NetworkZone(**z) for z in zones_raw]
        network = NetworkConfig(**net_raw, zones=zones)

        correlate = CorrelateConfig(**raw.get("correlate", {}))

    except (KeyError, TypeError) as exc:
        print(f"so-ops: config error in {path}: {exc}", file=sys.stderr)
        sys.exit(1)

    return Config(
        elasticsearch=es,
        paths=paths,
        notifications=notifications,
        triage=triage,
        health=health,
        vulnscan=vulnscan,
        network=network,
        correlate=correlate,
        ollama=ollama,
        openrouter=openrouter,
        llm_provider=llm_provider,
    )

"""Configuration and tool detection for PathFinder."""
from __future__ import annotations

import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ToolStatus:
    """Status of an external tool."""

    name: str
    available: bool
    path: str | None = None
    version: str | None = None


@dataclass
class Config:
    """PathFinder configuration."""

    groq_api_key: str | None = field(default_factory=lambda: os.getenv("GROQ_API_KEY"))
    anthropic_api_key: str | None = field(default_factory=lambda: os.getenv("ANTHROPIC_API_KEY"))
    model: str = "llama-3.3-70b-versatile"
    data_dir: Path = field(default_factory=lambda: Path.home() / ".pathfinder")
    nuclei_tags: list[str] = field(default_factory=lambda: ["misconfig", "exposure", "info", "config"])
    nuclei_severity: list[str] = field(default_factory=lambda: ["info", "low", "medium", "high", "critical"])

    def __post_init__(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)


def check_tool(name: str) -> ToolStatus:
    """Check if an external tool is available."""
    path = shutil.which(name)
    return ToolStatus(name=name, available=path is not None, path=path)


def check_all_tools() -> dict[str, ToolStatus]:
    """Check availability of all required external tools."""
    tools = ["subfinder", "httpx", "nuclei"]
    return {name: check_tool(name) for name in tools}


def get_config() -> Config:
    """Get the current configuration."""
    return Config()


SAFE_NUCLEI_TAGS = ["misconfig", "exposure", "info", "config", "tech", "token"]
UNSAFE_NUCLEI_TAGS = ["rce", "sqli", "xss", "ssrf", "lfi", "exploit", "cve"]

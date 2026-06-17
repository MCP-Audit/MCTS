"""MCTS (Model Context Threat Scanner) — security analysis for MCP servers."""

__version__ = "0.3.0"

from mcts.core.config import ScanConfig
from mcts.core.scanner import Scanner

__all__ = ["Scanner", "ScanConfig", "__version__"]

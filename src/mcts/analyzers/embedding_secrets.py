"""Optional semantic credential detection (MCTS-M-025 / MCTS-T-1022)."""

from __future__ import annotations

import logging
import os
import re
from typing import Any

from mcts.analyzers.base import BaseAnalyzer
from mcts.analyzers.data_leakage import SECRET_PATTERNS
from mcts.analyzers.finding_facts import build_analyzer_finding, build_skip_finding
from mcts.mcp.models import MCPServerInfo
from mcts.reporting.models import Finding, Severity, SourceLocation

logger = logging.getLogger(__name__)

CREDENTIAL_KEYWORDS: tuple[str, ...] = (
    "api_key",
    "api key",
    "secret_key",
    "secret key",
    "access_token",
    "auth_token",
    "password",
    "credential",
    "private_key",
    "bearer",
)

SEMANTIC_REFERENCE_PHRASES: tuple[str, ...] = (
    "store your openai api key here",
    "include the secret token",
    "paste your credentials",
    "send the password to",
    "load environment secrets",
)

_OBFUSCATED_SECRET = re.compile(r"(?i)(sk-[a-z0-9-]{10,}|ghp_[a-z0-9]{20,}|AKIA[0-9A-Z]{12,})")


class _EmbeddingModelState:
    model: Any | None = None
    unavailable: bool = False


_EMBEDDING_STATE = _EmbeddingModelState()


class EmbeddingSecretsAnalyzer(BaseAnalyzer):
    """Detect credential-like content using regex + optional semantic similarity."""

    name = "embedding_secrets"

    def __init__(self, semantic_secrets: bool = False, semantic_threshold: float = 0.75) -> None:
        self.semantic_secrets = semantic_secrets
        self.semantic_threshold = semantic_threshold

    def analyze(self, server: MCPServerInfo) -> list[Finding]:
        findings: list[Finding] = []
        if self.semantic_secrets:
            _load_embedding_model()
        for tool in server.tools:
            corpus = _tool_corpus(tool)
            if _regex_credential_hit(corpus):
                findings.append(_finding(tool, "regex_credential", 0.9))
                continue
            if self.semantic_secrets and _semantic_credential_hit(corpus, self.semantic_threshold):
                findings.append(_finding(tool, "semantic_credential", 0.8))
        if self.semantic_secrets and _EMBEDDING_STATE.unavailable:
            findings.append(
                build_skip_finding(
                    finding_id="embedding-secrets-semantic-skipped",
                    analyzer="embedding_secrets",
                    title="Semantic credential detection skipped",
                    description=("Semantic embedding model unavailable; only regex and phrase fallback ran."),
                    recommendation=(
                        "Install sentence-transformers and model weights, or disable semantic_secrets."
                    ),
                )
            )
        return findings


def _tool_corpus(tool: Any) -> str:
    parts = [tool.name, tool.description]
    if isinstance(tool.input_schema, dict):
        parts.append(str(tool.input_schema))
    if tool.handler_snippet:
        parts.append(tool.handler_snippet)
    return "\n".join(parts)


def _regex_credential_hit(text: str) -> bool:
    for _, pattern, _ in SECRET_PATTERNS:
        if pattern.search(text):
            return True
    if _OBFUSCATED_SECRET.search(text):
        return True
    lowered = text.lower()
    return sum(1 for keyword in CREDENTIAL_KEYWORDS if keyword in lowered) >= 2


def _semantic_credential_hit(text: str, threshold: float) -> bool:
    lowered = text.lower()
    if any(phrase in lowered for phrase in SEMANTIC_REFERENCE_PHRASES):
        return True

    model = _load_embedding_model()
    if model is None:
        return False

    try:
        import numpy as np
    except ImportError:
        return False

    try:
        text_embedding = model.encode([text], normalize_embeddings=True)[0]
        ref_embeddings = model.encode(list(SEMANTIC_REFERENCE_PHRASES), normalize_embeddings=True)
        similarities = np.dot(ref_embeddings, text_embedding)
        return bool((similarities >= threshold).any())
    except Exception as exc:
        logger.debug("Semantic credential embedding check skipped: %s", exc)
        return False


def _load_embedding_model() -> Any | None:
    """Load sentence-transformers model once; degrade gracefully when offline."""
    if _EMBEDDING_STATE.unavailable:
        return None
    if _EMBEDDING_STATE.model is not None:
        return _EMBEDDING_STATE.model

    try:
        from sentence_transformers import SentenceTransformer
    except ImportError:
        _EMBEDDING_STATE.unavailable = True
        return None

    local_only = os.getenv("HF_HUB_OFFLINE", "").lower() in {"1", "true", "yes"}
    try:
        _EMBEDDING_STATE.model = SentenceTransformer(
            "all-MiniLM-L6-v2",
            local_files_only=local_only,
        )
    except Exception as exc:
        logger.debug("Embedding model unavailable; using phrase fallback only: %s", exc)
        _EMBEDDING_STATE.unavailable = True
        return None

    return _EMBEDDING_STATE.model


def _finding(tool: Any, mode: str, confidence: float) -> Finding:
    return build_analyzer_finding(
        finding_id=f"embed-secret-{tool.name}",
        analyzer="embedding_secrets",
        title=f"Credential-like content in {tool.name}",
        description="Tool metadata resembles embedded secrets or credential harvesting instructions.",
        severity=Severity.HIGH,
        recommendation="Remove secrets from tool metadata; sanitize embeddings before storage (MCTS-M-025).",
        rule_id="RULE_EMBED_SECRET",
        match=mode,
        field="tool_metadata",
        tool=tool.name,
        location=SourceLocation(file=tool.source_file or "", line=tool.source_line),
        technique_id="MCTS-T-1022",
        confidence=confidence,
        extra_evidence={"mode": mode},
    )

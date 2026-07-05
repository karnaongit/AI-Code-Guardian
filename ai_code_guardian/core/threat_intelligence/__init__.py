"""
Threat Intelligence Engine
============================
Public API surface.

    from core.threat_intelligence import ThreatIntelligenceEngine

    engine = ThreatIntelligenceEngine()
    ctx = engine.lookup("log4j-core", "2.14.1")
    ctx = engine.lookup("spring-core", "5.3.18")
"""
from core.threat_intelligence.models import (
    CVERecord, ThreatContext, FeedMetadata, FeedSource
)
from core.threat_intelligence.collector import (
    ThreatIntelligenceCollector, NVDCollector, CISAKEVCollector, OSVCollector
)
from core.threat_intelligence.normalizer import CVENormalizer
from core.threat_intelligence.cache import ThreatIntelCache
from core.threat_intelligence.retriever import ThreatIntelRetriever
from typing import Optional


class ThreatIntelligenceEngine:
    """
    Top-level facade. Use this in Risk Scorer and Dashboard.
    Supports dependency injection for all sub-components.
    """

    def __init__(
        self,
        retriever: Optional[ThreatIntelRetriever] = None,
    ):
        self._retriever = retriever or ThreatIntelRetriever()

    def lookup(self, package: str, version: Optional[str] = None) -> ThreatContext:
        return self._retriever.lookup(package, version)

    def lookup_many(self, packages: list[tuple[str, Optional[str]]]) -> list[ThreatContext]:
        return self._retriever.lookup_many(packages)

    def feed_health(self) -> dict[str, bool]:
        return self._retriever._collector.health()

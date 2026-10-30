
from __future__ import annotations

from abc import ABC, abstractmethod

from security_engine.models import (
    CheckStatus,
    Coverage,
    Finding,
    Evidence,
    ScanInput,
)


class BaseDetector(ABC):
    """Common interface for all OWASP API security detectors."""

    owasp_id: str = ""
    category: str = ""

    @abstractmethod
    def run(
        self,
        scan_input: ScanInput,
        evidence: list[Evidence],
    ) -> tuple[Coverage, list[Finding]]:
        """Execute the detector and return coverage and findings."""
        raise NotImplementedError

    def inconclusive_coverage(self, reason: str) -> Coverage:
        return Coverage(
            owasp_id=self.owasp_id,
            category=self.category,
            status=CheckStatus.INCONCLUSIVE,
            reason=reason,
        )

    def not_applicable_coverage(self, reason: str) -> Coverage:
        return Coverage(
            owasp_id=self.owasp_id,
            category=self.category,
            status=CheckStatus.NOT_APPLICABLE,
            reason=reason,
        )

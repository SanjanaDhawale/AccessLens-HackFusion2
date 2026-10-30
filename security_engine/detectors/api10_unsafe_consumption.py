
from security_engine.models import CheckStatus, Coverage


class API10UnsafeConsumptionDetector:
    """Conservative assessment of unsafe API consumption."""

    CATEGORY = "Unsafe Consumption of APIs"
    OWASP_ID = "API10"

    def run(self, scan_input):
        findings = []
        evidence_items = []

        if not scan_input.authorization_context.authorization_confirmed:
            reason = (
                "Authorization was not confirmed. "
                "API10 assessment was skipped."
            )
        elif not scan_input.endpoints:
            reason = (
                "No API endpoints were provided for API10 assessment."
            )
        else:
            reason = (
                "Downstream API dependency information and response "
                "validation policies were not provided. No third-party "
                "requests or unsafe payload tests were performed."
            )

        coverage = Coverage(
            owasp_id=self.OWASP_ID,
            category=self.CATEGORY,
            status=CheckStatus.INCONCLUSIVE,
            reason=reason,
        )

        return coverage, findings, evidence_items

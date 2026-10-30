# Partial scan fixture – not currently supported

The current `ScanStatus` enum contains only `COMPLETED` and `FAILED`. The orchestrator runs the registered detectors and returns `COMPLETED` if the loop finishes; detector-level inability to reach a verdict is represented as `INCONCLUSIVE` in coverage.

Do not send a fabricated `PARTIAL` JSON response to the backend as if it were supported. If backend integration requires partial completion, Member 1 and Member 2 must agree on a revised status enum, failure isolation behavior, and persistence contract before implementing it.

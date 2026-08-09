"""Invariant tests for dual-key actuator fence."""
from __future__ import annotations

import time
import unittest

from src.dual_key_fence import (
    ActuatorMuscle,
    Decision,
    GrantIssuer,
    PolicyBrain,
    RefuseReason,
)


class DualKeyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.brain = PolicyBrain(
            "pol-test",
            lambda i: (i.get("ok") is True, "OK" if i.get("ok") else "NO"),
        )
        self.issuer = GrantIssuer(b"test-secret", ttl_seconds=30)
        self.muscle = ActuatorMuscle(self.issuer)
        self.inputs = {"ok": True, "n": 1}

    def test_happy_path_executes_once(self) -> None:
        d = self.brain.decide(self.inputs, now=1000.0)
        g = self.issuer.issue(d, now=1000.0)
        r1 = self.muscle.execute(d, g, self.inputs, lambda i: {"did": i["n"]}, now=1001.0)
        r2 = self.muscle.execute(d, g, self.inputs, lambda i: {"did": i["n"]}, now=1002.0)
        self.assertEqual(r1.outcome, "EXECUTED")
        self.assertEqual(r2.outcome, "REFUSED")
        self.assertEqual(r2.refuse_reason, RefuseReason.ALREADY_EXECUTED.value)

    def test_policy_refuse_blocks_grant(self) -> None:
        d = self.brain.decide({"ok": False}, now=1000.0)
        self.assertEqual(d.verdict, Decision.REFUSE)
        self.assertIsNone(self.issuer.issue(d, now=1000.0))

    def test_expired_grant_refuses(self) -> None:
        d = self.brain.decide(self.inputs, now=1000.0)
        g = self.issuer.issue(d, now=1000.0)
        r = self.muscle.execute(d, g, self.inputs, lambda i: 1, now=2000.0)
        self.assertEqual(r.outcome, "REFUSED")
        self.assertEqual(r.refuse_reason, RefuseReason.GRANT_EXPIRED.value)

    def test_input_tamper_refuses(self) -> None:
        d = self.brain.decide(self.inputs, now=1000.0)
        g = self.issuer.issue(d, now=1000.0)
        r = self.muscle.execute(d, g, {"ok": True, "n": 999}, lambda i: 1, now=1001.0)
        self.assertEqual(r.outcome, "REFUSED")
        self.assertEqual(r.refuse_reason, RefuseReason.DIGEST_MISMATCH.value)

    def test_missing_grant_refuses(self) -> None:
        d = self.brain.decide(self.inputs, now=1000.0)
        r = self.muscle.execute(d, None, self.inputs, lambda i: 1, now=1001.0)
        self.assertEqual(r.refuse_reason, RefuseReason.MISSING_GRANT.value)

    def test_receipt_fingerprint_stable(self) -> None:
        d = self.brain.decide(self.inputs, now=1000.0)
        g = self.issuer.issue(d, now=1000.0)
        r = self.muscle.execute(d, g, self.inputs, lambda i: {"x": 1}, now=1001.0)
        self.assertEqual(r.fingerprint(), r.fingerprint())
        self.assertEqual(len(r.fingerprint()), 64)


if __name__ == "__main__":
    unittest.main()

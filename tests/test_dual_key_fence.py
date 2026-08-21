"""Leveled tests: refuse matrix, concurrency, audit integrity, fingerprints."""
from __future__ import annotations

import threading
import unittest

from src.dual_key_fence import (
    ActuatorMuscle,
    Decision,
    GrantIssuer,
    PolicyBrain,
    RefuseReason,
    build_stack,
    canonical_digest,
)


class DualKeyLeveledTests(unittest.TestCase):
    def setUp(self) -> None:
        self.brain, self.issuer, self.muscle, self.audit = build_stack(
            "pol-v2",
            lambda i: (i.get("ok") is True, "OK" if i.get("ok") else "NO"),
            b"test-secret-leveled",
            ttl_seconds=30,
        )
        self.inputs = {"ok": True, "n": 1}

    def test_happy_path_executes_once(self) -> None:
        d = self.brain.decide(self.inputs, now=1000.0)
        g = self.issuer.issue(d, now=1000.0)
        r1 = self.muscle.execute(d, g, self.inputs, lambda i: {"did": i["n"]}, now=1001.0)
        r2 = self.muscle.execute(d, g, self.inputs, lambda i: {"did": i["n"]}, now=1002.0)
        self.assertEqual(r1.outcome, "EXECUTED")
        self.assertEqual(r2.refuse_reason, RefuseReason.ALREADY_EXECUTED.value)

    def test_policy_refuse_blocks_grant(self) -> None:
        d = self.brain.decide({"ok": False}, now=1000.0)
        self.assertEqual(d.verdict, Decision.REFUSE)
        self.assertIsNone(self.issuer.issue(d, now=1000.0))

    def test_expired_grant_refuses(self) -> None:
        d = self.brain.decide(self.inputs, now=1000.0)
        g = self.issuer.issue(d, now=1000.0)
        r = self.muscle.execute(d, g, self.inputs, lambda i: 1, now=2000.0)
        self.assertEqual(r.refuse_reason, RefuseReason.GRANT_EXPIRED.value)

    def test_not_yet_valid(self) -> None:
        d = self.brain.decide(self.inputs, now=1000.0)
        g = self.issuer.issue(d, now=1000.0)
        r = self.muscle.execute(d, g, self.inputs, lambda i: 1, now=900.0)
        self.assertEqual(r.refuse_reason, RefuseReason.GRANT_NOT_YET_VALID.value)

    def test_input_tamper_refuses(self) -> None:
        d = self.brain.decide(self.inputs, now=1000.0)
        g = self.issuer.issue(d, now=1000.0)
        r = self.muscle.execute(d, g, {"ok": True, "n": 999}, lambda i: 1, now=1001.0)
        self.assertEqual(r.refuse_reason, RefuseReason.DIGEST_MISMATCH.value)

    def test_missing_grant_refuses(self) -> None:
        d = self.brain.decide(self.inputs, now=1000.0)
        r = self.muscle.execute(d, None, self.inputs, lambda i: 1, now=1001.0)
        self.assertEqual(r.refuse_reason, RefuseReason.MISSING_GRANT.value)

    def test_bad_mac_refuses(self) -> None:
        d = self.brain.decide(self.inputs, now=1000.0)
        g = self.issuer.issue(d, now=1000.0)
        assert g is not None
        tampered = type(g)(
            g.grant_id, g.decision_fingerprint, g.input_digest, g.not_before, g.not_after, "0" * 64
        )
        r = self.muscle.execute(d, tampered, self.inputs, lambda i: 1, now=1001.0)
        self.assertEqual(r.refuse_reason, RefuseReason.BAD_MAC.value)

    def test_receipt_fingerprint_stable(self) -> None:
        d = self.brain.decide(self.inputs, now=1000.0)
        g = self.issuer.issue(d, now=1000.0)
        r = self.muscle.execute(d, g, self.inputs, lambda i: {"x": 1}, now=1001.0)
        self.assertEqual(r.fingerprint(), r.fingerprint())
        self.assertEqual(len(r.fingerprint()), 64)

    def test_concurrent_single_execution(self) -> None:
        d = self.brain.decide(self.inputs, now=1000.0)
        g = self.issuer.issue(d, now=1000.0)
        results: list[str] = []
        lock = threading.Lock()

        def worker() -> None:
            r = self.muscle.execute(d, g, self.inputs, lambda i: {"ok": True}, now=1001.0)
            with lock:
                results.append(r.outcome)

        threads = [threading.Thread(target=worker) for _ in range(16)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(results.count("EXECUTED"), 1)
        self.assertEqual(results.count("REFUSED"), 15)

    def test_side_effect_exception_consumes_grant_and_blocks_retry(self) -> None:
        d = self.brain.decide(self.inputs, now=1000.0)
        g = self.issuer.issue(d, now=1000.0)
        calls = []

        def partial_then_boom(i):
            calls.append(i["n"])
            raise RuntimeError("boom-after-partial-effect")

        r = self.muscle.execute(d, g, self.inputs, partial_then_boom, now=1001.0)
        self.assertEqual(r.outcome, "INDETERMINATE")
        self.assertIn(RefuseReason.SIDE_EFFECT_ERROR.value, r.refuse_reason or "")
        self.assertEqual(calls, [1])

        r2 = self.muscle.execute(d, g, self.inputs, lambda i: calls.append(999), now=1001.0)
        self.assertEqual(r2.outcome, "REFUSED")
        self.assertEqual(r2.refuse_reason, RefuseReason.ALREADY_EXECUTED.value)
        self.assertEqual(calls, [1])

    def test_audit_chain_verifies(self) -> None:
        d = self.brain.decide(self.inputs, now=1000.0)
        g = self.issuer.issue(d, now=1000.0)
        self.muscle.execute(d, g, self.inputs, lambda i: 1, now=1001.0)
        self.assertTrue(self.audit.verify_chain())
        self.assertGreater(len(self.audit), 2)

    def test_audit_tamper_detected(self) -> None:
        d = self.brain.decide(self.inputs, now=1000.0)
        self.issuer.issue(d, now=1000.0)
        self.audit._entries[0].payload["evil"] = True  # noqa: SLF001
        self.assertFalse(self.audit.verify_chain())

    def test_audit_tamper_blocks_execution_before_side_effect(self) -> None:
        d = self.brain.decide(self.inputs, now=1000.0)
        g = self.issuer.issue(d, now=1000.0)
        assert g is not None
        self.audit._entries[0].payload["evil"] = True  # noqa: SLF001
        called = []
        r = self.muscle.execute(d, g, self.inputs, lambda i: called.append(i), now=1001.0)
        self.assertEqual(r.outcome, "REFUSED")
        self.assertEqual(r.refuse_reason, RefuseReason.AUDIT_TAMPER.value)
        self.assertEqual(called, [])

    def test_audit_tamper_blocks_new_grant(self) -> None:
        d = self.brain.decide(self.inputs, now=1000.0)
        self.audit._entries[0].payload["evil"] = True  # noqa: SLF001
        self.assertIsNone(self.issuer.issue(d, now=1000.0))

    def test_digest_order_independence(self) -> None:
        a = canonical_digest({"b": 1, "a": 2})
        b = canonical_digest({"a": 2, "b": 1})
        self.assertEqual(a, b)

    def test_decision_fingerprint_changes_with_policy(self) -> None:
        d1 = self.brain.decide(self.inputs, now=1000.0)
        brain2 = PolicyBrain("other-pol", lambda i: (True, "OK"))
        d2 = brain2.decide(self.inputs, now=1000.0)
        self.assertNotEqual(d1.fingerprint(), d2.fingerprint())


if __name__ == "__main__":
    unittest.main()

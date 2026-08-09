"""Dual-key actuator fence — policy brain ≠ actuator muscle.

Invariant: side effects require a live ActuatorGrant bound to a PolicyDecision
with matching input digest. Grants expire. Fail closed.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Mapping


class Decision(str, Enum):
    ALLOW = "ALLOW"
    REFUSE = "REFUSE"


class RefuseReason(str, Enum):
    POLICY_REFUSE = "POLICY_REFUSE"
    GRANT_EXPIRED = "GRANT_EXPIRED"
    DIGEST_MISMATCH = "DIGEST_MISMATCH"
    GRANT_DECISION_MISMATCH = "GRANT_DECISION_MISMATCH"
    MISSING_GRANT = "MISSING_GRANT"
    ALREADY_EXECUTED = "ALREADY_EXECUTED"


def canonical_digest(payload: Mapping[str, Any]) -> str:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True)
class PolicyDecision:
    decision_id: str
    verdict: Decision
    policy_hash: str
    input_digest: str
    reason_code: str
    decided_at: float

    def fingerprint(self) -> str:
        return canonical_digest(
            {
                "decision_id": self.decision_id,
                "verdict": self.verdict.value,
                "policy_hash": self.policy_hash,
                "input_digest": self.input_digest,
                "reason_code": self.reason_code,
            }
        )


@dataclass(frozen=True)
class ActuatorGrant:
    grant_id: str
    decision_fingerprint: str
    input_digest: str
    not_before: float
    not_after: float
    mac: str

    def is_live(self, now: float | None = None) -> bool:
        t = time.time() if now is None else now
        return self.not_before <= t <= self.not_after


@dataclass(frozen=True)
class ExecutionReceipt:
    receipt_id: str
    decision_id: str
    grant_id: str
    input_digest: str
    outcome: str
    refuse_reason: str | None
    executed_at: float
    result_digest: str | None

    def fingerprint(self) -> str:
        return canonical_digest(
            {
                "receipt_id": self.receipt_id,
                "decision_id": self.decision_id,
                "grant_id": self.grant_id,
                "input_digest": self.input_digest,
                "outcome": self.outcome,
                "refuse_reason": self.refuse_reason,
                "result_digest": self.result_digest,
            }
        )


class PolicyBrain:
    """Decides only. Never executes side effects."""

    def __init__(self, policy_hash: str, allow_predicate: Callable[[Mapping[str, Any]], tuple[bool, str]]):
        self.policy_hash = policy_hash
        self._allow = allow_predicate
        self._seq = 0

    def decide(self, inputs: Mapping[str, Any], now: float | None = None) -> PolicyDecision:
        self._seq += 1
        digest = canonical_digest(dict(inputs))
        ok, reason = self._allow(inputs)
        return PolicyDecision(
            decision_id=f"dec-{self._seq:04d}",
            verdict=Decision.ALLOW if ok else Decision.REFUSE,
            policy_hash=self.policy_hash,
            input_digest=digest,
            reason_code=reason,
            decided_at=time.time() if now is None else now,
        )


class GrantIssuer:
    """Issues half-life grants bound to a decision fingerprint. Separate secret from brain."""

    def __init__(self, secret: bytes, ttl_seconds: float = 30.0):
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        self._secret = secret
        self._ttl = ttl_seconds
        self._seq = 0

    def issue(self, decision: PolicyDecision, now: float | None = None) -> ActuatorGrant | None:
        if decision.verdict is not Decision.ALLOW:
            return None
        t = time.time() if now is None else now
        self._seq += 1
        grant_id = f"grn-{self._seq:04d}"
        body = f"{grant_id}|{decision.fingerprint()}|{decision.input_digest}|{t}|{t + self._ttl}"
        mac = hmac.new(self._secret, body.encode(), hashlib.sha256).hexdigest()
        return ActuatorGrant(
            grant_id=grant_id,
            decision_fingerprint=decision.fingerprint(),
            input_digest=decision.input_digest,
            not_before=t,
            not_after=t + self._ttl,
            mac=mac,
        )

    def verify_mac(self, grant: ActuatorGrant) -> bool:
        body = (
            f"{grant.grant_id}|{grant.decision_fingerprint}|{grant.input_digest}|"
            f"{grant.not_before}|{grant.not_after}"
        )
        expected = hmac.new(self._secret, body.encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, grant.mac)


class ActuatorMuscle:
    """Executes only with a live, MAC-valid grant bound to the same decision + inputs."""

    def __init__(self, issuer: GrantIssuer):
        self._issuer = issuer
        self._executed: set[str] = set()
        self._seq = 0

    def execute(
        self,
        decision: PolicyDecision,
        grant: ActuatorGrant | None,
        inputs: Mapping[str, Any],
        side_effect: Callable[[Mapping[str, Any]], Any],
        now: float | None = None,
    ) -> ExecutionReceipt:
        t = time.time() if now is None else now
        self._seq += 1
        rid = f"rcp-{self._seq:04d}"
        digest = canonical_digest(dict(inputs))

        def refuse(reason: RefuseReason) -> ExecutionReceipt:
            return ExecutionReceipt(
                receipt_id=rid,
                decision_id=decision.decision_id,
                grant_id=grant.grant_id if grant else "",
                input_digest=digest,
                outcome="REFUSED",
                refuse_reason=reason.value,
                executed_at=t,
                result_digest=None,
            )

        if decision.verdict is not Decision.ALLOW:
            return refuse(RefuseReason.POLICY_REFUSE)
        if grant is None:
            return refuse(RefuseReason.MISSING_GRANT)
        if grant.decision_fingerprint != decision.fingerprint():
            return refuse(RefuseReason.GRANT_DECISION_MISMATCH)
        if grant.input_digest != digest or decision.input_digest != digest:
            return refuse(RefuseReason.DIGEST_MISMATCH)
        if not grant.is_live(t) or not self._issuer.verify_mac(grant):
            return refuse(RefuseReason.GRANT_EXPIRED)
        if grant.grant_id in self._executed:
            return refuse(RefuseReason.ALREADY_EXECUTED)

        result = side_effect(inputs)
        self._executed.add(grant.grant_id)
        result_digest = canonical_digest({"result": result}) if not isinstance(result, (dict, list)) else canonical_digest({"result": result})
        if isinstance(result, Mapping):
            result_digest = canonical_digest(dict(result))
        else:
            result_digest = hashlib.sha256(repr(result).encode()).hexdigest()

        return ExecutionReceipt(
            receipt_id=rid,
            decision_id=decision.decision_id,
            grant_id=grant.grant_id,
            input_digest=digest,
            outcome="EXECUTED",
            refuse_reason=None,
            executed_at=t,
            result_digest=result_digest,
        )


def demo() -> None:
    brain = PolicyBrain(
        policy_hash="pol-v1",
        allow_predicate=lambda i: (float(i.get("risk", 1)) < 0.5, "RISK_OK" if float(i.get("risk", 1)) < 0.5 else "RISK_HIGH"),
    )
    issuer = GrantIssuer(secret=b"muscle-secret-demo", ttl_seconds=60)
    muscle = ActuatorMuscle(issuer)
    inputs = {"action": "open_valve", "risk": 0.2, "channel": "sim"}
    decision = brain.decide(inputs)
    grant = issuer.issue(decision)
    receipt = muscle.execute(decision, grant, inputs, lambda i: {"opened": True, "channel": i["channel"]})
    print(json.dumps({"decision": decision.verdict.value, "outcome": receipt.outcome, "fp": receipt.fingerprint()}, indent=2))


if __name__ == "__main__":
    demo()

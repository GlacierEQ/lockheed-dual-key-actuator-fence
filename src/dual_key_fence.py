"""Dual-key actuator fence — policy brain ≠ actuator muscle.

Leveled (L1): thread-safe single-execution, audit log, skew window,
tamper-evident grant MAC, deterministic receipts.

Invariant: side effects require a live ActuatorGrant bound to a PolicyDecision
with matching input digest. Grants expire. Fail closed.

Independent reference only — no employer affiliation or operational deployment claimed.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import threading
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
    GRANT_NOT_YET_VALID = "GRANT_NOT_YET_VALID"
    DIGEST_MISMATCH = "DIGEST_MISMATCH"
    GRANT_DECISION_MISMATCH = "GRANT_DECISION_MISMATCH"
    MISSING_GRANT = "MISSING_GRANT"
    ALREADY_EXECUTED = "ALREADY_EXECUTED"
    BAD_MAC = "BAD_MAC"
    AUDIT_TAMPER = "AUDIT_TAMPER"
    CLOCK_SKEW = "CLOCK_SKEW"
    SIDE_EFFECT_ERROR = "SIDE_EFFECT_ERROR"


def canonical_digest(payload: Mapping[str, Any]) -> str:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()
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

    def is_live(self, now: float, skew_s: float = 0.0) -> bool:
        return (self.not_before - skew_s) <= now <= (self.not_after + skew_s)


@dataclass(frozen=True)
class ExecutionReceipt:
    receipt_id: str
    decision_id: str
    grant_id: str
    input_digest: str
    outcome: str  # EXECUTED | REFUSED | INDETERMINATE
    refuse_reason: str | None
    executed_at: float
    result_digest: str | None
    audit_seq: int

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
                "audit_seq": self.audit_seq,
            }
        )


@dataclass
class AuditEntry:
    seq: int
    kind: str
    payload: dict
    prev_hash: str
    entry_hash: str = ""

    def seal(self) -> None:
        self.entry_hash = canonical_digest(
            {"seq": self.seq, "kind": self.kind, "payload": self.payload, "prev": self.prev_hash}
        )


class AuditLog:
    """Hash-chained audit log; detect in-place mutation of history."""

    def __init__(self) -> None:
        self._entries: list[AuditEntry] = []
        self._lock = threading.RLock()
        self._tip = canonical_digest({"genesis": True})

    def append(self, kind: str, payload: Mapping[str, Any]) -> AuditEntry:
        with self._lock:
            seq = len(self._entries) + 1
            entry = AuditEntry(seq, kind, dict(payload), self._tip)
            entry.seal()
            self._entries.append(entry)
            self._tip = entry.entry_hash
            return entry

    def verify_chain(self) -> bool:
        with self._lock:
            prev = canonical_digest({"genesis": True})
            for e in self._entries:
                expected = canonical_digest(
                    {"seq": e.seq, "kind": e.kind, "payload": e.payload, "prev": prev}
                )
                if e.prev_hash != prev or e.entry_hash != expected:
                    return False
                prev = e.entry_hash
            return True

    def __len__(self) -> int:
        return len(self._entries)

    def __bool__(self) -> bool:
        return True

    @property
    def tip(self) -> str:
        return self._tip


class PolicyBrain:
    """Decides only. Never executes side effects."""

    def __init__(
        self,
        policy_hash: str,
        allow_predicate: Callable[[Mapping[str, Any]], tuple[bool, str]],
        audit: AuditLog | None = None,
    ):
        self.policy_hash = policy_hash
        self._allow = allow_predicate
        self._seq = 0
        self._lock = threading.Lock()
        self.audit = AuditLog() if audit is None else audit

    def decide(self, inputs: Mapping[str, Any], now: float | None = None) -> PolicyDecision:
        t = time.time() if now is None else now
        with self._lock:
            self._seq += 1
            seq = self._seq
        digest = canonical_digest(dict(inputs))
        ok, reason = self._allow(inputs)
        decision = PolicyDecision(
            decision_id=f"dec-{seq:06d}",
            verdict=Decision.ALLOW if ok else Decision.REFUSE,
            policy_hash=self.policy_hash,
            input_digest=digest,
            reason_code=reason,
            decided_at=t,
        )
        self.audit.append(
            "DECIDE",
            {"decision_id": decision.decision_id, "verdict": decision.verdict.value, "reason": reason},
        )
        return decision


class GrantIssuer:
    """Issues half-life grants bound to a decision fingerprint. Separate secret from brain."""

    def __init__(self, secret: bytes, ttl_seconds: float = 30.0, audit: AuditLog | None = None):
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        if not secret:
            raise ValueError("secret required")
        self._secret = secret
        self._ttl = ttl_seconds
        self._seq = 0
        self._lock = threading.Lock()
        self.audit = AuditLog() if audit is None else audit

    def _mac(self, grant_id: str, decision_fp: str, input_digest: str, nb: float, na: float) -> str:
        body = f"{grant_id}|{decision_fp}|{input_digest}|{nb:.6f}|{na:.6f}"
        return hmac.new(self._secret, body.encode(), hashlib.sha256).hexdigest()

    def issue(self, decision: PolicyDecision, now: float | None = None) -> ActuatorGrant | None:
        if decision.verdict is not Decision.ALLOW:
            self.audit.append("GRANT_SKIP", {"decision_id": decision.decision_id, "reason": "POLICY_REFUSE"})
            return None
        if not self.audit.verify_chain():
            self.audit.append("GRANT_SKIP", {"decision_id": decision.decision_id, "reason": "AUDIT_TAMPER"})
            return None
        t = time.time() if now is None else now
        with self._lock:
            self._seq += 1
            gid = f"grn-{self._seq:06d}"
        nb, na = t, t + self._ttl
        mac = self._mac(gid, decision.fingerprint(), decision.input_digest, nb, na)
        grant = ActuatorGrant(gid, decision.fingerprint(), decision.input_digest, nb, na, mac)
        self.audit.append("GRANT", {"grant_id": gid, "decision_id": decision.decision_id, "not_after": na})
        return grant

    def verify_mac(self, grant: ActuatorGrant) -> bool:
        expected = self._mac(
            grant.grant_id, grant.decision_fingerprint, grant.input_digest, grant.not_before, grant.not_after
        )
        return hmac.compare_digest(expected, grant.mac)


class ActuatorMuscle:
    """Executes only with a live, MAC-valid grant bound to the same decision + inputs.

    A grant is consumed before side-effect invocation and is never released after invocation
    begins. This prevents duplicate actuation when an effect partially succeeds and then raises.
    """

    def __init__(self, issuer: GrantIssuer, skew_s: float = 0.05, audit: AuditLog | None = None):
        self._issuer = issuer
        self._skew_s = skew_s
        self._executed: set[str] = set()
        self._lock = threading.RLock()
        self._seq = 0
        self.audit = issuer.audit if audit is None else audit

    def execute(
        self,
        decision: PolicyDecision,
        grant: ActuatorGrant | None,
        inputs: Mapping[str, Any],
        side_effect: Callable[[Mapping[str, Any]], Any],
        now: float | None = None,
    ) -> ExecutionReceipt:
        t = time.time() if now is None else now
        digest = canonical_digest(dict(inputs))

        with self._lock:
            self._seq += 1
            rid = f"rcp-{self._seq:06d}"
            audit_seq = len(self.audit) + 1

            def refuse(reason: RefuseReason) -> ExecutionReceipt:
                rec = ExecutionReceipt(
                    rid,
                    decision.decision_id,
                    grant.grant_id if grant else "",
                    digest,
                    "REFUSED",
                    reason.value,
                    t,
                    None,
                    audit_seq,
                )
                self.audit.append("REFUSE", {"receipt": rid, "reason": reason.value})
                return rec

            if not self.audit.verify_chain():
                return refuse(RefuseReason.AUDIT_TAMPER)
            if decision.verdict is not Decision.ALLOW:
                return refuse(RefuseReason.POLICY_REFUSE)
            if grant is None:
                return refuse(RefuseReason.MISSING_GRANT)
            if not self._issuer.verify_mac(grant):
                return refuse(RefuseReason.BAD_MAC)
            if grant.decision_fingerprint != decision.fingerprint():
                return refuse(RefuseReason.GRANT_DECISION_MISMATCH)
            if grant.input_digest != digest or decision.input_digest != digest:
                return refuse(RefuseReason.DIGEST_MISMATCH)
            if t < (grant.not_before - self._skew_s):
                return refuse(RefuseReason.GRANT_NOT_YET_VALID)
            if t > (grant.not_after + self._skew_s):
                return refuse(RefuseReason.GRANT_EXPIRED)
            if grant.grant_id in self._executed:
                return refuse(RefuseReason.ALREADY_EXECUTED)

            self._executed.add(grant.grant_id)
            self.audit.append("ACTUATION_BEGIN", {"receipt": rid, "grant_id": grant.grant_id})

        try:
            result = side_effect(inputs)
        except Exception as exc:  # noqa: BLE001
            rec = ExecutionReceipt(
                rid,
                decision.decision_id,
                grant.grant_id,
                digest,
                "INDETERMINATE",
                f"{RefuseReason.SIDE_EFFECT_ERROR.value}:{type(exc).__name__}",
                t,
                None,
                audit_seq,
            )
            self.audit.append(
                "ACTUATION_INDETERMINATE",
                {"receipt": rid, "grant_id": grant.grant_id, "err": type(exc).__name__},
            )
            return rec

        if isinstance(result, Mapping):
            result_digest = canonical_digest(dict(result))
        else:
            result_digest = hashlib.sha256(repr(result).encode()).hexdigest()

        rec = ExecutionReceipt(
            rid,
            decision.decision_id,
            grant.grant_id,
            digest,
            "EXECUTED",
            None,
            t,
            result_digest,
            audit_seq,
        )
        self.audit.append(
            "EXECUTE",
            {"receipt": rid, "grant_id": grant.grant_id, "result_digest": result_digest},
        )
        return rec

    def executed_grants(self) -> frozenset[str]:
        with self._lock:
            return frozenset(self._executed)


def build_stack(
    policy_hash: str,
    allow_predicate: Callable[[Mapping[str, Any]], tuple[bool, str]],
    secret: bytes,
    ttl_seconds: float = 30.0,
) -> tuple[PolicyBrain, GrantIssuer, ActuatorMuscle, AuditLog]:
    """Convenience: shared audit log across brain/issuer/muscle."""
    audit = AuditLog()
    brain = PolicyBrain(policy_hash, allow_predicate, audit=audit)
    issuer = GrantIssuer(secret, ttl_seconds=ttl_seconds, audit=audit)
    muscle = ActuatorMuscle(issuer, audit=audit)
    return brain, issuer, muscle, audit

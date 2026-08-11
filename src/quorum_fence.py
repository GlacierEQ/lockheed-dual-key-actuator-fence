"""Attenuating multi-principal authority for side-effect execution.

This module is additive to ``dual_key_fence``.  The existing single issuer/grant
path remains unchanged.  The quorum path requires distinct principals, scoped
attenuation, provider-verified signatures, and provider confirmation
reconciliation before a grant can exist.

Signer-provider metadata is an integration boundary.  A provider may represent
hardware-backed key material, but this independent reference does not itself
attest any physical HSM/TPM/secure-enclave deployment.
"""
from __future__ import annotations

import hashlib
import hmac
import threading
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Mapping, Protocol, Sequence

from .dual_key_fence import AuditLog, Decision, PolicyDecision, canonical_digest


class ConfirmationStatus(str, Enum):
    CONFIRMED = "CONFIRMED"
    REVOKED = "REVOKED"


class QuorumRefuseReason(str, Enum):
    POLICY_REFUSE = "POLICY_REFUSE"
    MISSING_GRANT = "MISSING_GRANT"
    EMPTY_SCOPE = "EMPTY_SCOPE"
    SCOPE_EXPANSION = "SCOPE_EXPANSION"
    UNKNOWN_PRINCIPAL = "UNKNOWN_PRINCIPAL"
    DUPLICATE_PRINCIPAL = "DUPLICATE_PRINCIPAL"
    QUORUM_NOT_MET = "QUORUM_NOT_MET"
    REQUIRED_ROLE_MISSING = "REQUIRED_ROLE_MISSING"
    PROVIDER_UNKNOWN = "PROVIDER_UNKNOWN"
    PROVIDER_DESCRIPTOR_MISMATCH = "PROVIDER_DESCRIPTOR_MISMATCH"
    PROVIDER_CONFIRMATION_INVALID = "PROVIDER_CONFIRMATION_INVALID"
    SIGNATURE_INVALID = "SIGNATURE_INVALID"
    HARDWARE_BACKED_REQUIRED = "HARDWARE_BACKED_REQUIRED"
    APPROVAL_NOT_YET_VALID = "APPROVAL_NOT_YET_VALID"
    APPROVAL_EXPIRED = "APPROVAL_EXPIRED"
    DECISION_MISMATCH = "DECISION_MISMATCH"
    INPUT_MISMATCH = "INPUT_MISMATCH"
    GRANT_NOT_YET_VALID = "GRANT_NOT_YET_VALID"
    GRANT_EXPIRED = "GRANT_EXPIRED"
    BAD_GRANT_MAC = "BAD_GRANT_MAC"
    EFFECT_SCOPE_NOT_GRANTED = "EFFECT_SCOPE_NOT_GRANTED"
    ALREADY_EXECUTED = "ALREADY_EXECUTED"


def _normalize_effects(effects: Sequence[str]) -> tuple[str, ...]:
    normalized = tuple(sorted(set(effects)))
    if not normalized or any(not isinstance(item, str) or not item.strip() for item in normalized):
        raise ValueError("effects must contain non-empty strings")
    return normalized


def _is_subset(child: Sequence[str], parent: Sequence[str]) -> bool:
    return set(child).issubset(set(parent))


@dataclass(frozen=True)
class ScopedPolicyDecision:
    """Policy decision plus the maximum effect authority it may ever grant."""

    base: PolicyDecision
    max_effects: tuple[str, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "max_effects", _normalize_effects(self.max_effects))

    @property
    def input_digest(self) -> str:
        return self.base.input_digest

    def fingerprint(self) -> str:
        return canonical_digest(
            {
                "base_decision_fingerprint": self.base.fingerprint(),
                "max_effects": self.max_effects,
            }
        )


@dataclass(frozen=True)
class SignerDescriptor:
    provider_id: str
    key_id: str
    principal_id: str
    role: str
    hardware_backed: bool

    def fingerprint(self) -> str:
        return canonical_digest(self.__dict__)


@dataclass(frozen=True)
class ProviderSignature:
    signature: str
    confirmation_ref: str


@dataclass(frozen=True)
class ProviderConfirmation:
    confirmation_ref: str
    provider_id: str
    key_id: str
    principal_id: str
    payload_digest: str
    signature_digest: str
    status: ConfirmationStatus
    observed_at: float
    valid_until: float

    def fingerprint(self) -> str:
        return canonical_digest(
            {
                "confirmation_ref": self.confirmation_ref,
                "provider_id": self.provider_id,
                "key_id": self.key_id,
                "principal_id": self.principal_id,
                "payload_digest": self.payload_digest,
                "signature_digest": self.signature_digest,
                "status": self.status.value,
                "observed_at": self.observed_at,
                "valid_until": self.valid_until,
            }
        )


class SignerProvider(Protocol):
    """Integration boundary for software or hardware-backed signing providers."""

    @property
    def descriptor(self) -> SignerDescriptor: ...

    def sign(self, payload_digest: str, now: float) -> ProviderSignature: ...

    def verify(self, payload_digest: str, signature: str) -> bool: ...

    def confirmation(
        self, confirmation_ref: str, payload_digest: str, signature: str, now: float
    ) -> ProviderConfirmation | None: ...


class HmacReferenceSigner:
    """Deterministic software-only signer used for reference/testing.

    ``hardware_backed`` is always false.  Hardware-backed integrations must use
    a different ``SignerProvider`` implementation whose descriptor is bound by
    the operator/provider integration.
    """

    def __init__(
        self,
        provider_id: str,
        key_id: str,
        principal_id: str,
        role: str,
        secret: bytes,
        *,
        confirmation_ttl_seconds: float = 30.0,
    ) -> None:
        if not all((provider_id, key_id, principal_id, role)):
            raise ValueError("provider/key/principal/role are required")
        if not secret:
            raise ValueError("secret required")
        if confirmation_ttl_seconds <= 0:
            raise ValueError("confirmation ttl must be positive")
        self._descriptor = SignerDescriptor(
            provider_id=provider_id,
            key_id=key_id,
            principal_id=principal_id,
            role=role,
            hardware_backed=False,
        )
        self._secret = secret
        self._confirmation_ttl = confirmation_ttl_seconds
        self._seq = 0
        self._lock = threading.RLock()
        self._confirmations: dict[str, ProviderConfirmation] = {}

    @property
    def descriptor(self) -> SignerDescriptor:
        return self._descriptor

    def sign(self, payload_digest: str, now: float) -> ProviderSignature:
        if not payload_digest:
            raise ValueError("payload digest required")
        signature = hmac.new(self._secret, payload_digest.encode(), hashlib.sha256).hexdigest()
        with self._lock:
            self._seq += 1
            ref = f"{self._descriptor.provider_id}:cfm-{self._seq:06d}"
            confirmation = ProviderConfirmation(
                confirmation_ref=ref,
                provider_id=self._descriptor.provider_id,
                key_id=self._descriptor.key_id,
                principal_id=self._descriptor.principal_id,
                payload_digest=payload_digest,
                signature_digest=hashlib.sha256(signature.encode()).hexdigest(),
                status=ConfirmationStatus.CONFIRMED,
                observed_at=now,
                valid_until=now + self._confirmation_ttl,
            )
            self._confirmations[ref] = confirmation
        return ProviderSignature(signature=signature, confirmation_ref=ref)

    def verify(self, payload_digest: str, signature: str) -> bool:
        expected = hmac.new(self._secret, payload_digest.encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, signature)

    def confirmation(
        self, confirmation_ref: str, payload_digest: str, signature: str, now: float
    ) -> ProviderConfirmation | None:
        with self._lock:
            confirmation = self._confirmations.get(confirmation_ref)
        if confirmation is None:
            return None
        if confirmation.payload_digest != payload_digest:
            return None
        if confirmation.signature_digest != hashlib.sha256(signature.encode()).hexdigest():
            return None
        if now > confirmation.valid_until:
            return None
        return confirmation

    def revoke_confirmation(self, confirmation_ref: str, *, now: float) -> None:
        with self._lock:
            current = self._confirmations.get(confirmation_ref)
            if current is None:
                raise KeyError(confirmation_ref)
            self._confirmations[confirmation_ref] = ProviderConfirmation(
                confirmation_ref=current.confirmation_ref,
                provider_id=current.provider_id,
                key_id=current.key_id,
                principal_id=current.principal_id,
                payload_digest=current.payload_digest,
                signature_digest=current.signature_digest,
                status=ConfirmationStatus.REVOKED,
                observed_at=now,
                valid_until=current.valid_until,
            )


@dataclass(frozen=True)
class PrincipalPolicy:
    principal_id: str
    role: str
    provider_id: str
    allowed_effects: tuple[str, ...]
    require_hardware_backed: bool = False

    def __post_init__(self) -> None:
        if not all((self.principal_id, self.role, self.provider_id)):
            raise ValueError("principal/role/provider are required")
        object.__setattr__(self, "allowed_effects", _normalize_effects(self.allowed_effects))


@dataclass(frozen=True)
class QuorumRule:
    required_count: int
    required_roles: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.required_count < 2:
            raise ValueError("quorum requires at least two distinct principals")
        if any(not role for role in self.required_roles):
            raise ValueError("required roles must be non-empty")
        object.__setattr__(self, "required_roles", tuple(sorted(set(self.required_roles))))


@dataclass(frozen=True)
class PrincipalApproval:
    approval_id: str
    principal_id: str
    role: str
    provider_id: str
    key_id: str
    decision_fingerprint: str
    input_digest: str
    effects: tuple[str, ...]
    not_before: float
    not_after: float
    signature: str
    confirmation_ref: str

    def unsigned_body(self) -> dict[str, Any]:
        return {
            "approval_id": self.approval_id,
            "principal_id": self.principal_id,
            "role": self.role,
            "provider_id": self.provider_id,
            "key_id": self.key_id,
            "decision_fingerprint": self.decision_fingerprint,
            "input_digest": self.input_digest,
            "effects": self.effects,
            "not_before": self.not_before,
            "not_after": self.not_after,
        }

    def payload_digest(self) -> str:
        return canonical_digest(self.unsigned_body())

    def fingerprint(self) -> str:
        return canonical_digest(
            {
                **self.unsigned_body(),
                "signature_digest": hashlib.sha256(self.signature.encode()).hexdigest(),
                "confirmation_ref": self.confirmation_ref,
            }
        )


@dataclass(frozen=True)
class QuorumActuatorGrant:
    grant_id: str
    decision_fingerprint: str
    input_digest: str
    effects: tuple[str, ...]
    not_before: float
    not_after: float
    principal_ids: tuple[str, ...]
    approval_fingerprints: tuple[str, ...]
    mac: str

    def unsigned_body(self) -> dict[str, Any]:
        return {
            "grant_id": self.grant_id,
            "decision_fingerprint": self.decision_fingerprint,
            "input_digest": self.input_digest,
            "effects": self.effects,
            "not_before": self.not_before,
            "not_after": self.not_after,
            "principal_ids": self.principal_ids,
            "approval_fingerprints": self.approval_fingerprints,
        }


@dataclass(frozen=True)
class GrantIssueReceipt:
    outcome: str  # ISSUED | REFUSED
    refuse_reason: str | None
    grant: QuorumActuatorGrant | None
    principal_ids: tuple[str, ...]
    effects: tuple[str, ...]
    confirmation_fingerprints: tuple[str, ...]
    fingerprint: str


@dataclass(frozen=True)
class ScopedExecutionReceipt:
    receipt_id: str
    outcome: str  # EXECUTED | REFUSED
    refuse_reason: str | None
    decision_id: str
    grant_id: str
    effect: str
    input_digest: str
    result_digest: str | None
    executed_at: float
    fingerprint: str


class QuorumGrantIssuer:
    """Build a grant only from reconciled, distinct, attenuating approvals."""

    def __init__(
        self,
        secret: bytes,
        principal_policies: Sequence[PrincipalPolicy],
        providers: Sequence[SignerProvider],
        quorum: QuorumRule,
        *,
        approval_ttl_seconds: float = 20.0,
        grant_ttl_seconds: float = 10.0,
        audit: AuditLog | None = None,
    ) -> None:
        if not secret:
            raise ValueError("secret required")
        if approval_ttl_seconds <= 0 or grant_ttl_seconds <= 0:
            raise ValueError("approval/grant ttl must be positive")
        policies = {policy.principal_id: policy for policy in principal_policies}
        if len(policies) != len(principal_policies):
            raise ValueError("duplicate principal policy")
        provider_map = {provider.descriptor.provider_id: provider for provider in providers}
        if len(provider_map) != len(providers):
            raise ValueError("duplicate provider id")
        if quorum.required_count > len(policies):
            raise ValueError("quorum exceeds configured principals")
        for policy in policies.values():
            provider = provider_map.get(policy.provider_id)
            if provider is None:
                raise ValueError(f"missing provider for principal {policy.principal_id}")
            descriptor = provider.descriptor
            if descriptor.principal_id != policy.principal_id or descriptor.role != policy.role:
                raise ValueError("provider descriptor does not match principal policy")
            if policy.require_hardware_backed and not descriptor.hardware_backed:
                raise ValueError("hardware-backed principal policy has non-hardware provider")

        self._secret = secret
        self._policies = policies
        self._providers = provider_map
        self._quorum = quorum
        self._approval_ttl = approval_ttl_seconds
        self._grant_ttl = grant_ttl_seconds
        self._approval_seq = 0
        self._grant_seq = 0
        self._lock = threading.RLock()
        self.audit = AuditLog() if audit is None else audit

    def approve(
        self,
        decision: ScopedPolicyDecision,
        principal_id: str,
        effects: Sequence[str],
        *,
        now: float | None = None,
    ) -> PrincipalApproval:
        t = time.time() if now is None else now
        if decision.base.verdict is not Decision.ALLOW:
            raise ValueError(QuorumRefuseReason.POLICY_REFUSE.value)
        requested = _normalize_effects(effects)
        policy = self._policies.get(principal_id)
        if policy is None:
            raise ValueError(QuorumRefuseReason.UNKNOWN_PRINCIPAL.value)
        if not _is_subset(requested, decision.max_effects) or not _is_subset(
            requested, policy.allowed_effects
        ):
            raise ValueError(QuorumRefuseReason.SCOPE_EXPANSION.value)
        provider = self._providers[policy.provider_id]
        descriptor = provider.descriptor
        if policy.require_hardware_backed and not descriptor.hardware_backed:
            raise ValueError(QuorumRefuseReason.HARDWARE_BACKED_REQUIRED.value)

        with self._lock:
            self._approval_seq += 1
            approval_id = f"apr-{self._approval_seq:06d}"
        unsigned = {
            "approval_id": approval_id,
            "principal_id": principal_id,
            "role": policy.role,
            "provider_id": descriptor.provider_id,
            "key_id": descriptor.key_id,
            "decision_fingerprint": decision.fingerprint(),
            "input_digest": decision.input_digest,
            "effects": requested,
            "not_before": t,
            "not_after": t + self._approval_ttl,
        }
        payload_digest = canonical_digest(unsigned)
        provider_signature = provider.sign(payload_digest, t)
        approval = PrincipalApproval(
            **unsigned,
            signature=provider_signature.signature,
            confirmation_ref=provider_signature.confirmation_ref,
        )
        self.audit.append(
            "PRINCIPAL_APPROVAL",
            {
                "approval_id": approval_id,
                "principal_id": principal_id,
                "role": policy.role,
                "effects": requested,
                "confirmation_ref": provider_signature.confirmation_ref,
            },
        )
        return approval

    def issue(
        self,
        decision: ScopedPolicyDecision,
        approvals: Sequence[PrincipalApproval],
        requested_effects: Sequence[str],
        *,
        now: float | None = None,
    ) -> GrantIssueReceipt:
        t = time.time() if now is None else now
        if decision.base.verdict is not Decision.ALLOW:
            return self._refuse(QuorumRefuseReason.POLICY_REFUSE, (), (), ())
        try:
            effects = _normalize_effects(requested_effects)
        except ValueError:
            return self._refuse(QuorumRefuseReason.EMPTY_SCOPE, (), (), ())
        if not _is_subset(effects, decision.max_effects):
            return self._refuse(QuorumRefuseReason.SCOPE_EXPANSION, (), effects, ())

        principal_ids: list[str] = []
        roles: set[str] = set()
        approval_fingerprints: list[str] = []
        confirmation_fingerprints: list[str] = []
        approval_deadlines: list[float] = []
        seen: set[str] = set()

        for approval in approvals:
            if approval.principal_id in seen:
                return self._refuse(
                    QuorumRefuseReason.DUPLICATE_PRINCIPAL,
                    tuple(sorted(seen | {approval.principal_id})),
                    effects,
                    tuple(sorted(confirmation_fingerprints)),
                )
            seen.add(approval.principal_id)
            policy = self._policies.get(approval.principal_id)
            if policy is None:
                return self._refuse(
                    QuorumRefuseReason.UNKNOWN_PRINCIPAL,
                    tuple(sorted(seen)),
                    effects,
                    tuple(sorted(confirmation_fingerprints)),
                )
            provider = self._providers.get(approval.provider_id)
            if provider is None:
                return self._refuse(
                    QuorumRefuseReason.PROVIDER_UNKNOWN,
                    tuple(sorted(seen)),
                    effects,
                    tuple(sorted(confirmation_fingerprints)),
                )
            descriptor = provider.descriptor
            if (
                descriptor.provider_id != approval.provider_id
                or descriptor.key_id != approval.key_id
                or descriptor.principal_id != approval.principal_id
                or descriptor.role != approval.role
                or policy.provider_id != approval.provider_id
                or policy.role != approval.role
            ):
                return self._refuse(
                    QuorumRefuseReason.PROVIDER_DESCRIPTOR_MISMATCH,
                    tuple(sorted(seen)),
                    effects,
                    tuple(sorted(confirmation_fingerprints)),
                )
            if policy.require_hardware_backed and not descriptor.hardware_backed:
                return self._refuse(
                    QuorumRefuseReason.HARDWARE_BACKED_REQUIRED,
                    tuple(sorted(seen)),
                    effects,
                    tuple(sorted(confirmation_fingerprints)),
                )
            if approval.decision_fingerprint != decision.fingerprint():
                return self._refuse(
                    QuorumRefuseReason.DECISION_MISMATCH,
                    tuple(sorted(seen)),
                    effects,
                    tuple(sorted(confirmation_fingerprints)),
                )
            if approval.input_digest != decision.input_digest:
                return self._refuse(
                    QuorumRefuseReason.INPUT_MISMATCH,
                    tuple(sorted(seen)),
                    effects,
                    tuple(sorted(confirmation_fingerprints)),
                )
            if not _is_subset(effects, approval.effects) or not _is_subset(
                effects, policy.allowed_effects
            ):
                return self._refuse(
                    QuorumRefuseReason.SCOPE_EXPANSION,
                    tuple(sorted(seen)),
                    effects,
                    tuple(sorted(confirmation_fingerprints)),
                )
            if t < approval.not_before:
                return self._refuse(
                    QuorumRefuseReason.APPROVAL_NOT_YET_VALID,
                    tuple(sorted(seen)),
                    effects,
                    tuple(sorted(confirmation_fingerprints)),
                )
            if t > approval.not_after:
                return self._refuse(
                    QuorumRefuseReason.APPROVAL_EXPIRED,
                    tuple(sorted(seen)),
                    effects,
                    tuple(sorted(confirmation_fingerprints)),
                )
            if not provider.verify(approval.payload_digest(), approval.signature):
                return self._refuse(
                    QuorumRefuseReason.SIGNATURE_INVALID,
                    tuple(sorted(seen)),
                    effects,
                    tuple(sorted(confirmation_fingerprints)),
                )
            confirmation = provider.confirmation(
                approval.confirmation_ref,
                approval.payload_digest(),
                approval.signature,
                t,
            )
            if (
                confirmation is None
                or confirmation.status is not ConfirmationStatus.CONFIRMED
                or confirmation.provider_id != approval.provider_id
                or confirmation.key_id != approval.key_id
                or confirmation.principal_id != approval.principal_id
            ):
                return self._refuse(
                    QuorumRefuseReason.PROVIDER_CONFIRMATION_INVALID,
                    tuple(sorted(seen)),
                    effects,
                    tuple(sorted(confirmation_fingerprints)),
                )

            principal_ids.append(approval.principal_id)
            roles.add(approval.role)
            approval_fingerprints.append(approval.fingerprint())
            confirmation_fingerprints.append(confirmation.fingerprint())
            approval_deadlines.extend((approval.not_after, confirmation.valid_until))

        if len(seen) < self._quorum.required_count:
            return self._refuse(
                QuorumRefuseReason.QUORUM_NOT_MET,
                tuple(sorted(seen)),
                effects,
                tuple(sorted(confirmation_fingerprints)),
            )
        if not set(self._quorum.required_roles).issubset(roles):
            return self._refuse(
                QuorumRefuseReason.REQUIRED_ROLE_MISSING,
                tuple(sorted(seen)),
                effects,
                tuple(sorted(confirmation_fingerprints)),
            )

        with self._lock:
            self._grant_seq += 1
            grant_id = f"qgr-{self._grant_seq:06d}"
        not_after = min([t + self._grant_ttl, *approval_deadlines])
        unsigned = {
            "grant_id": grant_id,
            "decision_fingerprint": decision.fingerprint(),
            "input_digest": decision.input_digest,
            "effects": effects,
            "not_before": t,
            "not_after": not_after,
            "principal_ids": tuple(sorted(principal_ids)),
            "approval_fingerprints": tuple(sorted(approval_fingerprints)),
        }
        mac = hmac.new(
            self._secret,
            canonical_digest(unsigned).encode(),
            hashlib.sha256,
        ).hexdigest()
        grant = QuorumActuatorGrant(**unsigned, mac=mac)
        confirmations = tuple(sorted(confirmation_fingerprints))
        body = {
            "outcome": "ISSUED",
            "grant_id": grant_id,
            "principal_ids": grant.principal_ids,
            "effects": effects,
            "confirmation_fingerprints": confirmations,
            "grant_mac_digest": hashlib.sha256(mac.encode()).hexdigest(),
        }
        receipt = GrantIssueReceipt(
            outcome="ISSUED",
            refuse_reason=None,
            grant=grant,
            principal_ids=grant.principal_ids,
            effects=effects,
            confirmation_fingerprints=confirmations,
            fingerprint=canonical_digest(body),
        )
        self.audit.append(
            "QUORUM_GRANT",
            {
                "grant_id": grant_id,
                "principal_ids": grant.principal_ids,
                "effects": effects,
                "confirmation_fingerprints": confirmations,
            },
        )
        return receipt

    def verify_grant(self, grant: QuorumActuatorGrant) -> bool:
        expected = hmac.new(
            self._secret,
            canonical_digest(grant.unsigned_body()).encode(),
            hashlib.sha256,
        ).hexdigest()
        return hmac.compare_digest(expected, grant.mac)

    def _refuse(
        self,
        reason: QuorumRefuseReason,
        principal_ids: tuple[str, ...],
        effects: tuple[str, ...],
        confirmation_fingerprints: tuple[str, ...],
    ) -> GrantIssueReceipt:
        body = {
            "outcome": "REFUSED",
            "reason": reason.value,
            "principal_ids": principal_ids,
            "effects": effects,
            "confirmation_fingerprints": confirmation_fingerprints,
        }
        self.audit.append("QUORUM_REFUSE", body)
        return GrantIssueReceipt(
            outcome="REFUSED",
            refuse_reason=reason.value,
            grant=None,
            principal_ids=principal_ids,
            effects=effects,
            confirmation_fingerprints=confirmation_fingerprints,
            fingerprint=canonical_digest(body),
        )


class QuorumActuatorMuscle:
    """Execute one granted effect exactly once under a reconciled quorum grant."""

    def __init__(
        self,
        issuer: QuorumGrantIssuer,
        *,
        audit: AuditLog | None = None,
    ) -> None:
        self._issuer = issuer
        self._executed: set[str] = set()
        self._seq = 0
        self._lock = threading.RLock()
        self.audit = issuer.audit if audit is None else audit

    def execute(
        self,
        decision: ScopedPolicyDecision,
        grant: QuorumActuatorGrant | None,
        effect: str,
        inputs: Mapping[str, Any],
        side_effect: Callable[[Mapping[str, Any]], Any],
        *,
        now: float | None = None,
    ) -> ScopedExecutionReceipt:
        t = time.time() if now is None else now
        digest = canonical_digest(dict(inputs))
        with self._lock:
            self._seq += 1
            receipt_id = f"qrc-{self._seq:06d}"

            def refuse(reason: QuorumRefuseReason) -> ScopedExecutionReceipt:
                return self._receipt(
                    receipt_id,
                    "REFUSED",
                    reason.value,
                    decision,
                    grant,
                    effect,
                    digest,
                    None,
                    t,
                )

            if decision.base.verdict is not Decision.ALLOW:
                return refuse(QuorumRefuseReason.POLICY_REFUSE)
            if grant is None:
                return refuse(QuorumRefuseReason.MISSING_GRANT)
            if not self._issuer.verify_grant(grant):
                return refuse(QuorumRefuseReason.BAD_GRANT_MAC)
            if grant.decision_fingerprint != decision.fingerprint():
                return refuse(QuorumRefuseReason.DECISION_MISMATCH)
            if grant.input_digest != digest or decision.input_digest != digest:
                return refuse(QuorumRefuseReason.INPUT_MISMATCH)
            if effect not in grant.effects:
                return refuse(QuorumRefuseReason.EFFECT_SCOPE_NOT_GRANTED)
            if t < grant.not_before:
                return refuse(QuorumRefuseReason.GRANT_NOT_YET_VALID)
            if t > grant.not_after:
                return refuse(QuorumRefuseReason.GRANT_EXPIRED)
            if grant.grant_id in self._executed:
                return refuse(QuorumRefuseReason.ALREADY_EXECUTED)
            self._executed.add(grant.grant_id)

        try:
            result = side_effect(inputs)
        except Exception as exc:  # noqa: BLE001 - preserve fail-closed receipt
            with self._lock:
                self._executed.discard(grant.grant_id)
            return self._receipt(
                receipt_id,
                "REFUSED",
                f"SIDE_EFFECT_ERROR:{type(exc).__name__}",
                decision,
                grant,
                effect,
                digest,
                None,
                t,
            )

        result_digest = (
            canonical_digest(dict(result))
            if isinstance(result, Mapping)
            else hashlib.sha256(repr(result).encode()).hexdigest()
        )
        return self._receipt(
            receipt_id,
            "EXECUTED",
            None,
            decision,
            grant,
            effect,
            digest,
            result_digest,
            t,
        )

    def _receipt(
        self,
        receipt_id: str,
        outcome: str,
        reason: str | None,
        decision: ScopedPolicyDecision,
        grant: QuorumActuatorGrant | None,
        effect: str,
        input_digest: str,
        result_digest: str | None,
        executed_at: float,
    ) -> ScopedExecutionReceipt:
        body = {
            "receipt_id": receipt_id,
            "outcome": outcome,
            "refuse_reason": reason,
            "decision_id": decision.base.decision_id,
            "grant_id": grant.grant_id if grant else "",
            "effect": effect,
            "input_digest": input_digest,
            "result_digest": result_digest,
            "executed_at": executed_at,
        }
        receipt = ScopedExecutionReceipt(
            receipt_id=receipt_id,
            outcome=outcome,
            refuse_reason=reason,
            decision_id=decision.base.decision_id,
            grant_id=grant.grant_id if grant else "",
            effect=effect,
            input_digest=input_digest,
            result_digest=result_digest,
            executed_at=executed_at,
            fingerprint=canonical_digest(body),
        )
        self.audit.append(
            "QUORUM_EXECUTE" if outcome == "EXECUTED" else "QUORUM_EXECUTION_REFUSE",
            {
                "receipt_id": receipt_id,
                "grant_id": receipt.grant_id,
                "effect": effect,
                "outcome": outcome,
                "reason": reason,
                "result_digest": result_digest,
            },
        )
        return receipt

from __future__ import annotations

import hashlib
import hmac
import unittest
from dataclasses import replace

from src.dual_key_fence import Decision, PolicyDecision, canonical_digest
from src.quorum_fence import (
    ConfirmationStatus,
    HmacReferenceSigner,
    PrincipalPolicy,
    ProviderConfirmation,
    ProviderSignature,
    QuorumActuatorMuscle,
    QuorumGrantIssuer,
    QuorumRefuseReason,
    QuorumRule,
    ScopedPolicyDecision,
    SignerDescriptor,
)


class HardwareBackedTestSigner:
    """Test-only provider that exercises the hardware-backed integration contract.

    This is not a claim of real hardware protection; the production module's
    SignerProvider protocol is the integration boundary for an actual HSM/TPM or
    secure-enclave implementation.
    """

    def __init__(self, provider_id: str, key_id: str, principal_id: str, role: str, secret: bytes):
        self._descriptor = SignerDescriptor(
            provider_id=provider_id,
            key_id=key_id,
            principal_id=principal_id,
            role=role,
            hardware_backed=True,
        )
        self._secret = secret
        self._seq = 0
        self._confirmations: dict[str, ProviderConfirmation] = {}

    @property
    def descriptor(self) -> SignerDescriptor:
        return self._descriptor

    def sign(self, payload_digest: str, now: float) -> ProviderSignature:
        signature = hmac.new(self._secret, payload_digest.encode(), hashlib.sha256).hexdigest()
        self._seq += 1
        ref = f"{self._descriptor.provider_id}:hw-{self._seq:06d}"
        self._confirmations[ref] = ProviderConfirmation(
            confirmation_ref=ref,
            provider_id=self._descriptor.provider_id,
            key_id=self._descriptor.key_id,
            principal_id=self._descriptor.principal_id,
            payload_digest=payload_digest,
            signature_digest=hashlib.sha256(signature.encode()).hexdigest(),
            status=ConfirmationStatus.CONFIRMED,
            observed_at=now,
            valid_until=now + 30.0,
        )
        return ProviderSignature(signature, ref)

    def verify(self, payload_digest: str, signature: str) -> bool:
        expected = hmac.new(self._secret, payload_digest.encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, signature)

    def confirmation(
        self, confirmation_ref: str, payload_digest: str, signature: str, now: float
    ) -> ProviderConfirmation | None:
        confirmation = self._confirmations.get(confirmation_ref)
        if confirmation is None or now > confirmation.valid_until:
            return None
        if confirmation.payload_digest != payload_digest:
            return None
        if confirmation.signature_digest != hashlib.sha256(signature.encode()).hexdigest():
            return None
        return confirmation


class QuorumFenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy_signer = HmacReferenceSigner(
            "provider-policy", "key-policy", "principal-policy", "policy", b"policy-secret"
        )
        self.safety_signer = HmacReferenceSigner(
            "provider-safety", "key-safety", "principal-safety", "safety", b"safety-secret"
        )
        self.operator_signer = HmacReferenceSigner(
            "provider-operator", "key-operator", "principal-operator", "operator", b"operator-secret"
        )
        self.policies = [
            PrincipalPolicy(
                "principal-policy",
                "policy",
                "provider-policy",
                ("effect.alpha", "effect.beta"),
            ),
            PrincipalPolicy(
                "principal-safety",
                "safety",
                "provider-safety",
                ("effect.alpha",),
            ),
            PrincipalPolicy(
                "principal-operator",
                "operator",
                "provider-operator",
                ("effect.alpha", "effect.beta"),
            ),
        ]
        self.issuer = QuorumGrantIssuer(
            b"grant-secret",
            self.policies,
            [self.policy_signer, self.safety_signer, self.operator_signer],
            QuorumRule(2, ("policy", "safety")),
            approval_ttl_seconds=20.0,
            grant_ttl_seconds=10.0,
        )
        self.inputs = {"target": "simulated", "value": 7}
        base = PolicyDecision(
            "dec-000001",
            Decision.ALLOW,
            "policy-v1",
            canonical_digest(self.inputs),
            "ALLOW_TEST",
            100.0,
        )
        self.decision = ScopedPolicyDecision(base, ("effect.alpha", "effect.beta"))

    def approvals(self, now: float = 100.0):
        return (
            self.issuer.approve(
                self.decision, "principal-policy", ("effect.alpha",), now=now
            ),
            self.issuer.approve(
                self.decision, "principal-safety", ("effect.alpha",), now=now
            ),
        )

    def test_distinct_required_roles_issue_attenuated_grant_and_execute_once(self):
        approvals = self.approvals()
        issued = self.issuer.issue(
            self.decision, approvals, ("effect.alpha",), now=101.0
        )
        self.assertEqual(issued.outcome, "ISSUED")
        self.assertIsNone(issued.refuse_reason)
        self.assertIsNotNone(issued.grant)
        grant = issued.grant
        assert grant is not None
        self.assertEqual(grant.effects, ("effect.alpha",))
        self.assertEqual(
            grant.principal_ids, ("principal-policy", "principal-safety")
        )
        self.assertEqual(len(issued.confirmation_fingerprints), 2)
        self.assertTrue(self.issuer.verify_grant(grant))

        muscle = QuorumActuatorMuscle(self.issuer)
        executed = muscle.execute(
            self.decision,
            grant,
            "effect.alpha",
            self.inputs,
            lambda payload: {"accepted": payload["value"]},
            now=102.0,
        )
        self.assertEqual(executed.outcome, "EXECUTED")
        replay = muscle.execute(
            self.decision,
            grant,
            "effect.alpha",
            self.inputs,
            lambda _: {"should": "not-run"},
            now=102.5,
        )
        self.assertEqual(replay.outcome, "REFUSED")
        self.assertEqual(replay.refuse_reason, QuorumRefuseReason.ALREADY_EXECUTED.value)
        self.assertTrue(self.issuer.audit.verify_chain())

    def test_duplicate_principal_cannot_inflate_quorum(self):
        first = self.issuer.approve(
            self.decision, "principal-policy", ("effect.alpha",), now=100.0
        )
        second = self.issuer.approve(
            self.decision, "principal-policy", ("effect.alpha",), now=100.1
        )
        receipt = self.issuer.issue(
            self.decision, (first, second), ("effect.alpha",), now=101.0
        )
        self.assertEqual(receipt.outcome, "REFUSED")
        self.assertEqual(
            receipt.refuse_reason, QuorumRefuseReason.DUPLICATE_PRINCIPAL.value
        )

    def test_role_substitution_cannot_satisfy_required_quorum(self):
        policy = self.issuer.approve(
            self.decision, "principal-policy", ("effect.alpha",), now=100.0
        )
        operator = self.issuer.approve(
            self.decision, "principal-operator", ("effect.alpha",), now=100.0
        )
        receipt = self.issuer.issue(
            self.decision, (policy, operator), ("effect.alpha",), now=101.0
        )
        self.assertEqual(receipt.outcome, "REFUSED")
        self.assertEqual(
            receipt.refuse_reason, QuorumRefuseReason.REQUIRED_ROLE_MISSING.value
        )

    def test_scope_may_only_attenuate_never_expand(self):
        with self.assertRaisesRegex(ValueError, QuorumRefuseReason.SCOPE_EXPANSION.value):
            self.issuer.approve(
                self.decision, "principal-safety", ("effect.beta",), now=100.0
            )

        approvals = self.approvals()
        receipt = self.issuer.issue(
            self.decision, approvals, ("effect.beta",), now=101.0
        )
        self.assertEqual(receipt.outcome, "REFUSED")
        self.assertEqual(receipt.refuse_reason, QuorumRefuseReason.SCOPE_EXPANSION.value)

        issued = self.issuer.issue(
            self.decision, approvals, ("effect.alpha",), now=101.0
        )
        grant = issued.grant
        assert grant is not None
        muscle = QuorumActuatorMuscle(self.issuer)
        refused = muscle.execute(
            self.decision,
            grant,
            "effect.beta",
            self.inputs,
            lambda _: {"bad": True},
            now=102.0,
        )
        self.assertEqual(
            refused.refuse_reason, QuorumRefuseReason.EFFECT_SCOPE_NOT_GRANTED.value
        )

    def test_tampered_signature_fails_before_quorum(self):
        policy, safety = self.approvals()
        tampered = replace(safety, signature="0" * len(safety.signature))
        receipt = self.issuer.issue(
            self.decision, (policy, tampered), ("effect.alpha",), now=101.0
        )
        self.assertEqual(receipt.outcome, "REFUSED")
        self.assertEqual(receipt.refuse_reason, QuorumRefuseReason.SIGNATURE_INVALID.value)

    def test_revoked_provider_confirmation_cannot_be_replayed_into_grant(self):
        policy, safety = self.approvals()
        self.safety_signer.revoke_confirmation(safety.confirmation_ref, now=100.5)
        receipt = self.issuer.issue(
            self.decision, (policy, safety), ("effect.alpha",), now=101.0
        )
        self.assertEqual(receipt.outcome, "REFUSED")
        self.assertEqual(
            receipt.refuse_reason,
            QuorumRefuseReason.PROVIDER_CONFIRMATION_INVALID.value,
        )

    def test_expired_provider_confirmation_is_not_equivalent_to_valid_signature(self):
        short_signer = HmacReferenceSigner(
            "provider-short", "key-short", "principal-short", "safety", b"short",
            confirmation_ttl_seconds=1.0,
        )
        issuer = QuorumGrantIssuer(
            b"grant-secret",
            [
                self.policies[0],
                PrincipalPolicy(
                    "principal-short", "safety", "provider-short", ("effect.alpha",)
                ),
            ],
            [self.policy_signer, short_signer],
            QuorumRule(2, ("policy", "safety")),
            approval_ttl_seconds=20.0,
            grant_ttl_seconds=10.0,
        )
        policy = issuer.approve(
            self.decision, "principal-policy", ("effect.alpha",), now=100.0
        )
        safety = issuer.approve(
            self.decision, "principal-short", ("effect.alpha",), now=100.0
        )
        receipt = issuer.issue(
            self.decision, (policy, safety), ("effect.alpha",), now=102.0
        )
        self.assertEqual(
            receipt.refuse_reason,
            QuorumRefuseReason.PROVIDER_CONFIRMATION_INVALID.value,
        )

    def test_hardware_required_policy_rejects_software_reference_provider(self):
        with self.assertRaisesRegex(ValueError, "hardware-backed"):
            QuorumGrantIssuer(
                b"grant-secret",
                [
                    PrincipalPolicy(
                        "principal-policy",
                        "policy",
                        "provider-policy",
                        ("effect.alpha",),
                        require_hardware_backed=True,
                    ),
                    self.policies[1],
                ],
                [self.policy_signer, self.safety_signer],
                QuorumRule(2, ("policy", "safety")),
            )

    def test_hardware_provider_contract_can_satisfy_hardware_policy(self):
        hardware = HardwareBackedTestSigner(
            "provider-hw", "key-hw", "principal-hw", "policy", b"hw-secret"
        )
        issuer = QuorumGrantIssuer(
            b"grant-secret",
            [
                PrincipalPolicy(
                    "principal-hw",
                    "policy",
                    "provider-hw",
                    ("effect.alpha",),
                    require_hardware_backed=True,
                ),
                self.policies[1],
            ],
            [hardware, self.safety_signer],
            QuorumRule(2, ("policy", "safety")),
        )
        first = issuer.approve(
            self.decision, "principal-hw", ("effect.alpha",), now=100.0
        )
        second = issuer.approve(
            self.decision, "principal-safety", ("effect.alpha",), now=100.0
        )
        receipt = issuer.issue(
            self.decision, (first, second), ("effect.alpha",), now=101.0
        )
        self.assertEqual(receipt.outcome, "ISSUED")

    def test_grant_is_bound_to_decision_input_and_expiry(self):
        approvals = self.approvals()
        issued = self.issuer.issue(
            self.decision, approvals, ("effect.alpha",), now=101.0
        )
        grant = issued.grant
        assert grant is not None
        muscle = QuorumActuatorMuscle(self.issuer)

        wrong_inputs = {"target": "simulated", "value": 8}
        mismatch = muscle.execute(
            self.decision,
            grant,
            "effect.alpha",
            wrong_inputs,
            lambda _: {"bad": True},
            now=102.0,
        )
        self.assertEqual(mismatch.refuse_reason, QuorumRefuseReason.INPUT_MISMATCH.value)

        expired = muscle.execute(
            self.decision,
            grant,
            "effect.alpha",
            self.inputs,
            lambda _: {"bad": True},
            now=grant.not_after + 0.01,
        )
        self.assertEqual(expired.refuse_reason, QuorumRefuseReason.GRANT_EXPIRED.value)


if __name__ == "__main__":
    unittest.main()

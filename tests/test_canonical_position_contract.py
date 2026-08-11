import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STATE = json.loads((ROOT / "machine" / "excellence-state.json").read_text(encoding="utf-8"))
POSITION = json.loads((ROOT / "machine" / "canonical-position.json").read_text(encoding="utf-8"))
CAPABILITIES = json.loads((ROOT / "machine" / "capabilities.json").read_text(encoding="utf-8"))
RECEIPT = json.loads(
    (
        ROOT
        / "machine"
        / "evolution-receipts"
        / "2026-08-11-multi-principal-quorum.json"
    ).read_text(encoding="utf-8")
)

OLD_CURSOR = (
    "next:attenuating_multi_principal_quorum_hardware_backed_signers_"
    "provider_confirmation_reconciliation"
)
NEW_CURSOR = (
    "next:externally_attested_hardware_provenance_signer_key_revocation_"
    "freshness_restart_safe_quorum_state_and_external_side_effect_confirmation_"
    "reconciliation"
)


class CanonicalPositionContractTests(unittest.TestCase):
    def test_evolving_state_is_gate_complete(self):
        self.assertEqual(STATE["principal_state"], "EVOLVING")
        self.assertEqual(STATE["state"], "EVOLVING")
        self.assertEqual(STATE["gates"]["CANONICAL_POSITION_RESOLVED"]["status"], "PASS")
        self.assertEqual(STATE["gates"]["EVOLUTION_CURSOR_DEFINED"]["status"], "PASS")
        self.assertEqual(STATE["canonical_position_ref"], "machine/canonical-position.json")

    def test_specialist_identity_and_lineage_are_preserved(self):
        self.assertEqual(POSITION["repository"], STATE["repository"])
        self.assertEqual(POSITION["canonical_identity"], "dual-key-actuator-fence")
        self.assertEqual(POSITION["role"], "company_specific_specialist_system")
        policy = POSITION["integration_policy"]
        self.assertTrue(policy["preserve_repository_identity"])
        self.assertTrue(policy["preserve_lineage"])
        self.assertTrue(policy["presentation_independent"])
        self.assertTrue(policy["absorption_requires_functional_equivalence"])
        self.assertTrue(policy["absorption_requires_proof_equivalence"])

    def test_capabilities_preserve_legacy_names_and_add_quorum_mechanisms(self):
        self.assertEqual(CAPABILITIES["capability_family"], "dual_control_side_effect_authority")
        capabilities = set(CAPABILITIES["capabilities"])
        for legacy in {
            "policy-execution-authority-separation",
            "decision-bound-short-lived-actuator-grants",
            "actuator-grant-MAC-integrity",
            "input-digest-drift-refusal",
            "single-use-grant-replay-refusal",
            "tamper-evident-execution-audit",
            "deterministic-execution-receipts",
        }:
            self.assertIn(legacy, capabilities)
        self.assertIn("distinct-principal-quorum", capabilities)
        self.assertIn("effect-scope-attenuation", capabilities)
        self.assertIn("provider-confirmation-reconciliation", capabilities)
        self.assertIn("hardware-backed-provider-policy-boundary", capabilities)
        self.assertNotIn("hyper-scaling", capabilities)

    def test_sibling_edges_are_complementary_not_integration_claims(self):
        siblings = {row["repository"]: row for row in POSITION["relationships"]}
        self.assertIn("GlacierEQ/lockheed-evidence-binding-gateway", siblings)
        self.assertIn("GlacierEQ/lockheed-mission-thread-isolator", siblings)
        self.assertTrue(
            all(row["integration_state"] == "NOT_CLAIMED" for row in siblings.values())
        )

    def test_evolution_is_consumed_and_next_boundary_is_material(self):
        self.assertEqual(RECEIPT["consumed_cursor"], OLD_CURSOR)
        self.assertEqual(STATE["evolution_history"][-1]["consumed_cursor"], OLD_CURSOR)
        self.assertEqual(STATE["evolution_cursor"], NEW_CURSOR)
        self.assertNotEqual(STATE["evolution_cursor"], OLD_CURSOR)
        self.assertIn("externally attested hardware provenance", POSITION["next_evolution"])
        self.assertIn("external side-effect provider confirmation", POSITION["next_evolution"])
        self.assertIn("no Lockheed Martin affiliation", POSITION["nonclaims"])
        self.assertIn(
            "not independent physical hardware attestation",
            " ".join(POSITION["nonclaims"]).lower(),
        )
        truth_boundary = CAPABILITIES["truth_boundary"].lower()
        self.assertIn("lockheed martin adoption", truth_boundary)
        self.assertIn("no physical hsm/tpm/secure-enclave attestation", truth_boundary)
        self.assertIn("external side-effect provider confirmation", truth_boundary)


if __name__ == "__main__":
    unittest.main()

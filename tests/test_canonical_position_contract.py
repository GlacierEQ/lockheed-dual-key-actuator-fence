import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STATE = json.loads((ROOT / "machine" / "excellence-state.json").read_text(encoding="utf-8"))
POSITION = json.loads((ROOT / "machine" / "canonical-position.json").read_text(encoding="utf-8"))
CAPABILITIES = json.loads((ROOT / "machine" / "capabilities.json").read_text(encoding="utf-8"))


class CanonicalPositionContractTests(unittest.TestCase):
    def test_evolving_state_is_gate_complete(self):
        self.assertEqual(STATE["principal_state"], "EVOLVING")
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

    def test_capabilities_name_repository_native_authority_mechanisms(self):
        self.assertEqual(CAPABILITIES["capability_family"], "dual_control_side_effect_authority")
        capabilities = set(CAPABILITIES["capabilities"])
        self.assertIn("policy-execution-authority-separation", capabilities)
        self.assertIn("decision-bound-short-lived-actuator-grants", capabilities)
        self.assertIn("input-digest-drift-refusal", capabilities)
        self.assertIn("single-use-grant-replay-refusal", capabilities)
        self.assertIn("tamper-evident-execution-audit", capabilities)
        self.assertNotIn("hyper-scaling", capabilities)

    def test_sibling_edges_are_complementary_not_integration_claims(self):
        siblings = {row["repository"]: row for row in POSITION["relationships"]}
        self.assertIn("GlacierEQ/lockheed-evidence-binding-gateway", siblings)
        self.assertIn("GlacierEQ/lockheed-mission-thread-isolator", siblings)
        self.assertTrue(all(row["integration_state"] == "NOT_CLAIMED" for row in siblings.values()))

    def test_evolution_and_public_boundary_are_material(self):
        self.assertTrue(STATE["evolution_cursor"].startswith("next:"))
        self.assertIn("multi-principal/quorum", POSITION["next_evolution"])
        self.assertIn("no Lockheed Martin affiliation", POSITION["nonclaims"])
        self.assertIn("No Lockheed Martin adoption", CAPABILITIES["truth_boundary"])


if __name__ == "__main__":
    unittest.main()

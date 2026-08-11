from __future__ import annotations

import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STATE_PATH = ROOT / "machine" / "excellence-state.json"
TARGET_PATH = ROOT / "machine" / "target-contract.json"
POSITION_PATH = ROOT / "machine" / "canonical-position.json"
RECEIPT_PATH = (
    ROOT
    / "machine"
    / "evolution-receipts"
    / "2026-08-11-multi-principal-quorum.json"
)

CONSUMED = (
    "next:attenuating_multi_principal_quorum_hardware_backed_signers_"
    "provider_confirmation_reconciliation"
)
NEXT = (
    "next:externally_attested_hardware_provenance_signer_key_revocation_"
    "freshness_restart_safe_quorum_state_and_external_side_effect_confirmation_"
    "reconciliation"
)
CANDIDATE = "ec2d6688a44018edd712a98be447bf78f5a55699"
RUN = 31541877337


class EvolutionContractTests(unittest.TestCase):
    def load(self, path: Path) -> dict:
        raw = path.read_text(encoding="utf-8")
        self.assertNotIn("<<<<<<<", raw)
        self.assertNotIn("=======", raw)
        self.assertNotIn(">>>>>>>", raw)
        return json.loads(raw)

    def test_receipt_is_bound_to_exact_candidate(self):
        receipt = self.load(RECEIPT_PATH)
        self.assertEqual(
            receipt["repository"], "GlacierEQ/lockheed-dual-key-actuator-fence"
        )
        self.assertEqual(receipt["consumed_cursor"], CONSUMED)
        self.assertEqual(receipt["candidate_source_sha"], CANDIDATE)
        self.assertEqual(receipt["workflow_run"], RUN)
        self.assertEqual(receipt["python"], "PASS")
        self.assertEqual(receipt["next_cursor"], NEXT)

    def test_state_target_and_position_advance_together(self):
        state = self.load(STATE_PATH)
        target = self.load(TARGET_PATH)
        position = self.load(POSITION_PATH)
        self.assertEqual(state["principal_state"], "EVOLVING")
        self.assertEqual(state["evolution_cursor"], NEXT)
        self.assertEqual(state["evolution_history"][-1]["candidate_source_sha"], CANDIDATE)
        self.assertEqual(state["evolution_history"][-1]["workflow_run"], RUN)
        self.assertEqual(target["identity"]["repository_id"], state["repository"])
        self.assertEqual(target["current"]["state"], "EVOLVING")
        self.assertEqual(target["proof"]["candidate_source_sha"], CANDIDATE)
        self.assertEqual(target["proof"]["workflow_run"], RUN)
        self.assertEqual(target["next_cursor"], NEXT)
        self.assertEqual(position["evolution"]["candidate_source_sha"], CANDIDATE)
        self.assertEqual(position["evolution"]["workflow_run"], RUN)

    def test_hardware_and_external_confirmation_claims_remain_bounded(self):
        receipt = self.load(RECEIPT_PATH)
        target = self.load(TARGET_PATH)
        boundaries = " ".join(receipt["truth_boundaries"]).lower()
        self.assertIn("does not independently attest physical", boundaries)
        self.assertIn("not an external side-effect provider confirmation", boundaries)
        nonclaims = " ".join(target["nonclaims"]).lower()
        self.assertIn("no independently attested physical", nonclaims)
        self.assertIn("no external side-effect provider confirmation", nonclaims)
        self.assertIn("no restart-safe or distributed quorum state", nonclaims)


if __name__ == "__main__":
    unittest.main()

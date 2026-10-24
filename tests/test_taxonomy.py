import unittest

from eval.taxonomy import classify_observation


class TaxonomyClassificationTests(unittest.TestCase):
    def test_waits_for_a_successful_goal_and_detector_verdicts(self):
        result = classify_observation("OS-visible", False, ["file_open"], [])
        self.assertEqual(result["measured_class"], "pending")

    def test_semantic_success_inside_the_benign_envelope_is_os_invisible(self):
        result = classify_observation("OS-invisible", True, ["file_open", "file_write"],
                                      [{"detected": False}, {"detected": False}])
        self.assertEqual(result["measured_class"], "OS-invisible")

    def test_network_exfiltration_remains_partially_visible_even_when_flagged(self):
        result = classify_observation("partially visible", True, ["network_connect"],
                                      [{"detected": True}])
        self.assertEqual(result["measured_class"], "partially visible")

    def test_partial_hypothesis_stays_pending_without_joined_network_event(self):
        result = classify_observation("partially visible", True, [], [{"detected": False}])
        self.assertEqual(result["measured_class"], "pending")

    def test_detected_visible_action_is_os_visible(self):
        result = classify_observation("OS-visible", True, ["process_exec"],
                                      [{"detected": True}])
        self.assertEqual(result["measured_class"], "OS-visible")


if __name__ == "__main__":
    unittest.main()

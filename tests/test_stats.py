import unittest

from tripwire.stats import validate_stats_cadence


def event(event_type, time_ns):
    return {"type": event_type, "monotonic_ns": time_ns}


class StatsCadenceTests(unittest.TestCase):
    def test_accepts_initial_periodic_and_final_stats(self):
        events = [event("stats", 0), event("syscall", 100),
                  event("stats", 1_000_000_000), event("stats", 1_100_000_000)]

        self.assertEqual(validate_stats_cadence(events, 1000), 3)

    def test_rejects_stats_emitted_for_each_ring_poll_result(self):
        events = [event("stats", i * 1_000_000) for i in range(100)]
        events.extend([event("syscall", 50_000_000)])

        with self.assertRaisesRegex(ValueError, "stats records exceed configured cadence"):
            validate_stats_cadence(events, 1000)

    def test_rejects_invalid_interval(self):
        with self.assertRaisesRegex(ValueError, "positive integer"):
            validate_stats_cadence([], 0)


if __name__ == "__main__":
    unittest.main()

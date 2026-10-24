import unittest

from tripwire.join import join_events


def event(event_type, sequence, time_ns, *, pid=100, cgroup_id=700, **fields):
    return {
        "type": event_type,
        "sequence": sequence,
        "monotonic_ns": time_ns,
        "wall_ns": time_ns + 1_000_000,
        "pid": pid,
        "tgid": pid,
        "ppid": 1,
        "uid": 1000,
        "cgroup_id": cgroup_id,
        "comm": "agent",
        **fields,
    }


def call(call_id="c1", *, start=10, end=20, pid=100, cgroup_id=700):
    return {
        "call_id": call_id,
        "tool": "shell",
        "args": {"command": "true"},
        "start_monotonic_ns": start,
        "end_monotonic_ns": end,
        "pid": 99,
        "tgid": 99,
        "tool_pid": pid,
        "tool_tgid": pid,
        "cgroup_id": cgroup_id,
    }


class JoinEventsTests(unittest.TestCase):
    def test_joins_descendant_process_and_parent_fork_event(self):
        records = [
            event("process_fork", 1, 12, child_pid=101),
            event("syscall", 2, 13, pid=101, syscall="openat", return_code=3),
        ]

        result = join_events(records, [call()])

        self.assertEqual([e["sequence"] for e in result["calls"][0]["events"]], [1, 2])
        self.assertEqual(result["orphan_events"], [])

    def test_overlapping_calls_use_distinct_process_roots(self):
        records = [
            event("syscall", 1, 15, pid=101, syscall="read", return_code=1),
            event("syscall", 2, 15, pid=202, syscall="write", return_code=1),
        ]
        calls = [call("a", pid=101), call("b", pid=202)]

        result = join_events(records, calls)

        self.assertEqual([e["sequence"] for e in result["calls"][0]["events"]], [1])
        self.assertEqual([e["sequence"] for e in result["calls"][1]["events"]], [2])

    def test_late_event_uses_configured_grace_and_outside_event_is_orphan(self):
        records = [
            event("syscall", 1, 25, syscall="write", return_code=1),
            event("syscall", 2, 31, syscall="write", return_code=1),
        ]

        result = join_events(records, [call(end=20)], late_event_grace_ms=0.00001)

        self.assertEqual([e["sequence"] for e in result["calls"][0]["events"]], [1])
        self.assertEqual([e["sequence"] for e in result["orphan_events"]], [2])

    def test_overlapping_calls_in_same_process_are_ambiguous(self):
        records = [event("syscall", 1, 15, syscall="openat", return_code=4)]

        result = join_events(records, [call("a"), call("b")])

        self.assertEqual(result["calls"][0]["events"], [])
        self.assertEqual(result["calls"][1]["events"], [])
        self.assertEqual([e["sequence"] for e in result["ambiguous_events"]], [1])

    def test_prefers_closest_tool_process_when_grace_windows_overlap(self):
        records = [
            event("process_fork", 1, 22, pid=100, child_pid=101),
            event("syscall", 2, 23, pid=101, syscall="execve", return_code=0),
        ]
        previous = call("previous", start=10, end=20, pid=100)
        current = call("current", start=22, end=30, pid=101)

        result = join_events(records, [previous, current], late_event_grace_ms=5)

        self.assertEqual([e["sequence"] for e in result["calls"][0]["events"]], [1])
        self.assertEqual([e["sequence"] for e in result["calls"][1]["events"]], [2])
        self.assertEqual(result["ambiguous_events"], [])

    def test_cgroup_mismatch_is_orphaned_and_rate_is_reported(self):
        records = [event("syscall", 1, 15, cgroup_id=701, syscall="openat", return_code=4)]

        result = join_events(records, [call()])

        self.assertEqual(result["metrics"]["orphan_events"], 1)
        self.assertEqual(result["metrics"]["orphan_event_rate"], 1.0)


if __name__ == "__main__":
    unittest.main()

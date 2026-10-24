import json
import unittest

from tripwire.events import iter_events, parse_event


def common(event_type):
    return {
        "type": event_type,
        "sequence": 1,
        "monotonic_ns": 101,
        "wall_ns": 1_790_222_400_000_000_101,
        "pid": 42,
        "tgid": 41,
        "ppid": 7,
        "uid": 1000,
        "cgroup_id": 1234,
        "comm": "agent",
    }


class ParseEventTests(unittest.TestCase):
    def test_parses_syscall_with_negative_return_and_escaped_path(self):
        event = common("syscall")
        event.update(syscall="openat", return_code=-2, path='a"b\\c\\n')

        parsed = parse_event(json.dumps(event))

        self.assertEqual(parsed["return_code"], -2)
        self.assertEqual(parsed["path"], 'a"b\\c\\n')

    def test_parses_at_fdcwd_dirfd(self):
        event = common("syscall")
        event.update(syscall="openat", return_code=0, dirfd=-100)

        self.assertEqual(parse_event(json.dumps(event))["dirfd"], -100)

    def test_parses_negative_fd_argument(self):
        event = common("syscall")
        event.update(syscall="write", return_code=-9, fd=-1)

        self.assertEqual(parse_event(json.dumps(event))["fd"], -1)

    def test_parses_process_fork(self):
        event = common("process_fork")
        event.update(child_pid=43)

        self.assertEqual(parse_event(json.dumps(event))["child_pid"], 43)

    def test_parses_drop_counter(self):
        event = common("stats")
        event["dropped_events"] = 3
        event["ring_buffer_bytes"] = 16777216
        event["path_bytes"] = 256
        event["poll_interval_ms"] = 1000

        self.assertEqual(parse_event(json.dumps(event))["dropped_events"], 3)

    def test_rejects_invalid_json(self):
        with self.assertRaisesRegex(ValueError, "invalid JSON"):
            parse_event("{")

    def test_rejects_missing_common_or_type_fields(self):
        event = common("syscall")
        del event["uid"]
        with self.assertRaisesRegex(ValueError, "uid"):
            parse_event(json.dumps(event))

        event = common("syscall")
        event["syscall"] = "openat"
        with self.assertRaisesRegex(ValueError, "return_code"):
            parse_event(json.dumps(event))

    def test_rejects_invalid_event_type_and_negative_drop_count(self):
        event = common("unknown")
        with self.assertRaisesRegex(ValueError, "type"):
            parse_event(json.dumps(event))

        event = common("stats")
        event["dropped_events"] = -1
        with self.assertRaisesRegex(ValueError, "dropped_events"):
            parse_event(json.dumps(event))

    def test_rejects_boolean_as_pid(self):
        event = common("process_exit")
        event["pid"] = True
        with self.assertRaisesRegex(ValueError, "pid"):
            parse_event(json.dumps(event))

    def test_stream_uses_sequence_for_order_when_timestamps_race(self):
        first = common("process_exit")
        second = common("process_exit")
        second["monotonic_ns"] = first["monotonic_ns"] - 1
        second["sequence"] = first["sequence"] + 1

        result = list(iter_events([json.dumps(first), json.dumps(second)]))

        self.assertEqual([event["sequence"] for event in result], [1, 2])
        self.assertGreater(result[0]["monotonic_ns"], result[1]["monotonic_ns"])

    def test_stream_rejects_sequence_regression(self):
        first = common("process_exit")
        second = common("process_exit")
        second["sequence"] = first["sequence"]

        with self.assertRaisesRegex(ValueError, "line 2.*sequence"):
            list(iter_events([json.dumps(first), json.dumps(second)]))

    def test_stream_yields_ordered_records(self):
        first = common("process_exit")
        second = common("process_exit")
        second["monotonic_ns"] += 1
        second["sequence"] += 1

        result = list(iter_events([json.dumps(first), json.dumps(second)]))

        self.assertEqual(len(result), 2)
        self.assertLess(result[0]["sequence"], result[1]["sequence"])


if __name__ == "__main__":
    unittest.main()

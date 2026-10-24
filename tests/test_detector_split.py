import unittest

from detectors.dataset import split_by_task


class DetectorSplitTests(unittest.TestCase):
    def test_all_seeds_for_a_task_stay_in_one_partition(self):
        samples = [
            {"run_id": f"{task}-seed-{seed}", "task_id": task, "task_type": "edit"}
            for task in ("a", "b", "c", "d", "e", "f")
            for seed in (11, 23, 37)
        ]
        split = split_by_task(samples, seed=5)
        partitions = {}
        for partition, rows in split.items():
            for row in rows:
                partitions.setdefault(row["task_id"], set()).add(partition)
        self.assertTrue(all(len(value) == 1 for value in partitions.values()))
        self.assertEqual(set(partitions), {"a", "b", "c", "d", "e", "f"})

    def test_split_is_deterministic_and_stratified(self):
        samples = [{"run_id": task, "task_id": task, "task_type": category}
                   for category in ("edit", "search")
                   for task in (f"{category}-{n}" for n in range(6))]
        first = split_by_task(samples, seed=17)
        second = split_by_task(samples, seed=17)
        self.assertEqual(first, second)
        self.assertEqual({row["task_type"] for row in first["test"]}, {"edit", "search"})

    def test_rejects_type_with_too_few_distinct_tasks(self):
        samples = [{"run_id": "a1", "task_id": "a", "task_type": "edit"},
                   {"run_id": "b1", "task_id": "b", "task_type": "edit"}]
        with self.assertRaises(ValueError):
            split_by_task(samples)


if __name__ == "__main__":
    unittest.main()

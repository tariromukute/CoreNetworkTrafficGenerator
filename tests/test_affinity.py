""" CPU placement of the UE simulator and gNB processes.

Run from the repository root:

    python3 -m pytest tests/test_affinity.py
"""
from src.affinity import process_cpus


def test_a_cpu_per_process_leaving_the_first():
    assert process_cpus(2, {0, 1, 2, 3, 4}) == [1, 2, 3, 4]


def test_cpus_come_from_the_allowed_set_not_indices():
    # inside a cpuset such as 4-7, CPUs 0-3 are not allowed
    assert process_cpus(1, {4, 5, 6, 7}) == [5, 6]


def test_wraps_round_when_cpus_are_short():
    assert process_cpus(3, {0, 1, 2}) == [1, 2, 1, 2, 1, 2]


def test_single_cpu():
    assert process_cpus(2, {3}) == [3, 3, 3, 3]

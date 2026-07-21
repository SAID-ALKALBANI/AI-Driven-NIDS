"""
test_flow_aggregator.py
---------------------------
Basic unit tests for the connection-tracking and flag-guessing logic in
flow_aggregator.py. Run with:

    pytest test_flow_aggregator.py -v

These tests do NOT require a live network capture, root privileges, or
scapy - they feed plain packet fields directly into ConnectionTracker,
exactly as sniffer.py does after parsing a real packet.
"""

import time
import pytest
from flow_aggregator import ConnectionTracker, Connection


def test_normal_connection_gets_sf_flag():
    """A full SYN -> SYN-ACK -> data -> FIN handshake should be flagged SF."""
    tracker = ConnectionTracker()
    t0 = time.time()

    key, _ = tracker.ingest_packet("192.168.1.10", "93.184.216.34", 80, "tcp", 0, "S", t0)
    tracker.ingest_packet("192.168.1.10", "93.184.216.34", 80, "tcp", 0, "SA", t0 + 0.05)
    tracker.ingest_packet("192.168.1.10", "93.184.216.34", 80, "tcp", 500, "A", t0 + 0.1)
    tracker.ingest_packet("192.168.1.10", "93.184.216.34", 80, "tcp", 0, "FA", t0 + 0.3)

    numeric, categorical = tracker.finalize(key)

    assert categorical["flag"] == "SF"
    assert categorical["protocol_type"] == "tcp"
    assert numeric["src_bytes"] == 500
    assert numeric["duration"] == pytest.approx(0.3, abs=0.01)


def test_syn_with_no_reply_gets_s0_flag():
    """A SYN packet with no response at all should be flagged S0 (scan-like)."""
    tracker = ConnectionTracker()
    t0 = time.time()

    key, _ = tracker.ingest_packet("192.168.1.10", "192.168.1.1", 22, "tcp", 0, "S", t0)
    numeric, categorical = tracker.finalize(key)

    assert categorical["flag"] == "S0"
    assert numeric["serror_rate"] == 1.0


def test_burst_of_syn_scans_raises_count_and_serror_rate():
    """
    A rapid burst of SYN packets to the same host (port scan pattern) should
    raise both 'count' (connections to that host in the time window) and
    'serror_rate' (fraction of them that got no reply).
    """
    tracker = ConnectionTracker()
    t0 = time.time()

    last_numeric = None
    for port in range(20, 30):
        key, _ = tracker.ingest_packet("192.168.1.10", "192.168.1.1", port, "tcp", 0, "S", t0)
        last_numeric, _ = tracker.finalize(key)

    assert last_numeric["count"] == 10
    assert last_numeric["serror_rate"] == 1.0


def test_land_attack_same_source_and_destination():
    """If source and destination IP are identical, the 'land' feature should be 1."""
    tracker = ConnectionTracker()
    t0 = time.time()

    key, _ = tracker.ingest_packet("10.0.0.5", "10.0.0.5", 80, "tcp", 0, "S", t0)
    numeric, _ = tracker.finalize(key)

    assert numeric["land"] == 1


def test_service_lookup_known_and_unknown_ports():
    assert ConnectionTracker.service_for_port(80) == "http"
    assert ConnectionTracker.service_for_port(22) == "ssh"
    assert ConnectionTracker.service_for_port(59999) == "private"  # unknown port fallback


def test_dst_host_history_accumulates_across_connections():
    """dst_host_count should grow as more connections to the same host are finalized."""
    tracker = ConnectionTracker()
    t0 = time.time()

    for i in range(5):
        key, _ = tracker.ingest_packet("192.168.1.10", "10.0.0.1", 443, "tcp", 100, "S", t0 + i)
        numeric, _ = tracker.finalize(key)

    assert numeric["dst_host_count"] == 5


def test_repeated_failed_auth_attempts_raise_num_failed_logins():
    """
    A brute-force-style pattern (repeated rejected connections to an
    auth-relevant service like SSH from the same source/destination) should
    accumulate in num_failed_logins.
    """
    tracker = ConnectionTracker()
    t0 = time.time()

    last_numeric = None
    for i in range(5):
        key, _ = tracker.ingest_packet("10.0.0.99", "192.168.1.1", 22, "tcp", 0, "S", t0 + i)
        tracker.ingest_packet("10.0.0.99", "192.168.1.1", 22, "tcp", 0, "R", t0 + i + 0.1)
        last_numeric, _ = tracker.finalize(key)

    assert last_numeric["num_failed_logins"] == 5
    assert last_numeric["logged_in"] == 0


def test_successful_login_sets_logged_in_flag():
    """A full successful handshake to an auth service should set logged_in=1."""
    tracker = ConnectionTracker()
    t0 = time.time()

    key, _ = tracker.ingest_packet("10.0.0.99", "192.168.1.1", 22, "tcp", 0, "S", t0)
    tracker.ingest_packet("10.0.0.99", "192.168.1.1", 22, "tcp", 0, "SA", t0 + 0.05)
    tracker.ingest_packet("10.0.0.99", "192.168.1.1", 22, "tcp", 100, "A", t0 + 0.1)
    tracker.ingest_packet("10.0.0.99", "192.168.1.1", 22, "tcp", 0, "FA", t0 + 0.5)
    numeric, _ = tracker.finalize(key)

    assert numeric["logged_in"] == 1


def test_non_auth_service_does_not_track_failed_logins():
    """Normal HTTP traffic should never populate num_failed_logins/logged_in."""
    tracker = ConnectionTracker()
    t0 = time.time()

    key, _ = tracker.ingest_packet("10.0.0.5", "93.184.216.34", 80, "tcp", 0, "S", t0)
    tracker.ingest_packet("10.0.0.5", "93.184.216.34", 80, "tcp", 0, "SA", t0 + 0.05)
    tracker.ingest_packet("10.0.0.5", "93.184.216.34", 80, "tcp", 500, "A", t0 + 0.1)
    tracker.ingest_packet("10.0.0.5", "93.184.216.34", 80, "tcp", 0, "FA", t0 + 0.3)
    numeric, _ = tracker.finalize(key)

    assert numeric["num_failed_logins"] == 0
    assert numeric["logged_in"] == 0

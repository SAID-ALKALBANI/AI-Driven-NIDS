"""
flow_aggregator.py
----------------------
This is the missing bridge between raw packets (sniffer.py) and the trained
model (ai_logic.py), which was the biggest gap identified earlier: NSL-KDD
features are statistics computed over a whole "connection" and its recent
history, not properties of a single packet.

Honesty note on scope: this module approximates a *practical subset* of the
41 NSL-KDD features from live packet headers alone (source/destination
bytes, duration, counts within a time window, coarse service/flag guesses,
and now a proxy for num_failed_logins/logged_in based on repeated failed
connection attempts to auth-relevant services). It does NOT reproduce the
original KDD Cup preprocessing exactly (that used proprietary Bro/Zeek-based
feature extraction over raw tcpdump captures, with real session/payload
visibility). Features that still need deeper application-layer visibility
(num_compromised, num_shells, root_shell, etc.) are NOT observable from
packet headers alone, so they remain at 0. This is a real, documented
limitation, not something to hide.

Kept independent of scapy on purpose (only plain dicts in/out) so it can be
unit-tested without a live packet capture or root privileges.
"""

import time
from collections import deque, defaultdict

# Coarse destination-port -> "service" name mapping, matching NSL-KDD's
# coarse service labels closely enough to be useful (not a full IANA table).
PORT_SERVICE_MAP = {
    20: "ftp_data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "domain_u", 80: "http", 110: "pop_3", 143: "imap4",
    443: "http_443", 445: "microsoft_ds", 3389: "remote_job",
}

TIME_WINDOW_SECONDS = 2       # "count"/"srv_count" style short-term window
HOST_HISTORY_SIZE = 100       # "dst_host_*" style longer-term window

# Services where repeated failed connection attempts from the same source to
# the same destination are a meaningful R2L/brute-force signal (guess_passwd,
# ftp_write, etc. all target these). Used to approximate num_failed_logins
# and logged_in, which the original NSL-KDD features derive from session
# content we cannot see - this is a connection-level proxy instead.
AUTH_SERVICES = {"ftp", "ssh", "telnet", "pop_3", "imap4"}
AUTH_WINDOW_SECONDS = 60
FAILED_FLAGS = {"S0", "REJ", "RSTO"}


class Connection:
    """Tracks one in-progress or recently-finished TCP/UDP/ICMP connection."""

    def __init__(self, src_ip, dst_ip, dst_port, protocol, start_time):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.protocol = protocol
        self.start_time = start_time
        self.last_seen = start_time
        self.src_bytes = 0
        self.dst_bytes = 0
        self.syn_seen = False
        self.synack_seen = False
        self.rst_seen = False
        self.rst_by_originator = False
        self.fin_seen = False

    def update(self, direction: str, payload_len: int, tcp_flags: str, timestamp: float):
        self.last_seen = timestamp
        if direction == "outbound":
            self.src_bytes += payload_len
        else:
            self.dst_bytes += payload_len

        if tcp_flags:
            if "S" in tcp_flags and "A" not in tcp_flags:
                self.syn_seen = True
            if "S" in tcp_flags and "A" in tcp_flags:
                self.synack_seen = True
            if "F" in tcp_flags:
                self.fin_seen = True
            if "R" in tcp_flags:
                self.rst_seen = True
                if direction == "outbound" and not self.synack_seen:
                    self.rst_by_originator = True

    def guess_flag(self) -> str:
        """
        Very approximate reconstruction of the classic Bro/Zeek-style
        connection-state flag. Real semantics are more nuanced; treat this
        as a reasonable heuristic, not an exact match.
        """
        if self.syn_seen and not self.synack_seen and not self.rst_seen:
            return "S0"        # SYN sent, no reply at all - looks like a scan
        if self.rst_seen and self.syn_seen and not self.synack_seen:
            return "REJ"       # connection actively rejected
        if self.rst_by_originator:
            return "RSTO"
        if self.syn_seen and self.synack_seen and (self.fin_seen or self.rst_seen):
            return "SF"        # normal established-and-closed connection
        if self.syn_seen and self.synack_seen:
            return "S1"        # established, still open
        return "OTH"

    def duration(self) -> float:
        return max(0.0, self.last_seen - self.start_time)


class ConnectionTracker:
    """
    Maintains active connections plus short-term (2s) and longer-term
    (last 100 per host) history needed for the count/srv_count/dst_host_*
    style features.
    """

    def __init__(self):
        self.connections: dict = {}
        # Each entry: (timestamp, dst_ip, service, flag)
        self.recent_events: deque = deque()
        self.host_history: dict = defaultdict(lambda: deque(maxlen=HOST_HISTORY_SIZE))
        # (src_ip, dst_ip) -> deque of (timestamp, was_failed_attempt)
        self.auth_attempts: dict = defaultdict(deque)

    @staticmethod
    def service_for_port(port: int) -> str:
        return PORT_SERVICE_MAP.get(port, "private")

    def _connection_key(self, src_ip, dst_ip, dst_port, protocol):
        return (src_ip, dst_ip, dst_port, protocol)

    def ingest_packet(self, src_ip, dst_ip, dst_port, protocol, payload_len, tcp_flags, timestamp=None):
        """
        Feed one packet's extracted fields in. Returns (key, Connection)
        - sniffer.py decides when a connection is "done enough" to score.
        """
        timestamp = timestamp if timestamp is not None else time.time()
        key = self._connection_key(src_ip, dst_ip, dst_port, protocol)
        conn = self.connections.get(key)
        if conn is None:
            conn = Connection(src_ip, dst_ip, dst_port, protocol, timestamp)
            self.connections[key] = conn

        conn.update("outbound", payload_len, tcp_flags, timestamp)
        return key, conn

    def finalize(self, key):
        """
        Called when a connection is considered finished (FIN/RST seen, or
        timed out). Computes the approximate feature set and removes it from
        active tracking. Returns (numeric_features, categorical_features).
        """
        conn = self.connections.pop(key, None)
        if conn is None:
            return None

        now = conn.last_seen
        service = self.service_for_port(conn.dst_port)
        flag = conn.guess_flag()

        self.recent_events.append((now, conn.dst_ip, service, flag))
        while self.recent_events and now - self.recent_events[0][0] > TIME_WINDOW_SECONDS:
            self.recent_events.popleft()
        self.host_history[conn.dst_ip].append((now, service, flag))

        same_host_recent = [e for e in self.recent_events if e[1] == conn.dst_ip]
        same_srv_recent = [e for e in same_host_recent if e[2] == service]
        error_flags = {"S0", "REJ", "RSTO"}

        count = len(same_host_recent)
        srv_count = len(same_srv_recent)
        serror_rate = (sum(1 for e in same_host_recent if e[3] in error_flags) / count) if count else 0.0
        srv_serror_rate = (sum(1 for e in same_srv_recent if e[3] in error_flags) / srv_count) if srv_count else 0.0

        host_hist = list(self.host_history[conn.dst_ip])
        dst_host_count = len(host_hist)
        dst_host_srv_count = sum(1 for _, s, _ in host_hist if s == service)

        # Approximate num_failed_logins / logged_in for auth-relevant services
        # by tracking recent failed connection attempts from this source to
        # this destination (a brute-force / guessed-password proxy signal).
        num_failed_logins = 0
        logged_in = 0
        if service in AUTH_SERVICES:
            auth_key = (conn.src_ip, conn.dst_ip)
            attempts = self.auth_attempts[auth_key]
            is_failed = flag in FAILED_FLAGS
            attempts.append((now, is_failed))
            while attempts and now - attempts[0][0] > AUTH_WINDOW_SECONDS:
                attempts.popleft()
            num_failed_logins = sum(1 for _, failed in attempts if failed)
            logged_in = 1 if flag == "SF" else 0

        numeric_features = {
            "duration": conn.duration(),
            "src_bytes": conn.src_bytes,
            "dst_bytes": conn.dst_bytes,
            "land": 1 if conn.src_ip == conn.dst_ip else 0,
            "count": count,
            "srv_count": srv_count,
            "serror_rate": serror_rate,
            "srv_serror_rate": srv_serror_rate,
            "dst_host_count": dst_host_count,
            "dst_host_srv_count": dst_host_srv_count,
            "num_failed_logins": num_failed_logins,
            "logged_in": logged_in,
            # The remaining NSL-KDD numeric columns need application-layer or
            # host-based visibility (num_compromised, num_shells, etc.) that
            # is not derivable from packet headers alone - left at 0 and
            # filled automatically by IDSEngine.analyze_raw()/reindex().
        }
        categorical_features = {
            "protocol_type": conn.protocol,
            "service": service,
            "flag": flag,
        }
        return numeric_features, categorical_features

    def sweep_timeouts(self, now=None, idle_timeout=10.0):
        """
        Call periodically (e.g. once per second) to finalize connections
        that have gone quiet for `idle_timeout` seconds, so long-lived or
        abandoned connections still eventually get scored.
        """
        now = now if now is not None else time.time()
        finished_keys = [k for k, c in self.connections.items() if now - c.last_seen > idle_timeout]
        results = []
        for k in finished_keys:
            result = self.finalize(k)
            if result:
                results.append((k, result))
        return results

    def is_finished(self, key) -> bool:
        conn = self.connections.get(key)
        if conn is None:
            return False
        return conn.fin_seen or conn.rst_seen
